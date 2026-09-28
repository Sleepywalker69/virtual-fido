package usbip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/bulwarkid/virtual-fido/util"
)

var usbipLogger = util.NewLogger("[USBIP] ", util.LogLevelTrace)
var errLogger = util.NewLogger("[ERR] ", util.LogLevelEnabled)

// DefaultAddress is the standard USB/IP port on the loopback interface. The
// device must never be reachable from the network.
const DefaultAddress = "127.0.0.1:3240"

// maxTransferLength bounds the buffer allocated for one URB so a corrupt or
// hostile header cannot make the server allocate gigabytes.
const maxTransferLength = 64 * 1024

type USBIPServer struct {
	devices []USBIPDevice

	// OnImportChanged, if set, is called when a host imports a device or its
	// connection ends. It must not block.
	OnImportChanged func(busID string, imported bool)

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	imported map[string]bool
	closed   bool
}

func NewUSBIPServer(devices []USBIPDevice) *USBIPServer {
	return &USBIPServer{
		devices:  devices,
		conns:    make(map[net.Conn]struct{}),
		imported: make(map[string]bool),
	}
}

// Start serves on DefaultAddress forever and panics if the port cannot be
// opened. Prefer ListenAndServe, which reports errors.
func (server *USBIPServer) Start() {
	err := server.ListenAndServe(DefaultAddress)
	util.CheckErr(err, "Could not run USB/IP server")
}

// ListenAndServe listens on address and serves connections until Close is
// called, after which it returns nil.
func (server *USBIPServer) ListenAndServe(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return server.Serve(listener)
}

// Serve accepts USB/IP connections on listener until Close is called.
func (server *USBIPServer) Serve(listener net.Listener) error {
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		listener.Close()
		return nil
	}
	server.listener = listener
	server.mu.Unlock()
	usbipLogger.Printf("USB/IP server listening on %s\n\n", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			if server.isClosed() {
				return nil
			}
			errLogger.Printf("USB/IP accept failed: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if !isLoopback(conn.RemoteAddr()) {
			errLogger.Printf("Rejected USB/IP connection from non-local address %s", conn.RemoteAddr())
			conn.Close()
			continue
		}
		if !server.trackConn(conn) {
			conn.Close()
			return nil
		}
		go server.serveConn(conn)
	}
}

// Close stops accepting connections and disconnects every host.
func (server *USBIPServer) Close() error {
	server.mu.Lock()
	server.closed = true
	listener := server.listener
	conns := make([]net.Conn, 0, len(server.conns))
	for conn := range server.conns {
		conns = append(conns, conn)
	}
	server.mu.Unlock()
	var err error
	if listener != nil {
		err = listener.Close()
	}
	for _, conn := range conns {
		conn.Close()
	}
	return err
}

// Imported reports whether a host currently has the device with busID imported.
func (server *USBIPServer) Imported(busID string) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.imported[busID]
}

func (server *USBIPServer) isClosed() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.closed
}

func (server *USBIPServer) trackConn(conn net.Conn) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed {
		return false
	}
	server.conns[conn] = struct{}{}
	return true
}

func (server *USBIPServer) untrackConn(conn net.Conn) {
	server.mu.Lock()
	delete(server.conns, conn)
	server.mu.Unlock()
}

// claim marks busID as imported; only one host may use a device at a time.
func (server *USBIPServer) claim(busID string) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.imported[busID] {
		return false
	}
	server.imported[busID] = true
	return true
}

func (server *USBIPServer) release(busID string) {
	server.mu.Lock()
	delete(server.imported, busID)
	server.mu.Unlock()
}

func (server *USBIPServer) notifyImport(busID string, imported bool) {
	if server.OnImportChanged != nil {
		server.OnImportChanged(busID, imported)
	}
}

func (server *USBIPServer) getDevice(busID string) USBIPDevice {
	for _, device := range server.devices {
		if device.BusID() == busID {
			return device
		}
	}
	return nil
}

func (server *USBIPServer) serveConn(netConn net.Conn) {
	conn := newUSBIPConnection(server, netConn)
	defer func() {
		if r := recover(); r != nil {
			errLogger.Printf("USB/IP connection %s failed: %v", netConn.RemoteAddr(), r)
		}
		conn.close()
		server.untrackConn(netConn)
		usbipLogger.Printf("USB/IP connection closed for %s\n\n", netConn.RemoteAddr())
	}()
	if err := conn.handle(); err != nil && !isDisconnect(err) && !server.isClosed() {
		errLogger.Printf("USB/IP connection %s failed: %v", netConn.RemoteAddr(), err)
	}
}

type usbipConnection struct {
	responseMutex sync.Mutex
	conn          net.Conn
	server        *USBIPServer
	dead          bool
}

func newUSBIPConnection(server *USBIPServer, conn net.Conn) *usbipConnection {
	return &usbipConnection{conn: conn, server: server}
}

func (conn *usbipConnection) handle() error {
	for {
		var header usbipControlHeader
		if err := readBE(conn.conn, &header); err != nil {
			return err
		}
		usbipLogger.Printf("[CONTROL MESSAGE] %#v\n\n", header)
		switch header.Command {
		case usbipCommandOpReqDevlist:
			conn.writeResponse(encodeOpRepDevlist(conn.server.devices))
		case usbipCommandOpReqImport:
			busIDData := make([]byte, 32)
			if _, err := io.ReadFull(conn.conn, busIDData); err != nil {
				return err
			}
			busID := cString(busIDData)
			device := conn.server.getDevice(busID)
			if device == nil {
				errLogger.Printf("USB/IP host asked for unknown device %q", busID)
				conn.writeResponse(util.ToBE(opRepImportError(opStatusNoDevice)))
				return nil
			}
			if !conn.server.claim(busID) {
				errLogger.Printf("USB/IP host asked for device %s, which is already attached elsewhere", busID)
				conn.writeResponse(util.ToBE(opRepImportError(opStatusDeviceBusy)))
				return nil
			}
			return conn.serveImport(busID, device)
		default:
			return fmt.Errorf("unknown USB/IP operation 0x%x", header.Command)
		}
	}
}

func (conn *usbipConnection) serveImport(busID string, device USBIPDevice) error {
	device.Attached()
	defer func() {
		device.Detached()
		conn.server.release(busID)
		conn.server.notifyImport(busID, false)
	}()
	reply := newOpRepImport(device)
	usbipLogger.Printf("[OP_REP_IMPORT] %s\n\n", reply)
	conn.writeResponse(util.ToBE(reply))
	conn.server.notifyImport(busID, true)
	return conn.handleCommands(device)
}

func (conn *usbipConnection) handleCommands(device USBIPDevice) error {
	for {
		var header usbipMessageHeader
		if err := readBE(conn.conn, &header); err != nil {
			return err
		}
		usbipLogger.Printf("[MESSAGE HEADER] %s\n\n", header)
		var err error
		switch header.Command {
		case usbipCmdSubmit:
			err = conn.handleCommandSubmit(device, header)
		case usbipCmdUnlink:
			err = conn.handleCommandUnlink(device, header)
		default:
			// The stream cannot be resynchronized after an unknown command.
			err = fmt.Errorf("unsupported USB/IP command %s", header)
		}
		if err != nil {
			return err
		}
	}
}

func (conn *usbipConnection) handleCommandSubmit(device USBIPDevice, header usbipMessageHeader) error {
	var command usbipCommandSubmitBody
	if err := readBE(conn.conn, &command); err != nil {
		return err
	}
	usbipLogger.Printf("[COMMAND SUBMIT] %s\n\n", command)
	if command.TransferBufferLength > maxTransferLength {
		return fmt.Errorf("URB transfer length %d exceeds the %d byte limit", command.TransferBufferLength, maxTransferLength)
	}
	transferBuffer := make([]byte, command.TransferBufferLength)
	if header.Direction == usbipDirOut && len(transferBuffer) > 0 {
		if _, err := io.ReadFull(conn.conn, transferBuffer); err != nil {
			return err
		}
	}
	// The response may not be immediate, so it is delivered through a callback.
	onReturnSubmit := func(response []byte, status int32) {
		actualLength := len(transferBuffer)
		var data []byte
		if header.Direction == usbipDirIn {
			data = response
			if len(data) > len(transferBuffer) {
				data = data[:len(transferBuffer)]
			}
			actualLength = len(data)
		}
		if status != StatusOK {
			data = nil
			actualLength = 0
		}
		replyBody := usbipReturnSubmitBody{
			Status:       status,
			ActualLength: uint32(actualLength),
		}
		usbipLogger.Printf("[RETURN SUBMIT] %v %#v\n\n", header.SequenceNumber, replyBody)
		conn.writeResponse(util.Concat(util.ToBE(header.replyHeader()), util.ToBE(replyBody), data))
	}
	device.HandleMessage(header.SequenceNumber, onReturnSubmit, header.Endpoint, command.SetupBytes[:], transferBuffer)
	return nil
}

func (conn *usbipConnection) handleCommandUnlink(device USBIPDevice, header usbipMessageHeader) error {
	var unlink usbipCommandUnlinkBody
	if err := readBE(conn.conn, &unlink); err != nil {
		return err
	}
	usbipLogger.Printf("[COMMAND UNLINK] %#v\n\n", unlink)
	// -ECONNRESET if the URB was still pending; 0 if it had already completed.
	var status int32 = 0
	if device.RemoveWaitingRequest(unlink.UnlinkSequenceNumber) {
		status = statusConnectionReset
	}
	replyBody := usbipReturnUnlinkBody{Status: status}
	conn.writeResponse(util.Concat(util.ToBE(header.replyHeader()), util.ToBE(replyBody)))
	return nil
}

// writeResponse sends one reply. Replies can arrive from other goroutines after
// the host has gone away; those are dropped rather than crashing the process.
func (conn *usbipConnection) writeResponse(data []byte) {
	conn.responseMutex.Lock()
	defer conn.responseMutex.Unlock()
	if conn.dead {
		return
	}
	if _, err := conn.conn.Write(data); err != nil {
		conn.dead = true
		usbipLogger.Printf("USB/IP write failed, dropping connection: %v\n\n", err)
		conn.conn.Close()
	}
}

func (conn *usbipConnection) close() {
	conn.responseMutex.Lock()
	conn.dead = true
	conn.responseMutex.Unlock()
	conn.conn.Close()
}

func isLoopback(addr net.Addr) bool {
	tcpAddr, ok := addr.(*net.TCPAddr)
	return ok && tcpAddr.IP.IsLoopback()
}

func readBE(reader io.Reader, value interface{}) error {
	return binary.Read(reader, binary.BigEndian, value)
}

// Winsock's WSAECONNABORTED / WSAECONNRESET, which is what a host dropping the
// connection looks like on Windows.
const (
	wsaConnAborted syscall.Errno = 10053
	wsaConnReset   syscall.Errno = 10054
)

// isDisconnect reports whether err just means the host went away.
func isDisconnect(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == wsaConnAborted || errno == wsaConnReset)
}

func cString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
