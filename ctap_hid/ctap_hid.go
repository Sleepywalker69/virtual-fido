package ctap_hid

import (
	"context"
	"encoding/binary"
	"sync"
	"time"

	"github.com/bulwarkid/virtual-fido/util"
)

var ctapHIDLogger = util.NewLogger("[CTAPHID] ", util.LogLevelDebug)
var ctapHIDTraceLogger = util.NewLogger("[CTAPHID] ", util.LogLevelTrace)
var ctapHIDErrLogger = util.NewLogger("[CTAPHID] ", util.LogLevelEnabled)

type CTAPHIDClient interface {
	HandleMessage(data []byte) []byte
}

// contextHandler is implemented by CTAP servers whose requests can be
// cancelled (CTAPHID_CANCEL, or the host detaching).
type contextHandler interface {
	HandleMessageContext(ctx context.Context, channelID uint32, data []byte) []byte
}

// channelHandler is implemented by CTAP servers that track per-channel state.
type channelHandler interface {
	HandleMessageForChannel(channelID uint32, data []byte) []byte
}

// presenceReporter lets keepalives report STATUS_UPNEEDED while the
// authenticator is waiting for the user to approve.
type presenceReporter interface {
	UserPresenceNeeded() bool
}

const (
	// CTAPHID requires a keepalive at least every 100 ms while processing.
	keepaliveInterval = 80 * time.Millisecond
	// maxChannels bounds allocated channels; platforms allocate one per session.
	maxChannels = 32
)

// CTAPHIDServer implements the CTAPHID transport. HandleMessage must be called
// with one HID report at a time, in the order the host sent them. At most one
// CBOR/MSG request runs at a time (in its own goroutine), so packets keep being
// processed while a request waits for the user: CTAPHID_CANCEL can abort it and
// other channels get ERR_CHANNEL_BUSY.
type CTAPHIDServer struct {
	ctapServer CTAPHIDClient
	u2fServer  CTAPHIDClient

	mu           sync.Mutex
	maxChannelID ctapHIDChannelID
	channels     map[ctapHIDChannelID]*ctapHIDChannel
	channelOrder []ctapHIDChannelID
	active       *activeRequest

	responsesLock   sync.Mutex
	responseHandler func(response []byte)
}

type activeRequest struct {
	channelID ctapHIDChannelID
	cancel    context.CancelFunc
	// abandoned is set (under CTAPHIDServer.mu) when the host detached: the
	// response must not be delivered to whoever attaches next.
	abandoned bool
}

func NewCTAPHIDServer(ctapServer CTAPHIDClient, u2fServer CTAPHIDClient) *CTAPHIDServer {
	return &CTAPHIDServer{
		ctapServer: ctapServer,
		u2fServer:  u2fServer,
		channels:   make(map[ctapHIDChannelID]*ctapHIDChannel),
	}
}

func (server *CTAPHIDServer) SetResponseHandler(handler func(response []byte)) {
	server.responsesLock.Lock()
	server.responseHandler = handler
	server.responsesLock.Unlock()
}

func (server *CTAPHIDServer) sendResponsePackets(packets [][]byte) {
	// All packets of one message go out back to back.
	server.responsesLock.Lock()
	defer server.responsesLock.Unlock()
	if server.responseHandler != nil {
		for _, packet := range packets {
			server.responseHandler(packet)
		}
	}
}

// HandleMessage processes one HID report from the host.
func (server *CTAPHIDServer) HandleMessage(message []byte) {
	if len(message) < 5 {
		return
	}
	channelID := ctapHIDChannelID(binary.BigEndian.Uint32(message[:4]))
	isInitPacket := message[4]&0x80 != 0
	command := ctapHIDCommand(message[4])

	if channelID == ctapHIDBroadcastChannel {
		if isInitPacket {
			server.handleBroadcastMessage(message)
		}
		return
	}
	server.mu.Lock()
	channel, exists := server.channels[channelID]
	server.mu.Unlock()
	if !exists {
		server.sendError(channelID, ctapHIDErrorInvalidChannel)
		return
	}

	if isInitPacket {
		switch command {
		case ctapHIDCommandCancel:
			channel.transaction = nil
			server.cancelRequest(channelID)
			return // CANCEL itself gets no response
		case ctapHIDCommandInit:
			// INIT on an allocated channel resynchronizes it.
			channel.transaction = nil
			server.cancelRequest(channelID)
			transaction := newCTAPHIDTransaction(message)
			if transaction.done && transaction.errorCode == 0 && len(transaction.result.payload) >= 8 {
				server.sendInitResponse(channelID, transaction.result.payload[:8], channelID)
			}
			return
		}
		if server.busyWith() != nil {
			server.sendError(channelID, ctapHIDErrorChannelBusy)
			return
		}
		channel.transaction = newCTAPHIDTransaction(message)
	} else {
		if channel.transaction == nil {
			return // continuation of a message we already rejected or abandoned
		}
		channel.transaction.addMessage(message)
	}

	transaction := channel.transaction
	if !transaction.done {
		return
	}
	channel.transaction = nil
	if transaction.errorCode != 0 {
		server.sendError(channelID, transaction.errorCode)
		return
	}
	if transaction.cancelled {
		server.cancelRequest(channelID)
		return
	}
	server.handleFinalizedMessage(channelID, transaction.result.header, transaction.result.payload)
}

func (server *CTAPHIDServer) handleFinalizedMessage(channelID ctapHIDChannelID, header ctapHIDMessageHeader, payload []byte) {
	ctapHIDTraceLogger.Printf("CTAPHID FINALIZED MESSAGE: %s %#v\n\n", header, payload)
	switch header.Command {
	case ctapHIDCommandPing:
		server.sendResponse(channelID, ctapHIDCommandPing, payload)
	case ctapHIDCommandMsg, ctapHIDCommandCBOR:
		server.startRequest(channelID, header.Command, payload)
	default:
		server.sendError(channelID, ctapHIDErrorInvalidCommand)
	}
}

func (server *CTAPHIDServer) busyWith() *activeRequest {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.active
}

func (server *CTAPHIDServer) startRequest(channelID ctapHIDChannelID, command ctapHIDCommand, payload []byte) {
	ctx, cancel := context.WithCancel(context.Background())
	request := &activeRequest{channelID: channelID, cancel: cancel}
	server.mu.Lock()
	if server.active != nil {
		server.mu.Unlock()
		cancel()
		server.sendError(channelID, ctapHIDErrorChannelBusy)
		return
	}
	server.active = request
	server.mu.Unlock()
	go server.runRequest(ctx, request, command, payload)
}

func (server *CTAPHIDServer) runRequest(ctx context.Context, request *activeRequest, command ctapHIDCommand, payload []byte) {
	defer request.cancel()
	var stopKeepalive func()
	if command == ctapHIDCommandCBOR {
		stopKeepalive = server.startKeepalive(request.channelID)
	}
	response := server.callHandler(ctx, request.channelID, command, payload)
	if stopKeepalive != nil {
		stopKeepalive()
	}
	server.mu.Lock()
	abandoned := request.abandoned
	if server.active == request {
		server.active = nil
	}
	server.mu.Unlock()
	if abandoned {
		return
	}
	ctapHIDTraceLogger.Printf("CTAPHID %s RESPONSE: %#v\n\n", ctapHIDCommandDescriptions[command], response)
	server.sendResponse(request.channelID, command, response)
}

func (server *CTAPHIDServer) callHandler(ctx context.Context, channelID ctapHIDChannelID, command ctapHIDCommand, payload []byte) (response []byte) {
	defer func() {
		if r := recover(); r != nil {
			ctapHIDErrLogger.Printf("%s request failed: %v\n\n", ctapHIDCommandDescriptions[command], r)
			if command == ctapHIDCommandCBOR {
				response = []byte{0x7F} // CTAP1_ERR_OTHER
			} else {
				response = []byte{0x6F, 0x00} // SW_UNKNOWN
			}
		}
	}()
	if command == ctapHIDCommandMsg {
		return server.u2fServer.HandleMessage(payload)
	}
	if handler, ok := server.ctapServer.(contextHandler); ok {
		return handler.HandleMessageContext(ctx, uint32(channelID), payload)
	}
	if handler, ok := server.ctapServer.(channelHandler); ok {
		return handler.HandleMessageForChannel(uint32(channelID), payload)
	}
	return server.ctapServer.HandleMessage(payload)
}

// startKeepalive sends CTAPHID_KEEPALIVE until the returned stop function is
// called; no keepalive is sent once stop has returned.
func (server *CTAPHIDServer) startKeepalive(channelID ctapHIDChannelID) func() {
	var mu sync.Mutex
	stopped := false
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			status := ctapHIDStatusProcessing
			if reporter, ok := server.ctapServer.(presenceReporter); ok && reporter.UserPresenceNeeded() {
				status = ctapHIDStatusUpneeded
			}
			mu.Lock()
			if !stopped {
				server.sendResponse(channelID, ctapHIDCommandKeepalive, []byte{status})
			}
			mu.Unlock()
		}
	}()
	return func() {
		mu.Lock()
		stopped = true
		mu.Unlock()
		close(done)
	}
}

// cancelRequest aborts the in-flight request if it belongs to channelID.
func (server *CTAPHIDServer) cancelRequest(channelID ctapHIDChannelID) {
	server.mu.Lock()
	active := server.active
	server.mu.Unlock()
	if active != nil && active.channelID == channelID {
		ctapHIDLogger.Printf("CTAPHID_CANCEL: aborting request on channel 0x%x\n\n", channelID)
		active.cancel()
	}
}

// HostDisconnected abandons the in-flight request and forgets all channels;
// the next host starts from a clean CTAPHID state.
func (server *CTAPHIDServer) HostDisconnected() {
	server.mu.Lock()
	active := server.active
	server.active = nil
	if active != nil {
		active.abandoned = true
	}
	server.channels = make(map[ctapHIDChannelID]*ctapHIDChannel)
	server.channelOrder = nil
	server.mu.Unlock()
	if active != nil {
		ctapHIDLogger.Printf("Host disconnected: abandoning request on channel 0x%x\n\n", active.channelID)
		active.cancel()
	}
}

// newChannel allocates a channel, evicting the oldest idle one when too many
// are open.
func (server *CTAPHIDServer) newChannel() *ctapHIDChannel {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.maxChannelID++
	if server.maxChannelID == 0 || server.maxChannelID == ctapHIDBroadcastChannel {
		server.maxChannelID = 1
	}
	channel := newCTAPHIDChannel(server.maxChannelID)
	server.channels[channel.channelId] = channel
	server.channelOrder = append(server.channelOrder, channel.channelId)
	for len(server.channelOrder) > maxChannels {
		oldest := server.channelOrder[0]
		server.channelOrder = server.channelOrder[1:]
		if server.active != nil && server.active.channelID == oldest {
			server.channelOrder = append(server.channelOrder, oldest)
			continue
		}
		delete(server.channels, oldest)
	}
	return channel
}

func (server *CTAPHIDServer) sendResponse(channelID ctapHIDChannelID, command ctapHIDCommand, payload []byte) {
	packets := createResponsePackets(channelID, command, payload)
	server.sendResponsePackets(packets)
}

func (server *CTAPHIDServer) sendError(channelID ctapHIDChannelID, errorCode ctapHIDErrorCode) {
	response := ctapHidError(channelID, errorCode)
	server.sendResponsePackets(response)
}

func createResponsePackets(channelId ctapHIDChannelID, command ctapHIDCommand, payload []byte) [][]byte {
	packets := [][]byte{}
	sequence := -1
	remaining := len(payload)
	// An empty payload still needs its initialization packet.
	for remaining > 0 || sequence < 0 {
		packet := []byte{}
		if sequence < 0 {
			// INIT frame
			packet = append(packet, util.ToBE(channelId)...)
			packet = append(packet, util.ToLE(command)...)
			packet = append(packet, util.ToBE(uint16(remaining))...)
		} else {
			// CONT frame
			packet = append(packet, util.ToBE(channelId)...)
			packet = append(packet, byte(uint8(sequence)))
		}
		chunk := ctapHIDMaxPacketSize - len(packet)
		if chunk > remaining {
			chunk = remaining
		}
		packet = append(packet, payload[:chunk]...)
		payload = payload[chunk:]
		remaining -= chunk
		sequence++
		packets = append(packets, util.Pad(packet, ctapHIDMaxPacketSize))
	}
	return packets
}
