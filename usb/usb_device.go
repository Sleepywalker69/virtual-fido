package usb

import (
	"bytes"
	"unsafe"

	"github.com/bulwarkid/virtual-fido/usbip"
	"github.com/bulwarkid/virtual-fido/util"
)

var usbLogger = util.NewLogger("[USB] ", util.LogLevelTrace)
var usbErrLogger = util.NewLogger("[USB] ", util.LogLevelEnabled)

type USBDeviceDelegate interface {
	HandleMessage(transferBuffer []byte)
	SetResponseHandler(handler func(response []byte))
}

// hostAwareDelegate is implemented by delegates that need to know when the
// host detaches (e.g. to abandon a request that is waiting for the user).
type hostAwareDelegate interface {
	HostDisconnected()
}

// configurationValue is the bConfigurationValue of our only configuration.
// It must not be 0: SET_CONFIGURATION(0) means "unconfigured".
const configurationValue = 1

type USBDevice struct {
	delegate      USBDeviceDelegate
	requestBuffer *util.RequestBuffer
	outReports    chan []byte
}

func NewUSBDevice(delegate USBDeviceDelegate) *USBDevice {
	device := &USBDevice{
		delegate:      delegate,
		requestBuffer: util.MakeRequestBuffer(),
		outReports:    make(chan []byte, 256),
	}
	delegate.SetResponseHandler(func(response []byte) {
		device.handleResponse(response)
	})
	go device.deliverReports()
	return device
}

// deliverReports hands host-to-device reports to the delegate one at a time,
// in arrival order: a CTAPHID message spans several reports that must be
// reassembled in sequence.
func (device *USBDevice) deliverReports() {
	for report := range device.outReports {
		device.deliverReport(report)
	}
}

func (device *USBDevice) deliverReport(report []byte) {
	defer func() {
		if r := recover(); r != nil {
			usbErrLogger.Printf("Dropped a HID report that crashed its handler: %v\n\n", r)
		}
	}()
	device.delegate.HandleMessage(report)
}

func (device *USBDevice) BusID() string {
	return "2-2"
}

func (device *USBDevice) DeviceSummary() usbip.USBIPDeviceSummary {
	summary := usbip.USBIPDeviceSummary{
		Header: usbip.USBIPDeviceSummaryHeader{
			Busnum:              2,
			Devnum:              2,
			Speed:               2,
			IdVendor:            0,
			IdProduct:           0,
			BcdDevice:           0,
			BDeviceClass:        0,
			BDeviceSubclass:     0,
			BDeviceProtocol:     0,
			BConfigurationValue: 0,
			BNumConfigurations:  1,
			BNumInterfaces:      1,
		},
		DeviceInterface: usbip.USBIPDeviceInterface{
			BInterfaceClass:    usbInterfaceClassHID,
			BInterfaceSubclass: 0,
			BInterfaceProtocol: 0,
		},
	}
	copy(summary.Header.Path[:], []byte("/device/0"))
	copy(summary.Header.BusID[:], []byte("2-2"))
	return summary
}

func (device *USBDevice) RemoveWaitingRequest(id uint32) bool {
	return device.requestBuffer.CancelRequest(id)
}

// Attached drops anything left over from a previous host session.
func (device *USBDevice) Attached() {
	device.requestBuffer.Reset()
}

// Detached forgets the departed host's pending transfers (their replies would
// go to a closed connection) and tells the delegate the host is gone.
func (device *USBDevice) Detached() {
	device.requestBuffer.Reset()
	if delegate, ok := device.delegate.(hostAwareDelegate); ok {
		delegate.HostDisconnected()
	}
}

func (device *USBDevice) HandleMessage(id uint32, onFinish func(response []byte, status int32), endpoint uint32, setupBytes []byte, data []byte) {
	setup := util.ReadLE[usbSetupPacket](bytes.NewBuffer(setupBytes))
	switch usbEndpoint(endpoint) {
	case usbEndpointControl:
		usbLogger.Printf("USB CONTROL: %s\n\n", setup)
		reply, status := device.handleControlMessage(setup)
		if status != usbip.StatusOK {
			usbLogger.Printf("Stalling unsupported control request: %s\n\n", setup)
		}
		onFinish(reply, status)
	case usbEndpointOutput:
		// Interrupt IN (device to host): the transfer stays pending until the
		// delegate has a report to send or the host unlinks it.
		device.requestBuffer.Request(id, func(response []byte) {
			onFinish(response, usbip.StatusOK)
		})
	case usbEndpointInput:
		// Interrupt OUT (host to device).
		usbLogger.Printf("INPUT DATA: %#v\n\n", data)
		device.outReports <- data
		onFinish(nil, usbip.StatusOK)
	default:
		usbErrLogger.Printf("Transfer to unknown endpoint %d, stalling\n\n", endpoint)
		onFinish(nil, usbip.StatusStall)
	}
}

func (device *USBDevice) handleResponse(response []byte) {
	device.requestBuffer.Respond(response)
}

func (device *USBDevice) handleControlMessage(setup usbSetupPacket) ([]byte, int32) {
	switch setup.requestClass() {
	case usbRequestClassStandard:
		return device.handleStandardRequest(setup)
	case usbRequestClassClass:
		if setup.recipient() == usbRequestRecipientInterface {
			return device.handleHIDRequest(setup)
		}
	}
	return nil, usbip.StatusStall
}

func (device *USBDevice) handleStandardRequest(setup usbSetupPacket) ([]byte, int32) {
	switch setup.BRequest {
	case usbRequestGetStatus:
		if setup.recipient() == usbRequestRecipientDevice {
			return []byte{1, 0}, usbip.StatusOK // self powered, no remote wakeup
		}
		return []byte{0, 0}, usbip.StatusOK
	case usbRequestClearFeature, usbRequestSetFeature, usbRequestSetAddress, usbRequestSetInterface:
		return nil, usbip.StatusOK
	case usbRequestSetConfiguration:
		usbLogger.Printf("SET_CONFIGURATION %d\n\n", setup.WValue)
		return nil, usbip.StatusOK
	case usbRequestGetConfiguration:
		return []byte{configurationValue}, usbip.StatusOK
	case usbRequestGetInterface:
		return []byte{0}, usbip.StatusOK
	case usbRequestGetDescriptor:
		descriptorType, descriptorIndex := getDescriptorTypeAndIndex(setup.WValue)
		var descriptor []byte
		switch setup.recipient() {
		case usbRequestRecipientDevice:
			descriptor = device.getDescriptor(descriptorType, descriptorIndex)
		case usbRequestRecipientInterface:
			descriptor = device.getInterfaceClassDescriptor(descriptorType)
		}
		if descriptor == nil {
			return nil, usbip.StatusStall
		}
		return descriptor, usbip.StatusOK
	}
	return nil, usbip.StatusStall
}

func (device *USBDevice) handleHIDRequest(setup usbSetupPacket) ([]byte, int32) {
	switch usbHIDRequestType(setup.BRequest) {
	case usbHIDRequestSetIdle, usbHIDRequestSetProtocol:
		return nil, usbip.StatusOK
	case usbHIDRequestGetIdle:
		return []byte{0}, usbip.StatusOK
	case usbHIDRequestGetProtocol:
		return []byte{1}, usbip.StatusOK // report protocol
	}
	return nil, usbip.StatusStall
}

// getInterfaceClassDescriptor answers GET_DESCRIPTOR addressed to the HID
// interface.
func (device *USBDevice) getInterfaceClassDescriptor(descriptorType usbDescriptorType) []byte {
	switch descriptorType {
	case usbDescriptorHID:
		return util.ToLE(device.getHIDDescriptor(device.getHIDReport()))
	case usbDescriptorHIDReport:
		return device.getHIDReport()
	}
	return nil
}

// getDescriptor returns a device descriptor, or nil (STALL) for descriptors a
// full-speed HID device does not have (device qualifier, BOS, MS OS strings...).
func (device *USBDevice) getDescriptor(descriptorType usbDescriptorType, index uint8) []byte {
	usbLogger.Printf("GET DESCRIPTOR: Type: %s Index: %d\n\n", descriptorType, index)
	switch descriptorType {
	case usbDescriptorDevice:
		return util.ToLE(device.getDeviceDescriptor())
	case usbDescriptorConfiguration:
		buffer := new(bytes.Buffer)
		buffer.Write(util.ToLE(device.getInterfaceDescriptor()))
		buffer.Write(util.ToLE(device.getHIDDescriptor(device.getHIDReport())))
		for _, endpoint := range device.getEndpointDescriptors() {
			buffer.Write(util.ToLE(endpoint))
		}
		configBytes := buffer.Bytes()
		config := device.getConfigurationDescriptor(uint16(len(configBytes)))
		return util.Concat(util.ToLE(config), configBytes)
	case usbDescriptorString:
		message := device.getStringDescriptor(index)
		if message == nil {
			return nil
		}
		header := usbStringDescriptorHeader{
			BLength:         0,
			BDescriptorType: usbDescriptorString,
		}
		header.BLength = uint8(unsafe.Sizeof(header)) + uint8(len(message))
		return util.Concat(util.ToLE(header), message)
	}
	return nil
}

func (device *USBDevice) getDeviceDescriptor() usbDeviceDescriptor {
	return usbDeviceDescriptor{
		BLength:            util.SizeOf[usbDeviceDescriptor](),
		BDescriptorType:    usbDescriptorDevice,
		BcdUSB:             0x0110,
		BDeviceClass:       0,
		BDeviceSubclass:    0,
		BDeviceProtocol:    0,
		BMaxPacketSize:     64,
		IDVendor:           0,
		IDProduct:          0,
		BcdDevice:          0x1,
		IManufacturer:      1,
		IProduct:           2,
		ISerialNumber:      3,
		BNumConfigurations: 1,
	}
}

func (device *USBDevice) getConfigurationDescriptor(configLength uint16) usbConfigurationDescriptor {
	totalLength := uint16(util.SizeOf[usbConfigurationDescriptor]()) + configLength
	return usbConfigurationDescriptor{
		BLength:             util.SizeOf[usbConfigurationDescriptor](),
		BDescriptorType:     usbDescriptorConfiguration,
		WTotalLength:        totalLength,
		BNumInterfaces:      1,
		BConfigurationValue: configurationValue,
		IConfiguration:      4,
		BmAttributes:        usbConfigAttributeBase | usbConfigAttributeSelfPowered,
		BMaxPower:           0,
	}
}

func (device *USBDevice) getInterfaceDescriptor() usbInterfaceDescriptor {
	return usbInterfaceDescriptor{
		BLength:            util.SizeOf[usbInterfaceDescriptor](),
		BDescriptorType:    usbDescriptorInterface,
		BInterfaceNumber:   0,
		BAlternateSetting:  0,
		BNumEndpoints:      2,
		BInterfaceClass:    usbInterfaceClassHID,
		BInterfaceSubclass: 0,
		BInterfaceProtocol: 0,
		IInterface:         5,
	}
}

func (device *USBDevice) getHIDDescriptor(hidReportDescriptor []byte) usbHIDDescriptor {
	return usbHIDDescriptor{
		BLength:                 util.SizeOf[usbHIDDescriptor](),
		BDescriptorType:         usbDescriptorHID,
		BcdHID:                  0x0101,
		BCountryCode:            usbHIDCountryCodeNone,
		BNumDescriptors:         1,
		BClassDescriptorType:    usbDescriptorHIDReport,
		WReportDescriptorLength: uint16(len(hidReportDescriptor)),
	}
}

// getHIDReport is the standard CTAPHID report descriptor: usage page 0xF1D0
// (FIDO Alliance), one 64-byte input and one 64-byte output report.
func (device *USBDevice) getHIDReport() []byte {
	return []byte{
		0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
		0x09, 0x01, // Usage (CTAPHID)
		0xA1, 0x01, // Collection (Application)
		0x09, 0x20, //   Usage (Input Report Data)
		0x15, 0x00, //   Logical Minimum (0)
		0x26, 0xFF, 0x00, //   Logical Maximum (255)
		0x75, 0x08, //   Report Size (8)
		0x95, 0x40, //   Report Count (64)
		0x81, 0x02, //   Input (Data, Var, Abs)
		0x09, 0x21, //   Usage (Output Report Data)
		0x15, 0x00, //   Logical Minimum (0)
		0x26, 0xFF, 0x00, //   Logical Maximum (255)
		0x75, 0x08, //   Report Size (8)
		0x95, 0x40, //   Report Count (64)
		0x91, 0x02, //   Output (Data, Var, Abs)
		0xC0, // End Collection
	}
}

func (device *USBDevice) getEndpointDescriptors() []usbEndpointDescriptor {
	length := util.SizeOf[usbEndpointDescriptor]()
	return []usbEndpointDescriptor{
		{
			BLength:          length,
			BDescriptorType:  usbDescriptorEndpoint,
			BEndpointAddress: 0b10000001,
			BmAttributes:     0b00000011,
			WMaxPacketSize:   64,
			BInterval:        255,
		},
		{
			BLength:          length,
			BDescriptorType:  usbDescriptorEndpoint,
			BEndpointAddress: 0b00000010,
			BmAttributes:     0b00000011,
			WMaxPacketSize:   64,
			BInterval:        255,
		},
	}
}

func (device *USBDevice) getStringDescriptor(index uint8) []byte {
	switch index {
	case 0:
		return util.ToLE[uint16](usbLangIDEngUSA)
	case 1:
		return util.Utf16encode("No Company")
	case 2:
		return util.Utf16encode("Virtual FIDO")
	case 3:
		return util.Utf16encode("No Serial Number")
	case 4:
		return util.Utf16encode("String 4")
	case 5:
		return util.Utf16encode("Default Interface")
	}
	return nil
}
