package usb

import (
	"bytes"
	"testing"

	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
)

type dummyUSBDeviceDelegate struct {
	transferBuffer []byte
}

func (delegate *dummyUSBDeviceDelegate) HandleMessage(transferBuffer []byte) {
	delegate.transferBuffer = transferBuffer
}
func (delegate *dummyUSBDeviceDelegate) SetResponseHandler(handler func(response []byte)) {}

func TestGetDescriptor(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	var response []byte = nil
	setResponse := func(other []byte, status int32) {
		response = other
	}
	var setup usbSetupPacket
	setup.setDirection(usbHostToDevice)
	setup.setRequestClass(usbRequestClassStandard)
	setup.setRecipient(usbRequestRecipientDevice)
	setup.BRequest = usbRequestGetDescriptor
	setup.WValue = (uint16(usbDescriptorDevice) << 8)
	setup.WLength = 64
	setupBytes := util.ToLE(setup)
	device.HandleMessage(0, setResponse, 0, setupBytes, []byte{})
	test.AssertNotNil(t, response, "Response is nil")
	deviceDescriptor := util.ReadLE[usbDeviceDescriptor](bytes.NewBuffer(response))
	test.AssertEqual(t, int(deviceDescriptor.BLength), len(response), "Incorrect descriptor length")
	test.AssertEqual(t, deviceDescriptor.BDescriptorType, usbDescriptorDevice, "Incorrect descriptor type")
	test.AssertEqual(t, deviceDescriptor.BcdUSB, 0x110, "Invalid bcdUSB")
	test.AssertEqual(t, deviceDescriptor.BNumConfigurations, 1, "Invalid number configurations")
}

func TestGetConfiguration(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	var response []byte = nil
	setResponse := func(other []byte, status int32) {
		response = other
	}
	var setup usbSetupPacket
	setup.setDirection(usbHostToDevice)
	setup.setRequestClass(usbRequestClassStandard)
	setup.setRecipient(usbRequestRecipientDevice)
	setup.BRequest = usbRequestGetDescriptor
	setup.WValue = (uint16(usbDescriptorConfiguration) << 8)
	setup.WLength = 64
	setupBytes := util.ToLE(setup)
	device.HandleMessage(0, setResponse, 0, setupBytes, []byte{})
	test.AssertNotNil(t, response, "Response is nil")
	responseBuffer := bytes.NewBuffer(response)
	configuration := util.ReadLE[usbConfigurationDescriptor](responseBuffer)
	test.AssertEqual(t, configuration.BLength, util.SizeOf[usbConfigurationDescriptor](), "BLength incorrect")
	test.AssertEqual(t, int(configuration.WTotalLength), len(response), "WTotalLength incorrect")
	test.AssertEqual(t, configuration.BDescriptorType, usbDescriptorConfiguration, "Incorrect descriptor type")
	test.AssertEqual(t, configuration.BNumInterfaces, 1, "Num interfaces incorrect")
	interfaceDesc := util.ReadLE[usbInterfaceDescriptor](responseBuffer)
	test.AssertEqual(t, interfaceDesc.BLength, util.SizeOf[usbInterfaceDescriptor](), "BLength incorrect")
	test.AssertEqual(t, interfaceDesc.BNumEndpoints, 2, "Incorrect num endpoints")
	hidDescriptor := util.ReadLE[usbHIDDescriptor](responseBuffer)
	test.AssertEqual(t, hidDescriptor.BLength, util.SizeOf[usbHIDDescriptor](), "BLength incorrect")
	test.AssertEqual(t, hidDescriptor.BDescriptorType, usbDescriptorHID, "Descriptor type wrong")
	test.AssertEqual(t, hidDescriptor.BCountryCode, usbHIDCountryCodeNone, "Invalid country code")
	for i := 0; i < int(interfaceDesc.BNumEndpoints); i++ {
		endpoint := util.ReadLE[usbEndpointDescriptor](responseBuffer)
		test.AssertEqual(t, endpoint.BDescriptorType, usbDescriptorEndpoint, "Endpoint type incorrect")
	}
}

func TestGetStringDescriptor(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	var response []byte = nil
	setResponse := func(other []byte, status int32) {
		response = other
	}
	// Right now there are 5 string descriptors; we just need to check if we can generally access them
	for i := 0; i < 5; i++ {
		var setup usbSetupPacket
		setup.setDirection(usbHostToDevice)
		setup.setRequestClass(usbRequestClassStandard)
		setup.setRecipient(usbRequestRecipientDevice)
		setup.BRequest = usbRequestGetDescriptor
		setup.WValue = (uint16(usbDescriptorString)<<8 | uint16(i))
		setup.WLength = 64
		setupBytes := util.ToLE(setup)
		device.HandleMessage(0, setResponse, 0, setupBytes, []byte{})
		stringBytes := append(response, 0)
		test.AssertNotEqual(t, util.CStringToString(stringBytes), "", "Invalid string")
	}
}

func TestGetHIDReport(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	var response []byte = nil
	setResponse := func(other []byte, status int32) {
		response = other
	}
	var setup usbSetupPacket
	setup.setDirection(usbHostToDevice)
	setup.setRequestClass(usbRequestClassStandard)
	setup.setRecipient(usbRequestRecipientInterface)
	setup.BRequest = usbRequestType(usbHIDRequestGetDescriptor)
	setup.WValue = (uint16(usbDescriptorHIDReport) << 8)
	setup.WLength = 64
	setupBytes := util.ToLE(setup)
	device.HandleMessage(0, setResponse, 0, setupBytes, []byte{})
	test.AssertNotNil(t, response, "Nil HID report")
	test.AssertNotEqual(t, len(response), 0, "Empty HID report")
}

func TestBusID(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	if device.BusID() != "2-2" {
		t.Fatalf("Bus ID is not 2-2")
	}
}

func TestDeviceSummary(t *testing.T) {
	delegate := dummyUSBDeviceDelegate{}
	device := NewUSBDevice(&delegate)
	// Check a few fields in the summary to make sure they are correct
	summary := device.DeviceSummary()
	if summary.Header.Busnum != 2 ||
		summary.Header.Devnum != 2 ||
		util.CStringToString(summary.Header.BusID[:]) != "2-2" ||
		util.CStringToString(summary.Header.Path[:]) != "/device/0" {
		t.Fatalf("Device summary incorrect")
	}
}

func controlRequest(t *testing.T, device *USBDevice, bmRequestType uint8, bRequest uint8, wValue uint16, wIndex uint16) ([]byte, int32) {
	t.Helper()
	setup := usbSetupPacket{BmRequestType: bmRequestType, BRequest: usbRequestType(bRequest), WValue: wValue, WIndex: wIndex, WLength: 255}
	called := false
	var response []byte
	var status int32
	device.HandleMessage(0, func(r []byte, s int32) {
		called = true
		response, status = r, s
	}, uint32(usbEndpointControl), util.ToLE(setup), nil)
	test.Assert(t, called, "control request was never completed")
	return response, status
}

func TestUnsupportedRequestsStall(t *testing.T) {
	device := NewUSBDevice(&dummyUSBDeviceDelegate{})
	stalled := map[string][4]uint16{
		"MS OS string descriptor": {0x80, 6, 0x03EE, 0},
		"device qualifier":        {0x80, 6, 0x0600, 0},
		"BOS descriptor":          {0x80, 6, 0x0F00, 0},
		"HID GET_REPORT":          {0xA1, 1, 0x0100, 0},
		"vendor request":          {0xC0, 1, 0, 0},
	}
	for name, req := range stalled {
		_, status := controlRequest(t, device, uint8(req[0]), uint8(req[1]), req[2], req[3])
		test.AssertEqual(t, status, int32(-32), name+" was not stalled")
	}
}

func TestStandardRequests(t *testing.T) {
	device := NewUSBDevice(&dummyUSBDeviceDelegate{})
	statusBytes, status := controlRequest(t, device, 0x80, 0, 0, 0)
	test.AssertEqual(t, status, int32(0), "GET_STATUS failed")
	test.AssertEqual(t, len(statusBytes), 2, "GET_STATUS must return two bytes")
	_, status = controlRequest(t, device, 0x02, 1, 0, 0x81) // CLEAR_FEATURE(ENDPOINT_HALT)
	test.AssertEqual(t, status, int32(0), "CLEAR_FEATURE failed")
	_, status = controlRequest(t, device, 0x00, 9, configurationValue, 0)
	test.AssertEqual(t, status, int32(0), "SET_CONFIGURATION failed")
	config, _ := controlRequest(t, device, 0x80, 8, 0, 0)
	test.AssertArrEqual(t, config, []byte{configurationValue}, "GET_CONFIGURATION")
	hid, status := controlRequest(t, device, 0x81, 6, uint16(usbDescriptorHID)<<8, 0)
	test.AssertEqual(t, status, int32(0), "GET_DESCRIPTOR(HID) failed")
	test.AssertEqual(t, hid[1], uint8(usbDescriptorHID), "wrong HID descriptor type")
	full, _ := controlRequest(t, device, 0x80, 6, uint16(usbDescriptorConfiguration)<<8, 0)
	test.AssertEqual(t, full[5], uint8(configurationValue), "bConfigurationValue must be non-zero")
}

func TestOutputReportsDeliveredInOrder(t *testing.T) {
	delegate := &orderedDelegate{got: make(chan byte, 100)}
	device := NewUSBDevice(delegate)
	for i := 0; i < 100; i++ {
		device.HandleMessage(uint32(i), func([]byte, int32) {}, uint32(usbEndpointInput), make([]byte, 8), []byte{byte(i)})
	}
	for i := 0; i < 100; i++ {
		test.AssertEqual(t, <-delegate.got, byte(i), "reports reordered")
	}
}

type orderedDelegate struct{ got chan byte }

func (d *orderedDelegate) HandleMessage(transferBuffer []byte)              { d.got <- transferBuffer[0] }
func (d *orderedDelegate) SetResponseHandler(handler func(response []byte)) {}

func TestHIDClassRequests(t *testing.T) {
	device := NewUSBDevice(&dummyUSBDeviceDelegate{})
	_, status := controlRequest(t, device, 0x21, uint8(usbHIDRequestSetIdle), 0, 0)
	test.AssertEqual(t, status, int32(0), "SET_IDLE (class request) failed")
	protocol, status := controlRequest(t, device, 0xA1, uint8(usbHIDRequestGetProtocol), 0, 0)
	test.AssertEqual(t, status, int32(0), "GET_PROTOCOL failed")
	test.AssertArrEqual(t, protocol, []byte{1}, "GET_PROTOCOL should report the report protocol")
}
