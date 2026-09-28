package ctap_hid

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
)

type dummyHandler struct{}

func (server *dummyHandler) HandleMessage(data []byte) []byte {
	return nil
}

func TestOpenChannel(t *testing.T) {
	dummyCTAP := dummyHandler{}
	dummyU2F := dummyHandler{}
	server := NewCTAPHIDServer(&dummyCTAP, &dummyU2F)
	initCmd := byte((1 << 7) | 0x06)
	nonce := crypto.RandomBytes(8)
	initializationMessage := util.Concat(
		util.ToBE[uint32](0xFFFFFFFF),
		[]byte{initCmd},
		util.ToBE[uint16](8),
		nonce)
	responseHandler := func(response []byte) {
		correctResponse := util.Concat(
			util.ToBE[uint32](0xFFFFFFFF),
			[]byte{initCmd},
			util.ToBE[uint16](17),
			nonce,
			util.ToBE[uint32](1),
			[]byte{2, 0, 0, 1, 0b00000100},
		)
		correctResponse = util.Pad(correctResponse, 64)
		if !bytes.Equal(response, correctResponse) {
			t.Errorf("Initialization message returned incorrect response: %#v vs %#v", response, correctResponse)
		}
	}
	server.SetResponseHandler(responseHandler)
	server.HandleMessage(initializationMessage)
}

// blockingCTAP blocks CBOR requests until released or cancelled.
type blockingCTAP struct {
	started   chan struct{}
	release   chan struct{}
	cancelled chan struct{}
}

func (b *blockingCTAP) HandleMessage(data []byte) []byte { return []byte{0} }

func (b *blockingCTAP) HandleMessageContext(ctx context.Context, channelID uint32, data []byte) []byte {
	b.started <- struct{}{}
	select {
	case <-b.release:
		return []byte{0x00}
	case <-ctx.Done():
		b.cancelled <- struct{}{}
		return []byte{0x2D}
	}
}

func (b *blockingCTAP) UserPresenceNeeded() bool { return true }

type packetLog struct{ packets chan []byte }

func newPacketLog() *packetLog { return &packetLog{packets: make(chan []byte, 1024)} }

func (p *packetLog) handler(packet []byte) { p.packets <- append([]byte{}, packet...) }

// next returns the next non-keepalive packet.
func (p *packetLog) next(t *testing.T) []byte {
	t.Helper()
	for {
		select {
		case packet := <-p.packets:
			if packet[4] != byte(ctapHIDCommandKeepalive) {
				return packet
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no response from CTAPHID server")
			return nil
		}
	}
}

func openChannel(t *testing.T, server *CTAPHIDServer, log *packetLog) ctapHIDChannelID {
	t.Helper()
	server.HandleMessage(util.Pad(util.Concat(util.ToBE[uint32](0xFFFFFFFF), []byte{byte(ctapHIDCommandInit)}, util.ToBE[uint16](8), crypto.RandomBytes(8)), 64))
	response := log.next(t)
	return ctapHIDChannelID(binary.BigEndian.Uint32(response[15:19]))
}

func cborPacket(channel ctapHIDChannelID, payload []byte) []byte {
	return util.Pad(util.Concat(util.ToBE(channel), []byte{byte(ctapHIDCommandCBOR)}, util.ToBE(uint16(len(payload))), payload), 64)
}

func TestBusyAndCancel(t *testing.T) {
	ctap := &blockingCTAP{started: make(chan struct{}, 1), release: make(chan struct{}), cancelled: make(chan struct{}, 1)}
	server := NewCTAPHIDServer(ctap, &dummyHandler{})
	log := newPacketLog()
	server.SetResponseHandler(log.handler)
	a := openChannel(t, server, log)
	b := openChannel(t, server, log)

	server.HandleMessage(cborPacket(a, []byte{0x02}))
	<-ctap.started
	// Keepalives report that the user needs to act.
	deadline := time.After(time.Second)
	for sawKeepalive := false; !sawKeepalive; {
		select {
		case packet := <-log.packets:
			if packet[4] == byte(ctapHIDCommandKeepalive) {
				test.AssertEqual(t, packet[7], ctapHIDStatusUpneeded, "keepalive status")
				sawKeepalive = true
			}
		case <-deadline:
			t.Fatalf("no keepalive while a request was waiting for the user")
		}
	}

	// Another channel is told the authenticator is busy.
	server.HandleMessage(cborPacket(b, []byte{0x04}))
	busy := log.next(t)
	test.AssertEqual(t, ctapHIDChannelID(binary.BigEndian.Uint32(busy)), b, "busy reply channel")
	test.AssertEqual(t, busy[4], byte(ctapHIDCommandError), "busy reply command")
	test.AssertEqual(t, busy[7], byte(ctapHIDErrorChannelBusy), "busy reply code")

	// CTAPHID_CANCEL aborts the waiting request, which then answers.
	server.HandleMessage(util.Pad(util.Concat(util.ToBE(a), []byte{byte(ctapHIDCommandCancel)}), 64))
	select {
	case <-ctap.cancelled:
	case <-time.After(time.Second):
		t.Fatalf("CTAPHID_CANCEL did not cancel the request")
	}
	response := log.next(t)
	test.AssertEqual(t, response[4], byte(ctapHIDCommandCBOR), "cancelled request response command")
	test.AssertEqual(t, response[7], byte(0x2D), "cancelled request status")
}

func TestEmptyResponseStillSendsPacket(t *testing.T) {
	packets := createResponsePackets(1, ctapHIDCommandCBOR, nil)
	test.AssertEqual(t, len(packets), 1, "empty payload must produce one packet")
	test.AssertEqual(t, packets[0][6], byte(0), "empty payload length")
}

func TestHostDisconnectAbandonsRequest(t *testing.T) {
	ctap := &blockingCTAP{started: make(chan struct{}, 1), release: make(chan struct{}), cancelled: make(chan struct{}, 1)}
	server := NewCTAPHIDServer(ctap, &dummyHandler{})
	log := newPacketLog()
	server.SetResponseHandler(log.handler)
	a := openChannel(t, server, log)
	server.HandleMessage(cborPacket(a, []byte{0x02}))
	<-ctap.started
	server.HostDisconnected()
	<-ctap.cancelled
	time.Sleep(50 * time.Millisecond)
	for len(log.packets) > 0 {
		packet := <-log.packets
		test.Assert(t, packet[4] == byte(ctapHIDCommandKeepalive), "abandoned request still answered")
	}
	// The old channel is gone.
	server.HandleMessage(cborPacket(a, []byte{0x04}))
	reply := log.next(t)
	test.AssertEqual(t, reply[7], byte(ctapHIDErrorInvalidChannel), "stale channel accepted after disconnect")
}
