package ctap_hid

import (
	"github.com/bulwarkid/virtual-fido/util"
)

// ctapHIDChannel holds the message being reassembled on one channel. It is
// only touched by HandleMessage, which processes reports sequentially.
type ctapHIDChannel struct {
	channelId   ctapHIDChannelID
	transaction *ctapHIDTransaction
}

func newCTAPHIDChannel(channelId ctapHIDChannelID) *ctapHIDChannel {
	return &ctapHIDChannel{channelId: channelId}
}

type ctapHIDInitResponse struct {
	Nonce              [8]byte
	NewChannelID       ctapHIDChannelID
	ProtocolVersion    uint8
	DeviceVersionMajor uint8
	DeviceVersionMinor uint8
	DeviceVersionBuild uint8
	CapabilitiesFlags  ctapHIDCapabilityFlag
}

// handleBroadcastMessage handles the broadcast channel, which only carries
// CTAPHID_INIT (channel allocation).
func (server *CTAPHIDServer) handleBroadcastMessage(message []byte) {
	transaction := newCTAPHIDTransaction(message)
	if !transaction.done || transaction.errorCode != 0 || transaction.cancelled {
		return
	}
	header := transaction.result.header
	if header.Command != ctapHIDCommandInit {
		server.sendError(ctapHIDBroadcastChannel, ctapHIDErrorInvalidCommand)
		return
	}
	if len(transaction.result.payload) < 8 {
		server.sendError(ctapHIDBroadcastChannel, ctapHIDErrorInvalidLength)
		return
	}
	channel := server.newChannel()
	server.sendInitResponse(ctapHIDBroadcastChannel, transaction.result.payload[:8], channel.channelId)
}

// sendInitResponse replies to CTAPHID_INIT. Payload layout:
// [8] nonce | [4] channel ID (big endian) | [1] protocol version | [3] device version | [1] capabilities
func (server *CTAPHIDServer) sendInitResponse(onChannel ctapHIDChannelID, nonce []byte, channelID ctapHIDChannelID) {
	response := ctapHIDInitResponse{
		NewChannelID:       channelID,
		ProtocolVersion:    2,
		DeviceVersionMajor: 0,
		DeviceVersionMinor: 0,
		DeviceVersionBuild: 1,
		CapabilitiesFlags:  ctapHIDCapabilityCBOR,
	}
	copy(response.Nonce[:], nonce)
	ctapHIDLogger.Printf("CTAPHID INIT RESPONSE: %#v\n\n", response)
	payload := util.Concat(
		response.Nonce[:],
		util.ToBE(response.NewChannelID),
		[]byte{response.ProtocolVersion, response.DeviceVersionMajor, response.DeviceVersionMinor, response.DeviceVersionBuild, byte(response.CapabilitiesFlags)},
	)
	server.sendResponse(onChannel, ctapHIDCommandInit, payload)
}
