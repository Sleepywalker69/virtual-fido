package ctap

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

// ctxApprover approves after an optional delay unless the context is cancelled.
type ctxApprover struct {
	delay   time.Duration
	deny    bool
	started chan struct{}
}

func (a *ctxApprover) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	return a.ApproveClientActionContext(context.Background(), action, params)
}

func (a *ctxApprover) ApproveClientActionContext(ctx context.Context, action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	if a.started != nil {
		a.started <- struct{}{}
	}
	select {
	case <-time.After(a.delay):
		return !a.deny
	case <-ctx.Done():
		return false
	}
}

func newTestServer(t *testing.T, pinSupport bool, approver fido_client.ClientRequestApprover) (*CTAPServer, *fido_client.DefaultFIDOClient) {
	t.Helper()
	caPriv, err := identities.CreateCAPrivateKey()
	util.CheckErr(err, "ca key")
	ca, err := identities.CreateSelfSignedCA(caPriv)
	util.CheckErr(err, "ca")
	client, err := fido_client.LoadDefaultClient(ca, caPriv, [32]byte{1}, pinSupport, approver, nil, &memSaver{})
	util.CheckErr(err, "client")
	return NewCTAPServer(client), client
}

var es256 = []webauthn.PublicKeyCredentialParams{{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256}}

func makeCredential(t *testing.T, server *CTAPServer, rpID string, userID []byte, rk bool, exclude []webauthn.PublicKeyCredentialDescriptor) (ctapStatusCode, []byte) {
	t.Helper()
	args := makeCredentialArgs{
		ClientDataHash:   crypto.RandomBytes(32),
		RP:               &webauthn.PublicKeyCredentialRPEntity{ID: rpID, Name: rpID},
		User:             &webauthn.PublicKeyCrendentialUserEntity{ID: userID, Name: "user", DisplayName: "User"},
		PubKeyCredParams: es256,
		ExcludeList:      exclude,
		Options:          &makeCredentialOptions{ResidentKey: rk},
	}
	resp := server.HandleMessageForChannel(1, util.Concat([]byte{byte(ctapCommandMakeCredential)}, util.MarshalCBOR(args)))
	if ctapStatusCode(resp[0]) != ctap1ErrSuccess {
		return ctapStatusCode(resp[0]), nil
	}
	var mc makeCredentialResponse
	util.CheckErr(cbor.Unmarshal(resp[1:], &mc), "decode MC")
	att := mc.AuthData[37:]
	l := int(att[16])<<8 | int(att[17])
	return ctap1ErrSuccess, append([]byte{}, att[18:18+l]...)
}

func getAssertion(server *CTAPServer, rpID string, allow []webauthn.PublicKeyCredentialDescriptor, pinAuth []byte, cdh []byte) (ctapStatusCode, getAssertionResponse) {
	args := getAssertionArgs{RPID: rpID, ClientDataHash: cdh, AllowList: allow}
	if pinAuth != nil {
		args.PINUVAuthParam = pinAuth
		args.PINUVAuthProtocol = 1
	}
	resp := server.HandleMessageForChannel(1, util.Concat([]byte{byte(ctapCommandGetAssertion)}, util.MarshalCBOR(args)))
	var ga getAssertionResponse
	if ctapStatusCode(resp[0]) == ctap1ErrSuccess {
		util.CheckErr(cbor.Unmarshal(resp[1:], &ga), "decode GA")
	}
	return ctapStatusCode(resp[0]), ga
}

func TestDiscoverableLoginWithoutPIN(t *testing.T) {
	server, _ := newTestServer(t, false, &autoApprove{})
	code, _ := makeCredential(t, server, "example.com", []byte{1}, true, nil)
	test.AssertEqual(t, code, ctap1ErrSuccess, "MakeCredential")
	code, ga := getAssertion(server, "example.com", nil, nil, crypto.RandomBytes(32))
	test.AssertEqual(t, code, ctap1ErrSuccess, "usernameless sign-in must not require UV when none was asked for")
	test.Assert(t, ga.AuthenticatorData[32]&byte(authDataFlagUserPresent) != 0, "UP flag missing")
}

func TestNonDiscoverableCredentialNotOfferedForUsernamelessLogin(t *testing.T) {
	server, _ := newTestServer(t, false, &autoApprove{})
	_, nonResident := makeCredential(t, server, "example.com", []byte{1}, false, nil)
	code, _ := getAssertion(server, "example.com", nil, nil, crypto.RandomBytes(32))
	test.AssertEqual(t, code, ctap2ErrNoCredentials, "non-resident credential offered for usernameless sign-in")
	code, ga := getAssertion(server, "example.com", []webauthn.PublicKeyCredentialDescriptor{{Type: "public-key", ID: nonResident}}, nil, crypto.RandomBytes(32))
	test.AssertEqual(t, code, ctap1ErrSuccess, "allowList sign-in")
	test.Assert(t, bytes.Equal(ga.Credential.ID, nonResident), "wrong credential")
}

func TestExcludeListAndResidentReplacement(t *testing.T) {
	server, client := newTestServer(t, false, &autoApprove{})
	_, first := makeCredential(t, server, "example.com", []byte{7}, true, nil)
	code, _ := makeCredential(t, server, "example.com", []byte{7}, true, []webauthn.PublicKeyCredentialDescriptor{{Type: "public-key", ID: first}})
	test.AssertEqual(t, code, ctap2ErrCredentialExcluded, "excludeList ignored")
	_, second := makeCredential(t, server, "example.com", []byte{7}, true, nil)
	ids := client.Identities()
	test.AssertEqual(t, len(ids), 1, "re-registering the same account should replace its passkey")
	test.Assert(t, bytes.Equal(ids[0].ID, second), "old passkey kept instead of the new one")
}

func TestGetNextAssertionKeepsUVFlag(t *testing.T) {
	server, client := newTestServer(t, true, &autoApprove{})
	client.SetPIN([]byte("1234"))
	token := client.PINToken()
	cdh := crypto.RandomBytes(32)
	for _, user := range [][]byte{{1}, {2}} {
		args := makeCredentialArgs{
			ClientDataHash: cdh, PubKeyCredParams: es256, Options: &makeCredentialOptions{ResidentKey: true},
			RP:             &webauthn.PublicKeyCredentialRPEntity{ID: "example.com"},
			User:           &webauthn.PublicKeyCrendentialUserEntity{ID: user, Name: "u"},
			PINUVAuthParam: hmac16(token, cdh), PINUVAuthProtocol: 1,
		}
		resp := server.HandleMessage(util.Concat([]byte{byte(ctapCommandMakeCredential)}, util.MarshalCBOR(args)))
		test.AssertEqual(t, ctapStatusCode(resp[0]), ctap1ErrSuccess, "MC with PIN")
	}
	gaArgs := getAssertionArgs{RPID: "example.com", ClientDataHash: cdh, PINUVAuthParam: hmac16(token, cdh), PINUVAuthProtocol: 1}
	resp := server.HandleMessage(util.Concat([]byte{byte(ctapCommandGetAssertion)}, util.MarshalCBOR(gaArgs)))
	test.AssertEqual(t, ctapStatusCode(resp[0]), ctap1ErrSuccess, "GA")
	var ga getAssertionResponse
	util.CheckErr(cbor.Unmarshal(resp[1:], &ga), "decode")
	test.AssertEqual(t, ga.NumberOfCredentials, int32(2), "numberOfCredentials")
	next := server.HandleMessage([]byte{byte(ctapCommandGetNextAssertion)})
	test.AssertEqual(t, ctapStatusCode(next[0]), ctap1ErrSuccess, "GetNextAssertion")
	var ga2 getAssertionResponse
	util.CheckErr(cbor.Unmarshal(next[1:], &ga2), "decode")
	test.Assert(t, ga2.AuthenticatorData[32]&byte(authDataFlagUserVerified) != 0, "UV flag lost in GetNextAssertion")
}

func TestInvalidInputsDoNotPanic(t *testing.T) {
	server, client := newTestServer(t, true, &autoApprove{})
	client.SetPIN([]byte("1234"))
	offCurve := &cose.COSEEC2Key{KeyType: 2, Algorithm: -25, Curve: 1, X: bytes.Repeat([]byte{1}, 32), Y: bytes.Repeat([]byte{2}, 32)}
	cases := map[string][]byte{
		"off-curve key agreement": util.Concat([]byte{byte(ctapCommandClientPIN)}, util.MarshalCBOR(clientPINArgs{PINUVAuthProtocol: 1, SubCommand: clientPinSubcommandGetPINToken, KeyAgreement: offCurve, PINHashEncoding: make([]byte, 16)})),
		"missing key agreement":   util.Concat([]byte{byte(ctapCommandClientPIN)}, util.MarshalCBOR(clientPINArgs{PINUVAuthProtocol: 1, SubCommand: clientPinSubcommandGetPINToken, PINHashEncoding: make([]byte, 16)})),
		"garbage MakeCredential":  {byte(ctapCommandMakeCredential), 0xFF, 0x00},
		"garbage GetAssertion":    {byte(ctapCommandGetAssertion), 0xA1},
		"empty message":           {},
	}
	for name, message := range cases {
		resp := server.HandleMessageForChannel(1, message)
		test.Assert(t, len(resp) > 0 && ctapStatusCode(resp[0]) != ctap1ErrSuccess, name+" was accepted")
	}
	test.AssertEqual(t, client.PINRetries(), int32(8), "malformed requests must not use up PIN retries")
}

func TestCancelledApprovalReturnsKeepaliveCancel(t *testing.T) {
	approver := &ctxApprover{delay: time.Minute, started: make(chan struct{}, 1)}
	server, _ := newTestServer(t, false, approver)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []byte)
	args := makeCredentialArgs{
		ClientDataHash: crypto.RandomBytes(32), PubKeyCredParams: es256,
		RP: &webauthn.PublicKeyCredentialRPEntity{ID: "example.com"}, User: &webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1}},
	}
	go func() {
		done <- server.HandleMessageContext(ctx, 1, util.Concat([]byte{byte(ctapCommandMakeCredential)}, util.MarshalCBOR(args)))
	}()
	<-approver.started
	test.Assert(t, server.UserPresenceNeeded(), "UserPresenceNeeded not set while waiting for approval")
	cancel()
	select {
	case resp := <-done:
		test.AssertEqual(t, ctapStatusCode(resp[0]), ctap2ErrKeepaliveCancel, "cancelled request status")
	case <-time.After(2 * time.Second):
		t.Fatalf("cancelling did not end the approval wait")
	}
	test.Assert(t, !server.UserPresenceNeeded(), "UserPresenceNeeded left set")
}

func TestPINRetriesPersist(t *testing.T) {
	caPriv, _ := identities.CreateCAPrivateKey()
	ca, _ := identities.CreateSelfSignedCA(caPriv)
	saver := &memSaver{}
	client, err := fido_client.LoadDefaultClient(ca, caPriv, [32]byte{1}, true, &autoApprove{}, nil, saver)
	util.CheckErr(err, "client")
	client.SetPIN([]byte("1234"))
	client.SetPINRetries(5)
	reloaded, err := fido_client.LoadDefaultClient(ca, caPriv, [32]byte{1}, true, &autoApprove{}, nil, saver)
	util.CheckErr(err, "reload")
	test.AssertEqual(t, reloaded.PINRetries(), int32(5), "PIN retries reset by a restart")
	_, err = fido_client.LoadDefaultClient(ca, caPriv, [32]byte{1}, true, &autoApprove{}, nil, &wrongPassphraseSaver{saver})
	test.Assert(t, err != nil, "wrong passphrase accepted")
}

type wrongPassphraseSaver struct{ *memSaver }

func (w *wrongPassphraseSaver) Passphrase() string { return "wrong" }
