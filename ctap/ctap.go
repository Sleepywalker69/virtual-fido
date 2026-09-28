package ctap

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"

	"github.com/fxamacker/cbor/v2"
)

var ctapLogger = util.NewLogger("[CTAP] ", util.LogLevelDebug)
var unsafeCtapLogger = util.NewLogger("[CTAP] ", util.LogLevelUnsafe)

var aaguid = [16]byte{117, 108, 90, 245, 236, 166, 1, 163, 47, 198, 211, 12, 226, 242, 1, 197}

type ctapCommand uint8

const (
	ctapCommandMakeCredential   ctapCommand = 0x01
	ctapCommandGetAssertion     ctapCommand = 0x02
	ctapCommandGetInfo          ctapCommand = 0x04
	ctapCommandClientPIN        ctapCommand = 0x06
	ctapCommandReset            ctapCommand = 0x07
	ctapCommandGetNextAssertion ctapCommand = 0x08
	// CTAP 2.1+: authenticatorSelection (aka authenticatorSelect)
	ctapCommandAuthenticatorSelection ctapCommand = 0x0B
)

var ctapCommandDescriptions = map[ctapCommand]string{
	ctapCommandMakeCredential:         "ctapCommandMakeCredential",
	ctapCommandGetAssertion:           "ctapCommandGetAssertion",
	ctapCommandGetInfo:                "ctapCommandGetInfo",
	ctapCommandClientPIN:              "ctapCommandClientPIN",
	ctapCommandReset:                  "ctapCommandReset",
	ctapCommandGetNextAssertion:       "ctapCommandGetNextAssertion",
	ctapCommandAuthenticatorSelection: "ctapCommandAuthenticatorSelection",
}

type ctapStatusCode byte

const (
	ctap1ErrSuccess          ctapStatusCode = 0x00
	ctap1ErrInvalidCommand   ctapStatusCode = 0x01
	ctap1ErrInvalidParameter ctapStatusCode = 0x02
	ctap1ErrInvalidLength    ctapStatusCode = 0x03
	ctap1ErrInvalidSequence  ctapStatusCode = 0x04
	ctap1ErrTimeout          ctapStatusCode = 0x05
	ctap1ErrChannelBusy      ctapStatusCode = 0x06

	ctap2ErrInvalidCBOR          ctapStatusCode = 0x12
	ctap2ErrMissingParam         ctapStatusCode = 0x14
	ctap2ErrCredentialExcluded   ctapStatusCode = 0x19
	ctap2ErrUnsupportedAlgorithm ctapStatusCode = 0x26
	ctap2ErrOperationDenied      ctapStatusCode = 0x27
	ctap2ErrInvalidOption        ctapStatusCode = 0x2C
	ctap2ErrKeepaliveCancel      ctapStatusCode = 0x2D
	ctap2ErrNoCredentials        ctapStatusCode = 0x2E
	ctap2ErrNotAllowed           ctapStatusCode = 0x30
	ctap2ErrPINInvalid           ctapStatusCode = 0x31
	ctap2ErrPINBlocked           ctapStatusCode = 0x32
	ctap2ErrPINAuthInvalid       ctapStatusCode = 0x33
	ctap2ErrPINAuthBlocked       ctapStatusCode = 0x34
	ctap2ErrNoPINSet             ctapStatusCode = 0x35
	ctap2ErrPINRequired          ctapStatusCode = 0x36
	ctap2ErrPINPolicyViolation   ctapStatusCode = 0x37
	ctap2ErrPINExpired           ctapStatusCode = 0x38
	ctap2ErrInvalidSubcommand    ctapStatusCode = 0x3E
	ctap1ErrOther                ctapStatusCode = 0x7F
)

const (
	pinMaxRetries      = 8
	pinMaxBootFailures = 3
)

type CTAPClient interface {
	SupportsResidentKey() bool
	SupportsPIN() bool
	SupportsUserVerification() bool

	NewCredentialSource(
		PubKeyCredParams []webauthn.PublicKeyCredentialParams,
		ExcludeList []webauthn.PublicKeyCredentialDescriptor,
		relyingParty *webauthn.PublicKeyCredentialRPEntity,
		user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource
	GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource
	// Returns all matching credential sources for GA
	GetAssertionSources(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) []*identities.CredentialSource
	CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte

	PINHash() []byte
	SetPINHash(pin []byte)
	PINRetries() int32
	SetPINRetries(retries int32)
	PINKeyAgreement() *crypto.ECDHKey
	RotatePINKeyAgreement()
	PINToken() []byte
	RotatePINToken()

	// Persist any state changes (e.g., credRandom or counters)
	SaveState()
	VerifyUser(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool

	ApproveAccountCreation(relyingParty string) bool
	ApproveAccountLogin(credentialSource *identities.CredentialSource) bool
}

// ContextApprover is implemented by clients whose approval prompts can be
// withdrawn when the host cancels, and that want the full relying party (its
// ID is the domain the browser vouches for).
type ContextApprover interface {
	ApproveAccountCreationContext(ctx context.Context, relyingParty *webauthn.PublicKeyCredentialRPEntity, user *webauthn.PublicKeyCrendentialUserEntity) bool
	ApproveAccountLoginContext(ctx context.Context, credentialSource *identities.CredentialSource) bool
}

// credentialDeleter lets MakeCredential replace an older discoverable
// credential for the same account instead of accumulating duplicates.
type credentialDeleter interface {
	DeleteIdentity(id []byte) bool
}

// credentialUpdater lets the client apply credential changes under its own lock.
type credentialUpdater interface {
	UpdateCredential(update func())
}

type CTAPServer struct {
	client CTAPClient
	// mu serializes CTAP message handling: an authenticator processes one
	// command at a time.
	mu sync.Mutex
	// ctx and currentChannelID describe the request being handled (guarded by mu).
	ctx              context.Context
	currentChannelID uint32
	// per-channel assertion sessions for GetNextAssertion
	assertionSessions map[uint32]*assertionSession
	// pinBootFailures counts consecutive wrong-PIN attempts this power cycle; at
	// pinMaxBootFailures the authenticator refuses further PIN auth until restart.
	pinBootFailures uint8
	// pinTokenIssued records that the current pinUvAuthToken was handed out via
	// getPINToken since it was last rotated.
	pinTokenIssued bool
	// userPresenceNeeded is set while waiting for the user's approval, so the
	// transport can report STATUS_UPNEEDED in keepalives.
	userPresenceNeeded atomic.Bool
}

func NewCTAPServer(client CTAPClient) *CTAPServer {
	return &CTAPServer{
		client:            client,
		assertionSessions: make(map[uint32]*assertionSession),
	}
}

// HandleMessageContext handles one CTAP request. Cancelling ctx withdraws any
// pending approval prompt and makes the request fail with KEEPALIVE_CANCEL.
func (server *CTAPServer) HandleMessageContext(ctx context.Context, channelID uint32, data []byte) []byte {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.ctx = ctx
	server.currentChannelID = channelID
	defer func() {
		server.ctx = nil
		server.currentChannelID = 0
	}()
	return server.dispatch(data)
}

func (server *CTAPServer) HandleMessageForChannel(channelID uint32, data []byte) []byte {
	return server.HandleMessageContext(context.Background(), channelID, data)
}

func (server *CTAPServer) HandleMessage(data []byte) []byte {
	return server.HandleMessageContext(context.Background(), 0, data)
}

// UserPresenceNeeded reports whether a request is waiting for the user.
func (server *CTAPServer) UserPresenceNeeded() bool {
	return server.userPresenceNeeded.Load()
}

func (server *CTAPServer) requestContext() context.Context {
	if server.ctx != nil {
		return server.ctx
	}
	return context.Background()
}

// dispatch runs the command switch; callers must hold server.mu.
func (server *CTAPServer) dispatch(data []byte) []byte {
	if len(data) == 0 {
		return []byte{byte(ctap1ErrInvalidLength)}
	}
	command := ctapCommand(data[0])
	ctapLogger.Printf("CTAP COMMAND: %s\n\n", ctapCommandDescriptions[command])
	if command != ctapCommandGetNextAssertion {
		// GetNextAssertion is only valid right after GetAssertion.
		delete(server.assertionSessions, server.currentChannelID)
	}
	switch command {
	case ctapCommandMakeCredential:
		return server.handleMakeCredential(data[1:])
	case ctapCommandGetInfo:
		return server.handleGetInfo()
	case ctapCommandGetAssertion:
		return server.handleGetAssertion(data[1:])
	case ctapCommandGetNextAssertion:
		return server.handleGetNextAssertion()
	case ctapCommandClientPIN:
		return server.handleClientPIN(data[1:])
	case ctapCommandAuthenticatorSelection:
		// CTAP2.1 authenticatorSelection requires only a success status and no CBOR payload.
		return []byte{byte(ctap1ErrSuccess)}
	default:
		ctapLogger.Printf("Invalid CTAP Command: %d\n\n", command)
		return []byte{byte(ctap1ErrInvalidCommand)}
	}
}

type attestedCredentialData struct {
	AAGUID             []byte
	CredentialIDLength uint16
	CredentialID       []byte
	EncodedPublicKey   []byte
}

type authDataFlags uint8

const (
	authDataFlagUserPresent           authDataFlags = 0b00000001
	authDataFlagUserVerified          authDataFlags = 0b00000100
	authDataFlagAttestedDataIncluded  authDataFlags = 0b01000000
	authDataFlagExtensionDataIncluded authDataFlags = 0b10000000
)

type authData struct {
	RelyingPartyIDHash     []byte
	Flags                  authDataFlags
	AttestedCredentialData *attestedCredentialData
}

type selfAttestationStatement struct {
	Alg cose.COSEAlgorithmID `cbor:"alg"`
	Sig []byte               `cbor:"sig"`
}

type basicAttestationStatement struct {
	Alg cose.COSEAlgorithmID `cbor:"alg"`
	Sig []byte               `cbor:"sig"`
	X5c [][]byte             `cbor:"x5c"`
}

func makeAttestedCredentialData(credentialSource *identities.CredentialSource) []byte {
	encodedCredentialPublicKey := cose.MarshalCOSEPublicKey(credentialSource.PrivateKey.Public())
	return util.Concat(aaguid[:], util.ToBE(uint16(len(credentialSource.ID))), credentialSource.ID, encodedCredentialPublicKey)
}

func makeAuthData(rpID string, credentialSource *identities.CredentialSource, attestedCredentialData []byte, flags authDataFlags) []byte {
	return makeAuthDataWithExtensions(rpID, credentialSource, attestedCredentialData, flags, nil)
}

func makeAuthDataWithExtensions(rpID string, credentialSource *identities.CredentialSource, attestedCredentialData []byte, flags authDataFlags, extensions []byte) []byte {
	if attestedCredentialData != nil {
		flags = flags | authDataFlagAttestedDataIncluded
	} else {
		attestedCredentialData = []byte{}
	}
	if len(extensions) > 0 {
		flags = flags | authDataFlagExtensionDataIncluded
	}
	rpIdHash := sha256.Sum256([]byte(rpID))
	return util.Concat(rpIdHash[:], []byte{uint8(flags)}, util.ToBE(credentialSource.SignatureCounter), attestedCredentialData, extensions)
}

type makeCredentialOptions struct {
	ResidentKey      bool  `cbor:"rk,omitempty"`
	UserVerification bool  `cbor:"uv,omitempty"`
	UserPresence     *bool `cbor:"up,omitempty"`
}

type makeCredentialArgs struct {
	ClientDataHash    []byte                                   `cbor:"1,keyasint,omitempty"`
	RP                *webauthn.PublicKeyCredentialRPEntity    `cbor:"2,keyasint,omitempty"`
	User              *webauthn.PublicKeyCrendentialUserEntity `cbor:"3,keyasint,omitempty"`
	PubKeyCredParams  []webauthn.PublicKeyCredentialParams     `cbor:"4,keyasint,omitempty"`
	ExcludeList       []webauthn.PublicKeyCredentialDescriptor `cbor:"5,keyasint,omitempty"`
	Extensions        map[string]interface{}                   `cbor:"6,keyasint,omitempty"`
	Options           *makeCredentialOptions                   `cbor:"7,keyasint,omitempty"`
	PINUVAuthParam    []byte                                   `cbor:"8,keyasint,omitempty"`
	PINUVAuthProtocol uint32                                   `cbor:"9,keyasint,omitempty"`
}

func (args makeCredentialArgs) String() string {
	return fmt.Sprintf("ctapMakeCredentialArgs{ ClientDataHash: 0x%s, Relying Party: %s, User: %s, PublicKeyCredentialParams: %#v, ExcludeList: %#v, Extensions: %#v, Options: %#v, PinAuth: %#v, PinProtocol: %d }",
		hex.EncodeToString(args.ClientDataHash),
		args.RP,
		args.User,
		args.PubKeyCredParams,
		args.ExcludeList,
		args.Extensions,
		args.Options,
		args.PINUVAuthParam,
		args.PINUVAuthProtocol,
	)
}

type makeCredentialResponse struct {
	FormatIdentifer      string                    `cbor:"1,keyasint"`
	AuthData             []byte                    `cbor:"2,keyasint"`
	AttestationStatement basicAttestationStatement `cbor:"3,keyasint"`
}

func status(code ctapStatusCode) []byte {
	return []byte{byte(code)}
}

func (server *CTAPServer) handleMakeCredential(data []byte) []byte {
	var args makeCredentialArgs
	if err := cbor.Unmarshal(data, &args); err != nil {
		ctapLogger.Printf("ERROR: invalid MakeCredential CBOR: %v\n\n", err)
		return status(ctap2ErrInvalidCBOR)
	}
	ctapLogger.Printf("MAKE CREDENTIAL: %s\n\n", args)
	if args.ClientDataHash == nil || args.RP == nil || args.RP.ID == "" || args.User == nil || args.PubKeyCredParams == nil {
		ctapLogger.Printf("ERROR: MakeCredential is missing a required parameter\n\n")
		return status(ctap2ErrMissingParam)
	}
	supported := false
	for _, param := range args.PubKeyCredParams {
		if param.Algorithm == cose.COSE_ALGORITHM_ID_ES256 && param.Type == "public-key" {
			supported = true
		}
	}
	if !supported {
		ctapLogger.Printf("ERROR: Unsupported Algorithm\n\n")
		return status(ctap2ErrUnsupportedAlgorithm)
	}
	if args.Options != nil && args.Options.UserPresence != nil && !*args.Options.UserPresence {
		return status(ctap2ErrInvalidOption)
	}
	if code, isProbe := server.pinProbeResponse(args.PINUVAuthParam); isProbe {
		return status(code)
	}

	residentKey := args.Options != nil && args.Options.ResidentKey
	wantsUV := args.Options != nil && args.Options.UserVerification
	params := fido_client.ClientActionRequestParams{RelyingPartyID: args.RP.ID, RelyingParty: args.RP.Name, UserName: args.User.Name}
	uvSatisfied := false
	if args.PINUVAuthParam != nil {
		if code := server.verifyPINUVAuthParam(args.PINUVAuthProtocol, args.PINUVAuthParam, args.ClientDataHash); code != ctap1ErrSuccess {
			return status(code)
		}
		uvSatisfied = true
	} else if wantsUV {
		verified, code := server.attemptUserVerification(fido_client.ClientActionFIDOMakeCredential, params)
		if !verified {
			if code != nil {
				return status(*code)
			}
			return status(ctap2ErrOperationDenied)
		}
		uvSatisfied = true
	} else if server.client.SupportsPIN() && server.client.PINHash() != nil {
		// A PIN is configured but the request supplied neither a pinUvAuthParam
		// nor a uv option: the platform must collect the PIN first.
		return status(ctap2ErrPINRequired)
	}

	// The site already has a credential on this authenticator.
	if len(args.ExcludeList) > 0 && len(server.client.GetAssertionSources(args.RP.ID, args.ExcludeList)) > 0 {
		ctapLogger.Printf("MakeCredential: authenticator already registered with %s\n\n", args.RP.ID)
		return status(ctap2ErrCredentialExcluded)
	}

	if code := server.requestApproval(func(ctx context.Context) bool {
		if approver, ok := server.client.(ContextApprover); ok {
			return approver.ApproveAccountCreationContext(ctx, args.RP, args.User)
		}
		return server.client.ApproveAccountCreation(args.RP.Name)
	}); code != ctap1ErrSuccess {
		ctapLogger.Printf("ERROR: Unapproved action (Create account)\n\n")
		return status(code)
	}
	var flags authDataFlags = authDataFlagUserPresent
	if uvSatisfied {
		flags |= authDataFlagUserVerified
	}

	credentialSource := server.client.NewCredentialSource(args.PubKeyCredParams, args.ExcludeList, args.RP, args.User)
	if credentialSource == nil {
		ctapLogger.Printf("ERROR: Unsupported Algorithm\n\n")
		return status(ctap2ErrUnsupportedAlgorithm)
	}
	extensionOutputs := map[string]interface{}{}
	server.updateCredential(func() {
		credentialSource.Discoverable = residentKey
		if enabled, ok := args.Extensions["hmac-secret"].(bool); ok && enabled {
			credentialSource.CredRandom = crypto.RandomBytes(32)
			extensionOutputs["hmac-secret"] = true
		}
	})
	if residentKey {
		server.replaceOlderDiscoverableCredentials(credentialSource)
	}
	var extensionData []byte
	if len(extensionOutputs) > 0 {
		extensionData = util.MarshalCBOR(extensionOutputs)
	}
	attestedCredentialData := makeAttestedCredentialData(credentialSource)
	authenticatorData := makeAuthDataWithExtensions(args.RP.ID, credentialSource, attestedCredentialData, flags, extensionData)

	attestationCert := server.client.CreateAttestationCertificiate(credentialSource.PrivateKey)
	attestationSignature := credentialSource.PrivateKey.Sign(append(authenticatorData, args.ClientDataHash...))
	attestationStatement := basicAttestationStatement{
		Alg: cose.COSE_ALGORITHM_ID_ES256,
		Sig: attestationSignature,
		X5c: [][]byte{attestationCert},
	}

	response := makeCredentialResponse{
		AuthData:             authenticatorData,
		FormatIdentifer:      "packed",
		AttestationStatement: attestationStatement,
	}
	ctapLogger.Printf("MAKE CREDENTIAL RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

// requestApproval asks the user (via the client) and maps the outcome to a
// CTAP status: success, OPERATION_DENIED, or KEEPALIVE_CANCEL if the host
// cancelled while the prompt was up.
func (server *CTAPServer) requestApproval(ask func(ctx context.Context) bool) ctapStatusCode {
	ctx := server.requestContext()
	server.userPresenceNeeded.Store(true)
	approved := ask(ctx)
	server.userPresenceNeeded.Store(false)
	if ctx.Err() != nil {
		return ctap2ErrKeepaliveCancel
	}
	if !approved {
		return ctap2ErrOperationDenied
	}
	return ctap1ErrSuccess
}

func (server *CTAPServer) updateCredential(update func()) {
	if updater, ok := server.client.(credentialUpdater); ok {
		updater.UpdateCredential(update)
		return
	}
	update()
	server.client.SaveState()
}

// replaceOlderDiscoverableCredentials removes discoverable credentials for the
// same relying party and user handle: a site re-registering an account
// replaces its passkey rather than adding a duplicate.
func (server *CTAPServer) replaceOlderDiscoverableCredentials(newSource *identities.CredentialSource) {
	deleter, ok := server.client.(credentialDeleter)
	if !ok || newSource.User == nil || newSource.RelyingParty == nil {
		return
	}
	for _, existing := range server.client.GetAssertionSources(newSource.RelyingParty.ID, nil) {
		if existing == newSource || !existing.Discoverable || existing.User == nil || bytes.Equal(existing.ID, newSource.ID) {
			continue
		}
		if bytes.Equal(existing.User.ID, newSource.User.ID) {
			deleter.DeleteIdentity(existing.ID)
		}
	}
}

// pinProbeResponse handles a zero-length pinUvAuthParam, which platforms send
// to make the user pick an authenticator (CTAP 2.1 §6.1.2 step 1). The answer
// tells them whether a PIN is set.
func (server *CTAPServer) pinProbeResponse(pinUVAuthParam []byte) (ctapStatusCode, bool) {
	if pinUVAuthParam == nil || len(pinUVAuthParam) != 0 || !server.client.SupportsPIN() {
		return 0, false
	}
	if server.client.PINHash() == nil {
		return ctap2ErrNoPINSet, true
	}
	return ctap2ErrPINInvalid, true
}

// verifyPINUVAuthParam checks pinUvAuthParam = LEFT(HMAC(pinUvAuthToken, clientDataHash), 16).
func (server *CTAPServer) verifyPINUVAuthParam(protocol uint32, pinUVAuthParam []byte, clientDataHash []byte) ctapStatusCode {
	if protocol != 1 {
		return ctap1ErrInvalidParameter
	}
	if !server.client.SupportsPIN() || server.client.PINHash() == nil {
		return ctap2ErrNoPINSet
	}
	// A token is only valid once handed out by getPINToken. Channel 0 (direct
	// calls without the HID transport, e.g. tests) may use the standing token.
	if !server.pinTokenIssued && server.currentChannelID != 0 {
		return ctap2ErrPINAuthInvalid
	}
	token := server.client.PINToken()
	if len(token) == 0 {
		return ctap2ErrPINAuthInvalid
	}
	if subtle.ConstantTimeCompare(server.derivePINAuth(token, clientDataHash), pinUVAuthParam) != 1 {
		return ctap2ErrPINAuthInvalid
	}
	return ctap1ErrSuccess
}

type getInfoOptions struct {
	IsPlatform       bool  `cbor:"plat"`
	CanResidentKey   bool  `cbor:"rk"`
	HasClientPIN     *bool `cbor:"clientPin,omitempty"`
	CanUserPresence  bool  `cbor:"up"`
	UserVerification *bool `cbor:"uv,omitempty"`
}

type getInfoResponse struct {
	Versions           []string       `cbor:"1,keyasint,omitempty"`
	Extensions         []string       `cbor:"2,keyasint,omitempty"`
	AAGUID             [16]byte       `cbor:"3,keyasint,omitempty"`
	Options            getInfoOptions `cbor:"4,keyasint,omitempty"`
	MaxMessageSize     uint32         `cbor:"5,keyasint,omitempty"`
	PINUVAuthProtocols []uint32       `cbor:"6,keyasint,omitempty"`
}

func (server *CTAPServer) handleGetInfo() []byte {
	response := getInfoResponse{
		// Advertise the versions we actually implement: legacy U2F, CTAP2.0, and
		// CTAP2.1 (authenticatorSelection 0x0B + getPinUvAuthTokenUsingPin 0x09).
		Versions: []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"},
		AAGUID:   aaguid,
		Options: getInfoOptions{
			IsPlatform:      false,
			CanResidentKey:  server.client.SupportsResidentKey(),
			CanUserPresence: true,
		},
		// A safe upper bound for our HID implementation; large enough for typical requests
		MaxMessageSize: 4096,
		Extensions:     []string{"hmac-secret"},
		// hmac-secret needs a PIN/UV protocol for its key agreement even when
		// PINs are disabled.
		PINUVAuthProtocols: []uint32{1},
	}
	if server.client.SupportsPIN() {
		var clientPINSet bool = server.client.PINHash() != nil
		response.Options.HasClientPIN = &clientPINSet
		// Do NOT set uv=true here; uv refers to on-device user verification, not PIN
	}
	if server.client.SupportsUserVerification() {
		uv := true
		response.Options.UserVerification = &uv
	}
	ctapLogger.Printf("GET_INFO RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

type getAssertionOptions struct {
	UserVerification bool  `cbor:"uv,omitempty"`
	UserPresence     *bool `cbor:"up,omitempty"`
}

type getAssertionArgs struct {
	RPID              string                                   `cbor:"1,keyasint"`
	ClientDataHash    []byte                                   `cbor:"2,keyasint"`
	AllowList         []webauthn.PublicKeyCredentialDescriptor `cbor:"3,keyasint"`
	Extensions        map[string]cbor.RawMessage               `cbor:"4,keyasint,omitempty"`
	Options           getAssertionOptions                      `cbor:"5,keyasint"`
	PINUVAuthParam    []byte                                   `cbor:"6,keyasint,omitempty"`
	PINUVAuthProtocol uint32                                   `cbor:"7,keyasint,omitempty"`
}

type getAssertionResponse struct {
	Credential          *webauthn.PublicKeyCredentialDescriptor  `cbor:"1,keyasint,omitempty"`
	AuthenticatorData   []byte                                   `cbor:"2,keyasint"`
	Signature           []byte                                   `cbor:"3,keyasint"`
	User                *webauthn.PublicKeyCrendentialUserEntity `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials int32                                    `cbor:"5,keyasint,omitempty"`
}

func (server *CTAPServer) handleGetAssertion(data []byte) []byte {
	var args getAssertionArgs
	if err := cbor.Unmarshal(data, &args); err != nil {
		ctapLogger.Printf("ERROR: invalid GetAssertion CBOR: %v\n\n", err)
		return status(ctap2ErrInvalidCBOR)
	}
	ctapLogger.Printf("GET ASSERTION: %#v\n\n", args)
	if args.RPID == "" || args.ClientDataHash == nil {
		return status(ctap2ErrMissingParam)
	}
	if code, isProbe := server.pinProbeResponse(args.PINUVAuthParam); isProbe {
		return status(code)
	}

	// With an empty allowList only discoverable (resident) credentials qualify.
	discoverable := len(args.AllowList) == 0
	sources := server.client.GetAssertionSources(args.RPID, args.AllowList)
	if discoverable {
		filtered := sources[:0:0]
		for _, source := range sources {
			if source.Discoverable {
				filtered = append(filtered, source)
			}
		}
		sources = filtered
	}

	// User verification is only required when the platform asks for it; a
	// pinUvAuthParam proves the user entered the PIN.
	uvSatisfied := false
	if args.PINUVAuthParam != nil {
		if code := server.verifyPINUVAuthParam(args.PINUVAuthProtocol, args.PINUVAuthParam, args.ClientDataHash); code != ctap1ErrSuccess {
			return status(code)
		}
		uvSatisfied = true
	} else if args.Options.UserVerification {
		params := fido_client.ClientActionRequestParams{RelyingPartyID: args.RPID}
		verified, code := server.attemptUserVerification(fido_client.ClientActionFIDOGetAssertion, params)
		if !verified {
			if code != nil {
				return status(*code)
			}
			return status(ctap2ErrOperationDenied)
		}
		uvSatisfied = true
	}

	if len(sources) == 0 {
		ctapLogger.Printf("ERROR: No Credentials\n\n")
		return status(ctap2ErrNoCredentials)
	}
	credentialSource := sources[0]
	unsafeCtapLogger.Printf("CREDENTIAL SOURCE: %#v\n\n", credentialSource)

	var flags authDataFlags = 0
	if args.Options.UserPresence == nil || *args.Options.UserPresence {
		if code := server.requestApproval(func(ctx context.Context) bool {
			if approver, ok := server.client.(ContextApprover); ok {
				return approver.ApproveAccountLoginContext(ctx, credentialSource)
			}
			return server.client.ApproveAccountLogin(credentialSource)
		}); code != ctap1ErrSuccess {
			ctapLogger.Printf("ERROR: Unapproved action (Account login)\n\n")
			return status(code)
		}
		flags |= authDataFlagUserPresent
	}
	if uvSatisfied {
		flags |= authDataFlagUserVerified
	}

	var hmacInput *hmacSecretInput
	if raw, ok := args.Extensions["hmac-secret"]; ok {
		var in hmacSecretInput
		if err := cbor.Unmarshal(raw, &in); err == nil && in.SaltEnc != nil && in.SaltAuth != nil && in.KeyAgreement != nil {
			hmacInput = &in
		}
	}
	response := server.makeAssertion(args.RPID, args.ClientDataHash, credentialSource, flags, hmacInput)
	if discoverable && len(sources) > 1 {
		response.NumberOfCredentials = int32(len(sources))
		sess := &assertionSession{
			rpID:           args.RPID,
			clientDataHash: args.ClientDataHash,
			flags:          flags,
			remaining:      append([]*identities.CredentialSource{}, sources[1:]...),
			hmacInput:      hmacInput,
		}
		server.assertionSessions[server.currentChannelID] = sess
	}
	ctapLogger.Printf("GET ASSERTION RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

// makeAssertion signs an assertion with credentialSource, advancing its
// signature counter.
func (server *CTAPServer) makeAssertion(rpID string, clientDataHash []byte, credentialSource *identities.CredentialSource, flags authDataFlags, hmacInput *hmacSecretInput) getAssertionResponse {
	var extensionData []byte
	if hmacInput != nil {
		if out, ok := server.computeHmacSecretOutput(credentialSource, hmacInput); ok {
			extensionData = util.MarshalCBOR(map[string][]byte{"hmac-secret": out})
		}
	}
	var authData []byte
	server.updateCredential(func() {
		credentialSource.SignatureCounter++
		authData = makeAuthDataWithExtensions(rpID, credentialSource, nil, flags, extensionData)
	})
	signature := credentialSource.PrivateKey.Sign(util.Concat(authData, clientDataHash))
	credentialDescriptor := credentialSource.CTAPDescriptor()
	return getAssertionResponse{
		Credential:        &credentialDescriptor,
		AuthenticatorData: authData,
		Signature:         signature,
		User:              credentialSource.User,
	}
}

// ---------- hmac-secret support ----------
type hmacSecretInput struct {
	KeyAgreement *cose.COSEEC2Key `cbor:"1,keyasint,omitempty"`
	SaltEnc      []byte           `cbor:"2,keyasint,omitempty"`
	SaltAuth     []byte           `cbor:"3,keyasint,omitempty"`
}

func (server *CTAPServer) computeHmacSecretOutput(cred *identities.CredentialSource, in *hmacSecretInput) ([]byte, bool) {
	if len(cred.CredRandom) == 0 || in.KeyAgreement == nil {
		return nil, false
	}
	sharedSecret, err := server.getPINSharedSecret(*in.KeyAgreement)
	if err != nil {
		ctapLogger.Printf("hmac-secret: %v\n\n", err)
		return nil, false
	}
	// Verify saltAuth = HMAC(sharedSecret, saltEnc)[:16]
	if subtle.ConstantTimeCompare(server.derivePINAuth(sharedSecret, in.SaltEnc), in.SaltAuth) != 1 {
		return nil, false
	}
	salts := crypto.DecryptAESCBC(sharedSecret, in.SaltEnc)
	if len(salts) != 32 && len(salts) != 64 {
		return nil, false
	}
	// HMAC-SHA256(credRandom, salt)
	h := hmac.New(sha256.New, cred.CredRandom)
	h.Write(salts[:32])
	out1 := h.Sum(nil)
	if len(salts) == 32 {
		// Per CTAP2, the hmac-secret output must be returned encrypted with the
		// shared secret (zero-IV AES-CBC, PIN protocol v1), not as raw HMAC.
		return crypto.EncryptAESCBC(sharedSecret, out1), true
	}
	h2 := hmac.New(sha256.New, cred.CredRandom)
	h2.Write(salts[32:])
	out2 := h2.Sum(nil)
	return crypto.EncryptAESCBC(sharedSecret, util.Concat(out1, out2)), true
}

type assertionSession struct {
	rpID           string
	clientDataHash []byte
	flags          authDataFlags
	remaining      []*identities.CredentialSource
	hmacInput      *hmacSecretInput
}

func (server *CTAPServer) handleGetNextAssertion() []byte {
	sess, ok := server.assertionSessions[server.currentChannelID]
	if !ok || sess == nil || len(sess.remaining) == 0 {
		return status(ctap2ErrNotAllowed)
	}
	cred := sess.remaining[0]
	sess.remaining = sess.remaining[1:]
	if len(sess.remaining) == 0 {
		delete(server.assertionSessions, server.currentChannelID)
	}
	// The user was present (and verified) for the GetAssertion this continues.
	response := server.makeAssertion(sess.rpID, sess.clientDataHash, cred, sess.flags, sess.hmacInput)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

type clientPINSubcommand uint32

const (
	clientPINSubcommandGetRetries      clientPINSubcommand = 1
	clientPinSubcommandGetKeyAgreement clientPINSubcommand = 2
	clientPINSubcommandSetPIN          clientPINSubcommand = 3
	clientPINSubcommandChangePIN       clientPINSubcommand = 4
	clientPinSubcommandGetPINToken     clientPINSubcommand = 5
	// CTAP 2.1 additions
	clientPinSubcommandGetPinUvAuthTokenUsingPin clientPINSubcommand = 9
)

var clientPINSubcommandDescriptions = map[clientPINSubcommand]string{
	clientPINSubcommandGetRetries:                "clientPINSubcommandGetRetries",
	clientPinSubcommandGetKeyAgreement:           "clientPinSubcommandGetKeyAgreement",
	clientPINSubcommandSetPIN:                    "clientPINSubcommandSetPIN",
	clientPINSubcommandChangePIN:                 "clientPINSubcommandChangePIN",
	clientPinSubcommandGetPINToken:               "clientPinSubcommandGetPINToken",
	clientPinSubcommandGetPinUvAuthTokenUsingPin: "clientPinSubcommandGetPinUvAuthTokenUsingPin",
}

type clientPINArgs struct {
	PINUVAuthProtocol uint32              `cbor:"1,keyasint"`
	SubCommand        clientPINSubcommand `cbor:"2,keyasint"`
	KeyAgreement      *cose.COSEEC2Key    `cbor:"3,keyasint,omitempty"`
	PINUVAuthParam    []byte              `cbor:"4,keyasint,omitempty"`
	NewPINEncoding    []byte              `cbor:"5,keyasint,omitempty"`
	PINHashEncoding   []byte              `cbor:"6,keyasint,omitempty"`
	// CTAP 2.1 optional fields for getPinUvAuthTokenUsingPin
	Permissions *uint8 `cbor:"9,keyasint,omitempty"`
	RPID        string `cbor:"10,keyasint,omitempty"`
}

func (args clientPINArgs) String() string {
	return fmt.Sprintf("ctapClientPINArgs{PinProtocol: %d, SubCommand: %s, KeyAgreement: %v, PINAuth: 0x%s, NewPINEncoding: 0x%s, PINHashEncoding: 0x%s}",
		args.PINUVAuthProtocol,
		clientPINSubcommandDescriptions[args.SubCommand],
		args.KeyAgreement,
		hex.EncodeToString(args.PINUVAuthParam),
		hex.EncodeToString(args.NewPINEncoding),
		hex.EncodeToString(args.PINHashEncoding))
}

type clientPINResponse struct {
	KeyAgreement interface{} `cbor:"1,keyasint,omitempty"`
	PinToken     []byte      `cbor:"2,keyasint,omitempty"`
	Retries      *uint8      `cbor:"3,keyasint,omitempty"`
}

func (args clientPINResponse) String() string {
	return fmt.Sprintf("ctapClientPINResponse{KeyAgreement: %s, PinToken: %s, Retries: %#v}",
		args.KeyAgreement,
		hex.EncodeToString(args.PinToken),
		args.Retries)
}

// getPINSharedSecret derives the PIN protocol 1 shared secret,
// SHA-256(ECDH x-coordinate), with the authenticator's key agreement key.
func (server *CTAPServer) getPINSharedSecret(remoteKey cose.COSEEC2Key) ([]byte, error) {
	x, err := server.client.PINKeyAgreement().SharedSecret(remoteKey.X, remoteKey.Y)
	if err != nil {
		return nil, err
	}
	return crypto.HashSHA256(x), nil
}

func (server *CTAPServer) derivePINAuth(sharedSecret []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, sharedSecret)
	hash.Write(data)
	return hash.Sum(nil)[:16]
}

func (server *CTAPServer) decryptPINHash(sharedSecret []byte, pinHashEncoding []byte) []byte {
	return crypto.DecryptAESCBC(sharedSecret, pinHashEncoding)
}

func (server *CTAPServer) decryptPIN(sharedSecret []byte, pinEncoding []byte) []byte {
	decryptedPINPadded := crypto.DecryptAESCBC(sharedSecret, pinEncoding)
	var decryptedPIN []byte = nil
	for i := range decryptedPINPadded {
		if decryptedPINPadded[i] == 0 {
			decryptedPIN = decryptedPINPadded[:i]
			break
		}
	}
	return decryptedPIN
}

func (server *CTAPServer) attemptUserVerification(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) (bool, *ctapStatusCode) {
	if !server.client.SupportsUserVerification() {
		if server.client.SupportsPIN() && server.client.PINHash() != nil {
			code := ctap2ErrPINRequired
			return false, &code
		}
		return false, nil
	}
	if server.client.VerifyUser(action, params) {
		return true, nil
	}
	if server.client.SupportsPIN() {
		if server.client.PINHash() != nil {
			code := ctap2ErrPINRequired
			return false, &code
		}
		code := ctap2ErrNoPINSet
		return false, &code
	}
	code := ctap2ErrOperationDenied
	return false, &code
}

func (server *CTAPServer) handleClientPIN(data []byte) []byte {
	var args clientPINArgs
	if err := cbor.Unmarshal(data, &args); err != nil {
		ctapLogger.Printf("ERROR: invalid ClientPIN CBOR: %v\n\n", err)
		return status(ctap2ErrInvalidCBOR)
	}
	ctapLogger.Printf("CLIENT_PIN: %v\n\n", args)
	if args.PINUVAuthProtocol != 1 {
		return status(ctap1ErrInvalidParameter)
	}
	// hmac-secret uses the key agreement too, so it works without PIN support.
	if args.SubCommand == clientPinSubcommandGetKeyAgreement {
		return server.handleGetKeyAgreement()
	}
	if !server.client.SupportsPIN() {
		return status(ctap1ErrInvalidCommand)
	}
	switch args.SubCommand {
	case clientPINSubcommandGetRetries:
		return server.handleGetRetries()
	case clientPINSubcommandSetPIN:
		return server.handleSetPIN(args)
	case clientPINSubcommandChangePIN:
		return server.handleChangePIN(args)
	case clientPinSubcommandGetPINToken, clientPinSubcommandGetPinUvAuthTokenUsingPin:
		return server.handleGetPINToken(args)
	default:
		return status(ctap2ErrInvalidSubcommand)
	}
}

func (server *CTAPServer) handleGetRetries() []byte {
	retries := uint8(server.client.PINRetries())
	response := clientPINResponse{Retries: &retries}
	ctapLogger.Printf("CLIENT_PIN_GET_RETRIES: %v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

// handleGetKeyAgreement returns the authenticator's key agreement public key.
// It stays the same until a wrong PIN rotates it, so a platform may reuse one
// shared secret for getPINToken and hmac-secret (libfido2 does).
func (server *CTAPServer) handleGetKeyAgreement() []byte {
	key := server.client.PINKeyAgreement()
	pad32 := func(b []byte) []byte {
		if len(b) >= 32 {
			return b
		}
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return out
	}
	// COSE EC2 public key map (CTAP requires alg = -25 for PIN key agreement)
	coseKey := map[int]interface{}{
		1:  int64(cose.COSE_KEY_TYPE_EC2),               // kty = 2 (EC2)
		3:  int64(cose.COSE_ALGORITHM_ID_ECDH_HKDF_256), // alg = -25 (ECDH-ES + HKDF-256)
		-1: int64(1),                                    // crv = 1 (P-256)
		-2: pad32(key.X.Bytes()),                        // x
		-3: pad32(key.Y.Bytes()),                        // y
	}
	response := clientPINResponse{KeyAgreement: coseKey}
	ctapLogger.Printf("CLIENT_PIN_GET_KEY_AGREEMENT RESPONSE: %#v\n\n", response)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}

func (server *CTAPServer) handleSetPIN(args clientPINArgs) []byte {
	if server.client.PINHash() != nil {
		return status(ctap2ErrPINAuthInvalid)
	}
	if args.KeyAgreement == nil || args.PINUVAuthParam == nil || args.NewPINEncoding == nil {
		return status(ctap2ErrMissingParam)
	}
	sharedSecret, err := server.getPINSharedSecret(*args.KeyAgreement)
	if err != nil {
		ctapLogger.Printf("setPIN: %v\n\n", err)
		return status(ctap1ErrInvalidParameter)
	}
	pinAuth := server.derivePINAuth(sharedSecret, args.NewPINEncoding)
	if subtle.ConstantTimeCompare(pinAuth, args.PINUVAuthParam) != 1 {
		return status(ctap2ErrPINAuthInvalid)
	}
	decryptedPIN := server.decryptPIN(sharedSecret, args.NewPINEncoding)
	if len(decryptedPIN) < 4 {
		return status(ctap2ErrPINPolicyViolation)
	}
	pinHash := crypto.HashSHA256(decryptedPIN)[:16]
	server.client.SetPINHash(pinHash)
	server.client.SetPINRetries(pinMaxRetries)
	server.pinBootFailures = 0
	// Setting a PIN invalidates previously issued tokens.
	server.client.RotatePINToken()
	server.pinTokenIssued = false
	unsafeCtapLogger.Printf("SETTING PIN HASH: %v\n\n", hex.EncodeToString(pinHash))
	return status(ctap1ErrSuccess)
}

// pinBootBlocked reports whether the per-power-cycle wrong-PIN limit is reached.
func (server *CTAPServer) pinBootBlocked() bool {
	return server.pinBootFailures >= pinMaxBootFailures
}

// pinFailureResponse records a wrong-PIN attempt: it rotates the key agreement
// (forcing the platform to re-handshake), counts the failure toward the
// per-power-cycle limit, then returns the appropriate CTAP error
// (Blocked > AuthBlocked > Invalid).
func (server *CTAPServer) pinFailureResponse() []byte {
	server.client.RotatePINKeyAgreement()
	server.pinBootFailures++
	if server.client.PINRetries() <= 0 {
		return status(ctap2ErrPINBlocked)
	}
	if server.pinBootBlocked() {
		return status(ctap2ErrPINAuthBlocked)
	}
	return status(ctap2ErrPINInvalid)
}

func (server *CTAPServer) handleChangePIN(args clientPINArgs) []byte {
	if server.client.PINHash() == nil {
		return status(ctap2ErrNoPINSet)
	}
	if args.KeyAgreement == nil || args.PINUVAuthParam == nil || args.NewPINEncoding == nil || args.PINHashEncoding == nil {
		return status(ctap2ErrMissingParam)
	}
	if server.client.PINRetries() <= 0 {
		return status(ctap2ErrPINBlocked)
	}
	if server.pinBootBlocked() {
		return status(ctap2ErrPINAuthBlocked)
	}
	sharedSecret, err := server.getPINSharedSecret(*args.KeyAgreement)
	if err != nil {
		ctapLogger.Printf("changePIN: %v\n\n", err)
		return status(ctap1ErrInvalidParameter)
	}
	pinAuth := server.derivePINAuth(sharedSecret, util.Concat(args.NewPINEncoding, args.PINHashEncoding))
	if subtle.ConstantTimeCompare(pinAuth, args.PINUVAuthParam) != 1 {
		return status(ctap2ErrPINAuthInvalid)
	}
	server.client.SetPINRetries(server.client.PINRetries() - 1)
	decryptedPINHash := crypto.DecryptAESCBC(sharedSecret, args.PINHashEncoding)
	if subtle.ConstantTimeCompare(server.client.PINHash(), decryptedPINHash) != 1 {
		return server.pinFailureResponse()
	}
	server.client.SetPINRetries(pinMaxRetries)
	server.pinBootFailures = 0
	newPIN := server.decryptPIN(sharedSecret, args.NewPINEncoding)
	if len(newPIN) < 4 {
		return status(ctap2ErrPINPolicyViolation)
	}
	server.client.SetPINHash(crypto.HashSHA256(newPIN)[:16])
	// Changing the PIN invalidates previously issued tokens.
	server.client.RotatePINToken()
	server.pinTokenIssued = false
	return status(ctap1ErrSuccess)
}

// handleGetPINToken implements getPINToken (0x05) and CTAP 2.1
// getPinUvAuthTokenUsingPin (0x09); permissions and rpId are not enforced.
func (server *CTAPServer) handleGetPINToken(args clientPINArgs) []byte {
	if server.client.PINHash() == nil {
		return status(ctap2ErrNoPINSet)
	}
	if args.PINHashEncoding == nil || args.KeyAgreement == nil {
		return status(ctap2ErrMissingParam)
	}
	if server.client.PINRetries() <= 0 {
		return status(ctap2ErrPINBlocked)
	}
	if server.pinBootBlocked() {
		return status(ctap2ErrPINAuthBlocked)
	}
	sharedSecret, err := server.getPINSharedSecret(*args.KeyAgreement)
	if err != nil {
		ctapLogger.Printf("getPINToken: %v\n\n", err)
		return status(ctap1ErrInvalidParameter)
	}
	server.client.SetPINRetries(server.client.PINRetries() - 1)
	pinHash := server.decryptPINHash(sharedSecret, args.PINHashEncoding)
	unsafeCtapLogger.Printf("TRYING PIN HASH: %v\n\n", hex.EncodeToString(pinHash))
	if subtle.ConstantTimeCompare(pinHash, server.client.PINHash()) != 1 {
		unsafeCtapLogger.Printf("MISMATCH: Provided PIN %v doesn't match stored PIN %v\n\n", hex.EncodeToString(pinHash), hex.EncodeToString(server.client.PINHash()))
		return server.pinFailureResponse()
	}
	server.client.SetPINRetries(pinMaxRetries)
	server.pinBootFailures = 0
	server.pinTokenIssued = true
	enc := crypto.EncryptAESCBC(sharedSecret, server.client.PINToken())
	response := clientPINResponse{PinToken: enc}
	ctapLogger.Printf("GET_PIN_TOKEN RESPONSE: token(enc_len=%d) chan=0x%x\n\n", len(enc), server.currentChannelID)
	return append([]byte{byte(ctap1ErrSuccess)}, util.MarshalCBOR(response)...)
}
