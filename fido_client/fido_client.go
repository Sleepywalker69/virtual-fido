package fido_client

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log"
	"sync"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

type ClientAction uint8

type ClientActionRequestParams struct {
	// RelyingPartyID is the site's domain as vouched for by the browser; show
	// this to the user. RelyingParty is the display name the site chose.
	RelyingPartyID string
	RelyingParty   string
	UserName       string
}

const (
	ClientActionU2FRegister         ClientAction = 0
	ClientActionU2FAuthenticate     ClientAction = 1
	ClientActionFIDOMakeCredential  ClientAction = 2
	ClientActionFIDOGetAssertion    ClientAction = 3
	ClientActionManageAuthenticator ClientAction = 4
)

const defaultPINRetries = 8

var clientLogger *log.Logger = util.NewLogger("[CLIENT] ", util.LogLevelDebug)

type ClientRequestApprover interface {
	ApproveClientAction(action ClientAction, params ClientActionRequestParams) bool
}

// ContextRequestApprover is an optional extension of ClientRequestApprover for
// approvers that can withdraw their prompt when the request is cancelled (the
// browser gave up, or the device was detached).
type ContextRequestApprover interface {
	ApproveClientActionContext(ctx context.Context, action ClientAction, params ClientActionRequestParams) bool
}

type UserVerifier interface {
	SupportsUserVerification() bool
	VerifyUser(action ClientAction, params ClientActionRequestParams) bool
}

type ClientDataSaver interface {
	SaveData(data []byte)
	RetrieveData() []byte
	Passphrase() string
}

// DefaultFIDOClient holds the authenticator's state: credentials, PIN and
// attestation keys. It is safe for concurrent use, so an app can manage
// credentials while the authenticator is serving requests.
type DefaultFIDOClient struct {
	mu sync.Mutex

	deviceEncryptionKey   []byte
	certificateAuthority  *x509.Certificate
	certPrivateKey        *cose.SupportedCOSEPrivateKey
	authenticationCounter uint32

	pinEnabled         bool
	pinToken           []byte
	pinKeyAgreement    *crypto.ECDHKey
	pinRetries         int32
	pinHash            []byte
	fingerprintEnabled bool

	vault           *identities.IdentityVault
	requestApprover ClientRequestApprover
	userVerifier    UserVerifier
	dataSaver       ClientDataSaver
}

// NewDefaultClient creates a client and loads any saved state, panicking if
// the saved state cannot be decrypted. LoadDefaultClient reports that as an
// error instead.
func NewDefaultClient(
	rootAttestationCertificate *x509.Certificate,
	rootAttestationCertPrivateKey *cose.SupportedCOSEPrivateKey,
	secretEncryptionKey [32]byte,
	enablePIN bool,
	requestApprover ClientRequestApprover,
	userVerifier UserVerifier,
	dataSaver ClientDataSaver) *DefaultFIDOClient {
	client, err := LoadDefaultClient(rootAttestationCertificate, rootAttestationCertPrivateKey, secretEncryptionKey, enablePIN, requestApprover, userVerifier, dataSaver)
	util.CheckErr(err, "Could not load vault data")
	return client
}

// LoadDefaultClient creates a client and loads its saved state. The defaults
// passed in (attestation CA, encryption key, PIN enabled) only apply when there
// is no saved state yet.
func LoadDefaultClient(
	rootAttestationCertificate *x509.Certificate,
	rootAttestationCertPrivateKey *cose.SupportedCOSEPrivateKey,
	secretEncryptionKey [32]byte,
	enablePIN bool,
	requestApprover ClientRequestApprover,
	userVerifier UserVerifier,
	dataSaver ClientDataSaver) (*DefaultFIDOClient, error) {
	if userVerifier == nil {
		userVerifier = &noopUserVerifier{}
	}
	client := &DefaultFIDOClient{
		pinEnabled:            enablePIN,
		deviceEncryptionKey:   secretEncryptionKey[:],
		certificateAuthority:  rootAttestationCertificate,
		certPrivateKey:        rootAttestationCertPrivateKey,
		authenticationCounter: 1,
		// CTAP2 spec: pinUvAuthToken length is 32 bytes for v1/v2
		pinToken:           crypto.RandomBytes(32),
		pinKeyAgreement:    crypto.GenerateECDHKey(),
		pinRetries:         defaultPINRetries,
		pinHash:            nil,
		fingerprintEnabled: false,
		vault:              identities.NewIdentityVault(),
		requestApprover:    requestApprover,
		userVerifier:       userVerifier,
		dataSaver:          dataSaver,
	}
	if data := dataSaver.RetrieveData(); data != nil {
		if err := client.importData(data, dataSaver.Passphrase()); err != nil {
			return nil, err
		}
	}
	return client, nil
}

func (client *DefaultFIDOClient) SupportsResidentKey() bool {
	return true
}

func (client *DefaultFIDOClient) NewCredentialSource(
	PubKeyCredParams []webauthn.PublicKeyCredentialParams,
	ExcludeList []webauthn.PublicKeyCredentialDescriptor,
	relyingParty *webauthn.PublicKeyCredentialRPEntity,
	user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource {
	supported := false
	for _, param := range PubKeyCredParams {
		if param.Algorithm == cose.COSE_ALGORITHM_ID_ES256 && param.Type == "public-key" {
			supported = true
			break
		}
	}
	if !supported {
		return nil
	}
	// A platform capability/health-check probe registers against the well-known
	// ".dummy" RP id; for that exact sentinel only, create an ephemeral credential
	// that is not persisted. Do NOT sniff rp.name / user.name — rp.name is optional
	// in WebAuthn, so those heuristics silently discarded legitimate registrations
	// (the credential vanished and could never be used to authenticate).
	if relyingParty != nil && relyingParty.ID == ".dummy" {
		priv := crypto.GenerateECDSAKey()
		eph := &identities.CredentialSource{
			Type:             "public-key",
			ID:               crypto.RandomBytes(16),
			PrivateKey:       &cose.SupportedCOSEPrivateKey{ECDSA: priv},
			RelyingParty:     relyingParty,
			User:             user,
			SignatureCounter: 0,
		}
		return eph
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	newSource := client.vault.NewIdentity(relyingParty, user)
	client.saveDataLocked()
	return newSource
}

func (client *DefaultFIDOClient) GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource {
	client.mu.Lock()
	defer client.mu.Unlock()
	sources := client.vault.GetMatchingCredentialSources(relyingPartyID, allowList)
	if len(sources) == 0 {
		clientLogger.Printf("ERROR: No Credentials\n\n")
		return nil
	}

	// TODO: Allow user to choose credential source
	credentialSource := sources[0]
	credentialSource.SignatureCounter++
	client.saveDataLocked()
	return credentialSource
}

func (client *DefaultFIDOClient) GetAssertionSources(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) []*identities.CredentialSource {
	client.mu.Lock()
	defer client.mu.Unlock()
	sources := client.vault.GetMatchingCredentialSources(relyingPartyID, allowList)
	if len(sources) == 0 {
		return []*identities.CredentialSource{}
	}
	// Do NOT bump the signature counter here: the request may still be denied at
	// approval. handleGetAssertion advances the selected credential's counter at
	// signing time (and GetNextAssertion does the same for the remaining ones), so
	// denied/aborted assertions no longer inflate the counter.
	return sources
}

// UpdateCredential applies update to credential state (counters, flags) under
// the client's lock and saves the result.
func (client *DefaultFIDOClient) UpdateCredential(update func()) {
	client.mu.Lock()
	defer client.mu.Unlock()
	update()
	client.saveDataLocked()
}

func (client *DefaultFIDOClient) ApproveAccountCreation(relyingParty string) bool {
	params := ClientActionRequestParams{
		RelyingParty: relyingParty,
	}
	return client.approve(context.Background(), ClientActionFIDOMakeCredential, params)
}

func (client *DefaultFIDOClient) ApproveAccountLogin(credentialSource *identities.CredentialSource) bool {
	return client.ApproveAccountLoginContext(context.Background(), credentialSource)
}

// ApproveAccountCreationContext asks the user to approve a new credential; the
// prompt is withdrawn if ctx is cancelled.
func (client *DefaultFIDOClient) ApproveAccountCreationContext(ctx context.Context, relyingParty *webauthn.PublicKeyCredentialRPEntity, user *webauthn.PublicKeyCrendentialUserEntity) bool {
	params := ClientActionRequestParams{}
	if relyingParty != nil {
		params.RelyingPartyID = relyingParty.ID
		params.RelyingParty = relyingParty.Name
	}
	if user != nil {
		params.UserName = user.Name
	}
	return client.approve(ctx, ClientActionFIDOMakeCredential, params)
}

// ApproveAccountLoginContext asks the user to approve a sign-in; the prompt is
// withdrawn if ctx is cancelled.
func (client *DefaultFIDOClient) ApproveAccountLoginContext(ctx context.Context, credentialSource *identities.CredentialSource) bool {
	params := ClientActionRequestParams{}
	if credentialSource.RelyingParty != nil {
		params.RelyingPartyID = credentialSource.RelyingParty.ID
		params.RelyingParty = credentialSource.RelyingParty.Name
	}
	if credentialSource.User != nil {
		params.UserName = credentialSource.User.Name
	}
	return client.approve(ctx, ClientActionFIDOGetAssertion, params)
}

func (client *DefaultFIDOClient) approve(ctx context.Context, action ClientAction, params ClientActionRequestParams) bool {
	if approver, ok := client.requestApprover.(ContextRequestApprover); ok {
		return approver.ApproveClientActionContext(ctx, action, params)
	}
	return client.requestApprover.ApproveClientAction(action, params)
}

// -----------------------
// PIN Management Methods
// -----------------------

func (client *DefaultFIDOClient) EnablePIN() {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.pinEnabled = true
	client.saveDataLocked()
}

func (client *DefaultFIDOClient) DisablePIN() {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.pinEnabled = false
	client.saveDataLocked()
}

func (client *DefaultFIDOClient) SupportsPIN() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.pinEnabled
}

func (client *DefaultFIDOClient) PINHash() []byte {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.pinHash
}

// SetPIN sets (or replaces) the PIN directly, resets the retry counter and
// invalidates issued PIN tokens.
func (client *DefaultFIDOClient) SetPIN(pin []byte) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.pinHash = crypto.HashSHA256(pin)[:16]
	client.pinRetries = defaultPINRetries
	client.pinToken = crypto.RandomBytes(32)
	client.saveDataLocked()
}

// ClearPIN removes the PIN (the recovery path when it is forgotten or blocked).
func (client *DefaultFIDOClient) ClearPIN() {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.pinHash = nil
	client.pinRetries = defaultPINRetries
	client.pinToken = crypto.RandomBytes(32)
	client.saveDataLocked()
}

func (client *DefaultFIDOClient) SetPINHash(newHash []byte) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.pinHash = newHash
	client.saveDataLocked()
}

// ---------------------------
// Fingerprint/Uv Methods
// ---------------------------

func (client *DefaultFIDOClient) FingerprintEnabled() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.fingerprintEnabled
}

func (client *DefaultFIDOClient) FingerprintAvailable() bool {
	if client.userVerifier == nil {
		return false
	}
	return client.userVerifier.SupportsUserVerification()
}

func (client *DefaultFIDOClient) EnableFingerprint() {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.fingerprintEnabled = true
	client.saveDataLocked()
}

func (client *DefaultFIDOClient) DisableFingerprint() {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.fingerprintEnabled = false
	client.saveDataLocked()
}

func (client *DefaultFIDOClient) SupportsUserVerification() bool {
	if !client.FingerprintEnabled() {
		return false
	}
	return client.FingerprintAvailable()
}

func (client *DefaultFIDOClient) VerifyUser(action ClientAction, params ClientActionRequestParams) bool {
	if !client.FingerprintAvailable() {
		return false
	}
	return client.userVerifier.VerifyUser(action, params)
}

func (client *DefaultFIDOClient) PINRetries() int32 {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.pinRetries
}

// SetPINRetries updates the retry counter; it is persisted so a restart does
// not reset it.
func (client *DefaultFIDOClient) SetPINRetries(retries int32) {
	if retries < 0 {
		retries = 0
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.pinRetries == retries {
		return
	}
	client.pinRetries = retries
	client.saveDataLocked()
}

func (client *DefaultFIDOClient) PINKeyAgreement() *crypto.ECDHKey {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.pinKeyAgreement
}

// RotatePINKeyAgreement generates a fresh ephemeral ECDH key for the next PIN protocol exchange.
func (client *DefaultFIDOClient) RotatePINKeyAgreement() {
	key := crypto.GenerateECDHKey()
	client.mu.Lock()
	client.pinKeyAgreement = key
	client.mu.Unlock()
}

func (client *DefaultFIDOClient) PINToken() []byte {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.pinToken
}

// RotatePINToken generates a fresh pinUvAuthToken, invalidating any previously
// issued tokens (e.g. after a PIN set/change so old tokens can no longer be used).
func (client *DefaultFIDOClient) RotatePINToken() {
	token := crypto.RandomBytes(32)
	client.mu.Lock()
	client.pinToken = token
	client.mu.Unlock()
}

func (client *DefaultFIDOClient) SaveState() {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.saveDataLocked()
}

// -----------------------------
// U2F Methods
// -----------------------------

func (client *DefaultFIDOClient) SealingEncryptionKey() []byte {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.deviceEncryptionKey
}

func (client *DefaultFIDOClient) NewPrivateKey() *ecdsa.PrivateKey {
	return crypto.GenerateECDSAKey()
}

func (client *DefaultFIDOClient) NewAuthenticationCounterId() uint32 {
	client.mu.Lock()
	defer client.mu.Unlock()
	num := client.authenticationCounter
	client.authenticationCounter++
	client.saveDataLocked()
	return num
}

func (client *DefaultFIDOClient) CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte {
	client.mu.Lock()
	ca, caKey := client.certificateAuthority, client.certPrivateKey
	client.mu.Unlock()
	cert, err := identities.CreateSelfSignedAttestationCertificate(ca, caKey, privateKey)
	util.CheckErr(err, "Could not create attestation certificate")
	return cert.Raw
}

func (client *DefaultFIDOClient) ApproveU2FRegistration(keyHandle *webauthn.KeyHandle) bool {
	params := ClientActionRequestParams{}
	return client.approve(context.Background(), ClientActionU2FRegister, params)
}

func (client *DefaultFIDOClient) ApproveU2FAuthentication(keyHandle *webauthn.KeyHandle) bool {
	params := ClientActionRequestParams{}
	return client.approve(context.Background(), ClientActionU2FAuthenticate, params)
}

func (client *DefaultFIDOClient) exportDataLocked(passphrase string) []byte {
	privKeyBytes := cose.MarshalCOSEPrivateKey(client.certPrivateKey)
	identityData := client.vault.Export()
	retries := client.pinRetries
	state := identities.FIDODeviceConfig{
		EncryptionKey:          client.deviceEncryptionKey,
		AttestationCertificate: client.certificateAuthority.Raw,
		AttestationPrivateKey:  privKeyBytes,
		AuthenticationCounter:  client.authenticationCounter,
		PINEnabled:             client.pinEnabled,
		PINHash:                client.pinHash,
		PINRetries:             &retries,
		FingerprintEnabled:     client.fingerprintEnabled,
		Sources:                identityData,
	}
	savedBytes, err := identities.EncryptFIDOState(state, passphrase)
	util.CheckErr(err, "Could not encode saved state")
	return savedBytes
}

func (client *DefaultFIDOClient) importData(data []byte, passphrase string) error {
	state, err := identities.DecryptFIDOState(data, passphrase)
	if err != nil {
		return fmt.Errorf("could not decrypt vault data: %w", err)
	}
	cert, err := x509.ParseCertificate(state.AttestationCertificate)
	if err != nil {
		return fmt.Errorf("could not parse attestation certificate: %w", err)
	}
	privateKey, err := cose.UnmarshalCOSEPrivateKey(state.AttestationPrivateKey)
	if err != nil {
		privateKeyECDSA, err := x509.ParseECPrivateKey(state.AttestationPrivateKey)
		if err != nil {
			return fmt.Errorf("could not parse attestation private key: %w", err)
		}
		privateKey = &cose.SupportedCOSEPrivateKey{ECDSA: privateKeyECDSA}
	}
	vault := identities.NewIdentityVault()
	if err := vault.Import(state.Sources); err != nil {
		return err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.deviceEncryptionKey = state.EncryptionKey
	client.certificateAuthority = cert
	client.certPrivateKey = privateKey
	client.authenticationCounter = state.AuthenticationCounter
	client.pinEnabled = state.PINEnabled
	client.pinHash = state.PINHash
	if state.PINRetries != nil {
		client.pinRetries = *state.PINRetries
	}
	client.fingerprintEnabled = state.FingerprintEnabled
	client.vault = vault
	return nil
}

func (client *DefaultFIDOClient) saveDataLocked() {
	data := client.exportDataLocked(client.dataSaver.Passphrase())
	client.dataSaver.SaveData(data)
}

// Identities returns a snapshot of the stored credentials.
func (client *DefaultFIDOClient) Identities() []identities.CredentialSource {
	client.mu.Lock()
	defer client.mu.Unlock()
	sources := make([]identities.CredentialSource, 0)
	for _, source := range client.vault.CredentialSources {
		sources = append(sources, *source)
	}
	return sources
}

func (client *DefaultFIDOClient) DeleteIdentity(id []byte) bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	success := client.vault.DeleteIdentity(id)
	if success {
		client.saveDataLocked()
	}
	return success
}

type noopUserVerifier struct{}

func (n *noopUserVerifier) SupportsUserVerification() bool {
	return false
}

func (n *noopUserVerifier) VerifyUser(action ClientAction, params ClientActionRequestParams) bool {
	return false
}
