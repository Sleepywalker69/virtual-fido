// Package desktop runs the virtual authenticator for a desktop app: it owns
// the encrypted vault, the USB/IP server, approval prompts and the USB/IP
// driver (usbip-win2 on Windows) that plugs the device into the OS.
package desktop

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/u2f"
	"github.com/bulwarkid/virtual-fido/usb"
	"github.com/bulwarkid/virtual-fido/usbip"
	"github.com/bulwarkid/virtual-fido/util"
)

var (
	ErrNoVault         = errors.New("no vault exists yet")
	ErrVaultExists     = errors.New("a vault already exists")
	ErrWrongPassphrase = errors.New("wrong passphrase (or the vault file is damaged)")
	ErrLocked          = errors.New("the vault is locked")
)

// MinPassphraseLength is the shortest vault passphrase CreateVault accepts.
const MinPassphraseLength = 8

// Status is a snapshot of the service for display.
type Status struct {
	VaultPath    string
	VaultExists  bool
	Unlocked     bool
	Running      bool
	HostAttached bool
	Attaching    bool
	AttachedPort int
	Driver       DriverInfo
	LastError    string
	PINSupported bool
	PINSet       bool
	PINRetries   int
	Credentials  int
}

// CredentialInfo describes a stored credential for display.
type CredentialInfo struct {
	ID       []byte
	Site     string
	SiteName string
	UserName string
	// Passkey is true for discoverable credentials (usable without typing a
	// username); false for second-factor-only credentials.
	Passkey   bool
	SignCount int32
}

// Service runs one virtual authenticator.
type Service struct {
	Settings  *Settings
	Approvals *ApprovalBroker
	Log       *LogRing
	// ListenAddress is where the USB/IP server listens (usbip.DefaultAddress).
	ListenAddress string
	// OnChange is called, from any goroutine, when Status may have changed.
	// It must not block.
	OnChange func()

	attacher Attacher

	mu           sync.Mutex
	store        *VaultStore
	client       *fido_client.DefaultFIDOClient
	device       *usb.USBDevice
	server       *usbip.USBIPServer
	hostAttached bool
	attaching    bool
	attachedPort int
	lastError    string
}

// NewService creates a locked service. attacher plugs the device into the OS
// (nil if that is done some other way).
func NewService(settings *Settings, attacher Attacher) *Service {
	service := &Service{
		Settings:      settings,
		Approvals:     &ApprovalBroker{Timeout: time.Duration(settings.ApprovalTimeoutSeconds) * time.Second},
		Log:           NewLogRing(2000),
		ListenAddress: usbip.DefaultAddress,
		attacher:      attacher,
	}
	return service
}

// SetVerboseLogging routes the authenticator's log output to Log (debug, or
// trace when verbose).
func (s *Service) SetVerboseLogging(verbose bool) {
	virtual_fido.SetLogOutput(s.Log)
	if verbose {
		virtual_fido.SetLogLevel(util.LogLevelTrace)
	} else {
		virtual_fido.SetLogLevel(util.LogLevelDebug)
	}
}

func (s *Service) changed() {
	if s.OnChange != nil {
		s.OnChange()
	}
}

func (s *Service) setError(err error) {
	s.mu.Lock()
	if err == nil {
		s.lastError = ""
	} else {
		s.lastError = err.Error()
	}
	s.mu.Unlock()
	if err != nil {
		s.Log.Printf("ERROR: %v", err)
	}
	s.changed()
}

// VaultExists reports whether the vault file exists.
func (s *Service) VaultExists() bool {
	_, err := os.Stat(s.Settings.VaultPath)
	return err == nil
}

// CreateVault creates a new, empty vault protected by passphrase and unlocks it.
func (s *Service) CreateVault(passphrase string) error {
	if s.VaultExists() {
		return ErrVaultExists
	}
	if utf8.RuneCountInString(passphrase) < MinPassphraseLength {
		return fmt.Errorf("use a passphrase of at least %d characters", MinPassphraseLength)
	}
	store := &VaultStore{path: s.Settings.VaultPath, passphrase: passphrase}
	client, err := s.newClient(store)
	if err != nil {
		return err
	}
	client.SaveState()
	if err := store.takeError(); err != nil {
		return fmt.Errorf("could not create the vault: %w", err)
	}
	s.Log.Printf("Created a new vault at %s", s.Settings.VaultPath)
	s.install(client, store)
	return nil
}

// Unlock decrypts the vault with passphrase.
func (s *Service) Unlock(passphrase string) error {
	data, err := os.ReadFile(s.Settings.VaultPath)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoVault
	}
	if err != nil {
		return fmt.Errorf("could not read the vault: %w", err)
	}
	store := &VaultStore{path: s.Settings.VaultPath, passphrase: passphrase, initial: data}
	client, err := s.newClient(store)
	if err != nil {
		s.Log.Printf("Unlock failed: %v", err)
		return ErrWrongPassphrase
	}
	s.Log.Printf("Unlocked the vault at %s", s.Settings.VaultPath)
	s.install(client, store)
	return nil
}

// newClient loads the authenticator state from store. The attestation CA and
// U2F key generated here are only used for a brand-new vault; an existing
// vault brings its own.
func (s *Service) newClient(store *VaultStore) (*fido_client.DefaultFIDOClient, error) {
	caPrivateKey, err := identities.CreateCAPrivateKey()
	if err != nil {
		return nil, err
	}
	certificateAuthority, err := identities.CreateSelfSignedCA(caPrivateKey)
	if err != nil {
		return nil, err
	}
	var encryptionKey [32]byte
	copy(encryptionKey[:], crypto.RandomBytes(32))
	// PIN support is on for new vaults: Windows then offers to create a PIN
	// the first time a site asks for user verification, like with a real key.
	return fido_client.LoadDefaultClient(certificateAuthority, caPrivateKey, encryptionKey, true, s.Approvals, nil, store)
}

func (s *Service) install(client *fido_client.DefaultFIDOClient, store *VaultStore) {
	ctapServer := ctap.NewCTAPServer(client)
	u2fServer := u2f.NewU2FServer(client)
	hidServer := ctap_hid.NewCTAPHIDServer(ctapServer, u2fServer)
	device := usb.NewUSBDevice(hidServer)
	store.onError = func(err error) { s.setError(fmt.Errorf("could not save the vault: %w", err)) }
	s.mu.Lock()
	s.client, s.store, s.device = client, store, device
	s.mu.Unlock()
	s.changed()
}

// Start runs the USB/IP server so the OS can attach the authenticator.
func (s *Service) Start() error {
	s.mu.Lock()
	if s.client == nil {
		s.mu.Unlock()
		return ErrLocked
	}
	if s.server != nil {
		s.mu.Unlock()
		return nil
	}
	listener, err := net.Listen("tcp", s.ListenAddress)
	if err != nil {
		s.mu.Unlock()
		err = fmt.Errorf("could not listen on %s (is another Virtual FIDO or USB/IP server running?): %w", s.ListenAddress, err)
		s.setError(err)
		return err
	}
	server := usbip.NewUSBIPServer([]usbip.USBIPDevice{s.device})
	server.OnImportChanged = s.onImportChanged
	s.server = server
	s.lastError = ""
	s.mu.Unlock()
	go func() {
		if err := server.Serve(listener); err != nil {
			s.setError(fmt.Errorf("USB/IP server stopped: %w", err))
		}
	}()
	s.Log.Printf("Authenticator running on %s", listener.Addr())
	s.changed()
	return nil
}

func (s *Service) onImportChanged(busID string, imported bool) {
	s.mu.Lock()
	s.hostAttached = imported
	if !imported {
		s.attachedPort = 0
	}
	s.mu.Unlock()
	if imported {
		s.Log.Printf("The computer attached the authenticator")
	} else {
		s.Log.Printf("The computer detached the authenticator")
	}
	s.changed()
}

// Attach asks the USB/IP driver to plug the authenticator in, unless it
// already is.
func (s *Service) Attach(ctx context.Context) error {
	s.mu.Lock()
	if s.server == nil {
		s.mu.Unlock()
		return errors.New("the authenticator is not running")
	}
	if s.hostAttached || s.attaching {
		s.mu.Unlock()
		return nil
	}
	if s.attacher == nil {
		s.mu.Unlock()
		return errors.New("no USB/IP driver is configured")
	}
	s.attaching = true
	s.mu.Unlock()
	s.changed()

	port, err := s.attacher.Attach(ctx)

	s.mu.Lock()
	s.attaching = false
	if err == nil && port > 0 {
		s.attachedPort = port
	}
	s.mu.Unlock()
	if err != nil {
		s.setError(err)
		return err
	}
	s.Log.Printf("Attached through the USB/IP driver (port %d)", port)
	s.changed()
	return nil
}

// AutoAttach waits briefly for the driver to reconnect on its own (usbip-win2
// retries after a disconnect) and otherwise attaches explicitly.
func (s *Service) AutoAttach(ctx context.Context) error {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Status().HostAttached {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return s.Attach(ctx)
}

// Stop detaches the authenticator and stops the USB/IP server.
func (s *Service) Stop() {
	s.mu.Lock()
	server, port, attacher := s.server, s.attachedPort, s.attacher
	s.server = nil
	s.mu.Unlock()
	if server == nil {
		return
	}
	if attacher != nil && port > 0 {
		if err := attacher.Detach(port); err != nil {
			s.Log.Printf("Detach failed: %v", err)
		}
	}
	server.Close()
	if attacher != nil {
		// Keep the driver from retrying against a server that is gone.
		attacher.StopAttempts()
	}
	s.mu.Lock()
	s.hostAttached = false
	s.attachedPort = 0
	s.mu.Unlock()
	s.Log.Printf("Authenticator stopped")
	s.changed()
}

// Status returns a snapshot for display.
func (s *Service) Status() Status {
	s.mu.Lock()
	status := Status{
		VaultPath:    s.Settings.VaultPath,
		Unlocked:     s.client != nil,
		Running:      s.server != nil,
		HostAttached: s.hostAttached,
		Attaching:    s.attaching,
		AttachedPort: s.attachedPort,
		LastError:    s.lastError,
	}
	client, attacher := s.client, s.attacher
	s.mu.Unlock()
	status.VaultExists = s.VaultExists()
	if attacher != nil {
		status.Driver = attacher.Driver()
	}
	if client != nil {
		status.PINSupported = client.SupportsPIN()
		status.PINSet = client.PINHash() != nil
		status.PINRetries = int(client.PINRetries())
		status.Credentials = len(client.Identities())
	}
	return status
}

func (s *Service) unlockedClient() (*fido_client.DefaultFIDOClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		return nil, ErrLocked
	}
	return s.client, nil
}

// Credentials lists the stored credentials, sorted by site and account.
func (s *Service) Credentials() []CredentialInfo {
	client, err := s.unlockedClient()
	if err != nil {
		return nil
	}
	var infos []CredentialInfo
	for _, source := range client.Identities() {
		info := CredentialInfo{ID: source.ID, Passkey: source.Discoverable, SignCount: source.SignatureCounter}
		if source.RelyingParty != nil {
			info.Site, info.SiteName = source.RelyingParty.ID, source.RelyingParty.Name
		}
		if source.User != nil {
			info.UserName = source.User.Name
			if info.UserName == "" {
				info.UserName = source.User.DisplayName
			}
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].Site != infos[j].Site {
			return infos[i].Site < infos[j].Site
		}
		return infos[i].UserName < infos[j].UserName
	})
	return infos
}

// DeleteCredential removes a credential for good.
func (s *Service) DeleteCredential(id []byte) error {
	client, err := s.unlockedClient()
	if err != nil {
		return err
	}
	if !client.DeleteIdentity(id) {
		return errors.New("that credential no longer exists")
	}
	s.Log.Printf("Deleted a credential")
	s.changed()
	return nil
}

// ValidatePIN checks the CTAP PIN rules: 4 to 63 bytes of UTF-8.
func ValidatePIN(pin string) error {
	if utf8.RuneCountInString(pin) < 4 {
		return errors.New("the PIN must be at least 4 characters")
	}
	if len(pin) > 63 {
		return errors.New("the PIN must be at most 63 bytes")
	}
	if strings.ContainsRune(pin, 0) {
		return errors.New("the PIN contains an invalid character")
	}
	return nil
}

// SetPIN sets or replaces the authenticator PIN (and enables PIN support).
func (s *Service) SetPIN(pin string) error {
	if err := ValidatePIN(pin); err != nil {
		return err
	}
	client, err := s.unlockedClient()
	if err != nil {
		return err
	}
	if !client.SupportsPIN() {
		client.EnablePIN()
	}
	client.SetPIN([]byte(pin))
	s.Log.Printf("PIN changed")
	s.changed()
	return nil
}

// ClearPIN removes the PIN (e.g. after it was forgotten or blocked).
func (s *Service) ClearPIN() error {
	client, err := s.unlockedClient()
	if err != nil {
		return err
	}
	client.ClearPIN()
	s.Log.Printf("PIN removed")
	s.changed()
	return nil
}

// SetPINSupport turns the authenticator's PIN feature on or off.
func (s *Service) SetPINSupport(enabled bool) error {
	client, err := s.unlockedClient()
	if err != nil {
		return err
	}
	if enabled {
		client.EnablePIN()
	} else {
		client.DisablePIN()
	}
	s.changed()
	return nil
}

// ChangePassphrase re-encrypts the vault with a new passphrase.
func (s *Service) ChangePassphrase(current, next string) error {
	client, err := s.unlockedClient()
	if err != nil {
		return err
	}
	s.mu.Lock()
	store := s.store
	s.mu.Unlock()
	if subtle.ConstantTimeCompare([]byte(current), []byte(store.Passphrase())) != 1 {
		return errors.New("the current passphrase is not correct")
	}
	if utf8.RuneCountInString(next) < MinPassphraseLength {
		return fmt.Errorf("use a passphrase of at least %d characters", MinPassphraseLength)
	}
	store.setPassphrase(next)
	client.SaveState()
	if err := store.takeError(); err != nil {
		store.setPassphrase(current)
		return fmt.Errorf("could not re-encrypt the vault: %w", err)
	}
	s.Log.Printf("Vault passphrase changed")
	return nil
}

// VaultStore keeps the encrypted vault in a file; it implements
// fido_client.ClientDataSaver.
type VaultStore struct {
	path string

	mu         sync.Mutex
	passphrase string
	initial    []byte
	lastErr    error
	onError    func(error)
}

func (v *VaultStore) SaveData(data []byte) {
	err := writeFileAtomic(v.path, data)
	v.mu.Lock()
	v.lastErr = err
	onError := v.onError
	v.mu.Unlock()
	if err != nil && onError != nil {
		onError(err)
	}
}

// RetrieveData returns the vault contents read by Service.Unlock. (Reading the
// file here would turn a read error into "no vault", and the next save would
// overwrite the real one.)
func (v *VaultStore) RetrieveData() []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.initial
}

func (v *VaultStore) Passphrase() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.passphrase
}

func (v *VaultStore) setPassphrase(passphrase string) {
	v.mu.Lock()
	v.passphrase = passphrase
	v.mu.Unlock()
}

func (v *VaultStore) takeError() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	err := v.lastErr
	v.lastErr = nil
	return err
}
