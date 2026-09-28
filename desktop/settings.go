package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const appDirName = "VirtualFIDO"

// Settings are the app's preferences, stored as JSON next to the vault.
type Settings struct {
	// VaultPath is the encrypted file holding the passkeys.
	VaultPath string `json:"vault_path"`
	// UsbipPath overrides where usbip.exe is looked for.
	UsbipPath string `json:"usbip_path,omitempty"`
	// ApprovalTimeoutSeconds denies a request nobody answers (0 = never).
	ApprovalTimeoutSeconds int `json:"approval_timeout_seconds"`
	// ApproveHotkey / DenyHotkey are global hotkeys such as "F13" or
	// "Ctrl+Alt+F12" ("" disables them); program a macropad key to send one.
	ApproveHotkey string `json:"approve_hotkey"`
	DenyHotkey    string `json:"deny_hotkey"`
	// AutoAttach plugs the authenticator into Windows as soon as it starts.
	AutoAttach bool `json:"auto_attach"`
	// StartMinimized starts in the notification area.
	StartMinimized bool `json:"start_minimized"`
	// ProtectedPassphrase is the vault passphrase encrypted for the current
	// Windows account (DPAPI), when the user chose to remember it.
	ProtectedPassphrase []byte `json:"protected_passphrase,omitempty"`

	path string
}

// DefaultSettingsDir is %APPDATA%\VirtualFIDO on Windows (the user config
// directory elsewhere).
func DefaultSettingsDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, appDirName), nil
}

// DefaultSettings returns the settings used before the user changes anything.
func DefaultSettings(dir string) *Settings {
	return &Settings{
		VaultPath:              filepath.Join(dir, "vault.json"),
		ApprovalTimeoutSeconds: 30,
		ApproveHotkey:          "F13",
		AutoAttach:             true,
		path:                   filepath.Join(dir, "settings.json"),
	}
}

// LoadSettings reads settings.json from dir, falling back to defaults for
// anything missing.
func LoadSettings(dir string) (*Settings, error) {
	settings := DefaultSettings(dir)
	data, err := os.ReadFile(settings.path)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	if err := json.Unmarshal(data, settings); err != nil {
		return DefaultSettings(dir), err
	}
	if settings.VaultPath == "" {
		settings.VaultPath = filepath.Join(dir, "vault.json")
	}
	return settings, nil
}

// Save writes the settings atomically.
func (s *Settings) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data)
}

// writeFileAtomic replaces path with data via a temporary file and a rename,
// so a crash never leaves a half-written file. The file is private (0600).
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), 0600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
