package desktop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bulwarkid/virtual-fido/fido_client"
)

func TestApprovalBrokerOutcomes(t *testing.T) {
	broker := &ApprovalBroker{Timeout: time.Second}
	var shown, resolved []*ApprovalRequest
	broker.OnRequest = func(r *ApprovalRequest) { shown = append(shown, r); go r.Approve() }
	broker.OnResolved = func(r *ApprovalRequest) { resolved = append(resolved, r) }
	params := fido_client.ClientActionRequestParams{RelyingPartyID: "github.com", RelyingParty: "GitHub", UserName: "alice"}
	if !broker.ApproveClientAction(fido_client.ClientActionFIDOGetAssertion, params) {
		t.Fatal("approved request returned false")
	}
	if len(shown) != 1 || len(resolved) != 1 || resolved[0].Outcome() != ApprovalApproved {
		t.Fatalf("unexpected callbacks: %d shown, %d resolved", len(shown), len(resolved))
	}
	if got := shown[0].Title(); got != "Sign in to github.com" {
		t.Fatalf("title %q", got)
	}
	if !strings.Contains(shown[0].Detail(), "alice") || !strings.Contains(shown[0].Detail(), "GitHub") {
		t.Fatalf("detail %q", shown[0].Detail())
	}

	broker.OnRequest = func(r *ApprovalRequest) { go r.Deny() }
	if broker.ApproveClientAction(fido_client.ClientActionFIDOMakeCredential, params) {
		t.Fatal("denied request returned true")
	}

	broker.OnRequest = nil
	broker.Timeout = 50 * time.Millisecond
	if broker.ApproveClientAction(fido_client.ClientActionFIDOMakeCredential, params) {
		t.Fatal("timed-out request returned true")
	}
	if resolved[len(resolved)-1].Outcome() != ApprovalTimedOut {
		t.Fatalf("outcome %v", resolved[len(resolved)-1].Outcome())
	}

	broker.Timeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	broker.OnRequest = func(r *ApprovalRequest) { cancel() }
	start := time.Now()
	if broker.ApproveClientActionContext(ctx, fido_client.ClientActionFIDOGetAssertion, params) {
		t.Fatal("cancelled request returned true")
	}
	if time.Since(start) > time.Second || resolved[len(resolved)-1].Outcome() != ApprovalCancelled {
		t.Fatal("cancellation did not end the wait")
	}
	if broker.Current() != nil {
		t.Fatal("resolved request still current")
	}
}

func TestApproveCurrentFromHotkey(t *testing.T) {
	broker := &ApprovalBroker{Timeout: 5 * time.Second}
	broker.OnRequest = func(r *ApprovalRequest) {
		go func() {
			if !broker.ApproveCurrent() {
				t.Error("no current request")
			}
		}()
	}
	if !broker.ApproveClientAction(fido_client.ClientActionFIDOGetAssertion, fido_client.ClientActionRequestParams{}) {
		t.Fatal("hotkey approval failed")
	}
	if broker.ApproveCurrent() {
		t.Fatal("ApproveCurrent with nothing pending")
	}
}

func TestParseHotkey(t *testing.T) {
	cases := map[string]Hotkey{
		"F13":          {Key: 0x7C},
		"f24":          {Key: 0x87},
		"Ctrl+Alt+F12": {Modifiers: ModControl | ModAlt, Key: 0x7B},
		"Shift+Win+Y":  {Modifiers: ModShift | ModWin, Key: 'Y'},
		"Pause":        {Key: 0x13},
		"Ctrl+Numpad5": {Modifiers: ModControl, Key: 0x65},
	}
	for text, want := range cases {
		got, err := ParseHotkey(text)
		if err != nil || got == nil || *got != want {
			t.Errorf("ParseHotkey(%q) = %+v, %v; want %+v", text, got, err, want)
		}
	}
	for _, bad := range []string{"Ctrl+", "Hyper+A", "F25", "Ctrl+Alt"} {
		if _, err := ParseHotkey(bad); err == nil {
			t.Errorf("ParseHotkey(%q) accepted", bad)
		}
	}
	if hotkey, err := ParseHotkey(""); hotkey != nil || err != nil {
		t.Errorf("empty hotkey: %v %v", hotkey, err)
	}
	for _, suggestion := range SuggestedHotkeys {
		if _, err := ParseHotkey(suggestion); err != nil {
			t.Errorf("suggested hotkey %q does not parse: %v", suggestion, err)
		}
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	settings, err := LoadSettings(dir)
	if err != nil || settings.ApprovalTimeoutSeconds != 30 || !settings.AutoAttach {
		t.Fatalf("defaults: %+v %v", settings, err)
	}
	settings.ApproveHotkey = "Ctrl+Alt+F12"
	if err := settings.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSettings(dir)
	if err != nil || loaded.ApproveHotkey != "Ctrl+Alt+F12" || loaded.VaultPath != filepath.Join(dir, "vault.json") {
		t.Fatalf("reloaded: %+v %v", loaded, err)
	}
}

type fakeAttacher struct {
	attached, detached, stopped int
	err                         error
}

func (f *fakeAttacher) Driver() DriverInfo {
	return DriverInfo{Found: true, Flavor: DriverUsbipWin2, Path: "usbip.exe"}
}
func (f *fakeAttacher) Attach(ctx context.Context) (int, error) {
	f.attached++
	return 3, f.err
}
func (f *fakeAttacher) Detach(port int) error { f.detached++; return nil }
func (f *fakeAttacher) StopAttempts() error   { f.stopped++; return nil }

func newTestService(t *testing.T) (*Service, *fakeAttacher) {
	t.Helper()
	settings := DefaultSettings(t.TempDir())
	attacher := &fakeAttacher{}
	service := NewService(settings, attacher)
	service.ListenAddress = "127.0.0.1:0"
	return service, attacher
}

func TestServiceVaultLifecycle(t *testing.T) {
	service, attacher := newTestService(t)
	if err := service.Unlock("whatever"); !errors.Is(err, ErrNoVault) {
		t.Fatalf("unlock without vault: %v", err)
	}
	if err := service.CreateVault("short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if err := service.CreateVault("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(service.Settings.VaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("vault is readable by others: %v", info.Mode())
	}
	status := service.Status()
	if !status.Unlocked || !status.PINSupported || status.PINSet {
		t.Fatalf("status after create: %+v", status)
	}
	if err := service.SetPIN("12"); err == nil {
		t.Fatal("short PIN accepted")
	}
	if err := service.SetPIN("1234"); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	if err := service.Attach(context.Background()); err != nil {
		t.Fatal(err)
	}
	if service.Status().AttachedPort != 3 || attacher.attached != 1 {
		t.Fatalf("attach not recorded: %+v", service.Status())
	}
	service.Stop()
	if attacher.detached != 1 || attacher.stopped != 1 || service.Status().Running {
		t.Fatalf("stop did not detach: %+v %+v", attacher, service.Status())
	}
	if err := service.ChangePassphrase("wrong", "another good passphrase"); err == nil {
		t.Fatal("wrong current passphrase accepted")
	}
	if err := service.ChangePassphrase("correct horse battery", "another good passphrase"); err != nil {
		t.Fatal(err)
	}

	reopened := NewService(service.Settings, attacher)
	if err := reopened.Unlock("correct horse battery"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("old passphrase: %v", err)
	}
	if err := reopened.Unlock("another good passphrase"); err != nil {
		t.Fatal(err)
	}
	if status := reopened.Status(); !status.PINSet || status.PINRetries != 8 {
		t.Fatalf("PIN not persisted: %+v", status)
	}
	if err := reopened.ClearPIN(); err != nil || reopened.Status().PINSet {
		t.Fatalf("ClearPIN: %v", err)
	}
}

func TestServiceStartReportsListenFailure(t *testing.T) {
	service, _ := newTestService(t)
	service.ListenAddress = "256.0.0.1:1" // cannot listen
	if err := service.CreateVault("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err == nil {
		t.Fatal("Start succeeded on an unusable address")
	}
	if service.Status().LastError == "" {
		t.Fatal("start failure not reported in status")
	}
}

func TestUsbipAttacherCommands(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "usbip.exe")
	os.WriteFile(tool, []byte("fake"), 0700)
	var calls []string
	attacher := &UsbipAttacher{
		Candidates: func() []string { return []string{filepath.Join(dir, "missing.exe"), tool} },
		Run: func(ctx context.Context, path string, args ...string) (string, error) {
			calls = append(calls, strings.Join(args, " "))
			switch args[0] {
			case "--version":
				return "0.9.8.1\n", nil
			case "attach":
				if args[1] == "-x" {
					return "", nil
				}
				return "4\n", nil
			}
			return "port 4 is successfully detached\n", nil
		},
	}
	driver := attacher.Driver()
	if !driver.Found || driver.Flavor != DriverUsbipWin2 || driver.Version != "0.9.8.1" || driver.Path != tool {
		t.Fatalf("driver: %+v", driver)
	}
	port, err := attacher.Attach(context.Background())
	if err != nil || port != 4 {
		t.Fatalf("attach: %d %v", port, err)
	}
	if err := attacher.Detach(port); err != nil {
		t.Fatal(err)
	}
	attacher.StopAttempts()
	want := []string{"--version", "attach -r 127.0.0.1 -b 2-2 --once --terse", "detach -p 4", "attach -x -r 127.0.0.1 -b 2-2"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("commands:\n%v\nwant\n%v", calls, want)
	}

	legacy := &UsbipAttacher{
		Candidates: func() []string { return []string{tool} },
		Run: func(ctx context.Context, path string, args ...string) (string, error) {
			if args[0] == "--version" {
				return "usage: usbip [--debug] ...", errors.New("exit status 1")
			}
			return "succesfully attached to port 2\n", nil
		},
	}
	if legacy.Driver().Flavor != DriverLegacy {
		t.Fatal("legacy usbip misdetected")
	}
	if port, _ := legacy.Attach(context.Background()); port != 2 {
		t.Fatalf("legacy port %d", port)
	}

	failing := &UsbipAttacher{
		Candidates: func() []string { return []string{tool} },
		Run: func(ctx context.Context, path string, args ...string) (string, error) {
			if args[0] == "--version" {
				return "0.9.8.1", nil
			}
			return "usbip: error: cannot connect to 127.0.0.1:3240\n", errors.New("exit status 1")
		},
	}
	if _, err := failing.Attach(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot connect") {
		t.Fatalf("attach error not surfaced: %v", err)
	}
	none := &UsbipAttacher{Candidates: func() []string { return nil }, Run: nil}
	if _, err := none.Attach(context.Background()); !errors.Is(err, ErrDriverNotFound) {
		t.Fatalf("missing driver: %v", err)
	}
}

func TestLogRing(t *testing.T) {
	ring := NewLogRing(3)
	ring.Write([]byte("one\ntwo\n"))
	ring.Write([]byte("thr"))
	ring.Write([]byte("ee\nfour\n\n"))
	lines, version := ring.Snapshot()
	if len(lines) != 3 || !strings.HasSuffix(lines[0], "two") || !strings.HasSuffix(lines[2], "four") || version != 3 {
		t.Fatalf("lines %q version %d", lines, version)
	}
}
