package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BusID is the USB/IP bus ID the virtual authenticator is exported as.
const BusID = "2-2"

// UsbipWin2DownloadURL is where Windows users get the signed USB/IP driver.
const UsbipWin2DownloadURL = "https://github.com/vadimgrn/usbip-win2/releases/latest"

var ErrDriverNotFound = errors.New("the USB/IP driver (usbip-win2) is not installed")

// DriverFlavor identifies the usbip command-line tool that was found.
type DriverFlavor int

const (
	DriverNone DriverFlavor = iota
	// DriverUsbipWin2 is vadimgrn/usbip-win2: Microsoft-signed drivers,
	// supports --once/--terse and reconnects by itself.
	DriverUsbipWin2
	// DriverLegacy is any other usbip tool (e.g. the old test-signed
	// usbip-win bundled in cmd/demo/usbip, or Linux usbip).
	DriverLegacy
)

// DriverInfo describes the usbip tool used to attach the authenticator.
type DriverInfo struct {
	Found   bool
	Path    string
	Flavor  DriverFlavor
	Version string
}

func (d DriverInfo) String() string {
	switch {
	case !d.Found:
		return "not installed"
	case d.Flavor == DriverUsbipWin2 && d.Version != "":
		return fmt.Sprintf("usbip-win2 %s", d.Version)
	case d.Flavor == DriverUsbipWin2:
		return "usbip-win2"
	}
	return "usbip (" + d.Path + ")"
}

// Attacher plugs the virtual device into the operating system.
type Attacher interface {
	Driver() DriverInfo
	// Attach attaches the device and returns the virtual hub port (0 if unknown).
	Attach(ctx context.Context) (int, error)
	Detach(port int) error
	// StopAttempts stops a driver from retrying to reconnect.
	StopAttempts() error
}

// CommandRunner runs a command and returns its combined output.
type CommandRunner func(ctx context.Context, path string, args ...string) (string, error)

// UsbipAttacher drives the usbip command-line tool.
type UsbipAttacher struct {
	// Candidates lists where to look for the tool, in order.
	Candidates func() []string
	Run        CommandRunner
	// Address is the USB/IP server host ("127.0.0.1").
	Address string

	mu       sync.Mutex
	cached   DriverInfo
	cachedAt time.Time
}

// Driver finds the usbip tool (the result is cached for a few seconds).
func (a *UsbipAttacher) Driver() DriverInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.cachedAt.IsZero() && time.Since(a.cachedAt) < 5*time.Second {
		return a.cached
	}
	a.cached = a.findDriver()
	a.cachedAt = time.Now()
	return a.cached
}

func (a *UsbipAttacher) findDriver() DriverInfo {
	for _, path := range a.Candidates() {
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			continue
		}
		if cached := a.cached; cached.Found && cached.Path == path {
			return cached // don't re-run the version probe
		}
		driver := DriverInfo{Found: true, Path: path, Flavor: DriverLegacy}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := a.Run(ctx, path, "--version")
		cancel()
		if version := strings.TrimSpace(output); err == nil && versionPattern.MatchString(version) {
			driver.Flavor = DriverUsbipWin2
			driver.Version = version
		}
		return driver
	}
	return DriverInfo{}
}

var versionPattern = regexp.MustCompile(`^v?\d+(\.\d+)+\S*$`)

func (a *UsbipAttacher) address() string {
	if a.Address != "" {
		return a.Address
	}
	return "127.0.0.1"
}

func (a *UsbipAttacher) Attach(ctx context.Context) (int, error) {
	driver := a.Driver()
	if !driver.Found {
		return 0, ErrDriverNotFound
	}
	args := []string{"attach", "-r", a.address(), "-b", BusID}
	if driver.Flavor == DriverUsbipWin2 {
		// --once: report failure now instead of retrying in the background;
		// --terse: print just the port number.
		args = append(args, "--once", "--terse")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, err := a.Run(ctx, driver.Path, args...)
	if err != nil {
		return 0, fmt.Errorf("usbip attach failed: %s", describeFailure(output, err))
	}
	return parseAttachedPort(output), nil
}

func (a *UsbipAttacher) Detach(port int) error {
	driver := a.Driver()
	if !driver.Found {
		return ErrDriverNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := a.Run(ctx, driver.Path, "detach", "-p", strconv.Itoa(port))
	if err != nil {
		return fmt.Errorf("usbip detach failed: %s", describeFailure(output, err))
	}
	return nil
}

func (a *UsbipAttacher) StopAttempts() error {
	driver := a.Driver()
	if driver.Flavor != DriverUsbipWin2 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := a.Run(ctx, driver.Path, "attach", "-x", "-r", a.address(), "-b", BusID)
	return err
}

var portPattern = regexp.MustCompile(`(?i)port\s+(\d+)`)

// parseAttachedPort reads the port from "usbip attach" output: a bare number
// (--terse) or "successfully attached to port N".
func parseAttachedPort(output string) int {
	trimmed := strings.TrimSpace(output)
	if port, err := strconv.Atoi(trimmed); err == nil {
		return port
	}
	if match := portPattern.FindStringSubmatch(output); match != nil {
		port, _ := strconv.Atoi(match[1])
		return port
	}
	return 0
}

func describeFailure(output string, err error) string {
	if text := strings.TrimSpace(output); text != "" {
		return text
	}
	return err.Error()
}
