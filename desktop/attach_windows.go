//go:build windows

package desktop

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const createNoWindow = 0x08000000

// NewUsbipAttacher returns an attacher for usbip-win2 (or the legacy bundled
// usbip-win found next to the executable). override is a user-chosen path.
func NewUsbipAttacher(override func() string) *UsbipAttacher {
	return &UsbipAttacher{
		Candidates: func() []string {
			var candidates []string
			if override != nil {
				candidates = append(candidates, override())
			}
			for _, dir := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramW6432")} {
				if dir != "" {
					candidates = append(candidates, filepath.Join(dir, "USBip", "usbip.exe"))
				}
			}
			if exe, err := os.Executable(); err == nil {
				dir := filepath.Dir(exe)
				candidates = append(candidates,
					filepath.Join(dir, "usbip.exe"),
					filepath.Join(dir, "usbip", "bin", "usbip.exe"))
			}
			if path, err := exec.LookPath("usbip.exe"); err == nil {
				candidates = append(candidates, path)
			}
			return candidates
		},
		Run: runHidden,
	}
}

// runHidden runs a console program without flashing a console window.
func runHidden(ctx context.Context, path string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = filepath.Dir(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	output, err := cmd.CombinedOutput()
	return string(output), err
}
