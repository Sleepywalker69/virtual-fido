//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

// platformUSBIPExec attaches the device with usbip-win2 if it is installed,
// otherwise with the bundled (test-signed) usbip-win tools.
func platformUSBIPExec() *exec.Cmd {
	candidates := []string{filepath.Join(os.Getenv("ProgramFiles"), "USBip", "usbip.exe")}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "usbip", "bin", "usbip.exe"))
	}
	candidates = append(candidates, filepath.Join("cmd", "demo", "usbip", "bin", "usbip.exe"))
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			command := exec.Command(candidate, "attach", "-r", "127.0.0.1", "-b", "2-2")
			command.Dir = filepath.Dir(candidate)
			return command
		}
	}
	return exec.Command("usbip.exe", "attach", "-r", "127.0.0.1", "-b", "2-2")
}
