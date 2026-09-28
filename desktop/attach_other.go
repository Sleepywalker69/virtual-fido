//go:build !windows

package desktop

import (
	"context"
	"os/exec"
)

// NewUsbipAttacher returns an attacher for the Linux usbip tool (which needs
// root and the vhci-hcd module). override is a user-chosen path.
func NewUsbipAttacher(override func() string) *UsbipAttacher {
	return &UsbipAttacher{
		Candidates: func() []string {
			var candidates []string
			if override != nil {
				candidates = append(candidates, override())
			}
			if path, err := exec.LookPath("usbip"); err == nil {
				candidates = append(candidates, path)
			}
			return candidates
		},
		Run: func(ctx context.Context, path string, args ...string) (string, error) {
			output, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
			return string(output), err
		},
	}
}
