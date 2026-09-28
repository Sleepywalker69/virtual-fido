//go:build !windows

// Command vfido-gui is the Windows app for Virtual FIDO. On other systems use
// the command-line demo instead: go run ./cmd/demo start
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "vfido-gui is a Windows app. On Linux, use the command-line version: sudo go run ./cmd/demo start")
	os.Exit(1)
}
