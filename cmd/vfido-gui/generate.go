package main

// Regenerate the icons and the Windows resources (manifest, icon, version)
// after changing appicon or winres/winres.json:
//
//	go install github.com/tc-hib/go-winres@v0.3.3
//	go generate ./cmd/vfido-gui

//go:generate go run ./appicon/gen winres
//go:generate go-winres make --arch amd64,arm64
