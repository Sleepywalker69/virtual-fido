// Command gen writes the icon PNGs that go-winres embeds in vfido-gui.exe
// (normal, waiting-for-approval and stopped variants):
//
//	go run ./cmd/vfido-gui/appicon/gen cmd/vfido-gui/winres
package main

import (
	"fmt"
	"image/color"
	"image/png"
	"log"
	"os"
	"path/filepath"

	"github.com/bulwarkid/virtual-fido/cmd/vfido-gui/appicon"
)

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	variants := map[string]color.RGBA{"icon": appicon.Blue, "attention": appicon.Amber, "stopped": appicon.Gray}
	for prefix, background := range variants {
		for _, size := range []int{16, 20, 24, 32, 40, 48, 64, 256} {
			path := filepath.Join(dir, fmt.Sprintf("%s%d.png", prefix, size))
			file, err := os.Create(path)
			if err != nil {
				log.Fatal(err)
			}
			if err := png.Encode(file, appicon.Draw(size, background)); err != nil {
				log.Fatal(err)
			}
			file.Close()
		}
	}
}
