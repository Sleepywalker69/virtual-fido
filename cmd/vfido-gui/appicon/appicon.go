// Package appicon draws the Virtual FIDO icon (a key on a rounded square) at
// any size, so the window, the tray and the .exe resource all match.
package appicon

import (
	"image"
	"image/color"
	"math"
)

var (
	// Blue is the normal icon; Amber marks "waiting for your approval".
	Blue  = color.RGBA{0x1D, 0x4E, 0xD8, 0xFF}
	Amber = color.RGBA{0xD9, 0x77, 0x06, 0xFF}
	Gray  = color.RGBA{0x6B, 0x72, 0x80, 0xFF}
)

const supersample = 4

// Draw renders the icon at size x size pixels on a background colour.
func Draw(size int, background color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	scale := float64(size)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var bgCover, keyCover float64
			for sy := 0; sy < supersample; sy++ {
				for sx := 0; sx < supersample; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/supersample) / scale
					y := (float64(py) + (float64(sy)+0.5)/supersample) / scale
					if inRoundedSquare(x, y) {
						bgCover++
						if inKey(x, y) {
							keyCover++
						}
					}
				}
			}
			total := float64(supersample * supersample)
			bgA, keyA := bgCover/total, keyCover/total
			// Composite white key over the background, then over transparency.
			r := float64(background.R)*(bgA-keyA) + 255*keyA
			g := float64(background.G)*(bgA-keyA) + 255*keyA
			b := float64(background.B)*(bgA-keyA) + 255*keyA
			img.SetRGBA(px, py, color.RGBA{uint8(r + 0.5), uint8(g + 0.5), uint8(b + 0.5), uint8(bgA*255 + 0.5)})
		}
	}
	return img
}

func inRoundedSquare(x, y float64) bool {
	const lo, hi, radius = 0.03, 0.97, 0.22
	if x < lo || x > hi || y < lo || y > hi {
		return false
	}
	cx := math.Min(math.Max(x, lo+radius), hi-radius)
	cy := math.Min(math.Max(y, lo+radius), hi-radius)
	return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= radius*radius
}

// inKey is a key lying on its side: a ring (the bow) on the left and a shaft
// with two teeth on the right.
func inKey(x, y float64) bool {
	const bowX, bowY, bowR, holeR = 0.33, 0.5, 0.20, 0.085
	d2 := (x-bowX)*(x-bowX) + (y-bowY)*(y-bowY)
	if d2 <= bowR*bowR && d2 >= holeR*holeR {
		return true
	}
	inRect := func(x0, y0, x1, y1 float64) bool { return x >= x0 && x <= x1 && y >= y0 && y <= y1 }
	return inRect(0.50, 0.445, 0.86, 0.555) || // shaft
		inRect(0.70, 0.555, 0.77, 0.69) || // tooth
		inRect(0.79, 0.555, 0.86, 0.65) // tooth
}
