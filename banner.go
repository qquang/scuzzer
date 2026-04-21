package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/color"
	"math"
)

//go:embed images.jpeg
var bannerImageData []byte

func banner() {
	img, _, err := image.Decode(bytes.NewReader(bannerImageData))
	if err != nil {
		fmt.Println("  [ scuzzer ]")
		return
	}

	bounds := img.Bounds()
	srcW := bounds.Max.X
	srcH := bounds.Max.Y

	// Target width in terminal chars; each char = 1px wide, 2px tall (half-block)
	const targetW = 52
	targetH := int(math.Round(float64(targetW) * float64(srcH) / float64(srcW)))
	if targetH%2 != 0 {
		targetH++
	}

	// Render: ▀ with fg=top-pixel color, bg=bottom-pixel color
	for y := 0; y < targetH; y += 2 {
		for x := 0; x < targetW; x++ {
			srcX := x * srcW / targetW
			srcY1 := y * srcH / targetH
			srcY2 := (y + 1) * srcH / targetH

			r1, g1, b1 := rgbAt(img, srcX, srcY1)
			r2, g2, b2 := rgbAt(img, srcX, srcY2)

			fmt.Printf("\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm▀", r1, g1, b1, r2, g2, b2)
		}
		fmt.Print("\x1b[0m\n")
	}
	fmt.Print("\x1b[0m")
}

func rgbAt(img image.Image, x, y int) (uint8, uint8, uint8) {
	c := img.At(x, y)
	r, g, b, _ := color.NRGBAModel.Convert(c).RGBA()
	return uint8(r >> 8), uint8(g >> 8), uint8(b >> 8)
}
