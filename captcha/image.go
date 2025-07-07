package captcha

import (
	"bytes"
	"encoding/base64"
	"image/color"
	"math/rand"
	"github.com/fogleman/gg"
	"golang.org/x/image/font"
)

var (
	fontSize = 48.0
	fontPath = "assets/htmlfont/comic.ttf"
)

func generateCaptcha() (string, string, error) {
	key := generateRandString(6)
	value := generateRandString(6)
	font, errs := loadFont(fontPath, fontSize)
	if errs != nil {
		return "", "", errs
	}

	dc := gg.NewContext(captchaWidth, captchaHeight)
	dc.SetColor(color.White)
	dc.Clear()

	// Add background noise: random lines
	for i := 0; i < 10; i++ {
		dc.SetRGBA(rand.Float64(), rand.Float64(), rand.Float64(), 0.7)
		x1 := rand.Float64() * float64(captchaWidth)
		y1 := rand.Float64() * float64(captchaHeight)
		x2 := rand.Float64() * float64(captchaWidth)
		y2 := rand.Float64() * float64(captchaHeight)
		dc.SetLineWidth(rand.Float64()*2 + 1)
		dc.DrawLine(x1, y1, x2, y2)
		dc.Stroke()
	}

	// Draw each character with random rotation, color, and position
	dc.SetFontFace(font)
	charSpacing := float64(captchaWidth) / float64(len(value)+1)
	for i, c := range value {
		angle := rand.Float64()*0.6 - 0.3 // -0.3 to +0.3 radians
		x := charSpacing*float64(i+1) + rand.Float64()*4 - 2
		y := float64(captchaHeight)/2 + rand.Float64()*10 - 5
		dc.Push()
		dc.RotateAbout(angle, x, y)
		dc.SetRGB(rand.Float64()*0.5, rand.Float64()*0.5, rand.Float64()*0.5)
		dc.DrawStringAnchored(string(c), x, y, 0.5, 0.5)
		dc.Pop()
	}

	// Add more noise: random dots
	for i := 0; i < 3000; i++ {
		x := rand.Intn(captchaWidth)
		y := rand.Intn(captchaHeight)
		dc.SetRGBA(rand.Float64(), rand.Float64(), rand.Float64(), rand.Float64()*0.7)
		dc.DrawPoint(float64(x), float64(y), rand.Float64()*1.5+0.5)
	}

	// Optionally: add random arcs/curves
	for i := 0; i < 3; i++ {
		dc.SetRGBA(rand.Float64(), rand.Float64(), rand.Float64(), 0.5)
		x := rand.Float64() * float64(captchaWidth)
		y := rand.Float64() * float64(captchaHeight)
		r := rand.Float64()*30 + 20
		start := rand.Float64() * 2 * 3.1415
		end := start + rand.Float64()*3.1415
		dc.SetLineWidth(rand.Float64()*2 + 1)
		dc.DrawArc(x, y, r, start, end)
		dc.Stroke()
	}

	// Store the CAPTCHA key and value
	captchaMu.Lock()
	captchas[key] = value
	captchaMu.Unlock()

	// Encode image as PNG
	var buf bytes.Buffer
	err := dc.EncodePNG(&buf)
	if err != nil {
		return "", "", err
	}
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return key, encoded, nil
}

func loadFont(fontPath string, size float64) (font.Face, error) {
	loadedFont, err := gg.LoadFontFace(string(fontPath), size)
	if err != nil {
		return nil, err
	}
	return loadedFont, nil
}

func generateRandString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}