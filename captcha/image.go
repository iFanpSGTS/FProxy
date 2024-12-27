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

	dc.SetColor(color.Black)
	dc.SetFontFace(font)
	dc.DrawStringAnchored(value, float64(captchaWidth/2), float64(captchaHeight/2), 0.5, 0.5)

	// Add noise
	for i := 0; i < 2000; i++ {
		x := rand.Intn(captchaWidth)
		y := rand.Intn(captchaHeight)
		dc.SetRGB(rand.Float64(), rand.Float64(), rand.Float64())
		dc.DrawPoint(float64(x), float64(y), 1)
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