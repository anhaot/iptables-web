package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// CaptchaQuestion holds a rendered mixed-character CAPTCHA and its answer.
type CaptchaQuestion struct {
	ID      string
	Display string // data:image/svg+xml;base64,...
	Answer  string
}

// Ambiguous glyphs (0/O, 1/I/l) are omitted without reducing the character
// classes available to the challenge.
const (
	captchaUppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	captchaLowercase = "abcdefghijkmnpqrstuvwxyz"
	captchaDigits    = "23456789"
	captchaAlphabet  = captchaUppercase + captchaLowercase + captchaDigits
)

// GenerateCaptchaQuestion creates a readable SVG CAPTCHA.
func GenerateCaptchaQuestion() (CaptchaQuestion, error) {
	characters := make([]byte, 0, 5)
	for _, alphabet := range []string{captchaUppercase, captchaLowercase, captchaDigits, captchaAlphabet, captchaAlphabet} {
		value, err := captchaByte(alphabet)
		if err != nil {
			return CaptchaQuestion{}, fmt.Errorf("generate CAPTCHA: %w", err)
		}
		characters = append(characters, value)
	}
	for i := len(characters) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return CaptchaQuestion{}, fmt.Errorf("shuffle CAPTCHA: %w", err)
		}
		j := int(n.Int64())
		characters[i], characters[j] = characters[j], characters[i]
	}
	code := string(characters)

	return CaptchaQuestion{
		Display: renderCaptchaSVG(code),
		Answer:  code,
	}, nil
}

func captchaByte(alphabet string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
	if err != nil {
		return 0, err
	}
	return alphabet[n.Int64()], nil
}

func renderCaptchaSVG(code string) string {
	var svg strings.Builder
	width := 164
	height := 52
	bg1 := captchaColor(238, 248)
	bg2 := captchaColor(232, 245)

	svg.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`, width, height, width, height))
	svg.WriteString(`<defs><filter id="soft"><feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="1" seed="7" result="noise"/><feColorMatrix in="noise" type="saturate" values=".18"/><feBlend in="SourceGraphic" mode="multiply"/></filter></defs>`)
	svg.WriteString(fmt.Sprintf(`<rect width="100%%" height="100%%" rx="10" fill="rgb(%d,%d,%d)"/>`, bg1, bg1+3, bg2))

	for i := 0; i < 5; i++ {
		x1 := captchaInt(width)
		y1 := captchaInt(height)
		x2 := captchaInt(width)
		y2 := captchaInt(height)
		stroke := captchaColor(120, 190)
		svg.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="rgb(%d,%d,%d)" stroke-width="1.2" opacity=".35"/>`, x1, y1, x2, y2, stroke, stroke, 210))
	}

	for i, ch := range code {
		x := 22 + i*28 + captchaInt(7) - 3
		y := 35 + captchaInt(9) - 4
		rotate := captchaInt(25) - 12
		color := captchaColor(35, 105)
		svg.WriteString(fmt.Sprintf(`<text x="%d" y="%d" transform="rotate(%d %d %d)" font-family="Verdana,Arial,sans-serif" font-size="28" font-weight="700" fill="rgb(%d,%d,%d)" filter="url(#soft)">%c</text>`, x, y, rotate, x, y, color, color+10, color+80, ch))
	}

	for i := 0; i < 26; i++ {
		cx := captchaInt(width)
		cy := captchaInt(height)
		fill := captchaColor(110, 190)
		svg.WriteString(fmt.Sprintf(`<circle cx="%d" cy="%d" r="1" fill="rgb(%d,%d,%d)" opacity=".42"/>`, cx, cy, fill, fill, 210))
	}

	svg.WriteString(`</svg>`)
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg.String()))
}

func captchaInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

func captchaColor(min, max int) int {
	if max <= min {
		return min
	}
	return min + captchaInt(max-min)
}
