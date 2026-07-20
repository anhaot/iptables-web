package auth

import (
	"strings"
	"testing"
)

func TestGenerateCaptchaQuestionUsesLetters(t *testing.T) {
	t.Parallel()

	captcha := GenerateCaptchaQuestion()
	if len(captcha.Answer) != 5 {
		t.Fatalf("Answer length = %d, want 5", len(captcha.Answer))
	}
	if !strings.HasPrefix(captcha.Display, "data:image/svg+xml;base64,") {
		t.Fatalf("Display = %q, want SVG data URL", captcha.Display)
	}
	for _, ch := range captcha.Answer {
		if !strings.ContainsRune(captchaAlphabet, ch) {
			t.Fatalf("Answer contains unexpected rune %q", ch)
		}
	}
}
