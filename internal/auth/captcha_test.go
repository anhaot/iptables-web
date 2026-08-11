package auth

import (
	"strings"
	"testing"
)

func TestGenerateCaptchaQuestionUsesMixedCharacterClasses(t *testing.T) {
	t.Parallel()

	captcha, err := GenerateCaptchaQuestion()
	if err != nil {
		t.Fatal(err)
	}
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
	if !strings.ContainsAny(captcha.Answer, captchaUppercase) ||
		!strings.ContainsAny(captcha.Answer, captchaLowercase) ||
		!strings.ContainsAny(captcha.Answer, captchaDigits) {
		t.Fatalf("Answer %q does not contain uppercase, lowercase, and digit classes", captcha.Answer)
	}
}
