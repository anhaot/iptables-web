package api

import (
	"net/http"
	"strings"

	"iptables-web/internal/store"
)

type AuthHandler struct {
	userStore *store.UserStore
}

func NewAuthHandler(us *store.UserStore) *AuthHandler {
	return &AuthHandler{userStore: us}
}

// ==================== CAPTCHA ====================

func (h *AuthHandler) GetCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	id, display := h.userStore.NewCaptcha()
	respondOK(w, map[string]string{"id": id, "question": display})
}

// ==================== Login ====================

type loginRequestBody struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	CaptchaID  string `json:"captcha_id"`
	CaptchaAns string `json:"captcha_ans"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req loginRequestBody
	if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "missing_fields", "用户名和密码不能为空")
		return
	}

	// Validate CAPTCHA
	if req.CaptchaID == "" || req.CaptchaAns == "" {
		respondError(w, http.StatusBadRequest, "captcha_required", "请完成验证")
		return
	}
	if !h.userStore.ValidateCaptcha(req.CaptchaID, req.CaptchaAns) {
		respondError(w, http.StatusBadRequest, "captcha_invalid", "验证错误，请重试")
		return
	}
	// Every authentication attempt consumes its challenge. This prevents one
	// solved CAPTCHA from being reused for a password-guessing burst.
	h.userStore.ConsumeCaptcha(req.CaptchaID)
	sourceIP := remoteRequestIP(r.RemoteAddr)

	// Check lockout
	if err := h.userStore.CheckLoginLocked(req.Username, sourceIP); err != nil {
		respondError(w, http.StatusTooManyRequests, "account_locked", err.Error())
		return
	}

	resp, err := h.userStore.Login(req.Username, req.Password)
	if err != nil {
		h.userStore.RecordLoginFailure(req.Username, sourceIP)
		respondError(w, http.StatusUnauthorized, "auth_failed", err.Error())
		return
	}

	h.userStore.RecordLoginSuccess(req.Username, sourceIP)
	respondOK(w, resp)
}

// ==================== Logout / Session ====================

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	token := extractBearerToken(r)
	if token != "" {
		h.userStore.Logout(token)
	}
	respondOK(w, map[string]string{"status": "logged_out"})
}

func (h *AuthHandler) SessionCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	token := extractBearerToken(r)
	if token == "" {
		respondError(w, http.StatusUnauthorized, "no_token", "未提供认证令牌")
		return
	}
	sess, err := h.userStore.ValidateSession(token)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	respondOK(w, map[string]interface{}{
		"username":                 sess.Username,
		"role":                     sess.Role,
		"requires_password_change": sess.MustChangePassword,
	})
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if token := r.Header.Get("X-Auth-Token"); token != "" {
		return token
	}
	return ""
}
