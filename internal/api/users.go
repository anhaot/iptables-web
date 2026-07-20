package api

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"

	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

type UserHandler struct {
	userStore *store.UserStore
	authStore *store.UserStore
}

func NewUserHandler(us *store.UserStore) *UserHandler {
	return &UserHandler{userStore: us, authStore: us}
}

func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	users := h.userStore.List()
	respondOK(w, users)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	id := extractUserID(r.URL.Path)
	user, err := h.userStore.Get(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	respondOK(w, user.ToResponse())
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req model.CreateUserRequest
	if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	user := &model.User{
		ID:        newRandomID(),
		Username:  req.Username,
		Password:  req.Password,
		Role:      req.Role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := user.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	if err := h.userStore.Create(user); err != nil {
		respondError(w, http.StatusConflict, "duplicate", err.Error())
		return
	}
	respondCreated(w, user.ToResponse())
}

func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PUT")
		return
	}
	id := extractUserID(r.URL.Path)
	existing, err := h.userStore.Get(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	var req model.CreateUserRequest
	if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	updated := &model.User{
		ID:        id,
		Username:  req.Username,
		Password:  req.Password,
		Role:      req.Role,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: time.Now(),
	}
	updated.Username = strings.TrimSpace(updated.Username)
	updated.Role = strings.TrimSpace(updated.Role)

	// Preserve existing values if not provided
	if updated.Username == "" {
		updated.Username = existing.Username
	}
	if updated.Role == "" {
		updated.Role = existing.Role
	}

	if len(updated.Username) < 3 || len(updated.Username) > 32 {
		respondError(w, http.StatusBadRequest, "validation_error", "用户名长度必须为 3-32 个字符")
		return
	}
	if updated.Role != "admin" && updated.Role != "user" {
		respondError(w, http.StatusBadRequest, "validation_error", "角色必须是 admin 或 user")
		return
	}
	if updated.Password != "" && len(updated.Password) < 6 {
		respondError(w, http.StatusBadRequest, "validation_error", "密码长度至少 6 个字符")
		return
	}

	if err := h.userStore.Update(updated); err != nil {
		respondError(w, http.StatusConflict, "update_failed", err.Error())
		return
	}
	respondOK(w, updated.ToResponse())
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use DELETE")
		return
	}
	id := extractUserID(r.URL.Path)
	token := extractBearerToken(r)
	if sess, _ := h.authStore.ValidateSession(token); sess != nil {
		if self, _ := h.userStore.Get(id); self != nil && strings.EqualFold(self.Username, sess.Username) {
			respondError(w, http.StatusBadRequest, "cannot_delete_self", "不能删除当前登录用户")
			return
		}
	}
	if err := h.userStore.Delete(id); err != nil {
		respondError(w, http.StatusBadRequest, "delete_failed", err.Error())
		return
	}
	respondNoContent(w)
}

func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	token := extractBearerToken(r)
	sess, err := h.authStore.ValidateSession(token)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	var userID string
	for _, u := range h.userStore.List() {
		if strings.EqualFold(u.Username, sess.Username) {
			userID = u.ID
			break
		}
	}
	if userID == "" {
		respondError(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if err := h.userStore.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		respondError(w, http.StatusBadRequest, "password_error", err.Error())
		return
	}
	respondOK(w, map[string]string{"status": "password_changed"})
}

func newRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func extractUserID(path string) string {
	rest := strings.TrimPrefix(path, "/api/v1/users/")
	rest = strings.TrimSuffix(rest, "/password")
	rest = strings.TrimSuffix(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}
	return ""
}
