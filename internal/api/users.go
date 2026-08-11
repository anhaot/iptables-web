package api

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

type UserHandler struct {
	userStore *store.UserStore
	authStore *store.UserStore
	hostStore *store.HostStore
}

func NewUserHandler(us *store.UserStore, hostStores ...*store.HostStore) *UserHandler {
	var hostStore *store.HostStore
	if len(hostStores) > 0 {
		hostStore = hostStores[0]
	}
	return &UserHandler{userStore: us, authStore: us, hostStore: hostStore}
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

	id, err := newRandomID()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "random_source_failed", "无法生成安全用户标识")
		return
	}
	user := &model.User{
		ID:         id,
		Username:   req.Username,
		Password:   req.Password,
		Role:       req.Role,
		HostIDs:    req.HostIDs,
		HostGroups: req.HostGroups,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := user.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	if err := h.userStore.ValidatePassword(user.Password); err != nil {
		respondError(w, http.StatusBadRequest, "password_policy", err.Error())
		return
	}
	if err := h.validateHostAssignments(user); err != nil {
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
		ID:         id,
		Username:   req.Username,
		Password:   req.Password,
		Role:       req.Role,
		HostIDs:    req.HostIDs,
		HostGroups: req.HostGroups,
		CreatedAt:  existing.CreatedAt,
		UpdatedAt:  time.Now(),
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
	if err := h.validateHostAssignments(updated); err != nil {
		respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	if updated.Password != "" {
		if err := h.userStore.ValidatePassword(updated.Password); err != nil {
			respondError(w, http.StatusBadRequest, "password_policy", err.Error())
			return
		}
	}

	if err := h.userStore.Update(updated); err != nil {
		respondError(w, http.StatusConflict, "update_failed", err.Error())
		return
	}
	stored, err := h.userStore.Get(id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	respondOK(w, stored.ToResponse())
}

func (h *UserHandler) validateHostAssignments(user *model.User) error {
	if user.Role == "admin" {
		user.HostIDs = nil
		user.HostGroups = nil
		return nil
	}
	if len(user.HostIDs) > 1000 {
		return fmt.Errorf("单个用户最多分配 1000 台主机")
	}
	seen := make(map[string]bool, len(user.HostIDs))
	validated := make([]string, 0, len(user.HostIDs))
	for _, raw := range user.HostIDs {
		id := strings.TrimSpace(raw)
		if (id != model.LocalHostID && !hostIDPattern.MatchString(id)) || seen[id] {
			return fmt.Errorf("主机授权包含无效或重复的主机 ID")
		}
		if id == model.LocalHostID {
			seen[id] = true
			validated = append(validated, id)
			continue
		}
		if h.hostStore == nil {
			return fmt.Errorf("主机授权存储不可用")
		}
		if _, err := h.hostStore.Get(id); err != nil {
			return fmt.Errorf("授权主机 %s 不存在", id)
		}
		seen[id] = true
		validated = append(validated, id)
	}
	user.HostIDs = validated
	if len(user.HostGroups) > 100 {
		return fmt.Errorf("单个用户最多分配 100 个主机组")
	}
	if len(user.HostGroups) > 0 && h.hostStore == nil {
		return fmt.Errorf("主机授权存储不可用")
	}
	availableGroups := make(map[string]string)
	if h.hostStore != nil {
		for _, host := range h.hostStore.List() {
			group := strings.TrimSpace(host.Group)
			if group != "" {
				availableGroups[strings.ToLower(group)] = group
			}
		}
	}
	seenGroups := make(map[string]bool, len(user.HostGroups))
	validatedGroups := make([]string, 0, len(user.HostGroups))
	for _, raw := range user.HostGroups {
		group := strings.TrimSpace(raw)
		key := strings.ToLower(group)
		if group == "" || len([]rune(group)) > 64 || seenGroups[key] {
			return fmt.Errorf("主机组授权包含无效或重复的主机组")
		}
		canonical, ok := availableGroups[key]
		if !ok {
			return fmt.Errorf("授权主机组 %s 不存在", group)
		}
		seenGroups[key] = true
		validatedGroups = append(validatedGroups, canonical)
	}
	user.HostGroups = validatedGroups
	return nil
}

func (h *UserHandler) GetSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	respondOK(w, h.userStore.AdminSecurityPolicy())
}

func (h *UserHandler) UpdateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PUT")
		return
	}
	var policy model.SecurityPolicyUpdateRequest
	if err := decodeJSONBody(w, r, &policy, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if err := h.userStore.UpdateSecurityPolicyRequest(policy); err != nil {
		respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	respondOK(w, h.userStore.AdminSecurityPolicy())
}

func (h *UserHandler) ResetAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	id := extractUserID(r.URL.Path)
	if err := h.userStore.ResetAccount(id); err != nil {
		respondError(w, http.StatusBadRequest, "reset_failed", err.Error())
		return
	}
	stored, err := h.userStore.Get(id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "reset_failed", err.Error())
		return
	}
	respondOK(w, stored.ToResponse())
}

func (h *UserHandler) UnlockAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	id := extractUserID(r.URL.Path)
	if err := h.userStore.UnlockAccount(id); err != nil {
		respondError(w, http.StatusBadRequest, "unlock_failed", err.Error())
		return
	}
	stored, err := h.userStore.Get(id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "unlock_failed", err.Error())
		return
	}
	respondOK(w, stored.ToResponse())
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

func newRandomID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
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
