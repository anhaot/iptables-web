package api

import (
	"net/http"
	"strings"

	"iptables-web/internal/store"
)

type AccessKeyHandler struct {
	store *store.APIKeyStore
}

func NewAccessKeyHandler(keyStore *store.APIKeyStore) *AccessKeyHandler {
	return &AccessKeyHandler{store: keyStore}
}

func (h *AccessKeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		respondError(w, http.StatusServiceUnavailable, "access_keys_unavailable", "access key management is not configured")
		return
	}
	adminRequired()(http.HandlerFunc(h.serveAdmin)).ServeHTTP(w, r)
}

func (h *AccessKeyHandler) serveAdmin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v1/access-keys" || r.URL.Path == "/api/v1/access-keys/" {
		switch r.Method {
		case http.MethodGet:
			respondOK(w, h.store.List())
		case http.MethodPost:
			var req struct {
				Name string `json:"name"`
			}
			if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
				respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
				return
			}
			metadata, plaintext, err := h.store.Create(req.Name)
			if err != nil {
				respondError(w, http.StatusBadRequest, "access_key_error", err.Error())
				return
			}
			respondCreated(w, map[string]interface{}{"access_key": metadata, "key": plaintext})
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
		}
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/access-keys/")
	if len(id) != 24 || strings.Contains(id, "/") {
		respondError(w, http.StatusNotFound, "not_found", "access key not found")
		return
	}
	if r.Method != http.MethodDelete {
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use DELETE")
		return
	}
	if err := h.store.Delete(id); err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	respondNoContent(w)
}
