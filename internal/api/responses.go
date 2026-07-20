package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const defaultJSONBodyLimit int64 = 64 * 1024

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
	Meta    *APIMeta    `json:"meta,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type APIMeta struct {
	Total   int    `json:"total,omitempty"`
	Chain   string `json:"chain,omitempty"`
	Version string `json:"version,omitempty"`
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIResponse{Success: true, Data: data})
}

func respondError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Error:   &APIError{Code: code, Message: message},
	})
}

func respondOK(w http.ResponseWriter, data interface{}) {
	respondJSON(w, http.StatusOK, data)
}

func respondCreated(w http.ResponseWriter, data interface{}) {
	respondJSON(w, http.StatusCreated, data)
}

func respondNoContent(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}, limit int64) error {
	if limit <= 0 {
		limit = defaultJSONBodyLimit
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func readRequestBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = defaultJSONBodyLimit
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	return io.ReadAll(r.Body)
}
