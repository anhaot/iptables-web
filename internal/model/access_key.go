package model

import "time"

// AccessKey is the persisted metadata for an API credential. Only a SHA-256
// digest is stored; the plaintext key is returned once when it is created.
type AccessKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
}

type AccessKeyResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (k *AccessKey) ToResponse() AccessKeyResponse {
	return AccessKeyResponse{ID: k.ID, Name: k.Name, CreatedAt: k.CreatedAt}
}
