package model

import (
	"fmt"
	"strings"
	"time"
)

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password,omitempty"` // stored hash; never return through API responses
	Role      string    `json:"role"`               // admin, user
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (u *User) Validate() error {
	u.Username = strings.TrimSpace(u.Username)
	if len(u.Username) < 3 || len(u.Username) > 32 {
		return fmt.Errorf("用户名长度必须为 3-32 个字符")
	}
	u.Role = strings.TrimSpace(u.Role)
	if u.Role != "admin" && u.Role != "user" {
		return fmt.Errorf("角色必须是 admin 或 user")
	}
	if len(u.Password) < 6 {
		return fmt.Errorf("密码长度至少 6 个字符")
	}
	return nil
}

// LoginRequest is the body for POST /api/v1/auth/login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is returned on successful login
type LoginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// CreateUserRequest is the body for creating or updating a user.
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role"`
}

// UserResponse is the safe representation of a user (no password)
type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:        u.ID,
		Username:  u.Username,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}
