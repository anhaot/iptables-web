package model

import (
	"fmt"
	"strings"
	"time"
)

// LocalHostID is the stable authorization ID for the controller's own
// firewall. It may be assigned to ordinary users just like a remote host.
const LocalHostID = "local"

type User struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	Password           string     `json:"password,omitempty"`         // stored hash; never return through API responses
	PasswordHistory    []string   `json:"password_history,omitempty"` // prior hashes only; never return through API responses
	Role               string     `json:"role"`                       // admin, user
	HostIDs            []string   `json:"host_ids,omitempty"`         // ordinary-user managed hosts; admins always manage all hosts
	HostGroups         []string   `json:"host_groups,omitempty"`      // ordinary-user group grants; membership is resolved dynamically
	MustChangePassword bool       `json:"must_change_password,omitempty"`
	PasswordChangedAt  time.Time  `json:"password_changed_at,omitempty"`
	LoginDisabled      bool       `json:"login_disabled,omitempty"`
	LoginDisabledAt    *time.Time `json:"login_disabled_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
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
	if u.Password == "" {
		return fmt.Errorf("密码不能为空")
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
	Token                  string   `json:"token"`
	Username               string   `json:"username"`
	Role                   string   `json:"role"`
	HostIDs                []string `json:"host_ids,omitempty"`
	HostGroups             []string `json:"host_groups,omitempty"`
	RequiresPasswordChange bool     `json:"requires_password_change"`
}

// CreateUserRequest is the body for creating or updating a user.
type CreateUserRequest struct {
	Username   string   `json:"username"`
	Password   string   `json:"password,omitempty"`
	Role       string   `json:"role"`
	HostIDs    []string `json:"host_ids,omitempty"`
	HostGroups []string `json:"host_groups,omitempty"`
}

// UserResponse is the safe representation of a user (no password)
type UserResponse struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	Role               string     `json:"role"`
	HostIDs            []string   `json:"host_ids"`
	HostGroups         []string   `json:"host_groups"`
	MustChangePassword bool       `json:"must_change_password"`
	PasswordChangedAt  time.Time  `json:"password_changed_at"`
	LoginDisabled      bool       `json:"login_disabled"`
	LoginDisabledAt    *time.Time `json:"login_disabled_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:                 u.ID,
		Username:           u.Username,
		Role:               u.Role,
		HostIDs:            append([]string(nil), u.HostIDs...),
		HostGroups:         append([]string(nil), u.HostGroups...),
		MustChangePassword: u.MustChangePassword,
		PasswordChangedAt:  u.PasswordChangedAt,
		LoginDisabled:      u.LoginDisabled,
		LoginDisabledAt:    cloneTimePointer(u.LoginDisabledAt),
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
