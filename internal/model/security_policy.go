package model

import "fmt"

// SecurityPolicy controls password creation and CAPTCHA verification. Existing
// passwords remain valid when the policy changes; the new rules apply the next
// time a password is created, reset, or changed.
type SecurityPolicy struct {
	Password PasswordPolicy `json:"password"`
	Captcha  CaptchaPolicy  `json:"captcha"`
	Login    LoginPolicy    `json:"login"`
}

type PasswordPolicy struct {
	MinLength            int `json:"min_length"`
	MinUppercase         int `json:"min_uppercase"`
	MinLowercase         int `json:"min_lowercase"`
	MinDigits            int `json:"min_digits"`
	MinSpecial           int `json:"min_special"`
	HistoryCount         int `json:"history_count"`
	MinChangedCharacters int `json:"min_changed_characters"`
}

type CaptchaPolicy struct {
	CaseSensitive bool `json:"case_sensitive"`
}

const (
	LockoutModeTimed         = "timed"
	LockoutModeAdministrator = "administrator"
)

// LoginPolicy contains account lockout and password-expiry settings. The
// default reset password is persisted only as a password hash and is never
// returned by an API response.
type LoginPolicy struct {
	MaxFailures              int    `json:"max_failures"`
	LockoutMode              string `json:"lockout_mode"`
	LockoutMinutes           int    `json:"lockout_minutes"`
	PasswordMaxAgeDays       int    `json:"password_max_age_days"`
	DefaultResetPasswordHash string `json:"default_reset_password_hash,omitempty"`
}

type PublicSecurityPolicy struct {
	Password PasswordPolicy `json:"password"`
	Captcha  CaptchaPolicy  `json:"captcha"`
}

type AdminSecurityPolicy struct {
	Password PasswordPolicy       `json:"password"`
	Captcha  CaptchaPolicy        `json:"captcha"`
	Login    AdminLoginPolicyView `json:"login"`
}

type AdminLoginPolicyView struct {
	MaxFailures                    int    `json:"max_failures"`
	LockoutMode                    string `json:"lockout_mode"`
	LockoutMinutes                 int    `json:"lockout_minutes"`
	PasswordMaxAgeDays             int    `json:"password_max_age_days"`
	DefaultResetPasswordConfigured bool   `json:"default_reset_password_configured"`
}

type SecurityPolicyUpdateRequest struct {
	Password PasswordPolicy           `json:"password"`
	Captcha  CaptchaPolicy            `json:"captcha"`
	Login    LoginPolicyUpdateRequest `json:"login"`
}

type LoginPolicyUpdateRequest struct {
	MaxFailures          int    `json:"max_failures"`
	LockoutMode          string `json:"lockout_mode"`
	LockoutMinutes       int    `json:"lockout_minutes"`
	PasswordMaxAgeDays   int    `json:"password_max_age_days"`
	DefaultResetPassword string `json:"default_reset_password,omitempty"`
}

func DefaultSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		Password: PasswordPolicy{
			MinLength: 1,
		},
		Captcha: CaptchaPolicy{CaseSensitive: false},
		Login: LoginPolicy{
			MaxFailures:        5,
			LockoutMode:        LockoutModeTimed,
			LockoutMinutes:     15,
			PasswordMaxAgeDays: 0,
		},
	}
}

func (p SecurityPolicy) PublicView() PublicSecurityPolicy {
	return PublicSecurityPolicy{Password: p.Password, Captcha: p.Captcha}
}

func (p SecurityPolicy) AdminView() AdminSecurityPolicy {
	return AdminSecurityPolicy{
		Password: p.Password,
		Captcha:  p.Captcha,
		Login: AdminLoginPolicyView{
			MaxFailures:                    p.Login.MaxFailures,
			LockoutMode:                    p.Login.LockoutMode,
			LockoutMinutes:                 p.Login.LockoutMinutes,
			PasswordMaxAgeDays:             p.Login.PasswordMaxAgeDays,
			DefaultResetPasswordConfigured: p.Login.DefaultResetPasswordHash != "",
		},
	}
}

func (p SecurityPolicy) Validate() error {
	password := p.Password
	if password.MinLength < 1 || password.MinLength > 128 {
		return fmt.Errorf("密码最小长度必须为 1-128")
	}
	counts := []struct {
		name  string
		value int
	}{
		{"大写字母数量", password.MinUppercase},
		{"小写字母数量", password.MinLowercase},
		{"数字数量", password.MinDigits},
		{"特殊字符数量", password.MinSpecial},
	}
	requiredCharacters := 0
	for _, count := range counts {
		if count.value < 0 || count.value > 16 {
			return fmt.Errorf("%s必须为 0-16", count.name)
		}
		requiredCharacters += count.value
	}
	if requiredCharacters > password.MinLength {
		return fmt.Errorf("各类字符的最低数量之和不能超过密码最小长度")
	}
	if password.HistoryCount < 0 || password.HistoryCount > 10 {
		return fmt.Errorf("密码历史数量必须为 0-10")
	}
	if password.MinChangedCharacters < 0 || password.MinChangedCharacters > password.MinLength {
		return fmt.Errorf("至少不同字符数必须为 0 到密码最小长度")
	}
	if p.Login.MaxFailures < 1 || p.Login.MaxFailures > 20 {
		return fmt.Errorf("登录失败次数必须为 1-20")
	}
	if p.Login.LockoutMode != LockoutModeTimed && p.Login.LockoutMode != LockoutModeAdministrator {
		return fmt.Errorf("锁定方式必须为 timed 或 administrator")
	}
	if p.Login.LockoutMinutes < 1 || p.Login.LockoutMinutes > 1440 {
		return fmt.Errorf("等待解锁时间必须为 1-1440 分钟")
	}
	if p.Login.PasswordMaxAgeDays < 0 || p.Login.PasswordMaxAgeDays > 3650 {
		return fmt.Errorf("密码有效期必须为 0-3650 天")
	}
	return nil
}
