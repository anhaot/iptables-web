package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"iptables-web/internal/auth"
	"iptables-web/internal/model"
)

// UserStore persists and manages users and active sessions.
type UserStore struct {
	mu            sync.RWMutex
	filePath      string
	policyPath    string
	users         []*model.User
	policy        model.SecurityPolicy
	sessions      map[string]*Session      // token -> session
	captchas      map[string]*CaptchaEntry // captcha ID -> code
	loginAttempts map[string]*LoginAttempt // username -> attempt tracking
}

type Session struct {
	UserID             string
	Username           string
	Role               string
	HostIDs            []string
	HostGroups         []string
	MustChangePassword bool
	ExpiresAt          time.Time
}

type CaptchaEntry struct {
	Answer        string
	Display       string
	CaseSensitive bool
	ExpiresAt     time.Time
}

type LoginAttempt struct {
	Failures    int
	LockedUntil time.Time
}

const (
	captchaTTL = 5 * time.Minute
)

func NewUserStore(filePath string) *UserStore {
	return &UserStore{
		filePath:      filePath,
		policyPath:    filepath.Join(filepath.Dir(filePath), "security-policy.json"),
		policy:        model.DefaultSecurityPolicy(),
		sessions:      make(map[string]*Session),
		captchas:      make(map[string]*CaptchaEntry),
		loginAttempts: make(map[string]*LoginAttempt),
	}
}

func (s *UserStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadSecurityPolicyLocked(); err != nil {
		return err
	}

	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		s.users = []*model.User{}
		if err := s.createDefaultAdminLocked(); err != nil {
			return err
		}
		return s.writeFileLocked()
	}
	if err != nil {
		return fmt.Errorf("读取用户文件: %w", err)
	}
	if len(data) == 0 {
		s.users = []*model.User{}
		if err := s.createDefaultAdminLocked(); err != nil {
			return err
		}
		return s.writeFileLocked()
	}
	var users []*model.User
	if err := json.Unmarshal(data, &users); err != nil {
		return fmt.Errorf("解析用户数据: %w", err)
	}
	seenIDs := make(map[string]bool, len(users))
	seenNames := make(map[string]bool, len(users))
	for _, user := range users {
		if user == nil || user.ID == "" || strings.TrimSpace(user.Username) == "" ||
			seenIDs[user.ID] || seenNames[strings.ToLower(user.Username)] ||
			(user.Role != "admin" && user.Role != "user") {
			return fmt.Errorf("用户文件包含空记录、无效角色或重复的用户 ID/用户名")
		}
		seenIDs[user.ID] = true
		seenNames[strings.ToLower(user.Username)] = true
	}
	s.users = users
	// Ensure at least one admin exists
	hasAdmin := false
	changed := false
	for _, u := range s.users {
		if u.PasswordChangedAt.IsZero() {
			u.PasswordChangedAt = u.UpdatedAt
			if u.PasswordChangedAt.IsZero() {
				u.PasswordChangedAt = u.CreatedAt
			}
			if u.PasswordChangedAt.IsZero() {
				u.PasswordChangedAt = time.Now()
			}
			changed = true
		}
		if u.Role == "admin" {
			hasAdmin = true
			if u.Password == "" {
				hash, err := auth.HashPassword("admin123")
				if err != nil {
					return fmt.Errorf("重置默认管理员密码失败: %w", err)
				}
				u.Password = string(hash)
				u.MustChangePassword = true
				u.UpdatedAt = time.Now()
				changed = true
			}
		}
		// Migrate installations that still use the published bootstrap
		// password but predate the explicit first-login flag.
		if strings.EqualFold(u.Username, "admin") && !u.MustChangePassword &&
			auth.VerifyPassword("admin123", u.Password) {
			u.MustChangePassword = true
			changed = true
		}
	}
	if !hasAdmin {
		if seenNames["admin"] {
			return fmt.Errorf("用户文件没有管理员，且 admin 用户名已被占用；请从备份恢复管理员数据")
		}
		if err := s.createDefaultAdminLocked(); err != nil {
			return err
		}
		return s.writeFileLocked()
	}
	if changed {
		return s.writeFileLocked()
	}
	return os.Chmod(s.filePath, 0600)
}

func (s *UserStore) loadSecurityPolicyLocked() error {
	data, err := os.ReadFile(s.policyPath)
	if os.IsNotExist(err) {
		s.policy = model.DefaultSecurityPolicy()
		return s.writeSecurityPolicyLocked()
	}
	if err != nil {
		return fmt.Errorf("读取安全策略: %w", err)
	}
	policy := model.DefaultSecurityPolicy()
	if err := json.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("解析安全策略: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("安全策略无效: %w", err)
	}
	s.policy = policy
	return os.Chmod(s.policyPath, 0600)
}

func (s *UserStore) SecurityPolicy() model.SecurityPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

func (s *UserStore) PublicSecurityPolicy() model.PublicSecurityPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy.PublicView()
}

func (s *UserStore) AdminSecurityPolicy() model.AdminSecurityPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy.AdminView()
}

func (s *UserStore) UpdateSecurityPolicy(policy model.SecurityPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.policy
	s.policy = policy
	if err := s.writeSecurityPolicyLocked(); err != nil {
		s.policy = previous
		return err
	}
	return nil
}

func (s *UserStore) UpdateSecurityPolicyRequest(request model.SecurityPolicyUpdateRequest) error {
	s.mu.RLock()
	currentLogin := s.policy.Login
	s.mu.RUnlock()
	login := request.Login
	// Keep PUT compatibility with clients from before login policy existed.
	if login.MaxFailures == 0 && login.LockoutMode == "" && login.LockoutMinutes == 0 && login.PasswordMaxAgeDays == 0 && login.DefaultResetPassword == "" {
		login.MaxFailures = currentLogin.MaxFailures
		login.LockoutMode = currentLogin.LockoutMode
		login.LockoutMinutes = currentLogin.LockoutMinutes
		login.PasswordMaxAgeDays = currentLogin.PasswordMaxAgeDays
	}
	policy := model.SecurityPolicy{
		Password: request.Password,
		Captcha:  request.Captcha,
		Login: model.LoginPolicy{
			MaxFailures:              login.MaxFailures,
			LockoutMode:              login.LockoutMode,
			LockoutMinutes:           login.LockoutMinutes,
			PasswordMaxAgeDays:       login.PasswordMaxAgeDays,
			DefaultResetPasswordHash: currentLogin.DefaultResetPasswordHash,
		},
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	if login.DefaultResetPassword != "" {
		if err := validatePasswordPolicy(login.DefaultResetPassword, "", policy.Password); err != nil {
			return fmt.Errorf("默认重置密码不符合密码策略: %w", err)
		}
		hash, err := auth.HashPassword(login.DefaultResetPassword)
		if err != nil {
			return fmt.Errorf("默认重置密码加密失败: %w", err)
		}
		policy.Login.DefaultResetPasswordHash = string(hash)
	}
	return s.UpdateSecurityPolicy(policy)
}

func (s *UserStore) ValidatePassword(password string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return validatePasswordPolicy(password, "", s.policy.Password)
}

func (s *UserStore) createDefaultAdminLocked() error {
	hash, err := auth.HashPassword("admin123")
	if err != nil {
		return fmt.Errorf("创建默认管理员失败: %w", err)
	}
	id, err := newUserID()
	if err != nil {
		return fmt.Errorf("创建默认管理员标识失败: %w", err)
	}
	admin := &model.User{
		ID:                 id,
		Username:           "admin",
		Password:           string(hash),
		Role:               "admin",
		MustChangePassword: true,
		PasswordChangedAt:  time.Now(),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	s.users = append(s.users, admin)
	return nil
}

// ==================== User CRUD ====================

func (s *UserStore) List() []model.UserResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.UserResponse, len(s.users))
	for i, u := range s.users {
		result[i] = u.ToResponse()
	}
	return result
}

func (s *UserStore) Get(id string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == id {
			return cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("用户 %s 不存在", id)
}

func (s *UserStore) Create(user *model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePasswordPolicy(user.Password, "", s.policy.Password); err != nil {
		return err
	}

	for _, u := range s.users {
		if strings.EqualFold(u.Username, user.Username) {
			return fmt.Errorf("用户名 %q 已存在", user.Username)
		}
	}

	hash, err := auth.HashPassword(user.Password)
	if err != nil {
		return fmt.Errorf("密码加密失败: %w", err)
	}
	user.Password = string(hash)
	user.PasswordHistory = nil
	user.MustChangePassword = true
	user.PasswordChangedAt = time.Now()
	user.LoginDisabled = false
	user.LoginDisabledAt = nil
	if user.Role == "admin" {
		user.HostIDs = nil
		user.HostGroups = nil
	}
	stored := cloneUser(user)
	s.users = append(s.users, stored)
	if err := s.writeFileLocked(); err != nil {
		s.users = s.users[:len(s.users)-1]
		return err
	}
	return nil
}

func (s *UserStore) Update(user *model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, u := range s.users {
		if u.ID == user.ID {
			for j, other := range s.users {
				if i != j && strings.EqualFold(other.Username, user.Username) {
					return fmt.Errorf("用户名 %q 已存在", user.Username)
				}
			}
			updated := cloneUser(user)
			if u.Role == "admin" && updated.Role != "admin" && s.enabledAdminsExceptLocked(u.ID) == 0 {
				return fmt.Errorf("不能降级最后一个未禁用的管理员，请先创建或解锁其他管理员")
			}
			passwordChanged := updated.Password != ""
			updated.UpdatedAt = time.Now()
			updated.CreatedAt = u.CreatedAt
			if updated.Role == "admin" {
				updated.HostIDs = nil
				updated.HostGroups = nil
			}
			if passwordChanged {
				if err := validatePasswordPolicy(updated.Password, "", s.policy.Password); err != nil {
					return err
				}
				if passwordMatchesHashes(updated.Password, passwordHashesToCheck(u.Password, u.PasswordHistory, s.policy.Password.HistoryCount)) {
					return fmt.Errorf("新密码不能与当前密码或最近使用的密码相同")
				}
				hash, err := auth.HashPassword(updated.Password)
				if err != nil {
					return fmt.Errorf("密码加密失败: %w", err)
				}
				updated.PasswordHistory = nextPasswordHistory(u.Password, u.PasswordHistory, s.policy.Password.HistoryCount)
				updated.Password = string(hash)
				updated.MustChangePassword = true
				updated.PasswordChangedAt = time.Now()
				updated.LoginDisabled = false
				updated.LoginDisabledAt = nil
			} else {
				updated.Password = u.Password
				updated.PasswordHistory = append([]string(nil), u.PasswordHistory...)
				updated.MustChangePassword = u.MustChangePassword
				updated.PasswordChangedAt = u.PasswordChangedAt
				updated.LoginDisabled = u.LoginDisabled
				updated.LoginDisabledAt = cloneTime(u.LoginDisabledAt)
			}
			s.users[i] = updated
			if err := s.writeFileLocked(); err != nil {
				s.users[i] = u
				return err
			}
			if passwordChanged {
				s.deleteSessionsForUserLocked(user.ID)
			}
			return nil
		}
	}
	return fmt.Errorf("用户 %s 不存在", user.ID)
}

func (s *UserStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, u := range s.users {
		if u.ID == id {
			if u.Role == "admin" && s.enabledAdminsExceptLocked(id) == 0 {
				return fmt.Errorf("不能删除最后一个未禁用的管理员，请先创建或解锁其他管理员")
			}
			original := append([]*model.User(nil), s.users...)
			s.users = append(s.users[:i], s.users[i+1:]...)
			if err := s.writeFileLocked(); err != nil {
				s.users = original
				return err
			}
			s.deleteSessionsForUserLocked(id)
			return nil
		}
	}
	return fmt.Errorf("用户 %s 不存在", id)
}

// Caller must hold s.mu. Timed locks expire; only persistent account disabling
// removes an administrator from the recovery paths counted here.
func (s *UserStore) enabledAdminsExceptLocked(excludeID string) int {
	count := 0
	for _, user := range s.users {
		if user.ID != excludeID && user.Role == "admin" && !user.LoginDisabled {
			count++
		}
	}
	return count
}

// ResetAccount restores an ordinary user to the administrator-configured
// default password, clears account lockout state, revokes active sessions and
// requires a password change at the next login.
func (s *UserStore) ResetAccount(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policy.Login.DefaultResetPasswordHash == "" {
		return fmt.Errorf("尚未配置账户重置默认密码")
	}
	for i, user := range s.users {
		if user.ID != id {
			continue
		}
		if user.Role != "user" {
			return fmt.Errorf("只能重置普通用户账户")
		}
		previous := cloneUser(user)
		updated := cloneUser(user)
		updated.PasswordHistory = nextPasswordHistory(user.Password, user.PasswordHistory, s.policy.Password.HistoryCount)
		updated.Password = s.policy.Login.DefaultResetPasswordHash
		updated.MustChangePassword = true
		updated.PasswordChangedAt = time.Now()
		updated.LoginDisabled = false
		updated.LoginDisabledAt = nil
		updated.UpdatedAt = time.Now()
		s.users[i] = updated
		if err := s.writeFileLocked(); err != nil {
			s.users[i] = previous
			return err
		}
		delete(s.loginAttempts, loginAttemptKey(user.Username, ""))
		s.deleteSessionsForUserLocked(user.ID)
		return nil
	}
	return fmt.Errorf("用户 %s 不存在", id)
}

// UnlockAccount clears a persistent administrator lock without changing the
// password. ResetAccount remains the separate default-password workflow for
// ordinary users.
func (s *UserStore) UnlockAccount(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, user := range s.users {
		if user.ID != id {
			continue
		}
		if !user.LoginDisabled {
			delete(s.loginAttempts, loginAttemptKey(user.Username, ""))
			return nil
		}
		previous := cloneUser(user)
		updated := cloneUser(user)
		updated.LoginDisabled = false
		updated.LoginDisabledAt = nil
		updated.UpdatedAt = time.Now()
		s.users[i] = updated
		if err := s.writeFileLocked(); err != nil {
			s.users[i] = previous
			return err
		}
		delete(s.loginAttempts, loginAttemptKey(user.Username, ""))
		return nil
	}
	return fmt.Errorf("用户 %s 不存在", id)
}

func (s *UserStore) ChangePassword(id, oldPassword, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.ID == id {
			if !auth.VerifyPassword(oldPassword, u.Password) {
				return fmt.Errorf("原密码不正确")
			}
			if err := validatePasswordPolicy(newPassword, oldPassword, s.policy.Password); err != nil {
				return err
			}
			if passwordMatchesHashes(newPassword, passwordHashesToCheck(u.Password, u.PasswordHistory, s.policy.Password.HistoryCount)) {
				return fmt.Errorf("新密码不能与当前密码或最近使用的密码相同")
			}
			hash, err := auth.HashPassword(newPassword)
			if err != nil {
				return fmt.Errorf("密码加密失败: %w", err)
			}
			oldPasswordHash := u.Password
			oldPasswordHistory := append([]string(nil), u.PasswordHistory...)
			oldUpdatedAt := u.UpdatedAt
			oldMustChangePassword := u.MustChangePassword
			oldPasswordChangedAt := u.PasswordChangedAt
			oldLoginDisabled := u.LoginDisabled
			oldLoginDisabledAt := cloneTime(u.LoginDisabledAt)
			u.PasswordHistory = nextPasswordHistory(u.Password, u.PasswordHistory, s.policy.Password.HistoryCount)
			u.Password = string(hash)
			u.MustChangePassword = false
			u.PasswordChangedAt = time.Now()
			u.LoginDisabled = false
			u.LoginDisabledAt = nil
			u.UpdatedAt = time.Now()
			if err := s.writeFileLocked(); err != nil {
				u.Password = oldPasswordHash
				u.PasswordHistory = oldPasswordHistory
				u.UpdatedAt = oldUpdatedAt
				u.MustChangePassword = oldMustChangePassword
				u.PasswordChangedAt = oldPasswordChangedAt
				u.LoginDisabled = oldLoginDisabled
				u.LoginDisabledAt = oldLoginDisabledAt
				return err
			}
			s.deleteSessionsForUserLocked(id)
			return nil
		}
	}
	return fmt.Errorf("用户 %s 不存在", id)
}

// ==================== Auth / Sessions ====================

func (s *UserStore) Login(username, password string) (*model.LoginResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if strings.EqualFold(u.Username, username) {
			if u.LoginDisabled {
				return nil, fmt.Errorf("账户已被管理员锁定")
			}
			if !auth.VerifyPassword(password, u.Password) {
				return nil, fmt.Errorf("用户名或密码错误")
			}
			if auth.NeedsRehash(u.Password) {
				oldPassword := u.Password
				oldUpdatedAt := u.UpdatedAt
				hash, err := auth.HashPassword(password)
				if err != nil {
					return nil, fmt.Errorf("密码加密失败: %w", err)
				}
				u.Password = hash
				u.UpdatedAt = time.Now()
				if err := s.writeFileLocked(); err != nil {
					u.Password = oldPassword
					u.UpdatedAt = oldUpdatedAt
					return nil, fmt.Errorf("更新密码哈希失败: %w", err)
				}
			}
			token, err := generateToken()
			if err != nil {
				return nil, fmt.Errorf("生成登录会话失败: %w", err)
			}
			s.sessions[token] = &Session{
				UserID:             u.ID,
				Username:           u.Username,
				Role:               u.Role,
				HostIDs:            append([]string(nil), u.HostIDs...),
				HostGroups:         append([]string(nil), u.HostGroups...),
				MustChangePassword: s.passwordChangeRequiredLocked(u, time.Now()),
				ExpiresAt:          time.Now().Add(24 * time.Hour),
			}
			return &model.LoginResponse{
				Token:                  token,
				Username:               u.Username,
				Role:                   u.Role,
				HostIDs:                append([]string(nil), u.HostIDs...),
				HostGroups:             append([]string(nil), u.HostGroups...),
				RequiresPasswordChange: s.passwordChangeRequiredLocked(u, time.Now()),
			}, nil
		}
	}
	return nil, fmt.Errorf("用户名或密码错误")
}

func (s *UserStore) passwordChangeRequiredLocked(user *model.User, now time.Time) bool {
	if user.MustChangePassword {
		return true
	}
	days := s.policy.Login.PasswordMaxAgeDays
	if days <= 0 || user.PasswordChangedAt.IsZero() {
		return false
	}
	return !now.Before(user.PasswordChangedAt.Add(time.Duration(days) * 24 * time.Hour))
}

func (s *UserStore) Logout(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *UserStore) ValidateSession(token string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[token]
	if !ok {
		return nil, fmt.Errorf("未登录或会话已过期")
	}
	if time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, token)
		return nil, fmt.Errorf("会话已过期，请重新登录")
	}
	for _, user := range s.users {
		if user.ID == sess.UserID {
			sess.Username = user.Username
			sess.Role = user.Role
			sess.HostIDs = append(sess.HostIDs[:0], user.HostIDs...)
			sess.HostGroups = append(sess.HostGroups[:0], user.HostGroups...)
			if user.LoginDisabled {
				delete(s.sessions, token)
				return nil, fmt.Errorf("账户已被管理员锁定")
			}
			sess.MustChangePassword = s.passwordChangeRequiredLocked(user, time.Now())
			copy := *sess
			return &copy, nil
		}
	}
	delete(s.sessions, token)
	return nil, fmt.Errorf("用户不存在或会话已撤销")
}

func (s *UserStore) CleanupExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, sess := range s.sessions {
		if time.Now().After(sess.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

// ==================== CAPTCHA ====================

func (s *UserStore) NewCaptcha() (id string, display string, caseSensitive bool, err error) {
	q, err := auth.GenerateCaptchaQuestion()
	if err != nil {
		return "", "", false, err
	}
	token, err := generateToken()
	if err != nil {
		return "", "", false, fmt.Errorf("生成验证码标识失败: %w", err)
	}
	id = token[:16]
	s.mu.Lock()
	caseSensitive = s.policy.Captcha.CaseSensitive
	s.captchas[id] = &CaptchaEntry{Answer: q.Answer, Display: q.Display, CaseSensitive: caseSensitive, ExpiresAt: time.Now().Add(captchaTTL)}
	s.mu.Unlock()
	return id, q.Display, caseSensitive, nil
}

func (s *UserStore) ValidateCaptcha(id string, answer string) bool {
	s.mu.RLock()
	entry, ok := s.captchas[id]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(entry.ExpiresAt) {
		s.mu.Lock()
		delete(s.captchas, id)
		s.mu.Unlock()
		return false
	}
	normalized := strings.ReplaceAll(strings.TrimSpace(answer), " ", "")
	if entry.CaseSensitive {
		return entry.Answer == normalized
	}
	return strings.EqualFold(entry.Answer, normalized)
}

// ValidateAndConsumeCaptcha atomically removes and checks a challenge. Every
// attempted answer consumes the challenge, including an incorrect answer.
func (s *UserStore) ValidateAndConsumeCaptcha(id string, answer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.captchas[id]
	if !ok {
		return false
	}
	delete(s.captchas, id)
	if time.Now().After(entry.ExpiresAt) {
		return false
	}
	normalized := strings.ReplaceAll(strings.TrimSpace(answer), " ", "")
	if entry.CaseSensitive {
		return entry.Answer == normalized
	}
	return strings.EqualFold(entry.Answer, normalized)
}

// ConsumeCaptcha removes a captcha after successful use.
func (s *UserStore) ConsumeCaptcha(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.captchas, id)
}

// ==================== Login Lockout ====================

// CheckLoginLocked returns an error if the account is locked.
func (s *UserStore) CheckLoginLocked(username, sourceIP string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if strings.EqualFold(user.Username, username) && user.LoginDisabled {
			return fmt.Errorf("账户已被管理员锁定，请联系管理员重置账户")
		}
	}

	att, ok := s.loginAttempts[loginAttemptKey(username, sourceIP)]
	if !ok {
		return nil
	}
	if !att.LockedUntil.IsZero() && time.Now().Before(att.LockedUntil) {
		remaining := att.LockedUntil.Sub(time.Now())
		minutes := int(remaining.Minutes()) + 1
		return fmt.Errorf("账户已被锁定，请 %d 分钟后再试", minutes)
	}
	return nil
}

// RecordLoginFailure increments the failure counter and locks if threshold reached.
func (s *UserStore) RecordLoginFailure(username, sourceIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := loginAttemptKey(username, sourceIP)
	att, ok := s.loginAttempts[key]
	if !ok || (!att.LockedUntil.IsZero() && time.Now().After(att.LockedUntil)) {
		// Reset if lock has expired naturally
		att = &LoginAttempt{}
		s.loginAttempts[key] = att
	}
	att.Failures++
	if att.Failures < s.policy.Login.MaxFailures {
		return nil
	}
	if s.policy.Login.LockoutMode == model.LockoutModeTimed {
		att.LockedUntil = time.Now().Add(time.Duration(s.policy.Login.LockoutMinutes) * time.Minute)
		return nil
	}
	for _, user := range s.users {
		if !strings.EqualFold(user.Username, username) {
			continue
		}
		// Preserve a recovery path: administrator mode may persistently lock an
		// admin only while another enabled admin remains. The last enabled admin
		// receives the configured timed lock instead.
		if user.Role == "admin" {
			if s.enabledAdminsExceptLocked(user.ID) == 0 {
				att.LockedUntil = time.Now().Add(time.Duration(s.policy.Login.LockoutMinutes) * time.Minute)
				return nil
			}
		}
		previousDisabled := user.LoginDisabled
		previousDisabledAt := cloneTime(user.LoginDisabledAt)
		now := time.Now()
		user.LoginDisabled = true
		user.LoginDisabledAt = &now
		if err := s.writeFileLocked(); err != nil {
			user.LoginDisabled = previousDisabled
			user.LoginDisabledAt = previousDisabledAt
			return err
		}
		s.deleteSessionsForUserLocked(user.ID)
		break
	}
	return nil
}

// RecordLoginSuccess resets the failure counter on successful login.
func (s *UserStore) RecordLoginSuccess(username, sourceIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.loginAttempts, loginAttemptKey(username, sourceIP))
}

func loginAttemptKey(username, sourceIP string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// CleanupExpiredCaptchas removes expired captcha entries; call periodically.
func (s *UserStore) CleanupExpiredCaptchas() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, entry := range s.captchas {
		if time.Now().After(entry.ExpiresAt) {
			delete(s.captchas, id)
		}
	}
}

// writeFileLocked writes users to disk; caller must hold s.mu write lock.
func (s *UserStore) writeFileLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(s.filePath, data, 0600)
}

func (s *UserStore) writeSecurityPolicyLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.policyPath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.policy, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(s.policyPath, data, 0600)
}

func (s *UserStore) deleteSessionsForUserLocked(userID string) {
	for token, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, token)
		}
	}
}

func cloneUser(user *model.User) *model.User {
	if user == nil {
		return nil
	}
	copy := *user
	copy.HostIDs = append([]string(nil), user.HostIDs...)
	copy.HostGroups = append([]string(nil), user.HostGroups...)
	copy.PasswordHistory = append([]string(nil), user.PasswordHistory...)
	copy.LoginDisabledAt = cloneTime(user.LoginDisabledAt)
	return &copy
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func validatePasswordPolicy(password, previous string, policy model.PasswordPolicy) error {
	if !utf8.ValidString(password) {
		return fmt.Errorf("密码必须是有效的 UTF-8 文本")
	}
	runes := []rune(password)
	if len(runes) < policy.MinLength {
		return fmt.Errorf("密码长度至少 %d 个字符", policy.MinLength)
	}
	if len(runes) > 128 {
		return fmt.Errorf("密码长度不能超过 128 个字符")
	}
	var uppercase, lowercase, digits, special int
	for _, value := range runes {
		switch {
		case unicode.IsUpper(value):
			uppercase++
		case unicode.IsLower(value):
			lowercase++
		case unicode.IsDigit(value):
			digits++
		default:
			special++
		}
	}
	if uppercase < policy.MinUppercase {
		return fmt.Errorf("密码至少包含 %d 个大写字母", policy.MinUppercase)
	}
	if lowercase < policy.MinLowercase {
		return fmt.Errorf("密码至少包含 %d 个小写字母", policy.MinLowercase)
	}
	if digits < policy.MinDigits {
		return fmt.Errorf("密码至少包含 %d 个数字", policy.MinDigits)
	}
	if special < policy.MinSpecial {
		return fmt.Errorf("密码至少包含 %d 个特殊字符", policy.MinSpecial)
	}
	if previous != "" && changedCharacterCount(previous, password) < policy.MinChangedCharacters {
		return fmt.Errorf("新密码与当前密码至少需要有 %d 个字符位置不同", policy.MinChangedCharacters)
	}
	return nil
}

func changedCharacterCount(previous, next string) int {
	oldRunes := []rune(previous)
	newRunes := []rune(next)
	length := len(oldRunes)
	if len(newRunes) > length {
		length = len(newRunes)
	}
	changed := 0
	for i := 0; i < length; i++ {
		if i >= len(oldRunes) || i >= len(newRunes) || oldRunes[i] != newRunes[i] {
			changed++
		}
	}
	return changed
}

func passwordMatchesHashes(password string, hashes []string) bool {
	for _, hash := range hashes {
		if hash != "" && auth.VerifyPassword(password, hash) {
			return true
		}
	}
	return false
}

func nextPasswordHistory(current string, existing []string, limit int) []string {
	if limit <= 1 {
		return nil
	}
	history := append([]string{current}, existing...)
	if len(history) > limit-1 {
		history = history[:limit-1]
	}
	return history
}

func passwordHashesToCheck(current string, existing []string, limit int) []string {
	hashes := []string{current}
	if limit <= 1 {
		return hashes
	}
	count := limit - 1
	if len(existing) < count {
		count = len(existing)
	}
	return append(hashes, existing[:count]...)
}

// RemoveHostAssignment removes a deleted host from every ordinary user's
// authorization scope. Stale host IDs would be harmless, but pruning them
// keeps the persisted permission model explainable and prevents accidental
// reuse if an ID is ever restored from backup.
func (s *UserStore) RemoveHostAssignment(hostID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	original := make([]*model.User, len(s.users))
	for i, user := range s.users {
		original[i] = cloneUser(user)
	}
	changed := false
	for _, user := range s.users {
		filtered := user.HostIDs[:0]
		for _, id := range user.HostIDs {
			if id == hostID {
				changed = true
				continue
			}
			filtered = append(filtered, id)
		}
		user.HostIDs = filtered
	}
	if !changed {
		return nil
	}
	if err := s.writeFileLocked(); err != nil {
		s.users = original
		return err
	}
	return nil
}

func newUserID() (string, error) {
	return randomHex(8)
}

func generateToken() (string, error) {
	return randomHex(32)
}

func randomHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
