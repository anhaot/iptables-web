package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"iptables-web/internal/auth"
	"iptables-web/internal/model"
)

// UserStore persists and manages users and active sessions.
type UserStore struct {
	mu            sync.RWMutex
	filePath      string
	users         []*model.User
	sessions      map[string]*Session      // token -> session
	captchas      map[string]*CaptchaEntry // captcha ID -> code
	loginAttempts map[string]*LoginAttempt // username -> attempt tracking
}

type Session struct {
	UserID    string
	Username  string
	Role      string
	ExpiresAt time.Time
}

type CaptchaEntry struct {
	Answer    string
	Display   string
	ExpiresAt time.Time
}

type LoginAttempt struct {
	Failures    int
	LockedUntil time.Time
}

const (
	maxLoginFailures = 5
	lockoutDuration  = 15 * time.Minute
	captchaTTL       = 5 * time.Minute
)

func NewUserStore(filePath string) *UserStore {
	return &UserStore{
		filePath:      filePath,
		sessions:      make(map[string]*Session),
		captchas:      make(map[string]*CaptchaEntry),
		loginAttempts: make(map[string]*LoginAttempt),
	}
}

func (s *UserStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	if err := json.Unmarshal(data, &s.users); err != nil {
		return fmt.Errorf("解析用户数据: %w", err)
	}
	// Ensure at least one admin exists
	hasAdmin := false
	changed := false
	for _, u := range s.users {
		if u.Role == "admin" {
			hasAdmin = true
			if u.Password == "" {
				hash, err := auth.HashPassword("admin123")
				if err != nil {
					return fmt.Errorf("重置默认管理员密码失败: %w", err)
				}
				u.Password = string(hash)
				u.UpdatedAt = time.Now()
				changed = true
			}
		}
	}
	if !hasAdmin {
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

func (s *UserStore) createDefaultAdminLocked() error {
	hash, err := auth.HashPassword("admin123")
	if err != nil {
		return fmt.Errorf("创建默认管理员失败: %w", err)
	}
	admin := &model.User{
		ID:        newUserID(),
		Username:  "admin",
		Password:  string(hash),
		Role:      "admin",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
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
			passwordChanged := updated.Password != ""
			updated.UpdatedAt = time.Now()
			updated.CreatedAt = u.CreatedAt
			if passwordChanged {
				hash, err := auth.HashPassword(updated.Password)
				if err != nil {
					return fmt.Errorf("密码加密失败: %w", err)
				}
				updated.Password = string(hash)
			} else {
				updated.Password = u.Password
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

	adminCount := 0
	targetIsAdmin := false
	for _, u := range s.users {
		if u.Role == "admin" {
			adminCount++
			if u.ID == id {
				targetIsAdmin = true
			}
		}
	}
	if targetIsAdmin && adminCount <= 1 {
		return fmt.Errorf("不能删除最后一个管理员")
	}

	for i, u := range s.users {
		if u.ID == id {
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

func (s *UserStore) ChangePassword(id, oldPassword, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.ID == id {
			if !auth.VerifyPassword(oldPassword, u.Password) {
				return fmt.Errorf("原密码不正确")
			}
			if len(newPassword) < 6 {
				return fmt.Errorf("新密码长度至少 6 个字符")
			}
			hash, err := auth.HashPassword(newPassword)
			if err != nil {
				return fmt.Errorf("密码加密失败: %w", err)
			}
			oldPassword := u.Password
			oldUpdatedAt := u.UpdatedAt
			u.Password = string(hash)
			u.UpdatedAt = time.Now()
			if err := s.writeFileLocked(); err != nil {
				u.Password = oldPassword
				u.UpdatedAt = oldUpdatedAt
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
			token := generateToken()
			s.sessions[token] = &Session{
				UserID:    u.ID,
				Username:  u.Username,
				Role:      u.Role,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}
			return &model.LoginResponse{
				Token:    token,
				Username: u.Username,
				Role:     u.Role,
			}, nil
		}
	}
	return nil, fmt.Errorf("用户名或密码错误")
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

func (s *UserStore) NewCaptcha() (id string, display string) {
	q := auth.GenerateCaptchaQuestion()
	id = generateToken()[:16]
	s.mu.Lock()
	s.captchas[id] = &CaptchaEntry{Answer: q.Answer, Display: q.Display, ExpiresAt: time.Now().Add(captchaTTL)}
	s.mu.Unlock()
	return id, q.Display
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
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(answer), " ", ""))
	return entry.Answer == normalized
}

// ConsumeCaptcha removes a captcha after successful use.
func (s *UserStore) ConsumeCaptcha(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.captchas, id)
}

// ==================== Login Lockout ====================

// CheckLoginLocked returns an error if the account is locked.
// DEBUG
func (s *UserStore) CheckLoginLocked(username, sourceIP string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

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
func (s *UserStore) RecordLoginFailure(username, sourceIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := loginAttemptKey(username, sourceIP)
	att, ok := s.loginAttempts[key]
	if !ok || (!att.LockedUntil.IsZero() && time.Now().After(att.LockedUntil)) {
		// Reset if lock has expired naturally
		att = &LoginAttempt{}
		s.loginAttempts[key] = att
	} else if !ok {
		att = &LoginAttempt{}
		s.loginAttempts[key] = att
	}
	att.Failures++
	if att.Failures >= maxLoginFailures {
		att.LockedUntil = time.Now().Add(lockoutDuration)
	}
}

// RecordLoginSuccess resets the failure counter on successful login.
func (s *UserStore) RecordLoginSuccess(username, sourceIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.loginAttempts, loginAttemptKey(username, sourceIP))
}

func loginAttemptKey(username, sourceIP string) string {
	return strings.ToLower(strings.TrimSpace(username)) + "\x00" + strings.TrimSpace(sourceIP)
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
	return &copy
}

func newUserID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
