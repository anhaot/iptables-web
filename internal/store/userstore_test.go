package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"iptables-web/internal/auth"
	"iptables-web/internal/model"
)

func TestUserStorePersistsPasswordHash(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "users.json")
	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	reloaded := NewUserStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload Load() error = %v", err)
	}
	login, err := reloaded.Login("admin", "admin123")
	if err != nil {
		t.Fatalf("Login(admin) after reload error = %v", err)
	}
	if !login.RequiresPasswordChange {
		t.Fatal("bootstrap admin login did not require a password change")
	}
}

func TestUserStoreRefreshesAndRevokesExistingSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	user := &model.User{ID: "operator-id", Username: "operator", Password: "secret123", Role: "user", CreatedAt: time.Now()}
	if err := s.Create(user); err != nil {
		t.Fatal(err)
	}
	login, err := s.Login("operator", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := s.Get(user.ID)
	stored.Role = "admin"
	stored.Password = ""
	if err := s.Update(stored); err != nil {
		t.Fatal(err)
	}
	session, err := s.ValidateSession(login.Token)
	if err != nil || session.Role != "admin" {
		t.Fatalf("session after role update = %#v, %v", session, err)
	}
	if err := s.Delete(user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateSession(login.Token); err == nil {
		t.Fatal("deleted user's session remained valid")
	}
}

func TestUserStoreRequiresAndCompletesFirstLoginPasswordChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}

	login, err := s.Login("admin", "admin123")
	if err != nil {
		t.Fatal(err)
	}
	if !login.RequiresPasswordChange {
		t.Fatal("default administrator was not marked for password change")
	}
	session, err := s.ValidateSession(login.Token)
	if err != nil || !session.MustChangePassword {
		t.Fatalf("bootstrap session = %#v, %v", session, err)
	}
	admin := s.List()[0]
	if err := s.ChangePassword(admin.ID, "admin123", "new-secret-123"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateSession(login.Token); err == nil {
		t.Fatal("password change did not revoke the bootstrap session")
	}
	newLogin, err := s.Login("admin", "new-secret-123")
	if err != nil {
		t.Fatal(err)
	}
	if newLogin.RequiresPasswordChange {
		t.Fatal("password-change requirement remained after changing password")
	}
}

func TestUserStoreRejectsReusingBootstrapPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	admin := s.List()[0]
	if err := s.ChangePassword(admin.ID, "admin123", "admin123"); err == nil {
		t.Fatal("ChangePassword accepted the existing bootstrap password")
	}
}

func TestUserStoreRollsBackMemoryWhenPersistenceFails(t *testing.T) {
	s := NewUserStore(filepath.Join("/proc", "iptables-web-review", "users.json"))
	user := &model.User{ID: "not-persisted", Username: "operator", Password: "secret123", Role: "user"}
	if err := s.Create(user); err == nil {
		t.Fatal("Create() unexpectedly succeeded")
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("failed create remained in memory: %#v", got)
	}
}

func TestUserStoreUsesPrivateFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("users.json mode = %o, want 600", got)
	}
}

func TestUserStoreRepairsLegacyAdminWithoutPassword(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "users.json")
	legacy := `[{"id":"legacy-admin","username":"admin","role":"admin","created_at":"2026-05-27T00:00:00Z","updated_at":"2026-05-27T00:00:00Z"}]`
	if err := os.WriteFile(path, []byte(legacy), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, err := s.Login("admin", "admin123"); err != nil {
		t.Fatalf("Login(admin) after legacy repair error = %v", err)
	}
}

func TestUserResponseDoesNotExposePassword(t *testing.T) {
	t.Parallel()

	hash, err := auth.HashPassword("secret123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user := model.User{Username: "admin", Password: hash, Role: "admin"}
	resp := user.ToResponse()
	if resp.Username != "admin" || resp.Role != "admin" || resp.MustChangePassword {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestUserStoreValidatesLetterCaptchaCaseInsensitively(t *testing.T) {
	t.Parallel()

	s := NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	id, _ := s.NewCaptcha()
	answer := s.captchas[id].Answer

	if !s.ValidateCaptcha(id, strings.ToLower(answer)) {
		t.Fatal("ValidateCaptcha() rejected a case-insensitive answer")
	}
}
