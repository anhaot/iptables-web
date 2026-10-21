package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"iptables-web/internal/auth"
	"iptables-web/internal/model"
)

func TestUserStorePreservesEnabledAdministrator(t *testing.T) {
	for _, operation := range []string{"demote", "delete"} {
		for _, backup := range []string{"none", "disabled", "enabled"} {
			t.Run(operation+"/"+backup, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "users.json")
				s := NewUserStore(path)
				s.users = []*model.User{{ID: "primary", Username: "primary", Password: "unchanged-hash", Role: "admin"}}
				if backup != "none" {
					s.users = append(s.users, &model.User{ID: "backup", Username: "backup", Password: "unchanged-hash", Role: "admin", LoginDisabled: backup == "disabled"})
				}
				if err := s.writeFileLocked(); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var updateErr error
				if operation == "delete" {
					updateErr = s.Delete("primary")
				} else {
					updateErr = s.Update(&model.User{ID: "primary", Username: "primary", Role: "user"})
				}
				if backup == "enabled" {
					if updateErr != nil {
						t.Fatal(updateErr)
					}
				} else {
					if updateErr == nil {
						t.Fatal("last enabled admin could be removed")
					}
					after, err := os.ReadFile(path)
					if err != nil || string(after) != string(before) {
						t.Fatalf("rejected change modified disk: %v", err)
					}
					user, err := s.Get("primary")
					if err != nil || user.Role != "admin" {
						t.Fatalf("rejected change modified memory: %v", err)
					}
				}
			})
		}
	}
}

func TestConcurrentAdminDemotionsLeaveOneAdministrator(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	s.users = []*model.User{{ID: "one", Username: "admin-one", Role: "admin"}, {ID: "two", Username: "admin-two", Role: "admin"}}
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for _, id := range []string{"one", "two"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			errors <- s.Update(&model.User{ID: id, Username: "admin-" + id, Role: "user"})
		}(id)
	}
	wg.Wait()
	close(errors)
	failed := 0
	for err := range errors {
		if err != nil {
			failed++
		}
	}
	admins := 0
	for _, user := range s.List() {
		if user.Role == "admin" && !user.LoginDisabled {
			admins++
		}
	}
	if failed != 1 || admins != 1 {
		t.Fatalf("errors=%d enabled admins=%d; want 1 each", failed, admins)
	}
}

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

func TestUserStoreRefreshesHostAssignmentsInExistingSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	user := &model.User{ID: "operator-hosts", Username: "operator2", Password: "secret123", Role: "user", HostIDs: []string{"00112233445566778899aabb"}, HostGroups: []string{"production"}, CreatedAt: time.Now()}
	if err := s.Create(user); err != nil {
		t.Fatal(err)
	}
	login, err := s.Login("operator2", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := s.Get(user.ID)
	stored.HostIDs = []string{"ffeeddccbbaa998877665544"}
	stored.HostGroups = []string{"staging"}
	stored.Password = ""
	if err := s.Update(stored); err != nil {
		t.Fatal(err)
	}
	session, err := s.ValidateSession(login.Token)
	if err != nil || len(session.HostIDs) != 1 || session.HostIDs[0] != "ffeeddccbbaa998877665544" || len(session.HostGroups) != 1 || session.HostGroups[0] != "staging" {
		t.Fatalf("session assignments were stale: %#v, %v", session, err)
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

func TestUserStoreCaptchaCaseSensitivityFollowsPolicy(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	id, _, sensitive, err := s.NewCaptcha()
	if err != nil {
		t.Fatal(err)
	}
	if sensitive {
		t.Fatal("default CAPTCHA policy must be case-insensitive")
	}
	answer := s.captchas[id].Answer
	swapped := swapCaptchaCase(answer)
	if !s.ValidateCaptcha(id, swapped) {
		t.Fatal("ValidateCaptcha() rejected different case under the default policy")
	}

	policy := s.SecurityPolicy()
	policy.Captcha.CaseSensitive = true
	if err := s.UpdateSecurityPolicy(policy); err != nil {
		t.Fatal(err)
	}
	id, _, sensitive, err = s.NewCaptcha()
	if err != nil {
		t.Fatal(err)
	}
	if !sensitive {
		t.Fatal("CAPTCHA did not adopt the case-sensitive policy")
	}
	answer = s.captchas[id].Answer
	if swapped := swapCaptchaCase(answer); swapped != answer && s.ValidateCaptcha(id, swapped) {
		t.Fatal("ValidateCaptcha() accepted different case under a case-sensitive policy")
	}
}

func TestUserStoreCaptchaIsConsumedAtomically(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := s.NewCaptcha()
	if err != nil {
		t.Fatal(err)
	}
	answer := s.captchas[id].Answer
	if !s.ValidateAndConsumeCaptcha(id, answer) {
		t.Fatal("first CAPTCHA validation failed")
	}
	if s.ValidateAndConsumeCaptcha(id, answer) {
		t.Fatal("consumed CAPTCHA was accepted a second time")
	}

	id, _, _, err = s.NewCaptcha()
	if err != nil {
		t.Fatal(err)
	}
	answer = s.captchas[id].Answer
	if s.ValidateAndConsumeCaptcha(id, answer+"wrong") {
		t.Fatal("incorrect CAPTCHA answer was accepted")
	}
	if s.ValidateAndConsumeCaptcha(id, answer) {
		t.Fatal("incorrect attempt did not consume CAPTCHA")
	}
}

func TestUserStorePersistsAndEnforcesPasswordPolicyAndHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	policy := s.SecurityPolicy()
	policy.Password.MinLength = 10
	policy.Password.MinUppercase = 1
	policy.Password.MinLowercase = 1
	policy.Password.MinDigits = 1
	policy.Password.MinSpecial = 1
	policy.Password.HistoryCount = 3
	policy.Password.MinChangedCharacters = 4
	policy.Captcha.CaseSensitive = true
	if err := s.UpdateSecurityPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidatePassword("weak-pass1"); err == nil {
		t.Fatal("policy accepted a password without an uppercase letter")
	}
	admin := s.List()[0]
	if err := s.ChangePassword(admin.ID, "admin123", "Strong!234"); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(admin.ID, "Strong!234", "Other#5678"); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(admin.ID, "Other#5678", "Strong!234"); err == nil {
		t.Fatal("password history allowed reuse")
	}

	reloaded := NewUserStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.SecurityPolicy(); got.Password.MinLength != 10 || !got.Captcha.CaseSensitive {
		t.Fatalf("reloaded policy = %#v", got)
	}
}

func TestUserStoreDefaultPasswordPolicyHasNoExtraComplexityRequirements(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	policy := s.SecurityPolicy().Password
	if policy.MinLength != 1 || policy.MinUppercase != 0 || policy.MinLowercase != 0 || policy.MinDigits != 0 || policy.MinSpecial != 0 || policy.HistoryCount != 0 || policy.MinChangedCharacters != 0 {
		t.Fatalf("unexpected default password policy: %#v", policy)
	}
	if err := s.ValidatePassword("x"); err != nil {
		t.Fatalf("default policy rejected a non-empty password: %v", err)
	}
	if err := s.ValidatePassword(""); err == nil {
		t.Fatal("default policy accepted an empty password")
	}
}

func TestUserStoreTimedLoginLockoutUsesConfiguredThreshold(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	policy := s.SecurityPolicy()
	policy.Login.MaxFailures = 2
	policy.Login.LockoutMode = model.LockoutModeTimed
	policy.Login.LockoutMinutes = 7
	if err := s.UpdateSecurityPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordLoginFailure("admin", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckLoginLocked("admin", "198.51.100.1"); err != nil {
		t.Fatalf("account locked before threshold: %v", err)
	}
	if err := s.RecordLoginFailure("admin", "198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckLoginLocked("admin", "203.0.113.2"); err == nil || !strings.Contains(err.Error(), "7 分钟") {
		t.Fatalf("configured lockout not enforced: %v", err)
	}
}

func TestUserStoreAdministratorLockoutAndDefaultPasswordReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	request := model.SecurityPolicyUpdateRequest{
		Password: s.SecurityPolicy().Password,
		Captcha:  s.SecurityPolicy().Captcha,
		Login: model.LoginPolicyUpdateRequest{
			MaxFailures:          2,
			LockoutMode:          model.LockoutModeAdministrator,
			LockoutMinutes:       15,
			PasswordMaxAgeDays:   90,
			DefaultResetPassword: "Default123",
		},
	}
	if err := s.UpdateSecurityPolicyRequest(request); err != nil {
		t.Fatal(err)
	}
	user := &model.User{ID: "reset-user", Username: "operator", Password: "secret123", Role: "user", CreatedAt: time.Now()}
	if err := s.Create(user); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordLoginFailure("operator", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordLoginFailure("operator", "192.0.2.11"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login("operator", "secret123"); err == nil || !strings.Contains(err.Error(), "锁定") {
		t.Fatalf("disabled account login error = %v", err)
	}
	if err := s.ResetAccount(user.ID); err != nil {
		t.Fatal(err)
	}
	login, err := s.Login("operator", "Default123")
	if err != nil {
		t.Fatal(err)
	}
	if !login.RequiresPasswordChange {
		t.Fatal("reset account did not require a password change")
	}
	reloaded := NewUserStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if reloaded.SecurityPolicy().Login.DefaultResetPasswordHash == "" {
		t.Fatal("default reset password hash was not persisted")
	}
}

func TestUserStoreAdministratorUnlockAndLastAdminRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s := NewUserStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	policy := s.SecurityPolicy()
	policy.Login.MaxFailures = 2
	policy.Login.LockoutMode = model.LockoutModeAdministrator
	policy.Login.LockoutMinutes = 9
	if err := s.UpdateSecurityPolicy(policy); err != nil {
		t.Fatal(err)
	}
	second := &model.User{ID: "backup-admin", Username: "backup-admin", Password: "Backup123", Role: "admin", CreatedAt: time.Now()}
	if err := s.Create(second); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.RecordLoginFailure("admin", "192.0.2.10"); err != nil {
			t.Fatal(err)
		}
	}
	admin := s.List()[0]
	if !admin.LoginDisabled {
		t.Fatal("administrator was not persistently locked while a backup admin existed")
	}
	if err := s.UnlockAccount(admin.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(admin.ID); err != nil || got.LoginDisabled {
		t.Fatalf("administrator was not unlocked: user=%#v err=%v", got, err)
	}
	if err := s.Delete(second.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.RecordLoginFailure("admin", "198.51.100.1"); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.Get(admin.ID); err != nil || got.LoginDisabled {
		t.Fatalf("last admin was persistently disabled: user=%#v err=%v", got, err)
	}
	if err := s.CheckLoginLocked("admin", "203.0.113.1"); err == nil || !strings.Contains(err.Error(), "9 分钟") {
		t.Fatalf("last admin did not receive timed lock: %v", err)
	}
}

func TestUserStorePasswordExpiryRequiresChange(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	user := &model.User{ID: "expiry-user", Username: "expiry", Password: "secret123", Role: "user", CreatedAt: time.Now()}
	if err := s.Create(user); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for _, stored := range s.users {
		if stored.ID == user.ID {
			stored.MustChangePassword = false
			stored.PasswordChangedAt = time.Now().Add(-48 * time.Hour)
		}
	}
	if err := s.writeFileLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	policy := s.SecurityPolicy()
	policy.Login.PasswordMaxAgeDays = 1
	if err := s.UpdateSecurityPolicy(policy); err != nil {
		t.Fatal(err)
	}
	login, err := s.Login("expiry", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if !login.RequiresPasswordChange {
		t.Fatal("expired password did not require change")
	}
}

func swapCaptchaCase(value string) string {
	var result strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			result.WriteRune(char - ('a' - 'A'))
		case char >= 'A' && char <= 'Z':
			result.WriteRune(char + ('a' - 'A'))
		default:
			result.WriteRune(char)
		}
	}
	return result.String()
}

func TestUserStoreLoadRejectsCorruptEntries(t *testing.T) {
	for name, data := range map[string]string{
		"null":                    `[null]`,
		"empty id":                `[{"username":"admin","role":"admin"}]`,
		"duplicate id":            `[{"id":"dup","username":"admin","role":"admin"},{"id":"dup","username":"other","role":"user"}]`,
		"duplicate name":          `[{"id":"one","username":"admin","role":"admin"},{"id":"two","username":"ADMIN","role":"user"}]`,
		"bad role":                `[{"id":"one","username":"admin","role":"owner"}]`,
		"occupied bootstrap name": `[{"id":"one","username":"admin","role":"user"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := NewUserStore(path).Load(); err == nil {
				t.Fatal("corrupt users file accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != data {
				t.Fatalf("invalid file was overwritten: %v", err)
			}
		})
	}
}
