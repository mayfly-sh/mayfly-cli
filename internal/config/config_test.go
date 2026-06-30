package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeJSON(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPrecedenceDefaultsToFlags(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "system.json")
	user := filepath.Join(dir, "user.json")

	writeJSON(t, system, `{"provider":"system-provider","log_level":"warn","server_url":"https://sys.example"}`)
	writeJSON(t, user, `{"provider":"user-provider","server_url":"https://user.example"}`)

	env := map[string]string{
		"MAYFLY_PROVIDER": "env-provider",
	}
	loader := &Loader{
		SystemPath: system,
		UserPath:   user,
		Getenv:     func(k string) string { return env[k] },
	}

	cfg, origins, err := loader.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// provider: env wins over user/system/default
	if cfg.Provider != "env-provider" {
		t.Errorf("provider = %q, want env-provider", cfg.Provider)
	}
	if origins["provider"] != SourceEnv {
		t.Errorf("provider origin = %q, want env", origins["provider"])
	}
	// server_url: user wins over system
	if cfg.ServerURL != "https://user.example" {
		t.Errorf("server_url = %q, want user", cfg.ServerURL)
	}
	if origins["server_url"] != SourceUser {
		t.Errorf("server_url origin = %q, want user-config", origins["server_url"])
	}
	// log_level: only system set it
	if cfg.LogLevel != "warn" || origins["log_level"] != SourceSystem {
		t.Errorf("log_level = %q (%q), want warn/system", cfg.LogLevel, origins["log_level"])
	}
	// log_format: untouched default
	if cfg.LogFormat != "text" || origins["log_format"] != SourceDefault {
		t.Errorf("log_format = %q (%q), want text/default", cfg.LogFormat, origins["log_format"])
	}

	// Flags override everything.
	flagProvider := "flag-provider"
	ApplyFlags(&cfg, origins, FlagOverride{Provider: &flagProvider})
	if cfg.Provider != "flag-provider" || origins["provider"] != SourceFlag {
		t.Errorf("after flag: provider = %q (%q)", cfg.Provider, origins["provider"])
	}
}

func TestCertLifecycleKnobsPrecedence(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "user.json")
	writeJSON(t, user, `{"renew_threshold_seconds":120,"cert_lifetime_seconds":600,"preferred_username":"file-user","default_ssh_options":["ServerAliveInterval=15"]}`)

	env := map[string]string{
		"MAYFLY_CERT_LIFETIME": "900",
		"MAYFLY_SSH_OPTIONS":   "BatchMode=yes,ServerAliveInterval=30",
	}
	loader := &Loader{
		UserPath: user,
		Getenv:   func(k string) string { return env[k] },
	}
	cfg, origins, err := loader.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// renew threshold: only the user file set it.
	if cfg.RenewThresholdSec != 120 || origins["renew_threshold_seconds"] != SourceUser {
		t.Errorf("renew = %d (%q)", cfg.RenewThresholdSec, origins["renew_threshold_seconds"])
	}
	// cert lifetime: env overrides the user file.
	if cfg.CertLifetimeSec != 900 || origins["cert_lifetime_seconds"] != SourceEnv {
		t.Errorf("lifetime = %d (%q)", cfg.CertLifetimeSec, origins["cert_lifetime_seconds"])
	}
	// preferred username: file value retained.
	if cfg.PreferredUsername != "file-user" {
		t.Errorf("preferred username = %q", cfg.PreferredUsername)
	}
	// ssh options: env parsed into a slice.
	if len(cfg.DefaultSSHOptions) != 2 || cfg.DefaultSSHOptions[0] != "BatchMode=yes" {
		t.Errorf("ssh options = %v", cfg.DefaultSSHOptions)
	}

	// Flags win over everything.
	thresh := 30
	cache := "/tmp/c"
	ApplyFlags(&cfg, origins, FlagOverride{RenewThresholdSec: &thresh, CertCachePath: &cache})
	if cfg.RenewThresholdSec != 30 || origins["renew_threshold_seconds"] != SourceFlag {
		t.Errorf("after flag renew = %d (%q)", cfg.RenewThresholdSec, origins["renew_threshold_seconds"])
	}
	if cfg.CertCachePath != "/tmp/c" || origins["cert_cache_path"] != SourceFlag {
		t.Errorf("after flag cache = %q (%q)", cfg.CertCachePath, origins["cert_cache_path"])
	}
}

func TestDefaultsForCertKnobs(t *testing.T) {
	d := Defaults()
	if d.RenewThresholdSec != 60 {
		t.Errorf("default renew threshold = %d, want 60", d.RenewThresholdSec)
	}
	if d.CertLifetimeSec != 0 {
		t.Errorf("default cert lifetime = %d, want 0 (server default)", d.CertLifetimeSec)
	}
}

func TestMalformedFileIsError(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "system.json")
	writeJSON(t, system, `{not json`)
	loader := &Loader{SystemPath: system, Getenv: func(string) string { return "" }}
	if _, _, err := loader.Load(); err == nil {
		t.Fatal("expected error for malformed config")
	}
}

func TestMissingFilesAreOK(t *testing.T) {
	loader := &Loader{
		SystemPath: filepath.Join(t.TempDir(), "nope.json"),
		UserPath:   filepath.Join(t.TempDir(), "nope.json"),
		Getenv:     func(string) string { return "" },
	}
	cfg, _, err := loader.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Provider != "github" {
		t.Errorf("default provider = %q, want github", cfg.Provider)
	}
}
