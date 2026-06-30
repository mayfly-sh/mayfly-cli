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
