// Package config implements Mayfly's layered CLI configuration with a strict,
// deterministic precedence:
//
//	CLI flags  >  environment  >  user config  >  system config  >  defaults
//
// Each effective value remembers where it came from (Origins), which developer
// mode surfaces so operators can debug "why is this setting X?" without guessing.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Source identifies the layer a value was resolved from.
type Source string

const (
	SourceDefault Source = "default"
	SourceSystem  Source = "system-config"
	SourceUser    Source = "user-config"
	SourceProfile Source = "profile"
	SourceEnv     Source = "environment"
	SourceFlag    Source = "flag"
)

// Config is the fully-resolved CLI configuration.
type Config struct {
	ServerURL         string `json:"server_url"`
	Provider          string `json:"provider"`
	LogLevel          string `json:"log_level"`
	LogFormat         string `json:"log_format"`
	CredentialBackend string `json:"credential_backend"`
	RequestTimeoutSec int    `json:"request_timeout_seconds"`
	Retries           int    `json:"retries"`
}

// Origins records the Source that supplied each field's final value, keyed by
// the JSON field name.
type Origins map[string]Source

// fileConfig is the on-disk representation. Pointer fields distinguish "unset"
// from "set to zero value" so layering is precise.
type fileConfig struct {
	ServerURL         *string `json:"server_url"`
	Provider          *string `json:"provider"`
	LogLevel          *string `json:"log_level"`
	LogFormat         *string `json:"log_format"`
	CredentialBackend *string `json:"credential_backend"`
	RequestTimeoutSec *int    `json:"request_timeout_seconds"`
	Retries           *int    `json:"retries"`
}

// Defaults returns the baseline configuration.
func Defaults() Config {
	return Config{
		ServerURL:         "",
		Provider:          "github",
		LogLevel:          "info",
		LogFormat:         "text",
		CredentialBackend: "auto",
		RequestTimeoutSec: 30,
		Retries:           2,
	}
}

// SystemConfigPath is the machine-wide config file path.
func SystemConfigPath() string {
	return filepath.Join("/etc", "mayfly", "config.json")
}

// UserConfigPath is the per-user config file path, or "" if undeterminable.
func UserConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "mayfly", "config.json")
}

// Loader resolves configuration from all layers.
type Loader struct {
	SystemPath string
	UserPath   string
	// Getenv is the environment accessor (overridable for tests).
	Getenv func(string) string
}

// NewLoader returns a Loader bound to the real filesystem and environment.
func NewLoader() *Loader {
	return &Loader{
		SystemPath: SystemConfigPath(),
		UserPath:   UserConfigPath(),
		Getenv:     os.Getenv,
	}
}

// Load resolves defaults -> system -> user -> environment. Flag overrides are
// applied afterward by the caller via Config.ApplyFlags. Missing files are not
// errors; malformed files are returned as errors so misconfiguration is loud.
func (l *Loader) Load() (Config, Origins, error) {
	cfg := Defaults()
	origins := Origins{
		"server_url": SourceDefault, "provider": SourceDefault,
		"log_level": SourceDefault, "log_format": SourceDefault,
		"credential_backend": SourceDefault, "request_timeout_seconds": SourceDefault,
		"retries": SourceDefault,
	}

	if l.SystemPath != "" {
		fc, err := readFileConfig(l.SystemPath)
		if err != nil {
			return cfg, origins, err
		}
		mergeFile(&cfg, origins, fc, SourceSystem)
	}
	if l.UserPath != "" {
		fc, err := readFileConfig(l.UserPath)
		if err != nil {
			return cfg, origins, err
		}
		mergeFile(&cfg, origins, fc, SourceUser)
	}
	l.mergeEnv(&cfg, origins)
	return cfg, origins, nil
}

func readFileConfig(path string) (*fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, err
	}
	return &fc, nil
}

func mergeFile(cfg *Config, origins Origins, fc *fileConfig, src Source) {
	if fc == nil {
		return
	}
	if fc.ServerURL != nil {
		cfg.ServerURL, origins["server_url"] = *fc.ServerURL, src
	}
	if fc.Provider != nil {
		cfg.Provider, origins["provider"] = *fc.Provider, src
	}
	if fc.LogLevel != nil {
		cfg.LogLevel, origins["log_level"] = *fc.LogLevel, src
	}
	if fc.LogFormat != nil {
		cfg.LogFormat, origins["log_format"] = *fc.LogFormat, src
	}
	if fc.CredentialBackend != nil {
		cfg.CredentialBackend, origins["credential_backend"] = *fc.CredentialBackend, src
	}
	if fc.RequestTimeoutSec != nil {
		cfg.RequestTimeoutSec, origins["request_timeout_seconds"] = *fc.RequestTimeoutSec, src
	}
	if fc.Retries != nil {
		cfg.Retries, origins["retries"] = *fc.Retries, src
	}
}

func (l *Loader) mergeEnv(cfg *Config, origins Origins) {
	get := l.Getenv
	if get == nil {
		get = os.Getenv
	}
	if v := get("MAYFLY_SERVER_URL"); v != "" {
		cfg.ServerURL, origins["server_url"] = v, SourceEnv
	}
	if v := get("MAYFLY_PROVIDER"); v != "" {
		cfg.Provider, origins["provider"] = v, SourceEnv
	}
	if v := get("MAYFLY_LOG_LEVEL"); v != "" {
		cfg.LogLevel, origins["log_level"] = v, SourceEnv
	}
	if v := get("MAYFLY_LOG_FORMAT"); v != "" {
		cfg.LogFormat, origins["log_format"] = v, SourceEnv
	}
	if v := get("MAYFLY_CREDENTIAL_BACKEND"); v != "" {
		cfg.CredentialBackend, origins["credential_backend"] = v, SourceEnv
	}
	if v := get("MAYFLY_REQUEST_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			cfg.RequestTimeoutSec, origins["request_timeout_seconds"] = n, SourceEnv
		}
	}
	if v := get("MAYFLY_RETRIES"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			cfg.Retries, origins["retries"] = n, SourceEnv
		}
	}
}

// FlagOverride is a single highest-precedence override sourced from a CLI flag.
// Only non-nil fields are applied, so unset flags never clobber lower layers.
type FlagOverride struct {
	ServerURL         *string
	Provider          *string
	LogLevel          *string
	LogFormat         *string
	CredentialBackend *string
	RequestTimeoutSec *int
	Retries           *int
}

// ApplyFlags applies flag overrides at the highest precedence.
func ApplyFlags(cfg *Config, origins Origins, o FlagOverride) {
	if o.ServerURL != nil {
		cfg.ServerURL, origins["server_url"] = *o.ServerURL, SourceFlag
	}
	if o.Provider != nil {
		cfg.Provider, origins["provider"] = *o.Provider, SourceFlag
	}
	if o.LogLevel != nil {
		cfg.LogLevel, origins["log_level"] = *o.LogLevel, SourceFlag
	}
	if o.LogFormat != nil {
		cfg.LogFormat, origins["log_format"] = *o.LogFormat, SourceFlag
	}
	if o.CredentialBackend != nil {
		cfg.CredentialBackend, origins["credential_backend"] = *o.CredentialBackend, SourceFlag
	}
	if o.RequestTimeoutSec != nil {
		cfg.RequestTimeoutSec, origins["request_timeout_seconds"] = *o.RequestTimeoutSec, SourceFlag
	}
	if o.Retries != nil {
		cfg.Retries, origins["retries"] = *o.Retries, SourceFlag
	}
}
