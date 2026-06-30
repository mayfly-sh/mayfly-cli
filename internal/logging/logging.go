// Package logging provides the CLI's structured logger, built on log/slog.
//
// Output goes to stderr so command results on stdout stay clean and pipeable.
// Verbosity is controlled centrally so every command and subsystem logs
// consistently. Secrets must never be passed as attributes.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Format selects the log encoding.
type Format string

const (
	// FormatText is human-friendly key=value output (default).
	FormatText Format = "text"
	// FormatJSON is machine-readable structured output.
	FormatJSON Format = "json"
)

// Options configures the logger.
type Options struct {
	Level   slog.Level
	Format  Format
	Verbose bool // -v: lower threshold to Debug
}

// New builds a *slog.Logger writing to stderr per the options.
func New(opts Options) *slog.Logger {
	level := opts.Level
	if opts.Verbose && level > slog.LevelDebug {
		level = slog.LevelDebug
	}

	handlerOpts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if opts.Format == FormatJSON {
		handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, handlerOpts)
	}
	return slog.New(handler)
}

// ParseLevel maps a case-insensitive name to an slog.Level, defaulting to Info.
func ParseLevel(name string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
