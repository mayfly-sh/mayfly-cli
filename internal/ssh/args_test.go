package ssh

import (
	"reflect"
	"testing"
)

func TestParseArgsTargetAndOptions(t *testing.T) {
	p, err := ParseArgs([]string{"-v", "-p", "2222", "-o", "BatchMode=yes", "user@host", "uptime"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Target != "user@host" || p.User != "user" || p.Host != "host" {
		t.Fatalf("target=%q user=%q host=%q", p.Target, p.User, p.Host)
	}
	wantOpts := []string{"-v", "-p", "2222", "-o", "BatchMode=yes"}
	if !reflect.DeepEqual(p.Options, wantOpts) {
		t.Fatalf("options=%v want=%v", p.Options, wantOpts)
	}
	if !reflect.DeepEqual(p.Command, []string{"uptime"}) {
		t.Fatalf("command=%v", p.Command)
	}
}

func TestParseArgsMayflyFlagsSeparated(t *testing.T) {
	p, err := ParseArgs([]string{"--profile", "work", "--ttl", "900", "--dev", "--no-cache", "-J", "jump", "host"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Profile != "work" {
		t.Errorf("profile=%q", p.Profile)
	}
	if !p.HasTTL || p.TTL != 900 {
		t.Errorf("ttl hasTTL=%v ttl=%d", p.HasTTL, p.TTL)
	}
	if !p.Dev || !p.NoCache {
		t.Errorf("dev=%v noCache=%v", p.Dev, p.NoCache)
	}
	wantOpts := []string{"-J", "jump"}
	if !reflect.DeepEqual(p.Options, wantOpts) {
		t.Fatalf("options=%v want=%v (mayfly flags must not leak to ssh)", p.Options, wantOpts)
	}
	if p.Host != "host" {
		t.Errorf("host=%q", p.Host)
	}
}

func TestParseArgsEqualsForm(t *testing.T) {
	p, err := ParseArgs([]string{"--ttl=600", "--profile=stage", "host"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.TTL != 600 || p.Profile != "stage" || p.Host != "host" {
		t.Fatalf("ttl=%d profile=%q host=%q", p.TTL, p.Profile, p.Host)
	}
}

func TestParseArgsAttachedValueNotConsumed(t *testing.T) {
	// -p2222 (attached) must not consume the following token as a value.
	p, err := ParseArgs([]string{"-p2222", "host"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Host != "host" {
		t.Fatalf("host=%q (attached value wrongly consumed target)", p.Host)
	}
	if !reflect.DeepEqual(p.Options, []string{"-p2222"}) {
		t.Fatalf("options=%v", p.Options)
	}
}

func TestParseArgsTokensAfterTargetArePassthrough(t *testing.T) {
	// Flags after the target belong to the remote command, untouched.
	p, err := ParseArgs([]string{"host", "ls", "-la", "--ttl", "1"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.HasTTL {
		t.Errorf("--ttl after target must not be interpreted as a mayfly flag")
	}
	if !reflect.DeepEqual(p.Command, []string{"ls", "-la", "--ttl", "1"}) {
		t.Fatalf("command=%v", p.Command)
	}
}

func TestParseArgsTTLError(t *testing.T) {
	if _, err := ParseArgs([]string{"--ttl", "abc", "host"}); err == nil {
		t.Fatal("expected error for non-integer ttl")
	}
}

func TestParseArgsHelp(t *testing.T) {
	p, err := ParseArgs([]string{"--help"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.Help {
		t.Fatal("help not set")
	}
}

func TestRenderCommandQuotesSpaces(t *testing.T) {
	got := RenderCommand("ssh", []string{"-o", "ProxyCommand=ssh -W %h:%p bast", "host"})
	want := "ssh -o 'ProxyCommand=ssh -W %h:%p bast' host"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
