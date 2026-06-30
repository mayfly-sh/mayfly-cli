package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// runCLI executes the root command with isolated config/credential state.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("XDG_DATA_HOME", tmp)
	t.Setenv("MAYFLY_CREDENTIAL_BACKEND", "file")
	t.Setenv("MAYFLY_CREDENTIAL_PASSPHRASE", "test-passphrase")
	t.Setenv("MAYFLY_SERVER_URL", "https://mayfly.example.test")

	root := NewRootCommand()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestAuthProvidersJSONGolden(t *testing.T) {
	out, err := runCLI(t, "auth", "providers", "--json")
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}

	var reports []providerReport
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	byID := map[string]providerReport{}
	for _, r := range reports {
		byID[r.ID] = r
	}

	gh, ok := byID["github"]
	if !ok {
		t.Fatalf("github provider missing: %+v", reports)
	}
	// Server-brokered: "configured" means a server is set.
	if !gh.Configured {
		t.Error("github should be configured (server set)")
	}
	if !gh.Default {
		t.Error("github should be the default provider")
	}
	if !gh.Capabilities.DeviceFlow {
		t.Error("github should support device flow")
	}

	kc, ok := byID["keycloak"]
	if !ok {
		t.Fatalf("keycloak provider missing: %+v", reports)
	}
	if !kc.Configured {
		t.Error("keycloak should be configured (server set)")
	}
	if !kc.Capabilities.OIDCDiscovery {
		t.Error("keycloak should advertise oidc discovery")
	}
}

func TestWhoamiNotLoggedInJSON(t *testing.T) {
	out, err := runCLI(t, "whoami", "--json")
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}
	if !strings.Contains(out, "\"authenticated\": false") {
		t.Fatalf("expected authenticated:false, got:\n%s", out)
	}
}
