package caadmin

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func gen(v int64) *int64 { return &v }

func sample() []CA {
	return []CA{
		{
			ID: "id-a", KeyID: "ca-01", PublicKey: "ssh-ed25519 AAAAaaaa", Fingerprint: "SHA256:aaaaaaaaaaaaaaaaaaaa",
			Enabled: true, CreatedAt: "2026-06-24T11:00:00Z", EnabledAt: "2026-06-24T11:00:00Z",
			IssuedCertificates: 12, Status: "active", InCurrentBundle: true, AgeSeconds: 3600,
			BundleGeneration: 5, LastUsedAt: "2026-06-24T12:00:00Z",
			ActivationHistory: []ActivationEvent{{Event: "created", At: "2026-06-24T11:00:00Z"}},
		},
		{
			ID: "id-b", KeyID: "ca-00", PublicKey: "ssh-ed25519 BBBBbbbb", Fingerprint: "SHA256:bbbbbbbbbbbbbbbbbbbb",
			Enabled: false, CreatedAt: "2026-06-20T11:00:00Z", DisabledAt: "2026-06-23T11:00:00Z",
			IssuedCertificates: 3, Status: "disabled", InCurrentBundle: false, AgeSeconds: 99999,
			BundleGeneration: 5, DisabledGeneration: gen(4),
		},
	}
}

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{"": FormatTable, "table": FormatTable, "WIDE": FormatWide, "json": FormatJSON, "yml": FormatYAML}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q)=%q,%v want %q", in, got, err, want)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("expected error for xml")
	}
}

func TestRenderCAsTableGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderCAs(&buf, sample(), FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "KEY ID") || !strings.Contains(out, "STATUS") || !strings.Contains(out, "IN BUNDLE") {
		t.Fatalf("missing table headers:\n%s", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header+2 rows, got %d:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[1], "ca-01") || !strings.Contains(lines[1], "active") {
		t.Errorf("row1=%q", lines[1])
	}
	if !strings.Contains(lines[2], "ca-00") || !strings.Contains(lines[2], "disabled") || !strings.Contains(lines[2], "never") {
		t.Errorf("row2=%q", lines[2])
	}
}

func TestRenderCAsWideHasExtraColumns(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderCAs(&buf, sample(), FormatWide); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, col := range []string{"ID", "GEN", "CREATED"} {
		if !strings.Contains(out, col) {
			t.Errorf("wide output missing %q:\n%s", col, out)
		}
	}
}

func TestRenderCAsJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderCAs(&buf, sample(), FormatJSON); err != nil {
		t.Fatal(err)
	}
	var got []CA
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 2 || got[0].KeyID != "ca-01" || got[1].Status != "disabled" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestRenderCADetailShowsHistoryAndKey(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderCA(&buf, sample()[0], FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "activation history") || !strings.Contains(out, "created") {
		t.Errorf("detail missing history:\n%s", out)
	}
	if !strings.Contains(out, "ssh-ed25519 AAAAaaaa") {
		t.Errorf("detail missing public key:\n%s", out)
	}
}

func TestRenderCAYAML(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderCA(&buf, sample()[0], FormatYAML); err != nil {
		t.Fatal(err)
	}
	var got CA
	if err := yaml.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, buf.String())
	}
	if got.KeyID != "ca-01" || !got.Enabled {
		t.Errorf("yaml mismatch: %+v", got)
	}
}

func TestRenderCAsEmptyTable(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderCAs(&buf, nil, FormatTable); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No certificate authorities configured.") {
		t.Errorf("empty message missing: %q", buf.String())
	}
}

func TestRenderStatsTable(t *testing.T) {
	s := Stats{
		TotalCAs: 2, EnabledCAs: 1, DisabledCAs: 1, TotalIssuedCertificates: 15,
		Generation: 5, BundleFingerprint: "sha256:abc",
		PerCA: []Usage{{KeyID: "ca-01", Enabled: true, IssuedCertificates: 12}},
	}
	var buf bytes.Buffer
	if err := RenderStats(&buf, s, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "total issued certs") || !strings.Contains(out, "15") || !strings.Contains(out, "KEY ID") {
		t.Errorf("stats table missing fields:\n%s", out)
	}
}

func TestRenderRotationGuidedWorkflow(t *testing.T) {
	r := RotationResult{
		NewCA:          CA{KeyID: "ca-new", Fingerprint: "SHA256:new"},
		PreviousActive: []CA{{KeyID: "ca-old"}},
		Rollout: Rollout{
			LatestGeneration: 6, TotalMachines: 4, RolloutPercentage: 25.0,
			Generations: []GenerationCount{{Generation: 6, Count: 1}, {Generation: 5, Count: 3}},
		},
		Warnings: []string{"Do NOT retire the old CA yet."},
	}
	var buf bytes.Buffer
	if err := RenderRotation(&buf, r, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "ca-new") || !strings.Contains(out, "ca-old") {
		t.Errorf("rotation missing CA names:\n%s", out)
	}
	// 4 total, 1 on latest gen 6 → 3 behind, 25.0%.
	if !strings.Contains(out, "25.0%") || !strings.Contains(out, "3 machine(s) behind") {
		t.Errorf("rotation rollout wrong:\n%s", out)
	}
	if !strings.Contains(out, "Do NOT retire") {
		t.Errorf("rotation warnings missing:\n%s", out)
	}
}

func TestRenderBundleTable(t *testing.T) {
	b := PublicBundle{Generation: 5, Fingerprint: "sha256:abc", Keys: []BundleKey{{KeyID: "ca-01", Fingerprint: "SHA256:aa"}}}
	var buf bytes.Buffer
	if err := RenderBundle(&buf, b, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "generation 5") || !strings.Contains(out, "ca-01") {
		t.Errorf("bundle table missing fields:\n%s", out)
	}
}

func TestRenderPublicKeyRaw(t *testing.T) {
	var buf bytes.Buffer
	k := PublicKey{KeyID: "ca-01", PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:aa"}
	if err := RenderPublicKey(&buf, k, FormatTable); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "ssh-ed25519 AAAA" {
		t.Errorf("public-key table should print raw key, got %q", buf.String())
	}
}

func TestRenderDelete(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderDelete(&buf, DeleteResult{Deleted: true, ID: "id-x", KeyID: "ca-x"}, FormatTable); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Deleted CA ca-x") {
		t.Errorf("delete message missing: %q", buf.String())
	}
}
