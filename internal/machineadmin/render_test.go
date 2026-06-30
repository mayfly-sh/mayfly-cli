package machineadmin

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func gen(v int64) *int64 { return &v }

func sample() []Machine {
	return []Machine{
		{
			MachineID: "srv_a", Hostname: "web-01", Status: "active", Liveness: "ONLINE",
			OS: "linux", Arch: "x86_64", AgentVersion: "0.1.0", Fingerprint: "SHA256:aaaaaaaaaaaaaaaaaaaa",
			IP: "10.0.0.1", CurrentGeneration: 5, SyncedGeneration: gen(5), LatestGeneration: gen(5),
			UpToDate: true, LastSeen: "2026-06-24T12:00:00Z", EnrolledAt: "2026-06-24T11:00:00Z",
		},
		{
			MachineID: "srv_b", Hostname: "db-01", Status: "disabled", Liveness: "OFFLINE",
			OS: "linux", Arch: "arm64", AgentVersion: "0.1.0", Fingerprint: "SHA256:bbbbbbbbbbbbbbbbbbbb",
			CurrentGeneration: 4, SyncedGeneration: gen(4), LatestGeneration: gen(5),
			UpToDate: false, EnrolledAt: "2026-06-24T11:30:00Z",
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

func TestRenderMachinesTableGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderMachines(&buf, sample(), FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Header columns present and ordered.
	if !strings.Contains(out, "HOSTNAME") || !strings.Contains(out, "LIVENESS") || !strings.Contains(out, "UP-TO-DATE") {
		t.Fatalf("missing table headers:\n%s", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header+2 rows, got %d:\n%s", len(lines), out)
	}
	// web-01: active/ONLINE/5/5/5/yes; db-01: disabled/OFFLINE/4/4/5/no/never.
	if !strings.Contains(lines[1], "web-01") || !strings.Contains(lines[1], "ONLINE") || !strings.Contains(lines[1], "5/5") {
		t.Errorf("row1=%q", lines[1])
	}
	if !strings.Contains(lines[2], "db-01") || !strings.Contains(lines[2], "OFFLINE") || !strings.Contains(lines[2], "4/5") || !strings.Contains(lines[2], "never") {
		t.Errorf("row2=%q", lines[2])
	}
}

func TestRenderMachinesWideHasExtraColumns(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderMachines(&buf, sample(), FormatWide); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, col := range []string{"MACHINE ID", "OS/ARCH", "IP", "FINGERPRINT"} {
		if !strings.Contains(out, col) {
			t.Errorf("wide output missing %q:\n%s", col, out)
		}
	}
	if !strings.Contains(out, "srv_a") || !strings.Contains(out, "linux/arm64") {
		t.Errorf("wide rows missing detail:\n%s", out)
	}
}

func TestRenderMachinesJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderMachines(&buf, sample(), FormatJSON); err != nil {
		t.Fatal(err)
	}
	var got []Machine
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 2 || got[0].Hostname != "web-01" || got[1].Status != "disabled" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestRenderMachineYAML(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderMachine(&buf, sample()[0], FormatYAML); err != nil {
		t.Fatal(err)
	}
	var got Machine
	if err := yaml.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, buf.String())
	}
	if got.Hostname != "web-01" || got.MachineID != "srv_a" || !got.UpToDate {
		t.Errorf("yaml mismatch: %+v", got)
	}
}

func TestRenderMachinesEmptyTable(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderMachines(&buf, nil, FormatTable); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No machines enrolled.") {
		t.Errorf("empty message missing: %q", buf.String())
	}
}

func TestRenderFleetTable(t *testing.T) {
	fleet := Fleet{
		LatestGeneration: 5, TotalMachines: 2, Online: 1, Stale: 0, Offline: 1,
		RolloutPercentage: 50.0, OldestGeneration: gen(4), NewestGeneration: gen(5),
		Generations: []GenerationCount{{Generation: 4, Count: 1}, {Generation: 5, Count: 1}},
	}
	var buf bytes.Buffer
	if err := RenderFleet(&buf, fleet, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "50.0%") || !strings.Contains(out, "latest generation") || !strings.Contains(out, "GENERATION") {
		t.Errorf("fleet table missing fields:\n%s", out)
	}
}

func TestRenderTokenShowsPlaintextOnce(t *testing.T) {
	var buf bytes.Buffer
	tok := EnrollmentToken{Token: "mf_enroll_secret", ID: "id-1", ExpiresAt: "2026-06-24T13:00:00Z", SingleUse: true}
	if err := RenderToken(&buf, "reenroll", tok, FormatTable); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "mf_enroll_secret") {
		t.Errorf("token plaintext missing:\n%s", buf.String())
	}
}
