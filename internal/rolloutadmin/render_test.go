package rolloutadmin

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func i64(v int64) *int64 { return &v }

func sampleStatus() Status {
	return Status{
		Configured:        true,
		LatestGeneration:  i64(4),
		BundleFingerprint: "sha256:abcd",
		TotalMachines:     10,
		ActiveMachines:    9,
		Completed:         6,
		Remaining:         3,
		NeverSynced:       1,
		Percentage:        66.7,
		Online:            7,
		Stale:             1,
		Offline:           2,
		Breakdown:         Breakdown{Healthy: 6, Pending: 1, Stale: 1, Offline: 1, Failed: 0},
		Generations: []GenerationDetail{
			{Generation: 3, Machines: 3, Percentage: 30, IsLatest: false},
			{Generation: 4, Machines: 6, Percentage: 60, IsLatest: true},
		},
		ETA:    ETA{Complete: false, Remaining: 3, AppliesLastHour: 6, PerHour: 6, ETASeconds: i64(1800), EstimatedCompletion: "2026-06-24T12:30:00Z"},
		Health: Health{Status: "Degraded", Score: 66, Reasons: []string{"6/9 active machine(s) on the latest generation (3 behind)"}},
	}
}

func TestProgressBar(t *testing.T) {
	if got := ProgressBar(0); got != "["+strings.Repeat("-", 30)+"]" {
		t.Errorf("0%%: %q", got)
	}
	if got := ProgressBar(100); got != "["+strings.Repeat("#", 30)+"]" {
		t.Errorf("100%%: %q", got)
	}
	half := ProgressBar(50)
	if strings.Count(half, "#") != 15 || strings.Count(half, "-") != 15 {
		t.Errorf("50%%: %q", half)
	}
	// Out-of-range values clamp.
	if got := ProgressBar(150); strings.Count(got, "#") != 30 {
		t.Errorf("clamp high: %q", got)
	}
}

func TestRenderStatusTable(t *testing.T) {
	var b bytes.Buffer
	if err := RenderStatus(&b, sampleStatus(), FormatTable); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Fleet rollout", "generation 4", "Degraded", "66.7%", "(6/9", "healthy 6", "pending 1", "offline 1", "ETA: ~30m"} {
		if !strings.Contains(out, want) {
			t.Errorf("status table missing %q:\n%s", want, out)
		}
	}
}

func TestRenderStatusWideAddsGenerations(t *testing.T) {
	var b bytes.Buffer
	if err := RenderStatus(&b, sampleStatus(), FormatWide); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "GENERATION") || !strings.Contains(out, "MACHINES") {
		t.Errorf("wide status missing generations table:\n%s", out)
	}
}

func TestRenderStatusJSONRoundTrips(t *testing.T) {
	var b bytes.Buffer
	if err := RenderStatus(&b, sampleStatus(), FormatJSON); err != nil {
		t.Fatal(err)
	}
	var s Status
	if err := json.Unmarshal(b.Bytes(), &s); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, b.String())
	}
	if s.Percentage != 66.7 || s.Health.Status != "Degraded" {
		t.Errorf("round trip: %+v", s)
	}
}

func TestRenderSummaryShowsReasons(t *testing.T) {
	var b bytes.Buffer
	if err := RenderSummary(&b, sampleStatus(), FormatTable); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "health: Degraded") || !strings.Contains(out, "3 behind") {
		t.Errorf("summary missing health reasons:\n%s", out)
	}
}

func TestRenderHealth(t *testing.T) {
	var b bytes.Buffer
	h := Health{Status: "Blocked", Score: 40, Reasons: []string{"all remaining offline"}}
	if err := RenderHealth(&b, h, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "Blocked") || !strings.Contains(out, "all remaining offline") {
		t.Errorf("health:\n%s", out)
	}
}

func TestRenderExplain(t *testing.T) {
	var b bytes.Buffer
	e := Explanation{
		Complete:  false,
		Remaining: 2,
		Categories: []ExplainCategory{
			{Category: "offline", Count: 1, Description: "no recent heartbeat", Recommendation: "power on the host", Machines: []string{"host-c"}},
			{Category: "generation_mismatch", Count: 1, Description: "not pulled yet", Recommendation: "no action", Machines: []string{"host-b"}},
		},
	}
	if err := RenderExplain(&b, e, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"incomplete", "offline (1)", "power on the host", "host-c", "generation_mismatch"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain missing %q:\n%s", want, out)
		}
	}
}

func TestRenderExplainComplete(t *testing.T) {
	var b bytes.Buffer
	if err := RenderExplain(&b, Explanation{Complete: true}, FormatTable); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "complete") {
		t.Errorf("expected complete message:\n%s", b.String())
	}
}

func TestRenderStuck(t *testing.T) {
	var b bytes.Buffer
	r := StuckReport{Count: 1, Stuck: []StuckMachine{
		{Hostname: "host-c", Category: "offline", GenerationsBehind: 2, Liveness: "OFFLINE", Recommendation: "power on the host"},
	}}
	if err := RenderStuck(&b, r, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "Stuck machines: 1") || !strings.Contains(out, "power on the host") {
		t.Errorf("stuck:\n%s", out)
	}
}

func TestRenderStuckNone(t *testing.T) {
	var b bytes.Buffer
	if err := RenderStuck(&b, StuckReport{Count: 0}, FormatTable); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No stuck machines") {
		t.Errorf("expected none message:\n%s", b.String())
	}
}

func TestRenderMachinesWide(t *testing.T) {
	var b bytes.Buffer
	m := MachinesResponse{Count: 1, Machines: []MachineRollout{
		{Hostname: "host-a", MachineID: "srv_a", Status: "active", Liveness: "ONLINE", SyncedGeneration: i64(4), LatestGeneration: i64(4), UpToDate: true, State: "current", Category: "up_to_date", LastSync: "2026-06-24T12:00:00Z"},
	}}
	if err := RenderMachines(&b, m, FormatWide); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"MACHINE ID", "host-a", "srv_a", "current", "up_to_date"} {
		if !strings.Contains(out, want) {
			t.Errorf("machines wide missing %q:\n%s", want, out)
		}
	}
}

func TestRenderTimeline(t *testing.T) {
	var b bytes.Buffer
	tl := Timeline{Count: 2, Events: []TimelineEvent{
		{Position: 2, At: "2026-06-24T12:00:02Z", EventType: "bundle.rollback", Outcome: "rolled_back", MachineID: "srv_b", Generation: i64(4), Reason: "sshd reload failed"},
		{Position: 1, At: "2026-06-24T12:00:01Z", EventType: "bundle.applied", Outcome: "applied", MachineID: "srv_a", Generation: i64(4)},
	}}
	if err := RenderTimeline(&b, tl, FormatWide); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"OUTCOME", "rolled_back", "applied", "srv_a", "sshd reload failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("timeline missing %q:\n%s", want, out)
		}
	}
}

func TestRenderGenerations(t *testing.T) {
	var b bytes.Buffer
	g := GenerationsResponse{LatestGeneration: i64(4), Generations: []GenerationDetail{
		{Generation: 4, Machines: 6, Percentage: 60, IsLatest: true},
	}}
	if err := RenderGenerations(&b, g, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "GENERATION") || !strings.Contains(out, "60.0%") {
		t.Errorf("generations:\n%s", out)
	}
}

func TestRenderHistory(t *testing.T) {
	var b bytes.Buffer
	h := History{LatestGeneration: i64(4), Generations: []GenerationHistory{
		{Generation: 4, IsLatest: true, MachinesOnGeneration: 6, TotalApplies: 8, FirstAppliedAt: "2026-06-24T11:00:00Z", LastAppliedAt: "2026-06-24T12:00:00Z"},
	}}
	if err := RenderHistory(&b, h, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"GENERATION", "APPLIES", "2026-06-24T11:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("history missing %q:\n%s", want, out)
		}
	}
}

func TestETATextVariants(t *testing.T) {
	if got := etaText(ETA{Complete: true}); got != "complete" {
		t.Errorf("complete: %q", got)
	}
	if got := etaText(ETA{Remaining: 3}); !strings.Contains(got, "unknown") {
		t.Errorf("unknown: %q", got)
	}
	if got := etaText(ETA{Remaining: 3, ETASeconds: i64(3600), PerHour: 3}); !strings.Contains(got, "~1h") {
		t.Errorf("eta: %q", got)
	}
}

func TestParseFormatErrors(t *testing.T) {
	if _, err := ParseFormat("toml"); err == nil {
		t.Error("expected error for unknown format")
	}
	for _, in := range []string{"", "table", "wide", "json", "yaml", "YML"} {
		if _, err := ParseFormat(in); err != nil {
			t.Errorf("ParseFormat(%q): %v", in, err)
		}
	}
}
