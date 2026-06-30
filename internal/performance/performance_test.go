package performance

import (
	"errors"
	"strings"
	"testing"
)

func TestDisabledProfilerIsNoOp(t *testing.T) {
	p := New(false)
	stop := p.Start(PhaseHTTP)
	stop()
	if err := p.Measure(PhaseOAuth, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if p.Enabled() {
		t.Error("disabled profiler reports enabled")
	}
	if p.Table() != "" {
		t.Error("disabled profiler should produce empty table")
	}
}

func TestMeasurePropagatesError(t *testing.T) {
	p := New(true)
	want := errors.New("boom")
	if got := p.Measure(PhaseHTTP, func() error { return want }); !errors.Is(got, want) {
		t.Errorf("Measure error = %v, want %v", got, want)
	}
}

func TestTableAggregatesAndOrders(t *testing.T) {
	p := New(true)
	_ = p.Measure(PhaseStartup, func() error { return nil })
	_ = p.Measure(PhaseHTTP, func() error { return nil })
	_ = p.Measure(PhaseHTTP, func() error { return nil })

	table := p.Table()
	if !strings.Contains(table, "PHASE") || !strings.Contains(table, "DURATION") {
		t.Errorf("table missing header:\n%s", table)
	}
	if !strings.Contains(table, "startup") || !strings.Contains(table, "http") {
		t.Errorf("table missing phases:\n%s", table)
	}
	// startup recorded first, so it must appear before http.
	if strings.Index(table, "startup") > strings.Index(table, "http") {
		t.Errorf("phases not ordered by first occurrence:\n%s", table)
	}
}
