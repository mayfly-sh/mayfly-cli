// Package performance implements the CLI developer-mode profiler.
//
// When developer mode is enabled (the global --dev flag), every command and
// subsystem records the wall-clock duration of well-known phases (startup,
// config, OAuth, DNS, TLS, HTTP, JSON, credential lookup, ...). At the end of a
// command the profiler renders an aligned timing table. When disabled, the
// recording calls are effectively free so production paths pay no cost.
package performance

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Phase names a measurable unit of work. Subsystems should reuse these standard
// names so timing tables are comparable across commands.
type Phase string

const (
	PhaseStartup           Phase = "startup"
	PhaseConfig            Phase = "configuration"
	PhaseProviderDiscovery Phase = "provider_discovery"
	PhaseOAuth             Phase = "oauth_start"
	PhaseDeviceAuth        Phase = "device_authorization"
	PhaseBrowser           Phase = "browser_launch"
	PhasePolling           Phase = "polling"
	PhaseTokenExchange     Phase = "token_exchange"
	PhaseDNS               Phase = "dns"
	PhaseTLS               Phase = "tls"
	PhaseHTTP              Phase = "http"
	PhaseJSONEncode        Phase = "json_serialize"
	PhaseJSONDecode        Phase = "json_parse"
	PhaseCredentialLoad    Phase = "credential_lookup"
	PhaseCredentialStore   Phase = "credential_storage"
	PhaseResponseParse     Phase = "response_parse"
	PhaseOverall           Phase = "overall"
)

type sample struct {
	phase    Phase
	duration time.Duration
	seq      int
}

// Profiler accumulates per-phase timings. It is safe for concurrent use.
type Profiler struct {
	enabled bool
	mu      sync.Mutex
	samples []sample
	seq     int
	created time.Time
}

// New returns a profiler. When enabled is false, all recording is a no-op
// (aside from a negligible boolean check).
func New(enabled bool) *Profiler {
	return &Profiler{enabled: enabled, created: time.Now()}
}

// Enabled reports whether developer mode is active.
func (p *Profiler) Enabled() bool { return p != nil && p.enabled }

// Start begins timing a phase. Call the returned function to stop it. The
// returned stopper is always safe to call, even on a nil/disabled profiler.
func (p *Profiler) Start(phase Phase) func() {
	if !p.Enabled() {
		return func() {}
	}
	begin := time.Now()
	return func() { p.record(phase, time.Since(begin)) }
}

// Measure times fn and returns its error unchanged.
func (p *Profiler) Measure(phase Phase, fn func() error) error {
	stop := p.Start(phase)
	err := fn()
	stop()
	return err
}

// Record adds a pre-measured duration for a phase (useful for timings captured
// by lower layers, e.g. httptrace DNS/TLS hooks).
func (p *Profiler) Record(phase Phase, d time.Duration) {
	if !p.Enabled() {
		return
	}
	p.record(phase, d)
}

func (p *Profiler) record(phase Phase, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seq++
	p.samples = append(p.samples, sample{phase: phase, duration: d, seq: p.seq})
}

// Table renders an aligned, deterministic timing table. Phases are ordered by
// first occurrence; repeated phases are aggregated (summed, with a count).
func (p *Profiler) Table() string {
	if !p.Enabled() {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	type agg struct {
		phase     Phase
		total     time.Duration
		count     int
		firstSeen int
	}
	order := map[Phase]*agg{}
	var list []*agg
	for _, s := range p.samples {
		a, ok := order[s.phase]
		if !ok {
			a = &agg{phase: s.phase, firstSeen: s.seq}
			order[s.phase] = a
			list = append(list, a)
		}
		a.total += s.duration
		a.count++
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].firstSeen < list[j].firstSeen })

	// Denominator for percentages: the `overall` phase when present (it wraps the
	// whole command), otherwise the sum of all samples.
	var denom time.Duration
	for _, a := range list {
		if a.phase == PhaseOverall {
			denom = a.total
		}
	}
	if denom <= 0 {
		for _, a := range list {
			denom += a.total
		}
	}

	const (
		colPhase = "PHASE"
		colDur   = "DURATION"
		colPct   = "PERCENT"
		colCalls = "CALLS"
	)
	width := len(colPhase)
	for _, a := range list {
		if l := len(string(a.phase)); l > width {
			width = l
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%-*s  %12s  %8s  %5s\n", width, colPhase, colDur, colPct, colCalls)
	fmt.Fprintf(&b, "%s  %12s  %8s  %5s\n", strings.Repeat("-", width), strings.Repeat("-", 12), strings.Repeat("-", 8), "-----")
	for _, a := range list {
		pct := 0.0
		if denom > 0 {
			pct = float64(a.total) / float64(denom) * 100
		}
		fmt.Fprintf(&b, "%-*s  %12s  %7.1f%%  %5d\n",
			width, string(a.phase), a.total.Round(time.Microsecond).String(), pct, a.count)
	}
	fmt.Fprintf(&b, "GRADE: %s  (total %s)\n", grade(denom), denom.Round(time.Microsecond).String())
	return b.String()
}

// grade assigns a coarse performance grade from the overall command duration.
func grade(total time.Duration) string {
	switch {
	case total <= 250*time.Millisecond:
		return "A"
	case total <= 750*time.Millisecond:
		return "B"
	case total <= 2*time.Second:
		return "C"
	case total <= 5*time.Second:
		return "D"
	default:
		return "F"
	}
}
