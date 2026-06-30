// Package rolloutadmin holds the client-side DTOs and renderers for the fleet
// rollout console (`mayfly rollout`). The structs mirror the additive JSON
// shapes returned by the mayfly-server rollout admin API (013D / ADR-0025);
// they are read-only views and never carry secrets. Rendering is pure and
// io.Writer-based so it is fully unit-testable (golden output).
package rolloutadmin

// MachineFailure is the most recent failed bundle-apply attributed to a machine.
type MachineFailure struct {
	EventType  string `json:"event_type" yaml:"event_type"`
	Generation *int64 `json:"generation,omitempty" yaml:"generation,omitempty"`
	Reason     string `json:"reason,omitempty" yaml:"reason,omitempty"`
	At         string `json:"at" yaml:"at"`
}

// MachineRollout is one machine's position in the current rollout.
type MachineRollout struct {
	MachineID         string          `json:"machine_id" yaml:"machine_id"`
	Hostname          string          `json:"hostname" yaml:"hostname"`
	Status            string          `json:"status" yaml:"status"`
	Liveness          string          `json:"liveness" yaml:"liveness"`
	SyncedGeneration  *int64          `json:"synced_generation,omitempty" yaml:"synced_generation,omitempty"`
	LatestGeneration  *int64          `json:"latest_generation,omitempty" yaml:"latest_generation,omitempty"`
	CurrentGeneration int64           `json:"current_generation" yaml:"current_generation"`
	UpToDate          bool            `json:"up_to_date" yaml:"up_to_date"`
	GenerationsBehind int64           `json:"generations_behind" yaml:"generations_behind"`
	State             string          `json:"state" yaml:"state"`
	Category          string          `json:"category" yaml:"category"`
	LastSync          string          `json:"last_sync,omitempty" yaml:"last_sync,omitempty"`
	LastSeen          string          `json:"last_seen,omitempty" yaml:"last_seen,omitempty"`
	LastFailure       *MachineFailure `json:"last_failure,omitempty" yaml:"last_failure,omitempty"`
}

// Breakdown is the active-machine breakdown for the watch dashboard.
type Breakdown struct {
	Healthy int64 `json:"healthy" yaml:"healthy"`
	Stale   int64 `json:"stale" yaml:"stale"`
	Offline int64 `json:"offline" yaml:"offline"`
	Failed  int64 `json:"failed" yaml:"failed"`
	Pending int64 `json:"pending" yaml:"pending"`
}

// GenerationDetail is the per-generation machine population.
type GenerationDetail struct {
	Generation int64   `json:"generation" yaml:"generation"`
	Machines   int64   `json:"machines" yaml:"machines"`
	Percentage float64 `json:"percentage" yaml:"percentage"`
	IsLatest   bool    `json:"is_latest" yaml:"is_latest"`
}

// ETA is the transparent completion estimate.
type ETA struct {
	Complete            bool    `json:"complete" yaml:"complete"`
	Remaining           int64   `json:"remaining" yaml:"remaining"`
	AppliesLastHour     int64   `json:"applies_last_hour" yaml:"applies_last_hour"`
	PerHour             float64 `json:"per_hour" yaml:"per_hour"`
	ETASeconds          *int64  `json:"eta_seconds,omitempty" yaml:"eta_seconds,omitempty"`
	EstimatedCompletion string  `json:"estimated_completion,omitempty" yaml:"estimated_completion,omitempty"`
}

// Health is the rollout health verdict.
type Health struct {
	Status  string   `json:"status" yaml:"status"`
	Score   int      `json:"score" yaml:"score"`
	Reasons []string `json:"reasons" yaml:"reasons"`
}

// Status is the headline rollout status (`GET /admin/rollout`).
type Status struct {
	Configured        bool               `json:"configured" yaml:"configured"`
	LatestGeneration  *int64             `json:"latest_generation,omitempty" yaml:"latest_generation,omitempty"`
	BundleFingerprint string             `json:"bundle_fingerprint,omitempty" yaml:"bundle_fingerprint,omitempty"`
	TotalMachines     int64              `json:"total_machines" yaml:"total_machines"`
	ActiveMachines    int64              `json:"active_machines" yaml:"active_machines"`
	Completed         int64              `json:"completed" yaml:"completed"`
	Remaining         int64              `json:"remaining" yaml:"remaining"`
	NeverSynced       int64              `json:"never_synced" yaml:"never_synced"`
	Percentage        float64            `json:"percentage" yaml:"percentage"`
	Online            int64              `json:"online" yaml:"online"`
	Stale             int64              `json:"stale" yaml:"stale"`
	Offline           int64              `json:"offline" yaml:"offline"`
	Breakdown         Breakdown          `json:"breakdown" yaml:"breakdown"`
	Generations       []GenerationDetail `json:"generations" yaml:"generations"`
	ETA               ETA                `json:"eta" yaml:"eta"`
	Health            Health             `json:"health" yaml:"health"`
}

// GenerationsResponse is the `GET /admin/rollout/generations` body.
type GenerationsResponse struct {
	LatestGeneration *int64             `json:"latest_generation,omitempty" yaml:"latest_generation,omitempty"`
	Generations      []GenerationDetail `json:"generations" yaml:"generations"`
}

// MachinesResponse is the `GET /admin/rollout/machines` body.
type MachinesResponse struct {
	Count    int              `json:"count" yaml:"count"`
	Machines []MachineRollout `json:"machines" yaml:"machines"`
}

// ExplainCategory is one categorized reason a rollout is incomplete.
type ExplainCategory struct {
	Category       string   `json:"category" yaml:"category"`
	Count          int64    `json:"count" yaml:"count"`
	Description    string   `json:"description" yaml:"description"`
	Recommendation string   `json:"recommendation" yaml:"recommendation"`
	Machines       []string `json:"machines" yaml:"machines"`
}

// Explanation is the `GET /admin/rollout/explain` body.
type Explanation struct {
	LatestGeneration *int64            `json:"latest_generation,omitempty" yaml:"latest_generation,omitempty"`
	Complete         bool              `json:"complete" yaml:"complete"`
	Remaining        int64             `json:"remaining" yaml:"remaining"`
	Categories       []ExplainCategory `json:"categories" yaml:"categories"`
}

// StuckMachine is one stuck machine plus its remediation.
type StuckMachine struct {
	MachineID         string          `json:"machine_id" yaml:"machine_id"`
	Hostname          string          `json:"hostname" yaml:"hostname"`
	Category          string          `json:"category" yaml:"category"`
	GenerationsBehind int64           `json:"generations_behind" yaml:"generations_behind"`
	Liveness          string          `json:"liveness" yaml:"liveness"`
	LastSync          string          `json:"last_sync,omitempty" yaml:"last_sync,omitempty"`
	LastSeen          string          `json:"last_seen,omitempty" yaml:"last_seen,omitempty"`
	LastFailure       *MachineFailure `json:"last_failure,omitempty" yaml:"last_failure,omitempty"`
	Recommendation    string          `json:"recommendation" yaml:"recommendation"`
}

// StuckReport is the `GET /admin/rollout/stuck` body.
type StuckReport struct {
	Count int            `json:"count" yaml:"count"`
	Stuck []StuckMachine `json:"stuck" yaml:"stuck"`
}

// TimelineEvent is one bundle rollout event projected from the audit log.
type TimelineEvent struct {
	Position   int64  `json:"position" yaml:"position"`
	At         string `json:"at" yaml:"at"`
	EventType  string `json:"event_type" yaml:"event_type"`
	Outcome    string `json:"outcome" yaml:"outcome"`
	MachineID  string `json:"machine_id,omitempty" yaml:"machine_id,omitempty"`
	Generation *int64 `json:"generation,omitempty" yaml:"generation,omitempty"`
	Reason     string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// Timeline is the `GET /admin/rollout/timeline` body.
type Timeline struct {
	Count  int             `json:"count" yaml:"count"`
	Events []TimelineEvent `json:"events" yaml:"events"`
}

// GenerationHistory is the adoption history for one generation.
type GenerationHistory struct {
	Generation           int64  `json:"generation" yaml:"generation"`
	IsLatest             bool   `json:"is_latest" yaml:"is_latest"`
	MachinesOnGeneration int64  `json:"machines_on_generation" yaml:"machines_on_generation"`
	FirstAppliedAt       string `json:"first_applied_at,omitempty" yaml:"first_applied_at,omitempty"`
	LastAppliedAt        string `json:"last_applied_at,omitempty" yaml:"last_applied_at,omitempty"`
	TotalApplies         int64  `json:"total_applies" yaml:"total_applies"`
}

// History is the `GET /admin/rollout/history` body.
type History struct {
	LatestGeneration *int64              `json:"latest_generation,omitempty" yaml:"latest_generation,omitempty"`
	Generations      []GenerationHistory `json:"generations" yaml:"generations"`
}
