# Fleet rollout guide

This guide covers `mayfly rollout` — the operator console for **observing and
managing CA-bundle rollouts across the fleet**. After a CA rotation (`mayfly ca
rotate`) the server advertises a new generation; agents converge on their own
sync cadence. These commands let you watch that convergence, find what's stuck,
and understand why — entirely from the CLI, no REST required.

All subcommands are read-only and **authorized server-side** (deny-by-default).
They support `-o table|wide|json|yaml`, `--watch`/`--interval`, and the global
`--dev` timings.

```bash
mayfly rollout status        # progress, completion %, ETA, health
mayfly rollout watch         # live dashboard (progress bar + breakdown)
mayfly rollout summary       # rich one-screen summary with health reasons
mayfly rollout generations   # machines per CA generation
mayfly rollout machines      # per-machine rollout state (filterable)
mayfly rollout stuck         # machines that can't progress + remediation
mayfly rollout health        # Healthy | Degraded | Blocked | Failed + reasons
mayfly rollout explain       # why the rollout is incomplete, by category
mayfly rollout timeline      # recent apply/rollback/verify events
mayfly rollout history       # generation adoption over time
```

## `status`, `watch`, `summary`

`status` shows the headline: latest generation, a progress bar, completion
percentage over **active** machines, the healthy/pending/stale/offline/failed
breakdown, liveness counts, and an ETA. `watch` is `status` on a refresh loop
(`--interval`, default 2s); `summary` adds the health verdict's reasons and the
per-generation table.

```bash
mayfly rollout status
mayfly rollout watch --interval 5s
mayfly rollout status -o json | jq '.percentage, .eta.eta_seconds'
```

The **ETA** is a transparent estimate: the recent apply rate
(`bundle.applied` for the latest generation in the last hour) divided into the
machines still remaining. It is `unknown` when no recent applies are observed and
`complete` at 100%. The inputs (`applies_last_hour`, `per_hour`) are in the JSON.

## `health`

Scores the rollout as one of four verdicts, with reasons:

| Verdict | Meaning |
|---|---|
| **Healthy** | every active machine is on the latest generation. |
| **Degraded** | incomplete, but reachable machines are still converging. |
| **Blocked** | incomplete and no reachable machine is lagging — progress needs operator action. |
| **Failed** | a published bundle failed signature verification on an agent (a trust signal). |

```bash
mayfly rollout health
mayfly rollout health -o json | jq '.status, .reasons'
```

## `explain` — why is the rollout incomplete?

Buckets every not-up-to-date machine into exactly one category (priority order)
and gives a recommended action per category:

| Category | Meaning | Recommended action |
|---|---|---|
| `bundle_verification_failure` | agent rejected the bundle signature | check the pinned signing key; re-enroll if rotated |
| `helper_failure` | rolled back after a failed `sshd` reload | inspect `journalctl -u mayfly-agent` + sshd config |
| `offline` | no recent heartbeat | power on the host / start the agent |
| `heartbeat_stale` | heartbeats arriving late | check network/agent health |
| `disabled_machine` | administratively disabled | `mayfly machine enable <id>` |
| `revoked_machine` | revoked; won't receive bundles | `mayfly machine delete <id>` or re-enroll |
| `generation_mismatch` | online, hasn't pulled yet | none; converges on next sync |

```bash
mayfly rollout explain
```

## `machines`, `stuck`

`machines` lists every machine's rollout state (`current`/`lagging`/`stuck`) with
its synced/latest generation and category. Filter with `--state` and
`--generation`. `stuck` is the actionable subset (offline, failed, disabled,
revoked) sorted most-behind-first, each with a concrete remediation.

```bash
mayfly rollout machines --state lagging
mayfly rollout machines --generation 3 -o wide
mayfly rollout stuck
```

## `generations`, `timeline`, `history`

- `generations` — machine population per synced generation, with the latest
  flagged.
- `timeline` — recent bundle events (`applied`/`rolled_back`/`verification_failed`
  /`downloaded`) from the audit log; `--limit` (max 500).
- `history` — per-generation adoption: current population, total applies, and the
  first/last applied timestamps.

```bash
mayfly rollout generations
mayfly rollout timeline --limit 100 -o wide
mayfly rollout history
```

## Typical flow after a rotation

```bash
mayfly ca rotate                 # publish a new generation
mayfly rollout watch             # watch the fleet converge
mayfly rollout explain           # if it stalls, why?
mayfly rollout stuck             # who needs a nudge, and how
mayfly rollout timeline          # confirm applies (and any rollbacks)
```

## Developer mode

Every command accepts `--dev` to emit DNS/TLS/HTTP/serialize/render/output
timings to stderr. See `developer-mode.md`.
