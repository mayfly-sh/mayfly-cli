# Diagnostics, health & troubleshooting guide

This guide covers the operator commands that answer **"is Mayfly healthy, and if
not, what's wrong?"** — `mayfly health`, `mayfly status`, `mayfly metrics`, and
`mayfly doctor`. All are read-only and **authorized server-side**.

```bash
mayfly health      # one-glance fleet health
mayfly status      # cluster / system status
mayfly doctor      # PASS/WARN/FAIL diagnostics with guidance
mayfly metrics     # API request statistics + timings
```

## `mayfly health`

A single rolled-up view of the platform:

- **overall status** (`healthy` / `degraded` / `unhealthy`),
- **machines** online / offline / stale / pending / total,
- **latest CA-bundle generation** and **rollout progress** (acked vs fleet),
- **certificate activity** (recent issuance counts),
- **authentication activity** (recent logins, per-provider) and login history,
- **bundle status** (current generation, signing key, expiry),
- **audit chain** health (length, last position).

```bash
mayfly health
mayfly health -o json
mayfly health --watch        # refresh on an interval (default 2s)
```

## `mayfly status`

Lower-level **cluster/system status**: server version, uptime, CA inventory
(active/disabled/retired + selected signer), bundle generation, machine counts,
and an API summary (total requests, error rate). Useful as the machine-readable
companion to `health`.

```bash
mayfly status -o yaml
```

## `mayfly metrics`

Per-route **API statistics and request timings** collected in-memory by the
server: request count, status-code breakdown, and latency (avg / p50 / p95 / max)
for each matched route. Metrics are ephemeral (reset on server restart) — they
are operational telemetry, not audit.

```bash
mayfly metrics -o table
mayfly metrics -o json | jq '.routes[] | select(.p95_ms > 100)'
```

## `mayfly doctor` (alias `mayfly diagnose`)

End-to-end diagnostics returning **PASS / WARN / FAIL** with actionable guidance
for each check. It degrades gracefully: client-side checks always run, and
server-side checks report `WARN` (not `FAIL`) if your account lacks admin
authorization, so the command is useful to everyone.

Checks performed:

| Area | Check |
|---|---|
| Connectivity | Server reachable over HTTPS. |
| TLS | Handshake + protocol/cipher; certificate chain validity & expiry. |
| Clock drift | Local clock vs server `Date` header (WARN > 30s, FAIL > 5m). |
| OAuth session | A stored, unexpired session exists for the active account. |
| Providers | Configured auth providers are reachable. |
| Machine enrollment | Fleet has machines; flags pending/stale/offline. |
| CA consistency | At least one active CA; a signer is selected. |
| Bundle generation | A signed bundle exists and is current/unexpired. |
| Helper status | `mayfly-helper` present/configured (client host). |
| Agent status | Agent convergence inferred from fleet rollout. |

```bash
mayfly doctor
mayfly doctor -o json          # machine-readable PASS/WARN/FAIL report
mayfly diagnose                # same command
```

Exit code is non-zero when any check is `FAIL`, so `mayfly doctor` is safe to use
as a readiness gate in scripts.

> Note: `mayfly diagnostics` (separate command) still prints the raw client
> foundation/context dump; `mayfly doctor`/`diagnose` is the health-check tool.

## Developer mode

Every command above accepts `--dev` to emit DNS/TLS/HTTP/serialize/render/output
timings to stderr. See `developer-mode.md`.

## Typical troubleshooting flow

```bash
mayfly doctor                 # what's wrong, with guidance
mayfly health                 # the fleet picture
mayfly history failures --tail 50   # recent denials/failures
mayfly audit --machine <id> --since 1h   # zoom into one machine
mayfly metrics                # is the server slow / erroring?
```
