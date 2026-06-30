# Audit & events guide

`mayfly audit` is the operator's window into **everything that happened** across
the Mayfly platform. It searches the tamper-evident, append-only audit log —
certificate issuance, authentication, machine lifecycle, CA changes, bundle
rollout, and authorization denials — with rich filters and live streaming. Every
query is authenticated with your active account and **authorized server-side
(deny-by-default)**; reads are *not* audited (so `--watch`/`--follow` polling
never floods the chain), but an authorization denial is.

```bash
mayfly audit                                   # most recent events
mayfly audit --event-type certificate. --result failure
mayfly audit --machine web-01 --since 24h
mayfly audit --follow                          # live tail
```

## Commands

| Command | Purpose |
|---|---|
| `audit` | Full search of the audit log with all filters. |
| `events [category]` | Shortcut: filter by category (`certificate`, `machine`, `ca`, `auth`, `bundle`, `ops`). |
| `history <kind>` | Curated reports: `certificates`, `issuance`, `logins`, `auth`, `machines`, `ca`, `bundles`, `rollout`, `failures`. |

`events` and `history` are thin presets over `audit` — they set an event-type
prefix (or `result=failure`) and accept the same flags.

## Filters

| Flag | Matches |
|---|---|
| `--event-type <t>` | Exact event type, or a prefix when it ends in `.` (e.g. `certificate.`). |
| `--actor` / `--operator` / `--username` | The actor (operator/user) — case-insensitive. |
| `--machine <id|host>` | Machine id (audit subject) or reported hostname. |
| `--provider <id>` | Auth provider (`github`, `keycloak`, …). |
| `--serial <n>` | Certificate serial. |
| `--request-id <id>` | Correlation id (`X-Request-Id`). |
| `--result success|failure` | Derived from the event type (denied/failed/rejected/rollback/error ⇒ failure). |
| `--since`, `--until` | RFC3339 (`2026-06-24T12:00:00Z`) or a relative duration (`30m`, `24h`, `7d`). |

## Paging, tailing, following

| Flag | Effect |
|---|---|
| `--limit N` | Maximum entries (default 50, server max 1000). |
| `--tail N` | Show only the most recent N (overrides `--limit`). |
| `--follow` / `-f` | Stream new entries until interrupted (polls with a position cursor). |
| `--watch` / `-w` | Re-render the whole view on an interval. |
| `--interval` | Poll/refresh interval for `--follow`/`--watch` (default 2s). |

`--follow` seeds from the latest entry and then prints only new events as they
are appended, advancing a `chain_position` cursor — it never replays history.
`--follow` is not available with `json`/`yaml` output (use `--watch` or repeated
queries instead).

## Output formats

All commands accept `-o`/`--output`: `table` (default), `wide` (adds provider +
request id), `json`, `yaml`. JSON/YAML are stable, scriptable shapes:

```bash
mayfly audit --event-type certificate.issued -o json | jq '.entries[].metadata.serial'
mayfly history failures -o yaml
```

## Examples

```bash
# Who was issued a certificate for web-01 in the last day?
mayfly audit --machine web-01 --event-type certificate.issued --since 24h

# Trace one request end-to-end by correlation id.
mayfly audit --request-id 0192f1a0-...-7b

# Recent denials across the platform.
mayfly history failures --tail 50

# Live-tail CA changes during a rotation.
mayfly events ca --follow
```

## Developer mode

Add `--dev` to any command to print per-phase timings (DNS, TLS, HTTP, JSON
serialize/parse, rendering, overall) to stderr. See `developer-mode.md`.

## Security notes

- The audit log is append-only and hash-chained; `mayfly audit` only *reads* it.
- Audit metadata never contains secrets (tokens, private keys, passphrases, or
  full certificates); the CLI displays exactly what the server recorded.
- Searching requires an authorized account; unauthorized attempts are denied and
  themselves audited (`ops.admin_denied`).
