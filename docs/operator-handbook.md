# Mayfly operator handbook

This handbook is the task-oriented entry point for operating a Mayfly fleet
**entirely from the CLI**. Every workflow below is authenticated with your active
account, authorized server-side (deny-by-default), and — for mutations — audited.
You should never need to call the REST API by hand.

For command-level detail follow the linked guides; this page is the "what do I
run for X?" index.

## First: who am I and is the platform healthy?

```bash
mayfly whoami            # active account / provider / server
mayfly health            # one-glance fleet health
mayfly doctor            # PASS/WARN/FAIL diagnostics + guidance
```

See [`diagnostics.md`](diagnostics.md).

## Daily access (engineers)

```bash
mayfly login                 # device-flow auth (see authentication.md)
mayfly ssh web-01            # auto issue cert + connect (see ssh.md / certificates.md)
```

## Fleet administration

| Goal | Command | Guide |
|---|---|---|
| List / inspect machines | `mayfly machine list` / `show <id>` | [`machines.md`](machines.md) |
| Approve / disable / revoke a machine | `mayfly machine approve|disable|revoke <id>` | [`machines.md`](machines.md) |
| Watch rollout convergence | `mayfly machine status` / `ca rollout --watch` | [`machines.md`](machines.md), [`rotation.md`](rotation.md) |
| Manage SSH CAs | `mayfly ca list|create|import|enable|disable|retire` | [`ca.md`](ca.md) |
| Rotate the CA | `mayfly ca rotate` (guided) | [`rotation.md`](rotation.md) |

## Investigate: "what happened?"

| Question | Command |
|---|---|
| Everything, filtered | `mayfly audit --machine <id> --since 24h` |
| By category | `mayfly events {certificate|machine|ca|auth|bundle|ops}` |
| Curated history | `mayfly history {certificates|logins|machines|ca|bundles|failures}` |
| Live tail | `mayfly audit --follow` |
| Trace one request | `mayfly audit --request-id <id>` |

Filters: `--machine`, `--operator`/`--username`, `--provider`, `--serial`,
`--request-id`, `--event-type`, `--result success|failure`, `--since`/`--until`.
See [`audit.md`](audit.md).

## Troubleshoot: "what's wrong?"

```bash
mayfly doctor                       # ranked PASS/WARN/FAIL with guidance + exit code
mayfly health                       # fleet picture (machines, rollout, activity)
mayfly history failures --tail 50   # recent denials / failures
mayfly metrics                      # API request stats + timings (is the server slow?)
mayfly status                       # cluster/system status (CAs, bundle, API summary)
```

`mayfly doctor` checks connectivity, TLS + certificate chain, clock drift, OAuth
session, provider availability, machine enrollment, CA consistency, bundle
generation, helper, and agent convergence. See [`diagnostics.md`](diagnostics.md).

## Output, watching, scripting

- Every read command accepts `-o table|wide|json|yaml`.
- `--watch [--interval]` re-renders on a cadence; `audit`/`events` also support
  `--follow`/`-f` for live tailing.
- `--dev` prints DNS/TLS/HTTP/serialize/render timings to stderr
  ([`developer-mode.md`](developer-mode.md)).
- JSON/YAML shapes are stable and safe to pipe into `jq`/`yq`.

## Security model (operator-relevant)

- Reads are authorized but **not** audited (so polling/watching never floods the
  log); **mutations and authorization denials are** audited with your operator
  identity and privacy-preserving client context.
- The audit log is append-only and hash-chained; the CLI only reads it.
- API metrics are in-memory operational telemetry and reset on server restart —
  they are not part of the durable audit trail.

## See also

- Server architecture & APIs: `../../mayfly-server/README.md`
- CLI architecture: `../../.cursor/outputs/analysis/architecture/cli.md`
- Decisions: `ADR-0018`–`ADR-0024`
