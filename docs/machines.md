# Machine administration guide

`mayfly machine` is the **primary operator interface** for the Mayfly fleet. It
lists, inspects, and drives the lifecycle of every enrolled machine so you never
have to call the REST API by hand. Every operation is authenticated with your
active account, **authorized server-side (deny-by-default)**, and **audited**
(mutations and denials are recorded in the tamper-evident audit log with your
operator identity and client context).

```bash
mayfly machine list
mayfly machine show <machine-id>
mayfly machine status
```

`machine` has the aliases `machines` and `m`.

## Commands

| Command | Purpose |
|---|---|
| `list` | List enrolled machines (filterable). |
| `show <id>` | Show one machine's full detail. |
| `status` | Fleet rollout summary (generations, liveness, rollout %). |
| `approve <id>` | Approve a pending machine (`pending → active`). |
| `enable <id>` | Re-enable a disabled machine. |
| `disable <id>` | Disable a machine (blocks it until re-enabled). |
| `revoke <id>` | Revoke a machine (permanently blocks it). |
| `delete <id>` | Permanently delete the machine record (`--yes`). |
| `reenroll <id>` | Revoke + mint a fresh enrollment token (`--yes`). |
| `rotate-identity <id>` | Rotate a machine's identity = revoke + new token (`--yes`). |
| `heartbeat <id>` | Observe a machine's liveness / last heartbeat. |
| `sync <id>` | Observe a machine's CA-bundle convergence. |

## Output formats

All read commands accept `-o`/`--output`:

```bash
mayfly machine list -o table   # default — a beautiful aligned table
mayfly machine list -o wide    # table + OS/arch/agent-version/fingerprint/last-sync
mayfly machine list -o json    # machine-readable, scripting-friendly
mayfly machine list -o yaml    # machine-readable, human-friendly
```

`json` and `yaml` emit exactly the server's response shape, so they round-trip
cleanly through `jq`, `yq`, and the like.

## Filtering

`machine list` filters server-side:

```bash
mayfly machine list --status active
mayfly machine list --online                 # shortcut for --liveness online
mayfly machine list --offline                # or --stale
mayfly machine list --liveness stale
mayfly machine list --hostname web           # case-insensitive substring
mayfly machine list --generation 7           # current OR synced generation == 7
mayfly machine list --os linux --arch arm64
mayfly machine list --agent-version 0.1.0
```

`--online`, `--offline`, `--stale`, and `--liveness` are mutually exclusive; the
CLI rejects contradictory combinations.

> **Note on `provider` / `group` / `role` / `label`.** Machines authenticate with
> their own Ed25519 keypair, not an identity provider — their public-key
> fingerprint *is* their identity. Identity-provider attributes (provider, group,
> role, label) therefore do not apply to machines and are intentionally not
> machine filters; use them when filtering *people* (`auth`/authorization), not
> hosts. See `ADR-0022`.

## Watch mode

Read commands (`list`, `show`, `status`, `heartbeat`, `sync`) support live
refresh:

```bash
mayfly machine list --watch                  # refresh every 2s (default)
mayfly machine list --watch --interval 5s
mayfly machine status -w --interval 10s
```

Watch mode shows status, heartbeat/liveness, generation, certificate/up-to-date,
and rollout. It is disabled for `-o json`/`-o yaml` (those emit a single
document); use `table`/`wide` to watch.

## Lifecycle and how it takes effect

Mayfly's agents are **pull-based**: they enroll, heartbeat, and fetch the signed
CA bundle on their own cadence — the server never pushes to them. Administrative
state changes are enforced at the server's per-request authentication gate:

- **`disable` / `revoke`** — the machine's next signed request (heartbeat or
  bundle fetch) is rejected by the server, so the machine stops converging
  immediately. `enable` restores it.
- **`delete`** — the record is removed; the machine becomes unknown and all its
  signed requests fail. Its hostname and key are freed for re-enrollment.
- **`reenroll` / `rotate-identity`** — the old machine is revoked and **deleted**,
  and the server mints a **fresh single-use enrollment token**. Apply it on the
  host (out-of-band) to enroll with a brand-new keypair — that is exactly an
  identity rotation. The old identity is dead the moment the command returns.

  ```bash
  mayfly machine rotate-identity <id> --yes -o json
  # -> { "token": "mf_enroll_…", "id": "…", "expires_at": "…", "single_use": true }
  ```

Destructive commands (`delete`, `reenroll`, `rotate-identity`) require `--yes`
in human output. In `-o json`/`-o yaml` they proceed unprompted for scripting.

## Observational `heartbeat` and `sync`

Because the server cannot push, `heartbeat` and `sync` **observe** rather than
force. They report the current liveness / convergence and, with `--watch`, keep
refreshing until the agent reports new state on its own cadence:

```bash
mayfly machine heartbeat <id> --watch        # wait for the next heartbeat
mayfly machine sync <id> --watch             # wait for the bundle to converge
```

## Developer mode

Add `--dev` to any command to print per-phase timings (API, formatting,
rendering, network):

```bash
mayfly machine list --dev
```

See [`developer-mode.md`](developer-mode.md).

## Security

- Every `machine` operation requires an authorized operator (deny-by-default;
  the same policy that guards the CA admin API).
- Every **mutation** (`approve`/`enable`/`disable`/`revoke`/`delete`/`reenroll`/
  `rotate-identity`) and every **authorization denial** is written to the
  hash-chained audit log with your operator identity and privacy-preserving
  client context. Read commands (`list`/`show`/`status`) are not audited (so
  `--watch` cannot flood the log) but still require authorization.
- Enrollment tokens returned by `reenroll`/`rotate-identity` are shown once and
  are single-use; treat them as secrets.
