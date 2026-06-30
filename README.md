# mayfly-cli

The Mayfly zero-trust SSH access CLI (Go).

> **Status (Milestone 013C).** The CLI is now the **operational console** and the
> **primary operator interface**: **authentication** (`login`/`logout`/`whoami`/
> `auth …`, 011B), **SSH/cert** (`ssh`, `cert …`, 011C), **machine administration**
> (`machine …`, 013A), **CA administration** (`ca …`, 013B), and **operations**
> (`audit`/`events`/`history`/`health`/`status`/`metrics`/`doctor`, 013C) are all
> implemented on the 011A SDK, with multi-account + profiles, `table`/`wide`/
> `json`/`yaml` output, `--watch`, `--follow`, filtering, guided CA rotation,
> PASS/WARN/FAIL diagnostics, and developer-mode timing. An operator can
> investigate and troubleshoot the whole platform without calling the REST API.
> See `docs/authentication.md`, `docs/configuration.md`, `docs/ssh.md`,
> `docs/certificates.md`, `docs/machines.md`, `docs/ca.md`, `docs/rotation.md`,
> `docs/audit.md`, `docs/diagnostics.md`, `docs/operator-handbook.md`,
> `docs/developer-mode.md`,
> `../.cursor/outputs/analysis/architecture/cli.md`, and `ADR-0018`–`ADR-0024`.

## Build & test

```bash
go build ./...
go test ./...
go vet ./...
gofmt -l .            # must print nothing
# golangci-lint run   # in CI
go build -o mayfly .  # binary
```

Release builds stamp version metadata:

```bash
go build -ldflags "\
  -X github.com/mayfly-ssh/mayfly-cli/internal/version.Version=$(git describe --tags) \
  -X github.com/mayfly-ssh/mayfly-cli/internal/version.Commit=$(git rev-parse --short HEAD) \
  -X github.com/mayfly-ssh/mayfly-cli/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o mayfly .
```

## Usage

```bash
# Authenticate (server-brokered device flow)
./mayfly login                 # default provider
./mayfly login github          # or: keycloak
./mayfly login --no-browser    # print URL + code instead of opening a browser

# Identity & status
./mayfly whoami                # add --json for machine-readable output
./mayfly auth status

# Providers & accounts
./mayfly auth providers
./mayfly auth accounts                  # active marked with *
./mayfly auth use github/vasugarg       # switch active account
./mayfly auth rename github/vasugarg work
./mayfly auth remove keycloak/vasu
./mayfly logout                         # or: logout --all

# SSH — native client experience (auto auth + certificate + OpenSSH passthrough)
./mayfly ssh web-01
./mayfly ssh deploy@web-01 -J bastion -p 2222
./mayfly ssh --dry-run web-01           # show the resolved ssh command, don't connect
./mayfly ssh web-01 -- systemctl status nginx

# Certificates (mayfly ssh manages these for you; direct control when needed)
./mayfly cert issue                     # request a fresh certificate
./mayfly cert inspect --json            # id, principals, validity, fingerprints, CA, extensions
./mayfly cert cache --prune             # list cached certs (drop expired)
./mayfly cert renew                     # reissue now
./mayfly cert remove --all

# Machine administration — the CLI is the operator interface (no manual REST)
./mayfly machine list                      # beautiful table; add -o wide|json|yaml
./mayfly machine list --status active --online
./mayfly machine list --hostname web --watch --interval 5s
./mayfly machine show <machine-id> -o yaml
./mayfly machine status                    # fleet rollout: generations, liveness, %
./mayfly machine approve <id>              # pending -> active
./mayfly machine disable <id>              # block until re-enabled (takes effect next request)
./mayfly machine enable  <id>
./mayfly machine revoke  <id> --yes        # permanently block
./mayfly machine delete  <id> --yes        # remove the record
./mayfly machine reenroll <id> --yes       # revoke + mint a fresh enrollment token
./mayfly machine rotate-identity <id> --yes
./mayfly machine heartbeat <id>            # observe liveness (agents heartbeat on their own cadence)
./mayfly machine sync <id>                 # observe CA-bundle convergence

# CA administration — the only interface needed to manage SSH CAs (no manual REST)
./mayfly ca list                           # status, in-bundle, issued counts; -o wide|json|yaml
./mayfly ca show <ca-id> -o yaml           # full detail incl. activation history
./mayfly ca create mayfly-ca-2026q3 --passphrase "$PASS"   # or set MAYFLY_CA_PASSPHRASE
./mayfly ca import legacy-ca --private-key-file ./ca_ed25519
./mayfly ca rotate                         # guided rotation: new CA + fleet rollout + warnings
./mayfly ca rollout --watch                # watch the fleet converge on the new generation
./mayfly ca enable  <ca-id>
./mayfly ca disable <ca-id>
./mayfly ca retire  <ca-id> --yes          # destroy key material, keep audit row
./mayfly ca delete  <ca-id> --yes          # remove row + key file (disabled CAs only)
./mayfly ca stats                          # aggregate signing statistics
./mayfly ca current                        # the active CA bundle (enabled CAs)
./mayfly ca export --all > trusted_user_ca_keys
./mayfly ca public-key <ca-id>             # raw OpenSSH key line (pipe-friendly)
./mayfly ca fingerprint                    # bundle fingerprint (or a CA's with an id)

# Operational console — investigate & troubleshoot the fleet (no manual REST)
./mayfly health                            # one-glance fleet health (status, machines, rollout, activity)
./mayfly status -o yaml                    # cluster/system status (CAs, bundle, API summary)
./mayfly doctor                            # PASS/WARN/FAIL diagnostics + guidance (alias: diagnose)
./mayfly audit --machine web-01 --since 24h        # search the tamper-evident audit log
./mayfly audit --event-type certificate. --result failure --tail 50
./mayfly audit --follow                    # live tail of new events
./mayfly events ca --follow                # category preset over audit
./mayfly history failures                  # curated reports: certificates|logins|machines|ca|bundles|failures
./mayfly metrics -o json                   # API request statistics + timings

# Profiles, JSON, developer timing
./mayfly --profile staging whoami --json
./mayfly --dev login github
./mayfly ssh --dev web-01               # certificate + connection timing
./mayfly machine list --dev            # API / formatting / rendering timings

# Foundation utilities
./mayfly version --json
./mayfly diagnostics            # client context, hardware caps, providers, config + origins
```

Full guides: [`docs/authentication.md`](docs/authentication.md),
[`docs/configuration.md`](docs/configuration.md),
[`docs/ssh.md`](docs/ssh.md), [`docs/certificates.md`](docs/certificates.md),
[`docs/machines.md`](docs/machines.md),
[`docs/ca.md`](docs/ca.md), [`docs/rotation.md`](docs/rotation.md),
[`docs/audit.md`](docs/audit.md), [`docs/diagnostics.md`](docs/diagnostics.md),
[`docs/operator-handbook.md`](docs/operator-handbook.md),
[`docs/developer-mode.md`](docs/developer-mode.md).

## Architecture (summary)

| Package | Responsibility |
|---|---|
| `internal/oauth` (+ `providers/mayflyserver`, `providers/github`, `providers/keycloak`) | provider-agnostic auth: `Provider`, `Registry`, `Session`, `Identity`, `TokenStore`, capabilities. `mayflyserver` brokers login through the server (default); the IdP-direct providers remain as SDK alternatives |
| `internal/authflow` | interactive device-flow orchestration: render, browser launch + manual fallback, polling, cancellation, retry, persist |
| `internal/account` | multi-account index (provider/username/email/server/timestamps — no secrets); active selection per profile |
| `internal/profile` | named server+provider profiles + resolution |
| `internal/credentials` | `Store` abstraction: OS keystore (keychain/secret-service) + AES-256-GCM encrypted-file fallback |
| `internal/clientcontext` | privacy-first per-invocation metadata + canonical `X-Mayfly-*` headers + session/request ids |
| `internal/client` | reusable HTTP client: auth + context injection, timeouts, retries, structured errors, `--dev` tracing |
| `internal/browser` | best-effort default-browser launcher |
| `internal/performance` | `--dev` profiler + timing table (duration / percent / grade) |
| `internal/ssh` | SSH primitives: verbosity, option-passthrough arg parsing (`ParseArgs`), cert/algorithm inspection, system-`ssh` launcher (`Exec`/`RenderCommand`) |
| `internal/sshkey` | Ed25519 keygen + OpenSSH private-key/public-line/fingerprint marshaling |
| `internal/certcache` | secure per-identity certificate cache (0700 dir / 0600 key, atomic, symlink-rejecting); metadata + expiry pruning |
| `internal/certs` | certificate lifecycle: issue + reuse/renew/reissue decision (never serves an expired cert) + local inspect |
| `internal/machineadmin` | machine-administration client types (mirror server DTOs) + presentation-only rendering (`table`/`wide`/`json`/`yaml` via `tabwriter` + `yaml.v3`): machine + fleet summaries |
| `internal/caadmin` | CA-administration client types (mirror server `CaView`/`CaStats`/`RotationResult` DTOs) + presentation-only rendering (`table`/`wide`/`json`/`yaml`): CA list/detail, stats, public bundle, rollout, guided rotation |
| `internal/opsadmin` | operational-console client types (mirror server audit/health/status/metrics + doctor DTOs) + presentation-only rendering (`table`/`wide`/`json`/`yaml`): audit entries/pages, health, status, API metrics, doctor report |
| `internal/config` | layered config: flags > profile > env > user > system > defaults, with value origins |
| `internal/platform` / `hardware` / `machine` / `version` / `logging` | environment & identity helpers |
| `cmd/` | cobra commands: `login`, `logout`, `whoami`, `auth …`, `ssh`, `cert …`, `machine …`, `ca …`, `audit`/`events`/`history`/`health`/`status`/`metrics`/`doctor`, `version`, `diagnostics` |
| `pkg/mayfly` | stable public API facade |

## Configuration precedence

`CLI flags` > selected `--profile` > `environment (MAYFLY_*)` > user config > system config > defaults.

- User config: `${XDG_CONFIG_HOME:-~/.config}/mayfly/config.json`
- System config: `/etc/mayfly/config.json`
- Key env vars: `MAYFLY_SERVER_URL`, `MAYFLY_PROVIDER`, `MAYFLY_CREDENTIAL_BACKEND`,
  `MAYFLY_GITHUB_CLIENT_ID`, `MAYFLY_KEYCLOAK_ISSUER`, `MAYFLY_KEYCLOAK_CLIENT_ID`,
  `MAYFLY_CA_PASSPHRASE` (storage passphrase for `ca create`/`import`/`rotate`).

## Privacy

The CLI collects only non-identifying environment context. It never collects MAC
addresses, serial numbers, browser information, or installed-software inventory.
The stable machine id is an opaque SHA-256 hash; the raw OS identifier never
leaves the host.

## License

Apache-2.0 (see `LICENSE`).
