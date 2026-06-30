# mayfly-cli

The Mayfly zero-trust SSH access CLI (Go).

> **Status (Milestone 011B).** The full **authentication experience** is
> implemented on the 011A SDK: `login` / `logout` / `whoami` / `auth …` /
> `version`, multi-account + profiles, and developer-mode timing. Login is
> brokered through the mayfly-server (ADR-0019). SSH commands come next.
> See `docs/authentication.md`, `docs/configuration.md`, `docs/developer-mode.md`,
> `../.cursor/outputs/analysis/architecture/cli.md`, and `ADR-0018`/`ADR-0019`.

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

# Profiles, JSON, developer timing — available on every auth command
./mayfly --profile staging whoami --json
./mayfly --dev login github

# Foundation utilities
./mayfly version --json
./mayfly diagnostics            # client context, hardware caps, providers, config + origins
```

Full guides: [`docs/authentication.md`](docs/authentication.md),
[`docs/configuration.md`](docs/configuration.md),
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
| `internal/ssh` | SSH diagnostics primitives (verbosity, option passthrough, cert/algorithm inspection) — no commands |
| `internal/config` | layered config: flags > profile > env > user > system > defaults, with value origins |
| `internal/platform` / `hardware` / `machine` / `version` / `logging` | environment & identity helpers |
| `cmd/` | cobra commands: `login`, `logout`, `whoami`, `auth …`, `version`, `diagnostics` |
| `pkg/mayfly` | stable public API facade |

## Configuration precedence

`CLI flags` > selected `--profile` > `environment (MAYFLY_*)` > user config > system config > defaults.

- User config: `${XDG_CONFIG_HOME:-~/.config}/mayfly/config.json`
- System config: `/etc/mayfly/config.json`
- Key env vars: `MAYFLY_SERVER_URL`, `MAYFLY_PROVIDER`, `MAYFLY_CREDENTIAL_BACKEND`,
  `MAYFLY_GITHUB_CLIENT_ID`, `MAYFLY_KEYCLOAK_ISSUER`, `MAYFLY_KEYCLOAK_CLIENT_ID`.

## Privacy

The CLI collects only non-identifying environment context. It never collects MAC
addresses, serial numbers, browser information, or installed-software inventory.
The stable machine id is an opaque SHA-256 hash; the raw OS identifier never
leaves the host.

## License

Apache-2.0 (see `LICENSE`).
