# mayfly-cli

The Mayfly zero-trust SSH access CLI (Go).

> **Milestone 011A — foundation only.** This repository currently provides the
> reusable **client SDK** that every future command will share (OAuth provider
> framework, client context, secure credential storage, HTTP client, developer
> mode, SSH diagnostics, layered configuration). The user-facing `login` / `ssh`
> / `cert` commands are added in later milestones. See
> `../.cursor/outputs/analysis/architecture/cli.md` and `ADR-0018`.

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

## Try the foundation

```bash
./mayfly version --json
./mayfly diagnostics            # shows client context, hardware caps, providers, config + origins
./mayfly --dev diagnostics      # also prints a developer timing table
```

## Architecture (summary)

| Package | Responsibility |
|---|---|
| `internal/oauth` (+ `providers/github`, `providers/keycloak`) | provider-agnostic auth: `Provider`, `Registry`, `Session`, `Identity`, `TokenStore` |
| `internal/credentials` | `Store` abstraction: OS keystore (keychain/secret-service) + AES-256-GCM encrypted-file fallback |
| `internal/clientcontext` | privacy-first per-invocation metadata + canonical `X-Mayfly-*` headers + session/request ids |
| `internal/client` | reusable HTTP client: auth + context injection, timeouts, retries, structured errors, `--dev` tracing |
| `internal/performance` | `--dev` profiler + timing table |
| `internal/ssh` | SSH diagnostics primitives (verbosity, option passthrough, cert/algorithm inspection) — no commands |
| `internal/config` | layered config: flags > env > user > system > defaults, with value origins |
| `internal/platform` / `hardware` / `machine` / `version` / `logging` | environment & identity helpers |
| `pkg/mayfly` | stable public API facade |

## Configuration precedence

`CLI flags` > `environment (MAYFLY_*)` > user config > system config > defaults.

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
