# Configuration guide

## Precedence (highest wins)

1. Command-line flags (`--server`, `--provider`, `--credential-backend`, …)
2. Selected **profile** (`--profile`, `MAYFLY_PROFILE`, or the default profile)
3. Environment variables (`MAYFLY_SERVER_URL`, `MAYFLY_PROVIDER`, …)
4. User config file
5. System config file
6. Built-in defaults

`mayfly diagnostics` (alias `doctor`) prints the effective values and where each
came from (the "origin").

## Profiles

A profile bundles a target **server** and default **provider**, so you can keep
several environments and switch without editing config or deleting credentials.

Profiles are stored in `profiles.json` under your user config dir
(`~/.config/mayfly/` on Linux, `~/Library/Application Support/mayfly/` on macOS):

```json
{
  "default": "work",
  "profiles": [
    { "name": "work",    "server": "https://mayfly.corp.example", "provider": "github" },
    { "name": "staging", "server": "https://mayfly.stg.example",  "provider": "keycloak" }
  ]
}
```

Select a profile per command:

```bash
mayfly --profile staging login
mayfly --profile staging whoami
```

The active account is tracked **per profile**, so each environment has its own
"current" identity. Credentials are namespaced by profile so the same identity in
two environments never collides.

## Accounts

Account metadata (provider, username, email, server, timestamps — never secrets)
lives in `accounts.json` next to `profiles.json`. Tokens live only in the
platform credential store, never in these files.

## Credential backend

```bash
mayfly --credential-backend auto|keyring|file ...
# or
export MAYFLY_CREDENTIAL_BACKEND=file
export MAYFLY_CREDENTIAL_PASSPHRASE=...   # for the encrypted file fallback
```

`auto` prefers the OS keychain / Secret Service and falls back to an encrypted
file (AES-256-GCM + scrypt).
