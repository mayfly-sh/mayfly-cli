# Authentication guide

Mayfly authenticates you through your organization's identity provider and stores
a short-lived credential securely on your machine. Login is **brokered through the
mayfly-server** — OAuth client secrets stay server-side and every login is
authorized and audited centrally (see ADR-0019).

## Logging in

```bash
mayfly login                 # use the configured default provider
mayfly login github          # choose GitHub explicitly
mayfly login keycloak        # choose Keycloak explicitly
```

What happens:

1. The CLI asks the server to start a device flow for the chosen provider.
2. It prints a short **user code** and a **verification URL**, and tries to open
   your browser. If it can't (headless/SSH/CI, or `--no-browser`), copy the URL
   and code manually.
3. It polls until you approve, you cancel (Ctrl-C), or the code expires (it will
   request a new code automatically once).
4. On approval the credential is stored via your platform credential store and
   the account becomes active.

Nothing secret is ever printed — only the non-secret user code and URL.

## Inspecting your identity and status

```bash
mayfly whoami                # identity, session, environment
mayfly whoami --json         # machine-readable
mayfly auth status           # authenticated? token valid? server reachable?
mayfly auth status --json
```

`auth status` also reports request latency and clock drift against the server.

## Multiple accounts

You can be logged into several accounts at once (across providers) and switch
between them. Tokens are kept separately; switching does not delete credentials.

```bash
mayfly auth accounts                 # list (active marked with *)
mayfly auth accounts --all-profiles  # across all profiles
mayfly auth use github/vasugarg      # switch active account
mayfly auth rename github/vasugarg work   # set a display alias
mayfly auth remove keycloak/vasu     # remove one account + its credential
mayfly logout                        # log out the active account
mayfly logout --all                  # log out everything in this profile
```

Account selectors accept the `provider/username` form, a bare username (when
unambiguous), or an alias.

## Providers

```bash
mayfly auth providers          # name, configured, enabled, default, capabilities
mayfly auth providers --json
```

Capabilities reported: Device Flow, Browser Flow (future), Refresh Support, OIDC
Discovery.

## Flags

All authentication commands support `--json`, `--profile <name>`, and `--dev`
(developer timing). See `configuration.md` and `developer-mode.md`.

## Notes

- The server-brokered flow returns a short-lived access token (no refresh token),
  so when a token expires you simply `mayfly login` again. Transparent refresh is
  planned (BL-032).
- Organizations/groups/roles in `whoami` are shown best-effort and depend on
  server support (BL-028).
