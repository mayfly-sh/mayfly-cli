# Certificate Authority administration guide

`mayfly ca` is the **only interface** an operator needs to manage Mayfly's SSH
User Certificate Authorities — the keys the server signs short-lived engineer
certificates with. It lists, inspects, creates, imports, exports, rotates,
enables, disables, retires, and deletes CAs so you never have to call the REST
API by hand. Every operation is authenticated with your active account,
**authorized server-side (deny-by-default)**, and every **mutation** is
**audited** (recorded in the tamper-evident, hash-chained audit log with your
operator identity and privacy-preserving client context).

```bash
mayfly ca list
mayfly ca show <ca-id>
mayfly ca stats
mayfly ca rollout
```

`ca` has the aliases `certificate-authority` and `authorities`.

## Commands

| Command | Purpose |
|---|---|
| `list` | List all CAs (status, in-bundle, issued counts). |
| `show <id>` | Show one CA's full detail incl. synthesized activation history. |
| `create <key-id>` | Generate a new Ed25519 CA (enabled). |
| `import <key-id>` | Import an existing OpenSSH private key as a CA. |
| `export [id]` | Print a CA public key, or the whole active bundle with `--all`. |
| `rotate` | Guided rotation: generate a new CA + report fleet rollout. |
| `enable <id>` | Add a CA to the signing set + trust bundle. |
| `disable <id>` | Remove a CA from the signing set + trust bundle. |
| `retire <id>` | Destroy a disabled CA's key material (keeps the audit row). |
| `delete <id>` | Permanently remove a disabled, unused CA (row + key file). |
| `stats` | Aggregate signing statistics (issued counts per CA). |
| `rollout` | Machine rollout status across CA generations. |
| `current` | The currently active CA bundle (the enabled CAs). |
| `public-key <id>` | Print a CA's public key. |
| `fingerprint [id]` | Print a CA fingerprint, or the bundle fingerprint with no id. |

## Output formats

All read commands accept `-o`/`--output`:

```bash
mayfly ca list -o table   # default — aligned table (key id, status, in bundle, issued)
mayfly ca list -o wide    # table + id, generation, created
mayfly ca list -o json    # machine-readable, scripting-friendly
mayfly ca list -o yaml    # machine-readable, human-friendly
```

`json` and `yaml` emit exactly the server's response shape (`CaView`), so they
round-trip cleanly through `jq`, `yq`, and the like. `public-key`/`export` print
the raw OpenSSH key line in `table` mode so you can pipe it straight into
`authorized_keys`, `TrustedUserCAKeys`, or `ssh-keygen -l`.

## Watch mode

Read commands (`list`, `show`, `stats`, `rollout`, `current`) support live
refresh:

```bash
mayfly ca rollout --watch                  # refresh every 2s (default)
mayfly ca list --watch --interval 5s
mayfly ca stats -w --interval 10s
```

Watch is disabled for `-o json`/`-o yaml` (those emit a single document); use
`table`/`wide` to watch.

## Creating, importing, and exporting

```bash
# Generate a new CA (passphrase via flag or MAYFLY_CA_PASSPHRASE)
mayfly ca create mayfly-ca-2026q3 --passphrase "$PASS"
export MAYFLY_CA_PASSPHRASE=…    # then omit --passphrase

# Import an existing OpenSSH CA private key
mayfly ca import legacy-ca --private-key-file ./ca_ed25519 --passphrase "$PASS"

# Export the active trust bundle (e.g. to seed TrustedUserCAKeys out-of-band)
mayfly ca export --all > trusted_user_ca_keys
mayfly ca public-key <ca-id>          # one CA's public key
mayfly ca fingerprint                 # the current bundle fingerprint
```

The passphrase must match the server's storage passphrase; it is **never logged
or audited**. No command ever prints, returns, or audits private key material —
only public keys and fingerprints.

## Lifecycle and how it takes effect

Mayfly's agents are **pull-based** and the server runs **1–64 CAs**, picking an
enabled one at random to sign each certificate. Admin changes flow to the fleet
through the signed CA trust bundle, which agents fetch on their own cadence:

- **`enable`** — the CA joins the signing set and the published bundle; the
  bundle generation bumps and the fleet picks it up on the next sync.
- **`disable`** — the CA leaves the signing set and bundle (generation bumps).
  The key still exists; `enable` restores it.
- **`retire`** — destroys the private key material but keeps the metadata row so
  the audit trail and history remain intact. The CA must be disabled first.
- **`delete`** — removes the metadata row **and** the key file. The CA must be
  disabled first; an active CA is refused.

`retire` and `delete` are **dependency-gated**: if any machine may still depend
on the key the server refuses unless you pass `--force` (which is loudly
audited). In human output they also require `--yes`; structured output proceeds
unprompted for scripting.

```bash
mayfly ca disable <ca-id>
mayfly ca retire  <ca-id> --yes          # destroys key material, keeps row
mayfly ca delete  <ca-id> --yes          # removes row + key file
mayfly ca delete  <ca-id> --yes --force  # override dependency safety (audited)
```

## Safety guards

The server refuses unsafe operations (fail-closed, `409 Conflict`):

- **Cannot delete an active CA** — disable it first.
- **Cannot empty the bundle** — the last enabled CA cannot be disabled, and
  retire/delete require a disabled CA, so there is always ≥1 CA to sign with.
- **Cannot import a duplicate** — a key whose fingerprint, public key, or key id
  collides with a managed CA is rejected.
- **Cannot enable an invalid key** — non-Ed25519 or unparseable keys are
  rejected at import/load, so they can never enter the signing set.

## Rotation

Use `mayfly ca rotate` for the guided rotation workflow — see
[`rotation.md`](rotation.md).

## Developer mode

Add `--dev` to any command to print per-phase timings (HTTP/network latency,
JSON serialize/parse, DNS/TLS):

```bash
mayfly ca list --dev
mayfly ca rotate --dev
```

See [`developer-mode.md`](developer-mode.md).

## Security

- Every `ca` operation requires an authorized operator (deny-by-default; the
  same policy that guards the machine admin API).
- Every **mutation** (`create`/`import`/`enable`/`disable`/`rotate`/`retire`/
  `delete` and forced/denied variants) and every **authorization denial** is
  written to the hash-chained audit log with your operator identity and
  privacy-preserving client context. Read commands (`list`/`show`/`stats`/
  `rollout`/`current`/`public-key`/`fingerprint`) are not audited (so `--watch`
  cannot flood the log) but still require authorization.
- Passphrases and private keys never appear in logs, audit entries, or any API
  response.
