# Certificate guide

`mayfly ssh` manages certificates automatically, but the `cert` commands let you
inspect and control them directly.

```bash
mayfly cert issue [host]        # request a fresh certificate now
mayfly cert renew [host]        # reissue immediately
mayfly cert inspect [--file p]  # show the cached (or a given) certificate
mayfly cert cache [--prune]     # list cached certificates (and drop expired)
mayfly cert remove [--all]      # delete cached material
```

All of these support `--json`.

## Lifecycle

Mayfly issues **short-lived, principal-based** certificates. The principal is
derived server-side from your authenticated identity — you cannot request a
principal. Because the certificate is not host-scoped, one certificate is valid
for every host you may reach, and the cache holds at most one certificate per
identity (profile + provider + subject + server).

There is no separate renewal API: **renew = reissue**. When connecting, Mayfly
decides automatically:

- **reuse** — cached cert has more than `renew_threshold_seconds` remaining;
- **renew** — cached cert is within the threshold or expired;
- **issue** — nothing cached.

Expired certificates are never used and are pruned from the cache.

## The cache

Cached material lives under the cert cache directory (default
`<user-config>/mayfly/certs/`), one directory per identity:

```
<root>/<id-hash>/
  id_ed25519           private key   (0600)
  id_ed25519.pub       public key    (0644)
  id_ed25519-cert.pub  certificate   (0644)
  meta.json            metadata      (0600)
```

The directory is `0700`, the private key `0600`, writes are atomic, and symlinked
cache paths are rejected. Tracked metadata: certificate serial, issued/expiry
times, principal, key fingerprint, server, provider, hostname, and CA id/
fingerprint. OAuth tokens are **not** stored here — they remain in the secure
credential store.

> Why the private key is on disk: the system `ssh` client consumes it via `-i`,
> and ControlMaster/ProxyJump require a stable key path — exactly like
> `~/.ssh/id_*`. Short-lived certificates bound the exposure (a key without a
> current certificate is useless). See ADR-0020.

## Inspecting

```bash
mayfly cert inspect
mayfly cert inspect --json
mayfly cert inspect --file ./id_ed25519-cert.pub
```

Shows: type, key id, serial, principals, valid-after/before, signature
algorithm, subject-key fingerprint, issuing-CA fingerprint, critical options,
and extensions.

## Configuration

| Setting | Flag | Env | Default |
|---------|------|-----|---------|
| Cache directory | `--cert-cache` | `MAYFLY_CERT_CACHE_PATH` | `<user-config>/mayfly/certs` |
| Renew threshold (s) | `--renew-threshold` | `MAYFLY_RENEW_THRESHOLD` | `60` |
| Requested lifetime (s) | `--cert-lifetime` | `MAYFLY_CERT_LIFETIME` | `0` (server default; clamped 60–3600) |
| Preferred SSH user | `--ssh-user` | `MAYFLY_PREFERRED_USERNAME` | (none) |
| Default SSH options | — (config file) | `MAYFLY_SSH_OPTIONS` | (none) |

See [configuration.md](configuration.md) for precedence and profiles.

## Notes

- Certificate issuance currently authenticates with a GitHub token; Keycloak-only
  accounts cannot yet issue certificates (tracked as BL-033).
- Provider tokens may expire; if issuance fails with an auth error, run
  `mayfly login` (BL-032).
