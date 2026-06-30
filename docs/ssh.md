# SSH guide

`mayfly ssh` makes Mayfly feel like a native SSH client. It authenticates, obtains
or reuses a short-lived certificate, and then hands off to your system `ssh`
client with full OpenSSH option compatibility. You never manage certificates by
hand.

```bash
mayfly ssh web-01
mayfly ssh deploy@web-01
mayfly ssh -J bastion -p 2222 web-01
mayfly ssh web-01 -- systemctl status nginx
```

## What happens on `mayfly ssh`

1. **Authenticate** — the active account's stored session is reused. If you are
   not logged in and the terminal is interactive, a device-flow login starts
   automatically; otherwise run `mayfly login` first.
2. **Cache lookup** — Mayfly looks for a cached certificate for your identity.
3. **Reuse / renew / issue**:
   - **Reuse** a cached certificate when it has more than the renew threshold of
     life remaining.
   - **Renew (reissue)** when it is within the threshold or expired.
   - **Issue** a fresh certificate when none is cached.
   An expired certificate is never handed to OpenSSH.
4. **Launch OpenSSH** — Mayfly injects `-i <key>`, `-o CertificateFile=<cert>`,
   and `-o IdentitiesOnly=yes`, then execs your system `ssh`, inheriting the
   terminal. OpenSSH's behavior and output are unchanged, and its exit code is
   propagated.

Certificates are **principal-based** (the principal is your authenticated
identity, decided by the server), so one cached certificate works for every host
you are allowed to reach.

## OpenSSH option passthrough

All OpenSSH options are forwarded unchanged, including:

```
-v -vv -vvv   -p   -l   -i   -J   -o   -L   -R   -D   -A   -F
ProxyCommand  ProxyJump  ControlMaster  ControlPath  ControlPersist
IdentityAgent BatchMode  PreferredAuthentications  … and any future option
```

Unknown options and the remote command (everything after the host) are passed
through verbatim. Mayfly only interprets its own long flags:

| Mayfly flag | Meaning |
|-------------|---------|
| `--profile <name>` | configuration profile to use |
| `--server <url>` | Mayfly server URL |
| `--ttl <seconds>` | requested certificate lifetime (server clamps 60–3600) |
| `--no-cache` | force a fresh certificate even if a valid one is cached |
| `--dev` | print developer timing diagnostics |
| `--dry-run` | print the resolved `ssh` command without connecting |

Because `mayfly ssh` forwards OpenSSH options, `-v`/`-vv`/`-vvv` are OpenSSH
verbosity. When you pass them, Mayfly prints a short diagnostics block (account,
certificate action, principal, expiry, the exact `ssh` command) to **stderr**
before handing off — OpenSSH's own output is untouched.

## Dry run

See exactly what will run, without connecting:

```bash
mayfly ssh --dry-run -J bastion deploy@web-01
# ssh -J bastion -i ~/.config/mayfly/certs/<id>/id_ed25519 \
#     -o CertificateFile=~/.config/mayfly/certs/<id>/id_ed25519-cert.pub \
#     -o IdentitiesOnly=yes deploy@web-01
```

## Preferred username

If you usually log in as a specific remote user, set it once:

```bash
mayfly config / profile … (preferred_username)   # or:
mayfly ssh --ssh-user deploy web-01
```

When the target has no `user@` and a preferred username is configured, Mayfly
adds `-l <user>`.

## Troubleshooting

- **"not logged in"** — run `mayfly login` (or connect from an interactive
  terminal to auto-login).
- **"system ssh client not found"** — install OpenSSH; Mayfly uses your `ssh`.
- **Permission denied (publickey)** — confirm the remote account maps to your
  certificate principal (`mayfly cert inspect`) and that the host trusts the
  Mayfly CA.
- **Certificate keeps reissuing** — your renew threshold may exceed the cert
  lifetime; lower `renew_threshold_seconds` or raise `cert_lifetime_seconds`.
- See also [certificates.md](certificates.md) and [developer-mode.md](developer-mode.md).
