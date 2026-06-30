# CA rotation guide

Rotating a Certificate Authority in Mayfly is an **overlap**, not an in-place
swap. Because the server runs multiple CAs and picks an enabled one at random to
sign each certificate, and because agents are **pull-based** (they fetch the
signed trust bundle on their own cadence), a safe rotation introduces a new CA,
waits for the whole fleet to trust it, and only then retires the old one. Pull
the old CA too early and any host that hasn't synced yet loses trust and rejects
freshly minted certificates.

`mayfly ca rotate` performs the safe first step and hands you the information you
need to finish.

## The workflow

```bash
# 1. Generate a new active CA and see the rollout state.
mayfly ca rotate --passphrase "$MAYFLY_CA_PASSPHRASE"
```

`rotate` prints a guided report:

- **New CA** — the freshly generated, enabled CA (key id + fingerprint).
- **Previous active** — the CA(s) that were active before, which stay active.
- **Fleet rollout %** — how much of the fleet is on the new generation.
- **Machines behind** — how many hosts are still on the previous generation.
- **Warnings** — explicit "do NOT retire the old CA yet" guidance until the
  fleet converges.

```text
Rotation: generated new CA ca-2026q3
  new CA:          ca-2026q3  (SHA256:…)  generation 6
  previous active: ca-2026q2
  rollout:         25.0% on generation 6  (3 machine(s) behind)

  ! New CA 'ca-2026q3' is active at generation 6. The previous CA(s) remain active during rollout.
  ! Do NOT disable or retire the previous CA(s) until the fleet reaches 100% on the new generation.
  ! 3 machine(s) are not yet on generation 6 (25.0% converged).
```

```bash
# 2. Watch the fleet converge on the new generation.
mayfly ca rollout --watch
```

```bash
# 3. Once rollout is 100%, disable then retire the old CA.
mayfly ca disable <old-ca-id>
mayfly ca retire  <old-ca-id> --yes
```

`retire` is **dependency-gated**: if any machine still depends on the old key
the server refuses unless you pass `--force` (loudly audited). Wait for 100%
convergence instead of forcing.

## Options

```bash
mayfly ca rotate --key-id ca-2026q3 --passphrase "$PASS"   # name the new CA
mayfly ca rotate -o json                                    # scriptable result
```

Without `--key-id`, the new CA is named `mayfly-ca-<UTC-timestamp>`. The
passphrase comes from `--passphrase` or `MAYFLY_CA_PASSPHRASE` and must match the
server's storage passphrase.

## Why rotate doesn't retire for you

`rotate` deliberately stops after creating the new CA and reporting rollout. The
server cannot push to agents, so it cannot know the fleet has converged at the
moment of rotation — only you, watching `mayfly ca rollout`, can decide it is
safe to retire the predecessor. This keeps rotation **fail-safe**: the worst
case is two valid CAs during overlap, never a fleet that has lost trust.

## Bundle Signing Key vs. SSH CA keys

This guide covers rotating the **SSH User CA keys** that sign engineer
certificates. The **Bundle Signing Key** (which agents pin at enrollment to
verify the trust bundle itself) is a separate key with a separate rotation story
— see risk **R-005**; it is not rotated by `mayfly ca rotate`.

## Security

- `rotate` is authorized (deny-by-default) and audited (`ca.rotated` with
  operator identity, client context, the new generation, and the previous active
  key ids). The passphrase is never logged or audited.
- The new CA is a fresh Ed25519 key generated server-side and encrypted at rest;
  its private material never leaves the server.
