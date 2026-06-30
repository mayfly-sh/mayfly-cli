# Developer mode (`--dev`)

Add `--dev` to any command to print a per-phase timing table to stderr after the
command runs. Every command inherits this automatically through the shared
profiler.

```bash
mayfly --dev login github
mayfly --dev whoami
mayfly --dev auth status
```

Example:

```
=== developer timing ===
PHASE                    DURATION   PERCENT  CALLS
-----------------------  --------  --------  -----
startup                     2.1ms      0.8%      1
configuration             900µs       0.3%      1
provider_discovery        120µs       0.0%      1
oauth_start               260ms      92.1%      1
device_authorization       40ms      14.2%      1
browser_launch             12ms       4.3%      1
polling                   210ms      74.5%      1
token_exchange             18ms       6.4%      1
credential_storage          9ms       3.2%      1
http                       62ms      22.0%      4
json_serialize            300µs       0.1%      2
json_parse                450µs       0.2%      3
overall                   282ms     100.0%      1
GRADE: B  (total 282ms)
```

Columns:

- **Operation / PHASE** — the measured unit of work.
- **Duration** — total wall-clock time for that phase (aggregated across calls).
- **Percent** — share of the overall command time.
- **Calls** — how many times the phase was measured.
- **Grade** — a coarse overall grade (A ≤250ms, B ≤750ms, C ≤2s, D ≤5s, F >5s).

Phases include the full authentication lifecycle: configuration load, provider
discovery, OAuth start, device authorization, browser launch, polling, token
exchange, credential storage, plus HTTP and JSON serialize/parse timings (the
HTTP client also records DNS/TLS via httptrace in `--dev`).

Developer mode is effectively free when disabled — recording calls reduce to a
boolean check, so production paths pay no cost.
