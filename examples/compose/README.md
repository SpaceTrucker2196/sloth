# Compose demo — sloth → forwarder → Loki → Grafana

The smallest full-pipeline demo of sloth's JSONL stream landing in a
SIEM-like surface. One `docker compose up` brings up four containers
and you can query records in Grafana within seconds.

## Run it

```sh
cd examples/compose
docker compose up
```

Then open <http://localhost:3000>:

- Login `admin` / `admin` (skip the password change prompt).
- Open **Explore** (compass icon).
- Datasource picker is pre-set to **Loki**.
- Query: `{job="sloth"}`
- Hit Run — you should see records arriving once per second, one per
  type cycle. The `type` label lets you filter:
  `{job="sloth", type="alert"}`, `{job="sloth", type="twin_episode"}`,
  etc.

## What's running

| Service     | Image                    | Role                                                   |
|-------------|--------------------------|--------------------------------------------------------|
| `producer`  | python:3.12-slim         | Synthetic JSONL emitter on `tcp://producer:8765`       |
| `forwarder` | python:3.12-slim         | Mounts `../forwarder/sloth-forward.py` and pushes Loki |
| `loki`      | grafana/loki:3.1.0       | Single-binary Loki, filesystem storage, no auth        |
| `grafana`   | grafana/grafana:11.2.0   | Grafana + auto-provisioned Loki datasource             |

The `producer` is **not** the real sloth — it's a tiny Python script
(`mock-sloth.py`) that emits one record per record-type per second
over TCP. The wire format matches what real sloth produces under
`sloth --data-socket tcp:0.0.0.0:8765`, so swapping the producer for a
real sloth instance is a single line change in `docker-compose.yml`:

```yaml
services:
  producer:
    image: ghcr.io/your-org/sloth:latest
    network_mode: host        # need raw 802.11 access
    privileged: true
    command: ["sloth", "-i", "wlan0mon", "--data-socket", "tcp:0.0.0.0:8765"]
```

(Real sloth needs monitor mode and root, which is why the default
demo uses the synthetic producer.)

## What's in the stream

Every record type sloth supports cycles every ~9 seconds:

- `dns`, `tls`, `quic`, `http`, `ntp`, `icmp` — observation records.
- `alert` — synthesis alerts (this demo seeds a `THREAT_DOMAIN`
  example).
- `connections` — per-flow snapshots (TCP + UDP).
- `twin_episode` — Evil-twin Phase 5 record (this demo seeds one
  with `attack_in_progress=1`, `attacker_oui=1`, `hash_mismatch=1`
  so all three flags are visible).

See [`docs/wiki/jsonl-schema.md`](../../docs/wiki/jsonl-schema.md) for
the full field reference.

## Trying other sinks

Edit `docker-compose.yml`'s `forwarder.command` block. The forwarder
also ships HEC (Splunk), syslog (RFC 5424), and Elastic Bulk sinks —
the README in `../forwarder/` covers the flags for each.

## Tearing down

```sh
docker compose down -v
```

`-v` removes the Loki chunk storage. Loki keeps everything in
`/tmp/loki` inside its container so omitting `-v` is fine if you want
to inspect past traffic.

## Smoke test

The `smoke_test.py` script in this directory runs the full pipeline
end-to-end without Docker — useful for CI and for verifying that a
new record type added to `mock-sloth.py` actually flows through the
forwarder:

```sh
python3 examples/compose/smoke_test.py
```

It spawns mock-sloth on a random port, sloth-forward against an
in-process fake Loki, then asserts that every record type the
producer emits arrives at the sink within 30 s. Wired into
`.github/workflows/examples-smoke.yml` so any PR that touches
`examples/` runs it.

## Why Loki specifically?

Smallest moving parts for a "show me data" demo:

- No JVM (vs Elasticsearch).
- No auth setup (vs Splunk HEC).
- Native Grafana integration.
- Plain HTTP push API the forwarder can speak directly.

The forwarder's other sinks are appropriate for different
deployments — Loki is just the easiest path to "see it working".
