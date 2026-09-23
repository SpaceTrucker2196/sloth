# sloth v1.8.2 — say when you are not looking

Weekly patch release, and an unusual one: **no new detectors, no new
views, no new alert types.** Every line in it makes an existing claim
true — the sensor now reports when it has stopped observing, alerts
report transitions instead of repeating state, exports stop leaking
through the umask, and the documentation stops describing a version of
sloth that has not existed since v1.1.

Four issues closed (#83, #88, #93, #99), seven advanced and deliberately
left open (#82, #85, #87, #91, #96, #97, #98). Suite went **8358 → 9304
assertions**. The alert-type enum and `VIEW_COUNT` are byte-identical to
v1.8.1.

---

## Upgrade notes

**No schema bump — `DB_SCHEMA_VERSION` stays 4.** An existing v4 `--db`
file opens unchanged.

**No CLI change at all.** The flag set is byte-identical to v1.8.1.
`--db-max-mb` is *described* differently (it is a pruning trigger, not a
hard cap — it always was) but behaves exactly as before.

**JSONL is additive only.** One new record type and one new record
family; nothing removed, renamed or re-typed:

- `sensor_health` — one line per tick about the collector itself, the
  stream's only singleton record
- `alert.create` / `alert.escalate` / `alert.update` / `alert.resolve` —
  the alert lifecycle family, emitted *alongside* the unchanged `alert`
  record
- New fields on `eapol`: `handshake_progress`, `replay_counter_ok`,
  `assoc_evidence`. New fields on `beacon` for WPS Config Methods and
  Device Password ID. New channel fields on the interface record.

A consumer that ignores unknown record types and unknown fields needs no
changes.

**One behaviour change worth reading before you upgrade:** capture scope
now **fails closed** (#85). If you pass `--monitor-only` or `--iface`
and the restriction cannot be enforced, sloth refuses to start rather
than capturing wider than you asked. That is the correct behaviour for
an authorization boundary, but it can turn a previously-starting
configuration into a startup refusal. The refusal says why.

---

## Security fixes

**EAPOL-Key heap over-read (#83, `89e8ff0`).** The parser trusted the
frame to be as long as its own headers claimed. A truncated or crafted
EAPOL-Key frame read past the end of the buffer. Parsing is now bounded
by the declared span, with the contract written down in
`docs/views/eapol.md` so the next parser does not re-introduce it.
Attacker-reachable from any station in range.

**Export artifacts were created under the process umask (#87,
`c588ba9`).** Handshake exports, JSONL, the DB and pcaps landed
world-readable on a default umask. New `src/secure_file.c` creates
directories **0700** and files **0600** by descriptor with
`O_NOFOLLOW|O_CLOEXEC`, so the umask is irrelevant, and a write that
fails is now reported instead of silently dropped.

**Capture scope failed open (#85, `cda85c5`).** `--monitor-only` and
`--iface` were advisory. They are now an authorization boundary: an
allow-list admits a frame only if every condition holds, and an
unenforceable restriction is a startup refusal.

---

## The sensor now says when it is not looking (#91, slices 1–3)

Three separate paths made "healthy with no detections" and "not
observing" look identical:

- `chanhop_drive()` discarded `set_channel()`'s return code, so a retune
  refused for want of `CAP_NET_ADMIN` left the `--hop` scan bar showing
  the channel it *intended*. The bar now renders an unconfirmed retune
  as `[11?]`, and a lifetime failure count is kept that a later success
  does not clear — a flapping radio stays visible.
- Both capture workers broke out of `pcap_dispatch()` on error and
  returned with the handle still open, so `capture_is_open()` kept
  saying yes. On a hopping radio an empty dwell is normal, so a dead
  monitor thread was indistinguishable from a quiet channel
  *indefinitely*. Each worker now classifies why it stopped — `stopped`,
  `iface_gone`, `perm_lost`, `not_activated`, `error` — and publishes
  libpcap's raw text beside the verdict.
- `pcap_stats()` was never called, so NIC and libpcap buffer drops were
  invisible, and every bounded table discarded silently at capacity.
  Stats are polled per tick, with totals accumulated from deltas so a
  32-bit counter reset never shows a consumer a negative rate.

A healthy sensor renders exactly `health: cap up  mon up` in the
interface view. Everything after those two words is a fault and appears
only when non-zero — a strip that printed `drop 0  evict 0` every second
would train you to stop reading it.

**Known limit, stated rather than papered over:** the eviction tally
covers alerts, top hosts, PNL clients, per-client PNL SSIDs, DHCP
events, 802.1X sessions and the device table. It does **not** cover the
probe-client, beacon, seqnum, assoc or per-protocol rings. The docs say
which, because a tally that silently omits a table reads as "no loss"
when it means "not measured".

Slice 4 (occupancy benchmark) is not in this release, and the measured
adapter/driver/kernel support matrix needs hardware. #91 stays open.

---

## Alerts report transitions, not just state (#98, `54568c8`)

The `alert` record was emitted once per rule tick with no notion of a
run, so a WARN that became CRIT was byte-identical to the same WARN
repeating, and a condition that stopped simply went quiet. Consumers
could see *state* and never *transitions*.

A run of one dedup key is now an **incident**: one `alert.create`, any
number of `alert.escalate` / `alert.update`, one `alert.resolve`, all
carrying a stable `incident_id` and an ordered `event_id`.

Severity changes always emit, in both directions, never throttled —
severity is the paging signal. Detail-only changes are floored at one
per 60s against a signature of the detail, and the signature is not
advanced while throttled, so the next real change still fires with
current detail. Resolve is 300s with no rule re-asserting the key,
measured on `last_evaluated` rather than `last_observed`: rules
re-derive from retained state every poll, so keying on observation would
resolve a standing condition that is still true and immediately
re-create it.

The legacy `alert` record is untouched and `count` is still populated —
now documented as an explicit alias of `evaluations` (rule ticks). It
was never a packet or incident count.

---

## Flood windows are real windows now (#88, `40b65dc`)

Deauth and probe flood detection used a counter reset on a boundary, so
a burst straddling the reset could double its effective budget and an
attacker pacing to the boundary could stay under it forever. Both are
true sliding windows on `CLOCK_MONOTONIC`, with the evidence line
reporting the span it actually measured.

---

## Data socket frames records whole (#93, `aecf2ae`)

Under backpressure a record could be split across writes, handing a
consumer half a JSON object. Records are framed whole, and a gap is
accounted and reported rather than silently papered over.

---

## EAPOL handshake pairing (#97, `ff96a71`)

The `(BSSID, STA)` record carried sticky `m1_seen` / `m2_seen` flags
with no replay counter and no expiry, so an M1 cached at boot paired
with *any* later M2, across associations and rekeys — and that
half-exchange was then promoted to association evidence. Pairing now
requires equal Key Replay Counters within a 10s window, a new M1
discards everything that depended on the old one, and association
promotion moved from M2 to M3.

The hashcat 22000 export wrote a literal `02` message-pair byte
(hashcat's M2+M3 category) for what is actually an M1+M2 pair (`00`).
The byte is now derived from what was validated, with the
"not replaycount checked" bit set so the export reports what sloth
actually compared. Sloth still does not verify the MIC and never
cracks anything — §2.2 — so the offline validation against a known PSK
remains a lab step and #97 stays open.

---

## Documentation that matches the code (#96, `dd71a06`)

From an external CISO/GRC review. Our own documentation was claiming
things the code does not back:

- `SECURITY.md` named **1.4.x** as current while the code was 1.8.1. It
  now names the real version, points at the `#define` as the source of
  truth, and states the actual policy: one branch, newest tag only, no
  LTS, no backports, no patch SLA. Inventing a support window we cannot
  keep would be the same defect pointing the other way.
- **The embedded IOC list is synthetic demo data**, and an operator had
  no way to know. The disclosure now lives on three surfaces pinned by
  tests — the alert detail reads `demo IOC`, the help card has an
  "Embedded data" section, and the source says why no feed ships (a
  fetch is a network write, MISSION §2). `THREAT_DOMAIN` and
  `THREAT_IP` detect nothing until you replace it.
- **Retention was documented as a 30-day deletion and a hard disk cap.**
  It is neither. New `docs/wiki/retention.md`, written from
  `db_maintain()`: 1x/3x/12x tiers, age from `last_seen` so a
  still-observed row never expires, hourly and only while sloth runs, a
  size guard that prunes only observation rows and is allowed to exceed
  target. It lists what nothing covers — JSONL, pcap, EAPOL exports,
  WAL, backups — and says plainly that row deletion is logical, not
  secure erasure.
- Counts swept against source: **35 views**, **61 alert rules**, ~48.6k
  lines across 147 `.c` files. `MISSION.md` §3 still opened with "As of
  v1.1".

The licensing bullet of #96 is the maintainer's and is untouched here.

---

## Build hygiene (#99, `741e6f1`)

`make WITH_WIFI=0` was the one build in the matrix that was not
warning-clean — two helpers in `src/views/wifi.c` sat outside the guard
that removes their only callers. Fixed, and the rule in
`agents/AGENTS.md` was widened from "`make` produces no warnings" to
name all six variants, since checking one build out of six is how it
drifted unnoticed in the first place.

---

## Verification

Every variant built warning-clean and the suite green, on `main`, before
the tag:

```
make                  0 warnings
make WITH_NCURSES=0   0 warnings
make WITH_PCAP=0      0 warnings
make WITH_WIFI=0      0 warnings
make WITH_SQLITE=0    0 warnings
make embedded         0 warnings
make test             9304 assertions passed, 0 failed
```

Still no `.pcap` files in `tests/` — every detector test is
hand-built bytes per the relevant IEEE clause.
