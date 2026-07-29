# PROGRESS.md — Agent activity log

A warm-start view of the repo: what's in flight, what just landed, what
was decided. Companion to [`MISSION.md`](MISSION.md) (the charter, slow
moving) and [`docs/wiki/log.md`](docs/wiki/log.md) (wiki edits only).

**Who writes here**: every agent that lands a non-trivial change.
**When**: at the end of a working session, before pushing the commits
that close out the work.
**Where to read first**: top of the file. Newest entries at the top of
their section; the "In progress" section is mutable, the "Recently
landed" section is append-only.

---

## Format

Each landed entry is one block:

```
### YYYY-MM-DD — short title
**Commits**: <hash1>, <hash2>
**Touched**: paths or modules
**Why**: one to three sentences on what motivated the change
**Follow-ups**: open work this exposed, if any (link to the In-progress entry)
```

Each in-progress entry is one block:

```
### <short title>
**Owner**: agent name + session (or human if a human is driving)
**Started**: YYYY-MM-DD
**Goal**: one sentence
**Status**: free text — where it is right now
**Blockers**: if any
**Next concrete step**: what the next agent picking it up should do
```

When an in-progress item lands, **move** it to "Recently landed" (do
not duplicate). Add the commit hashes. Append any follow-up that the
work exposed as a new In-progress entry.

---

## In progress

*(nothing actively in flight — pick from "Open follow-ups" or the
paused work below)*

### Paused: Mutation-testing follow-ups (rounds 10+)
**Owner**: next agent
**Started**: 2026-05-28 — paused 2026-05-28 by operator request
**Status**: rounds 1-9 closed. Aggregate kill rate is **51.0% of
considered** (estimated 938 killed / 1844 considered / 2311
mutants total). The campaign delivered ~600 net mutants killed and
the `--ignore-file` machinery; remaining work is small per-round
gains against the noise floor (see "diminishing returns" pattern in
the "Recently landed" entries). Resume at will; everything is
non-blocking and stateless.
**Next concrete step** (in priority order, if resuming):
1. ~~Bulk-add LZT / SBL / TIP entries for `dns_log.c`, `tls_log.c`,
   `http_log.c`~~ — landed 2026-06-03 (round 10).
2. ~~Mutate `src/probe_pnl.c`, `src/eapol_log.c`,
   `src/seqnum_track.c`, `src/assoc_track.c`~~ — landed 2026-06-04
   (round 11). 20 entries; modest because the WiFi-SIGINT engines
   reject fewer inputs than the protocol logs and the search-loop
   LZTs are not safely equivalent when zero-MAC inputs aren't
   filtered.
3. Skip `src/views/*.c` — render code, low semantic value.
4. Cosmetic: tighten the "killed (build broke)" sub-counter so
   compile failures and test-binary segfaults are categorised
   distinctly (both currently produce stderr containing "error"
   + "make"; the heuristic conflates them).

---

## Recently landed

### 2026-07-28 — Field-reported fixes, the operator persona, and the SQLite sink
**Commits**: `4b1b577`, `f5c848d`, `a6af13d`, `e2effaa`, `6e58de0`,
`52cf47a`, `fc1d9d3`, `247731c`, `61700b5`, `01dc317`, `ec4a9b7`,
`78305dc`, `376ab88`, `bf10952`, `c1f616c`, `85ae491`, `c4e7467`,
`43a95a6`, `e7ddd7a`, `b408817`, `f3682c1`, `8166b6a`
**Touched**: `src/capture/`, `src/db*`, `src/ownership.c`,
`src/presence.c`, `src/transit.c`, `src/radiotap.c`,
`src/rf_quality.c`, `src/tui*`, `src/alerts.c`, `src/beacon_snoop.c`,
`src/platform/linux_wifi.c`, `docs/personas/`, `docs/wiki/`,
`ROADMAP.md`
**Why**: three field reports arrived (`#46` scoping silently disabled by
a misread `pcap_activate` return, `#47` data-socket clients never
getting a baseline, `#48` the no-ncurses build not compiling). Fixing
them prompted writing `docs/personas/wifi-surveyor.md` — an operator
persona scored against eleven executable scenarios — which found `#51`
within an hour and then drove `#50`, `#52`–`#56`. `#42`'s SQLite sink
landed across six slices in parallel. Roadmap items B3b and B3 followed.

Closed every open issue. Suite went 3813 → 5636 assertions.

**What the day actually demonstrated**: seven defects were caught by
tests or measurements taken *during* implementation rather than by
review — the `pcap_activate` sign convention, an `ASSOC_SRC_*`
inversion that would have downgraded every confirmed handshake, flow
counters erased by ring eviction, MISSION §2 guardrails too coarse to
tell a flag from key material, a recycled probe slot inheriting the
previous device's RSSI ring, a schema-versioning defect introduced
earlier the same day, and a radiotap extended-bitmap loop that made
some captures yield no signal or channel at all. Four tests also caught
their own inadequate fixtures.

**Follow-ups**: see `ROADMAP.md` §B — B1 (assoc-requests, action
frames, control frames) is next. Two validations are outstanding and
cannot be done from this tree:

1. **`#42` has never been measured on real traffic.** The 12.6 GB/8 h
   that motivated the sink came from a production node; only that node
   can say what `--db` did to it.
2. **Every persona verdict came from reading implementations**, not
   from executing the suite — this is a macOS/BSD tree where the 802.11
   path does not exist. Each verdict cites its source so a run on a
   Linux monitor rig can overturn it.

Also unverified on hardware, and older: the nl80211 `SET_CHANNEL` path
(`--hop`) and concurrent multi-radio capture.

---

## Current state (2026-07-28)

- Passive C99 network monitor for Linux; single binary, 33 ncurses
  views, warning-clean across `make`, `WITH_NCURSES=0`, `WITH_SQLITE=0`
  and `embedded`, **5636 test assertions** green, smoke test 40/40 JSONL
  record types end-to-end. No open GitHub issues.
- **Durable state**: `--db FILE` writes a 40-table SQLite artifact
  (schema v2) with tiered retention, a size ceiling that never drops
  findings, and schema-level MISSION §2 guardrails enforced by tests.
  `-o` and `--data-socket` are unchanged and remain the wire format.
- **Operator-supplied context** is a new input class as of 2026-07-28:
  `--my-ssid` / `--my-bssid` designate the operator's own network and
  `--known-mac` / `--known-macs` their known devices. Together they
  raise `MY_NET_RECON` and `UNKNOWN_DEVICE`.
- **Presence and movement**: clients are classified resident / visitor /
  passing from RSSI trajectory rather than dwell, and devices that pass
  repeatedly raise `RECURRING_TRANSIT` — resolved through the seqnum
  correlation table so MAC randomisation does not defeat the count.
- **Headless**: `--headless` never touches the terminal; `--no-color` /
  `NO_COLOR` suppress escape sequences. A poll-loop spin that burned a
  core whenever stdin was not a terminal is fixed.
- One IE parser now serves both the monitor and nl80211 paths, so
  capability depth no longer depends on interface mode.
- The original passive-observable queue is fully landed: NDP, SMB,
  Kerberos, LDAP, BGP, SSH, RDP, SNMP, MQTT — each fronted by a CRIT
  alert. Tier 2 expansions per protocol remain queued (see wiki pages).
- Evil-twin AP detection landed in 6 phases: fingerprint carrier,
  vendor-IE hash + attacker OUI, RSSI proximity, deauth-correlated
  attack chain, Twins view, JSONL surface.
- Export: 40 JSONL record types; `--out-format jsonl|cef|syslog`;
  forwarder sinks HEC / syslog / Elastic / Loki / Datadog / webhook with
  fan-out; Compose demo + CI smoke test.
- Dashboard is event-driven (250 ms default refresh + self-pipe wakes)
  and monitor-radio-aware: with a monitor interface active it shows
  STA↔AP associations and raw 802.11 frames (2026-07-04).
- Adaptive passive channel-hop scheduler (`--hop`, opt-in, MISSION §2
  amendment) + packet dedup landed 2026-07-04; the nl80211 SET_CHANNEL
  path is still unverified on a real Linux monitor interface.
- Mutation-testing campaign paused after rounds 1-11 at ~51%
  kill-rate-of-considered; only the cosmetic build-broke/segfault
  sub-counter split remains (see the paused entry above).
- docs-drift LLM judge runs as an advisory GitHub Action (weekly cron +
  PR trigger) over 42 (src, doc) pairs.
- Known gaps: tiny control frames (ACK/CTS) not captured in the monitor
  packets band; no dedicated full-screen monitor-frames view yet.

## Open follow-ups (not yet owned)

### Forwarder / consumer extensions

- **Additional forwarder sinks** — `examples/forwarder/` ships
  HEC, syslog, Elastic, Loki, Datadog, and webhook. OpenSearch
  compatibility documented under the Elastic section (wire-
  compatible `_bulk`). Slack/Discord-style incoming webhooks
  intentionally not supported as a built-in sink (their message
  envelope is outside the schema-agnostic remit); operators write
  a transform proxy or use a Slack app.

### iOS / Tailscale (out of this repo)

- **Tailscale integration** — install + configure on the deployment
  host so `--data-socket tcp:100.x.x.x:8765` actually reaches the
  iOS client. Out of repo (configuration, not code), but blocks the
  iOS client from being useful.
- **iOS SwiftUI client** — consume the data socket and render the
  same panels sloth shows in the TUI. Lives in a separate repo
  (confirmed by the operator 2026-05-28).

### Product depth (sloth itself)

- **More passive observables** — per MISSION §4(1) "coverage > precision".
  The original AD/infrastructure-substrate set is now landed:
  IPv6 RA/NDP, SMB, Kerberos, and LDAP (all 2026-06-04) plus BGP
  (2026-06-01), each fronted by a CRIT alert: `ROGUE_RA`,
  `SMB1_USE`, `KERB_PREAUTH_BURST`, `LDAP_SEARCH_FLOOD`,
  `BGP_NOTIFICATION_BURST`. Each has Tier 2 follow-ups documented
  in its wiki page — NS/NA neighbor cache for NDP; NTLMSSP /
  admin-share tracking for SMB; username extraction + AS-REP
  roasting + kerberoasting for Kerberos; per-attribute query
  inspection + result-size analysis + referral URL extraction
  for LDAP; AS-number extraction + prefix-hijack detection +
  route-flap dampening for BGP. Next candidates from the
  internet-substrate side: SSH (brute-force detection on
  TCP/22), RDP (TCP/3389 NLA / lateral-movement substrate),
  SNMP (UDP/161 snmpwalk enumeration), and MQTT/IoT control
  planes.

---

Completed-phase history: see docs/progress-archive.md (append-only).
