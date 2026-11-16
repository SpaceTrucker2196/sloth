# sloth v1.8.7 — a second daemon, three new passive sources, and counters that forgot to forget

One week since v1.8.6: **279 commits** (181 of them substantive, 56
merges, 42 `chore(metrics)`/`chore(ledger)` rows) and **28 closed
issues**. Alert types go **95 → 100**; `VIEW_COUNT` stays **38**. Suite
went **44132 → 156156 assertions**.

Three things carry it.

The first is the **wifi/rf split** (#211, ADR 0010): the sensor is now
two daemons built from one tree. `sloth` keeps the IP capture, the
802.11 monitor radio and BLE; the new **`sloth-rf`** is a headless
reader for the SDR decoders' output and GNSS, with its own store, its
own data socket and its own alert table. Slices S1–S4 landed (#212,
#213, #214, #215). It is built by a plain `make` and is **not installed
and not cut over** — `sloth` still reads every RF flag itself, so
nothing an operator runs today changes.

The second is **three new passive sources**: rtl_433's JSON event log
(#208, `--rtl433`), the owner's Victron gear through a new helper
(`--victron`, ADR 0011), and a one-minute SDR sweep behind slothweb's
Spectrum tab. Each is a file or socket another process writes.

The third is a **detector-correctness wave**. Six rules were counting
things they had no window for, and two were accusing the wrong party:
`SSH_BRUTE_FORCE` measured 131k on one flow (#202), `device_risk_score`
put 97% of devices in HIGH (#191), `EVIL_TWIN_PROXIMITY` fired on 254 of
300 BSSIDs with no twin candidate (#189), and `ATTACK_PATH` named every
victim server as its own attacker (#197). All are now windowed or gated
on evidence.

---

## ⚠️ Upgrade notes — read before upgrading

This is a patch tag by the owner's scheme, but **two schema versions
moved and both upgrades are one-way.** Nothing else here changes what a
working v1.8.6 invocation does.

**1. `DB_SCHEMA_VERSION` 13 → 15.** An existing v1–v14 `--db` file is
migrated forward automatically inside `db_open()`, one version at a
time, each step in its own transaction; no step rewrites a recorded
value. **A file this build has migrated to v15 is refused by v1.8.6 and
older**, which refuse any file from a newer build. If you may roll back,
copy the `--db` file before the first v1.8.7 run.

| Step | Change |
|---|---|
| v13 → v14 | `ALTER TABLE beacon_aps ADD COLUMN operating_width` (#207 slice 1) |
| v14 → v15 | `victron_devices` and the Victron reading tables; new in the unconditional schema, so the step is a stamp alone |

**2. `WEB_STORE_SCHEMA` 7 → 12** — `slothweb.db` gained the incident and
bulk-triage tables (#198, v12), the fleet `peer_sites` tables (#192, v8)
and the BLE and link tables between. Same one-way rule: a v12 file is
refused by an older slothweb. `slothweb.db` is a cache plus triage
state, so the cheap rollback is to delete it and let it refill — except
for triage notes and verdicts, which only live there.

**3. JSONL remains additive only.** The stream gained an explicit
contract version this cycle (`SLOTH_JSONL_VERSION`, reported in
`sensor_health`, #185) and it went **1.0.0 → 1.10.0** — ten MINOR bumps,
no MAJOR. Every field is new; no record changed shape, and a consumer
ignoring them sees what it saw before. The 2.0.0 cutover is reserved for
the daemon split (#216) and needs the owner's sign-off per ADR 0007.

**4. No CLI flag was renamed or removed.** Seventeen flags were added
across `sloth` and the new helpers. `sloth-rf` has no `--jsonl`
spelling, and neither does `sloth` — both refuse it as an unknown
argument, exit 2, compared byte for byte by `make replay-check`.

**5. One caveat if you run both daemons: do not point `sloth` and
`sloth-rf` at the same serial GPS.** A serial device opens once. Both
can read one `gpsd`.

---

## The sensor is two daemons (#211, ADR 0010)

The RF readers were already modules of their own, but everything around
them existed once — `sloth_state_t`, the `src/poll.c` stage table, the
alert engine, the JSONL writer, the database handle. A stall of the
Wi-Fi monitor therefore stopped the SDR decoders' records too. The owner
asked for them to run independently.

**S1, the build seam (#212).** The source list became three groups —
`RF_SRCS`, `GNSS_SRCS`, `CORE_BASE_SRCS`, with `CORE_COMMON_SRCS` their
union — the run flag moved out of `capture.c`, and the poll stages
became a per-app table (`g_poll_sloth`, `g_poll_rf` in
`src/poll_core.c`).

**S2, the binary (#213).** `src/rf/{main,rf_args,platform_rf}.c`, an
`nm` gate (`check_rf_no_capture`) that keeps capture, 802.11 and
BLE-capture code out of `sloth-rf`, a JSONL writer split three ways
(`jsonl_core.c` shared, `jsonl_rf.c` the RF records, `jsonl.c` the
capture's), and a per-daemon alert table (`alerts_set_table()`).
`sloth-rf` writes `gnss_*`, `adsb_aircraft`, `aprs_packet`,
`aprs_station`, `rtl433_device` and `victron_device` **as the same bytes
`sloth` writes for the same input** — pinned by `tests/test_rf_loop.c`.
Its `sensor_health` says `"daemon":"rf"`; its `source_status` has five
rows, not nine; it owns `GNSS_*`, `ADSB_EMERGENCY` and
`SENSOR_SOURCE_DOWN` for its own sources, but not `SENSOR_UNDERVOLT`
(owner ruling 2026-11-15: the host has one supply and the daemon with
the capture reports it). It refuses every capture flag — `--iface`,
`--hop`, `--allow-active`, `--bt-monitor`, `--replay`, `--pcap-dir`,
`--headless` — because a daemon that accepted `--hop` and did nothing
would read as one that can retune a radio. SIGUSR1 is ignored: it has no
report to write.

**S3, one slothweb reads both (#214).** `--rf-socket SPEC` and
`--rf-db PATH` beside the existing pair. An RF alert's ids, figures and
verdict stay `sloth-rf.db`'s; slothweb opens one incident per
occurrence.

**S4, packaging (#215).** `sloth-rf.service`, its defaults file, and
`packaging/bin/sloth-migrate-rf`. `slothweb` gained
`Wants=sloth-rf.service`, which starts it with slothweb whether enabled
or not, and `sloth-rf.service` is installed only beside its binary. The
`slothweb` unit and binary now travel together.

Flag validation both daemons share lives in `src/rf_flags.c`,
`src/gnss_flags.c` and `src/daemon_start.c`, so the meaning, the refusal
text and the exit code are identical — `make replay-check` runs both
binaries on 22 refused command lines and compares stderr.

## Three new passive sources

**rtl_433 (#208, `--rtl433 SPEC`)** tails the JSON event log a local,
already-running `rtl_433 -F json` writes, one object per decode.
Absolute path or `file:///path`, read-only on a worker started after the
privilege drop. The dedup key, the stale-sensor block and a temperature
bound were corrected in review. slothweb gained an rtl_433 tab and
`/api/rtl433`. No table in `sloth.db` yet, and rtl_433 rows are
**withheld from the fleet, fail closed**, until the owner classifies
them (ADR 0009).

**Victron (`--victron SPEC`, ADR 0011)** — and this one needs stating
plainly. The owner's camper carries a BMV-712, an Orion-Tr Smart and a
VE.Direct dongle. Their Instant Readout values are AES-CTR encrypted
with a per-device key and the richer data is behind a paired GATT
connection. MISSION.md §2 holds sloth to receiving and rule 2 forbids
decrypting a captured frame, so **sloth does neither**: a separate,
opt-in helper, **`sloth-va`**, does the connecting and the decrypting,
appends one JSONL record per reading to
`/var/lib/sloth-va/victron.jsonl`, and sloth reads that file the same
way it reads `--rtl433` and `--aprs`.

`sloth-va` is **the first sloth-family component that transmits**, at
the owner's explicit request and rulings of 2026-11-15. It is built only
where sd-bus is found, linked into neither `sloth` nor `slothweb`
(`tests/test_va.c` fails if `src/va/` reaches their source lists),
`make install-service` installs its unit and **never enables it**, and
its peers are exactly the addresses in `/etc/sloth/victron.keys` and
`/etc/sloth/victron-va.conf`. It never starts discovery — a device is
reached only once BlueZ has already heard it. Instant Readout costs
nothing on the air: a BlueZ `AdvertisementMonitor` holds a passive
background scan with no `SCAN_REQ`. GATT sessions are one at a time,
every `--interval` seconds (300 default), at most 60 s, and the link is
down between them so the owner's phone app can still connect. PINs and
keys stay in root-only files handed over with `LoadCredential=`, are
never logged or exported, and a world-readable secret file is refused.
The unit's description, every session's log line, `make install-service`
and `docs/wiki/victron.md` all say it transmits. And **sloth's own
`BT_OWN_TRANSMIT` is left to fire on it** — WARN, naming the controller
— rather than exempted.

**ADS-B over a socket (#186).** `--adsb` now also takes
`sbs://[HOST[:PORT]]` for a decoder's SBS / BaseStation TCP output and
`beast://[HOST[:PORT]]` for its Beast binary output, decoded in sloth;
v1.8.6 refused both with "not yet supported". The review corrected the
source kind, the canonical host and a readsb claim, and the DF18 IMF bit
is read only where readsb reads it.

**SDR spectrum sweep.** A one-minute sweep behind slothweb's Spectrum
tab with an isometric waterfall, ranges from a rolling 5-minute sweep
history (last 3, 1h..24h), and `sloth-sdrsweep` as its own binary and
unit. The helper refuses when its cooldown record is unreadable, and the
tab clears its "queued" note when a run ends. `beacon_aps.operating_width`
is persisted for the overlay (#207, schema v14).

## Alert types: 95 → 100

Five new types, each with its cited basis.

**`KARMA_PROBE_FORGE`** (T1557, #187 S2) — one BSSID sending directed
Probe Responses naming SSIDs it never beaconed, to stations that had
just asked for them. WARN while it only forges answers; CRIT once a
station was captured. `karma.forge_ssids` 2, `karma.forge_window_s` 600.
Sources: Dai Zovi & Macaulay, *Attacking Automatic Wireless Network
Selection*, 2005 (`research/papers/daizovi-macaulay-2005-karma.md`);
airbase-ng's documentation (`research/tools/airbase-ng.md`); ATT&CK
T1557. Fills a gap `KARMA_AP`'s own assessment had recorded: the
probe-response-only KARMA radio was out of its sight. The one unverified
false positive is an 802.11ax Multiple BSSID transmitter writing a
nontransmitted profile's SSID into its own response, which sloth does
not decode and which the assessment states.

**`PMKID_HARVEST`** (T1040, #172) — one station soliciting several
BSSIDs, each answering with an M1, none answered back. WARN for the
pattern; CRIT when ≥3 of the unanswered M1s carried a PMKID KDE and the
station answered no M1 at all, i.e. offline-attackable material left the
air. `harvest.window_s` 900, `harvest.min_bssids` 3,
`harvest.unanswered_pct` 50. Sources: Steube's 2018 hashcat disclosure
(`research/papers/steube-2018-pmkid.md`); hcxdumptool's README
(`research/tools/hcxdumptool.md`); IEEE Std 802.11-2020 §12.7
(`research/ieee/802.11-2020-12.7-eapol-key.md`). Roaming, PMK caching
and FT are excluded by construction — they are answered, or have no M1.

**`HANDSHAKE_HARVEST`** (T1040, #172) — deauthentication of a station
from a BSSID followed by that station's fresh M1/M2 within
`harvest.reconnect_s` (30 s). WARN at one victim, because an AP
band-steering a client by deauth has the same shape; CRIT at two
distinct victims of one BSSID inside the window. The deauth count sits
deliberately under `DEAUTH_FLOOD`'s 5-in-5s: the slow form is the point.
Sources: hcxdumptool's README (*"Disconnecting a CLIENT from an
associated ACCESS POINT to get a complete handshake"*); 802.11-2020
§12.7; CVE-2022-47522 (`research/cve/2022-47522.md`).

**`SENSOR_UNDERVOLT`** (no technique — own operational state) — the
kernel's own `inN_lcrit_alarm` reading 1. WARN: a supply below the
board's minimum is how SD cards get corrupted and how USB receivers drop
off the bus, but it is a fault, not an attack. One incident per episode,
held across a flapping alarm, closed `recovered` after
`SENSOR_RECOVER_S` (120 s). No tuning knobs.

**`SENSOR_SOURCE_DOWN`** (no technique — own operational state) — a
configured source that is `down` for `SENSOR_SRC_DOWN_HOLD_S` (10 s) or
not `ok` for `SENSOR_SRC_STALE_S` (300 s). **CRIT for the monitor radio
and the IP capture**, WARN for the rest: a sensor that lost its monitor
radio keeps drawing views, and an operator reading an empty Probes view
as "nobody is probing" is the failure this rule exists to prevent. The
detail carries the reader's own words (`not open`, `exit: iface_gone`,
`error: connection refused`, `no frame yet`).

Both `SENSOR_*` types are the first exemption form — own operational
state, empty technique, pinned by
`tests/test_research_corpus.c :: test_own_state_kinds_are_named`.

## Detectors: windows, and the right party

- **`SSH_BRUTE_FORCE` / `RDP_BRUTE_FORCE` (#202)** counted banners for
  the lifetime of a flow with no window, so a few key-auth logins
  re-fired CRIT every tick forever — 131k on one flow here. Now
  windowed.
- **`SNMP_COMMUNITY_BRUTE` / `MQTT_BROKER_BRUTE` (#203)** had the same
  bug; SNMP now counts guesses past a full community set rather than a
  lifetime total.
- **`ATTACK_PATH` (#197)** matched HTTP responses as well as requests,
  so every malicious request fired a second CRIT naming the victim
  server as its own attacker. It now judges the request half only, and
  attributes to it.
- **`device_risk_score` (#191)** put 97% of devices in HIGH — random MAC
  plus no hostname plus probe-only stacked to 3, including the sensor's
  own adapter. HIGH/CRIT are now gated on evidence rather than
  weak-signal stacking, the sensor's own devices are exempt, and
  anonymity is scored once.
- **`EVIL_TWIN_PROXIMITY` (#189)** fired on BSSIDs with no twin
  candidate — 254 of 300 on the reference host. Gated on a same-SSID
  twin.
- **`EVIL_TWIN` (#188)** went CRIT on one device's own band siblings,
  comparing a vendor-IE hash or a BTM steer across the 2.4 and 5 GHz
  radios of the same AP. One device's own radios are no longer scored as
  a pair; a late arrival is counted only beside a locally administered
  BSSID; carrier and barely-heard twins hold at WARN (#188, #189).
- **`EVIL_TWIN` late arrival (#194)** survives the two ways to switch
  the signal off: announcing ahead of the legitimate AP, and burying it
  in a beacon flood. A full beacon table no longer hides one either.
- **`GNSS_TIME_JUMP` (#182)** logged 97 held steps in one hour on a
  static host. The step is now judged on gpsd's TOFF with `time` as the
  fallback, a late GNSS read neither judges nor anchors, and only the
  host's own gap counts as read lateness.
- **The sensor's own radio (#183)** — every MAC the `iface` records
  carry is rostered automatically, and a rostered device's
  `RECURRING_TRANSIT` is demoted and says so. (The issue closed with
  `MY_NETWORK_RECON` and `ATTACK_PATH` handled.)
- **IPv6-only clients (#176)** are now tied to a BSS: the kernel's
  neighbour table is read into the sensor's table.
- **APRS (#204)** derives region and channel from the GNSS fix and flags
  a wrong or silent decoder; `--aprs-freq` and `--aprs-silent-hours`.
- **Attack-hardware fingerprints (#151)** — a stack table, Pineapple
  pairing and a verdict; the SDRplay RSP2, RSPduo, RSPdx, RSP1B and
  RSPdx-R2 added to the known receivers.
- **KARMA and key harvest (#172, #187)** write their tables to the
  stream, number their clusters, mark `QUEUE_EVICT` and flag
  harvest-friendly APs; probe-response latency is measured per BSSID as
  observation only.

## Fleet (#192, #196) — and a new hard rule

The owner's sloths now share over the tailnet and infer across
locations: merged Devices, AP, BLE, Probes and ADS-B views with other
hosts' rows in grey, identity read against each other across sites,
GNSS events classified regional / local / undetermined, emitters located
from two or more sensors' signal strength, and Radar fleet areas drawn
as polygons where other sloths place an emitter.

**ADR 0009 supersedes ADR 0008's "full fidelity" with a hard rule the
owner set on 2026-11-12: share monitor data only.** The rule is
*provenance, not subject* — everything heard in monitor mode travels,
including the joined network's own APs and stations as heard over the
air; nothing that came through the managed interface or the wire ever
does (ARP, DHCP, mDNS, DNS, HTTP, TLS, flows, IP addresses, host names,
the managed card's MAC and scan). It fails closed: unknown provenance
does not travel, a new alert type is withheld until classified, every
export names its host, and the importer refuses what the rule forbids
from any peer. `agents/AGENTS.md` and `agents/converge.md` now name the
enforcement points, list the tests that must stay green unweakened, and
make "an order that would relax it" an escalation rather than a
converge.

## slothweb

- **Incidents and bulk triage (#198)** — the Alerts page groups alerts
  under their incidents and triages many as one. The issue's own
  measurement: 952 per-alert verdicts were 5 causes. `slothweb.db` v12,
  plus MCP incident and bulk-triage tools.
- **`/api/alerts` paging (#200)** — with `incident=` or `triage=`
  filters, `more` stayed true and `next_offset` never advanced, so a
  client paged forever. Fixed, and `expect.sh` now ends the loop on an
  empty page or a stuck offset.
- **New tabs** — Fleet, Probes, rtl_433, Spectrum, Camera (a capture
  helper's latest still), and ATC-style radar scopes for APRS and ADS-B
  positions sharing `ppi.js`.
- **Sensor health** — sources, receivers, host status and trends; the
  host's own name in the header instead of "M6"; `sloth.db` and
  `slothweb.db` size tracked against their limits.
- **#171, #195 and #102 closed** — the visual system V0–V4, the TUI
  forms of the glyph set (S-meter, hour grid, horizon, rug, chain lanes)
  and the browser-dashboard tracker.

## Build, suite and repo

- **#221** — `make sloth_test_noflags` did not link on main and nothing
  gated it. `draw_dns_log_panel` and `probe_test_dispatch` calls are
  guarded, and CI now builds it.
- **#209** — the suite guards its file-descriptor table at every
  test-case boundary; `fd_guard` reports, names and caps what leaked.
- **Red main swept** — a sweep-history leak, two `readdir`
  suppressions, and a bound checked after its index.
- **ADR 0001** records the owner's rulings on #184 §5 (sloth-mesh, the
  licence, the artifact home). ADRs 0008–0011 are new this cycle.
- **#145 closed** — the 2026-10-19 resolution plan, having done its job.

## Known gaps

- **The five new alert types have no firing data.** All are
  `noise_verdict: not measured`; the three Wi-Fi ones are new rules of
  2026-11-11 and the reference host has seen neither a harvester nor a
  KARMA radio.
- **`sloth-rf` is built but not installed and not cut over** (#216).
  Until then both binaries carry the RF flags and the duplicate is real:
  point only one of them at a given decoder.
- **No rtl_433 table in `sloth.db`**, and rtl_433 and APRS are
  unclassified for the fleet, so they are withheld.
- **`sloth` is not yet renamed `sloth-wifi`** (#216), and the ADS-B
  terminal view retires at that cutover, not here.
- **`HANDSHAKE_HARVEST`'s WARN has a known benign twin** — an AP
  band-steering or load-balancing by deauthentication. CRIT needs two
  distinct victims for exactly that reason.
- **Meshtastic, a sloth-rf terminal UI, an rtl_433 table in the
  database and fleet classification of rtl_433 or APRS** are explicitly
  outside #211's programme, not oversights.

---

**Verified on this tag's tree:** `make`, `make test`,
`make WITH_NCURSES=0`, `make embedded`, `make WITH_SQLITE=0` and a final
`make` — all exit 0, **zero warnings**, **156156 assertions passed, 0
failed**.

Passive throughout, with one announced exception that is not sloth: the
two daemons open no radio, tune no SDR and transmit nothing but gpsd's
one announced `?WATCH` line. `sloth-va` transmits, by the owner's
request, as a separate opt-in binary that ships disabled and that
sloth's own `BT_OWN_TRANSMIT` alert still reports — see
[`MISSION.md`](MISSION.md) §2 and
[ADR 0011](docs/wiki/adr/0011-sloth-va-transmits.md).
