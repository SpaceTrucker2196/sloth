# sloth v1.8.5 — the architecture wave, slothweb, and a Bluetooth sideband

Three weeks of work in one patch, not one: no release was cut on
2026-10-12 or 2026-10-19, so this tag carries **441 commits** (336 of
them substantive) since v1.8.4 and **64 closed issues**. The
alert-type enum goes **64 → 90**; `VIEW_COUNT` goes **35 → 36** (the
`[*]` BLE view). Suite went **12254 → 33398 assertions**.

Three things carry it. The first is #143, the October architecture
remediation: 30 issues (#108–#142) that rewrote parsing, state, build
and security discipline under one tracker — every 802.11 frame decoded
once, one bounded reader and one TLV iterator, one clock seam, one
alert-key builder, `alerts.c` split by domain, and the test binary
finally built the way the program ships. The second is **slothweb**,
a new top-level `web/` tree and a second binary: a local browser
dashboard that reads sloth's data socket and `sloth.db`, built across
W0 and M0–M6 (#157–#164). The third is the **charter widening of
2026-10-21** — sloth now observes Bluetooth Classic and BLE,
receive-only, with optional Ubertooth capture (#144), under the same
absolute passivity rule as 802.11.

Alongside those: camera identity became a classifier rather than an
OUI guess (#106, #155), the regulatory IE parsers that landed inert in
v1.8.4 grew their three rules (#101), the Multi-Link Element work
reached six rules and client MLDs (#104, #129), the surveillance-vendor
watchlist shipped (#105), WPS gained the two Pixie-Dust rules (#82),
Framing Frames reached `PM_FORGE` and `QUEUE_EVICT` (#107), the
evidence ring grew per-session manifests and alert citations (#92), and
the `--db` migration chain now runs the full **v1 → v7** (#154, #145).

---

## ⚠️ Upgrade notes — read before upgrading

This is a patch tag by the owner's scheme, but six operator-visible
things changed. **The schema bump and the privilege drop are the two
that can change what a working v1.8.4 invocation does.**

**1. `DB_SCHEMA_VERSION` 4 → 7, and the upgrade is one-way.** An
existing v1–v6 `--db` file is migrated forward automatically inside
`db_open()`, one version at a time, each step in a single
`BEGIN IMMEDIATE` transaction tested against a file built at the
previous version — including the failure case, which leaves the file
unchanged. A migration never rewrites a recorded value: it adds columns
or tables with defaults, and where a change would alter the meaning of
stored data it keeps the old column beside the new one. **But a file
this build has migrated to v7 is refused by v1.8.4 and older**, which
refuse any file from a newer build. If you may roll back, copy the
`--db` file before the first v1.8.5 run. v4 → v5 (#90) adds
`karma_candidates.pnl_best`; v5 → v6 and v6 → v7 (#155) add the camera
classifier columns (`cam_score`, `cam_evidence`, `cam_vetoes`,
`cam_conflict`) and the DHCP option 55/60 display fields.

**2. A root run now drops privileges by default (#140).** Owner ruling
2026-10-15. After the capture handles and netlink sockets are open,
sloth sets `NO_NEW_PRIVS`, drops to the `sloth` account when that
account exists (`--user NAME` overrides), and otherwise keeps the uid
but drops every capability and says so on stderr. `CAP_NET_ADMIN` is
retained only with `--hop` or `--allow-active`; `CAP_NET_RAW` never is.
**A deployment that relied on root privileges persisting past capture
open — a root-owned `--pcap-dir`, `--eapol-dir` or `data/` — will now
fail to write.** `--no-privdrop` is the announced escape hatch and
keeps every privilege for the whole run. `--user` with `--no-privdrop`
exits 2, as does a `--user` naming no account, or a drop that failed or
did not read back. Raw `capset`/`prctl`; no libcap linked.

**3. Bare `--data-socket` now defaults to `unix:/run/sloth/sloth.sock`
and can exit 2 (#136).** Owner ruling 2026-10-15. If `/run/sloth` is
absent, a symlink, owned by neither root nor sloth's effective user, or
group/other-writable, the bare flag **refuses at argv time and returns
2** with the remedy printed (`RuntimeDirectory=sloth`, or
`install -d -m 0750 -o <uid> /run/sloth`). There is deliberately **no
fallback to TCP** — a flag that named no transport must never silently
become one every local account can read. Explicit specs are unchanged;
loopback TCP must now be typed in full.

**4. JSONL is additive only, but three field *meanings* changed.** No
record type or field was removed, renamed or re-typed, and 14 record
types remain 14. However: `phy` changes value on `beacon`, `pnl_client`
and `wifi_assoc_req` (#127 — extension IDs 106/107/108 are Wi-Fi 7, not
81, which the old mapping had wrong); `wifi_ap.channel` is corrected at
four frequency ranges (#167 — nl80211 now reports 32–35 for 5160–5175
instead of 0, both paths report 0 instead of 178–180 for 5890–5900,
5935 is 6 GHz channel 2, and 5960 reports 6 GHz with no channel); and
an RSNE advertising AKM 24/25 (SAE-EXT-KEY) is now labelled **WPA3**
where it was labelled WPA2 (#128). **Record order within one poll tick
also changed** (#113): the declared phase table emits JSONL after the
snapshots, twins after beacons, and transit before alerts, fixing five
stale reads. A consumer that depended on the old intra-tick order will
see records in a different sequence.

**5. Nine rules' alert dedup keys changed (#112).** The typed key
builder replaced `%.30s` prefix truncation with a sanitised prefix plus
an FNV-1a hash of the full string, so remote-chosen key components can
no longer collide by sharing 30 characters. `CLEARTEXT_CRED`,
`DGA_DOMAIN`, `CAPTIVE_PORTAL`, `SAE_PSK_SPLIT`, `SSID_CONFUSION`, the
evil-twin chain, `ROGUE_DHCP`, `WPS_PIN_BRUTE` and `BEACONING` all emit
different `key` strings than v1.8.4 did. An archive joining incidents
across the upgrade boundary on `key` will not match. New additive
`reopen_count` on every `alert.*` record.

**6. `--replay --allow-active` is refused (#119).** Replay would
otherwise resolve addresses out of somebody else's savefile.

**No CLI flag was renamed or removed.** Seven were added:
`--replay`, `--ticks`, `--user`, `--no-privdrop`, `--bt-monitor`,
`--bt-capture`, `--ble-rotation-hints`. slothweb carries its own
separate flag set (`--web-bind`, `--web-allow`, `--web-allow-sql`,
`--web-token`, `--sloth-db`, `--store`, and the rest) on its own binary.

---

## New alert types (64 → 90)

26 added, none removed or renamed. Every row has its research-corpus
source on file — an `ALERT_TYPE_*` without one turns
`test_every_citable_alert_kind_is_cited` red.

### Bluetooth and BLE (#144, #156)

| Alert | Source |
|-------|--------|
| `BT_OWN_TRANSMIT` | the second own-state alert kind: the Bluetooth host's own transmissions, held on/off until disabled (#144 slice 2) |
| `BLE_ADV_FLOOD` | `research/bluetooth/ble-spam-flood.md` — Flipper/Marauder advertising flood; `research/bluetooth/ble-address-rotation.md` |
| `BLE_WATCHLIST` | `research/bluetooth/ble-watchlist-categories.md` — surveillance-beacon categories |
| `BLE_HID_UNEXPECTED` | `research/cve/2023-45866.md` (NVD, Apple HT214035) — unauthenticated HID advertisement; `research/bluetooth/ble-address-rotation.md` |

### Cameras (#106, #155)

| Alert | Source |
|-------|--------|
| `CAM_WS_DISCOVERY` | `research/papers/ws-discovery-onvif.md`, `camera-vendor-identity.md`, `camera-setup-softap.md` |
| `CAM_SSDP_DEVICE` | `research/papers/camera-vendor-identity.md` — UPnP `DigitalSecurityCamera:1` NOTIFY, once per device |
| `CAM_MDNS_SERVICE` | `research/papers/camera-vendor-identity.md` — DNS-SD service types IANA registers for cameras |
| `CAM_SETUP_SSID` | `research/papers/camera-setup-softap.md`, `camera-vendor-identity.md` |
| `CAM_SETUP_OUI` | `research/papers/camera-vendor-identity.md`, `camera-router-role.md` |
| `CAM_RTSP_UNAUTH` | `research/rfc/2326-7826-rtsp.md` — a DESCRIBE answered with no challenge |

### Multi-Link / Wi-Fi 7 (#104, #129)

| Alert | Source |
|-------|--------|
| `MLE_INVALID_LINK_ID` | `research/cve/2026-58374.md`, `research/ieee/802.11be-9.4.2.312-mld-identity.md` |
| `MLE_COMMON_INFO_LEN_BAD` | same, plus `802.11be-2024-9.4.2.322-bss-mle-consistency.md` |
| `MLE_SUBELEM_OVERRUN` | `research/cve/2026-58374.md`, `802.11be-9.4.2.312-mld-identity.md` |
| `MLD_MAC_COLLISION` | `802.11be-9.4.2.312-mld-identity.md`, `802.11be-2024-9.4.2.322` |
| `MLE_RECONFIG_NO_MLO` | `802.11be-2024-9.4.2.322` — a Reconfiguration MLE from a BSSID that has never sent a Basic MLE |
| `MLE_PR_BEACON_DIFF` | `802.11be-2024-9.4.2.322` — a Probe Response whose Basic MLE disagrees with the same BSSID's newest Beacon within 30 s |
| `MLE_CROSS_LINK_CIPHER_DOWNGRADE` | `802.11be-9.4.2.312`, `802.11be-2024-9.4.2.322` — an MLD whose links disagree on cipher or PMF |

### Regulatory (#101)

| Alert | Source |
|-------|--------|
| `COUNTRY_ABSENT` | `research/ieee/802.11d-country-element.md` |
| `DFS_MASKING` | `research/regulatory/dfs-15.407-en301893.md` |
| `TPC_ABSENT_HIGH_BAND` | `802.11d-country-element.md`, `802.11-2020-11.8-spectrum-management.md` |

### Framing Frames, WPS, surveillance (#107, #82, #105)

| Alert | Source |
|-------|--------|
| `PM_FORGE` | `research/cve/2022-47522.md` — PM-bit forgery against a station's sleep declaration |
| `QUEUE_EVICT` | `research/cve/2022-47522.md` — queued-frame release after a session change |
| `WPS_PIXIE_PROBE` | `research/papers/bongard-pixie-dust-2014.md`, `research/mitre/T1110.md` — 60 s of silence after M3 with no M4 (`--tune wps.pixie_silence_s=N`) |
| `WPS_PIXIE_LIKELY_SUCCESS` | same |
| `SURV_DNS` | `research/papers/surveillance-vendor-endpoints.md` — DNS lookups of surveillance-vendor service domains |
| `SURV_CLOUD_SNI` | same — TLS to a surveillance vendor's cloud, and nothing more |

Two corrections went in behind these: `SURV_DNS`, `SURV_CLOUD_SNI` and
then `THREAT_DOMAIN` were all matching a **cut** DNS name and churning
updates (#105, #152), and the #152 docs claim that SNI and Host are
IOC-matched was wrong and is corrected rather than left standing.

---

## slothweb: a second binary (#102, #157–#164)

New top-level `web/` tree, permitted by an explicit `agents/` change
(#102) rather than slipped in. `make web` builds `./slothweb`;
`make web WITH_SQLITE=0` builds one with no SQLite at all. It is
**not** built by `make`, is not linked into `sloth`, and shares no
process with it.

It runs beside sloth on the same host, reads the data socket and
optionally `sloth.db`, and serves one page on `127.0.0.1:8770`. It
never writes to sloth or to `sloth.db`, and never sends anything onto
a network. W0 (#157) built the allowed-peer list and its refusals
*before any route existed*; M0–M6 added the embedded page and SSE tick
(#158), the live view (#159), rollups and `slothweb.db` (#160),
baselines and nine anomaly rules as episodes (#161), the `sloth.db`
reader, query language, OUI table and lookup (#162), the WiFi and
History views with the SQL box behind `--web-allow-sql` (#163), and the
Flows view plus a five-minute README (#164).

Its own suite is separate (`make web-test`) and is **not** counted in
the 33398 figure above.

---

## #143: the architecture remediation wave

One tracker, 30 issues, closed 2026-10-20. The parts worth naming:

**Parsing.** Every 802.11 frame is decoded once into a `dot11_frame_t`
view and every observer consumes it; the per-file Frame Control
decoders are gone (#122, #130). One bounded reader and one TLV iterator
in `src/bytes.h` replaced 13 hand-rolled walks, with a parse-fault
tally in `sensor_health` (#126). The RSN element is parsed once
(#128), the DNS name read once (#131), L4 dispatched once with IPv4
Total Length honoured, non-first fragments no longer parsed as TCP/UDP
and IPv6 extension headers walked (#132), and the SSID/PHY/OUI element
helpers written once (#127). Radiotap metadata is applied before
parsing — FCS strip, DATAPAD, one radiotap gate — which fixes the false
`MGMT_FUZZ` on FCS-including drivers (#123). Action frames honour the
Protected bit and read Beacon Request mode from octet 9, so the SA
Query detector is no longer blind on PMF links (#124).

**State.** One clock seam: every libc clock read in `src/` goes through
`sloth_clock`, verified by a code scan that catches `time(0)`,
`time(&t)`, `gettimeofday` and `timespec_get`, not just one spelling
(#109). `stab_t` replaced eight copy-pasted snoop tables and the three
that refused new entries forever (#110). `fragattack` got its mutex and
the packet ring became a per-poll snapshot (#111). The typed alert-key
builder, incident side-state that survives slot reuse, and hash-first
lookup (#112). `poll_tick()` runs from a declared phase table (#113).
A reset registry and a zero-assertion gate in the runner (#114).

**Build and test.** `CORE_SRCS` + `libsloth_core.a`, every build's
sources derived from one list, per-config object dirs (#115).
`sloth_test` is now built the way sloth ships — `WITH_NCURSES` +
`WITH_PCAP` against an offscreen ncurses screen — and ~25 view test
files went from `ASSERT(1)` smoke tests to rendered-output assertions,
each conversion mutation-proved (#116). The view and alert-type lists
are X-macro `.def` files that generate the enums, labels, dispatch and
key switch; the hardcoded counts and two 150-line switches are gone,
and prose counts are rewritten by `make docs-counts` (#117). `alerts.c`
(5,346 lines, 75 rules) split into `src/alerts/{engine,rules_table,
rules_wired,rules_wifi_mgmt,rules_twin,rules_enterprise,rules_mle}.c`
behind an ordered rule table (#118). Headless `--replay`/`--ticks` and
a golden-JSONL integration job (#119). The last thresholds and the five
`atoi` flags folded onto the `--tune` registry (#120).

**Security.** A threat-model page every security issue cites by ID
(#133). The two `secure_file.c` bypasses closed, NOFOLLOW made a
compile-time requirement (#134). Per-peer data-socket connection caps,
idle reaping, a loopback-TCP notice (#135). Operator-supplied files
treated as untrusted bytes — `research.db` opened DEFENSIVE with
`TRUSTED_SCHEMA=0`, no extensions, a 1 MiB length limit (#137). One
render/export sanitisation choke point and valid-UTF-8 `json_escape`,
which found 75 bare `printf` calls in the views' ANSI `#else` branches
still printing SSIDs and process names raw — the exact CWE-150 surface
the issue named (#138). A checked `frame_view_t` in front of both
capture callbacks (#141). Dependency floors, commit-pinned runner
images, an SBOM job and release attestation (#142). `make install` and
a shipped hardened systemd unit, so the build tree is no longer
executed as root (#139).

**Memory.** #121 diagnosed the 7.7 GB RSS on the live sensor read-only
first and then instrumented `sensor_health` with `rss`/`rss_hwm`,
`sqlite_mem`, `malloc`, `fd_count` and `resolver_calls`. The new binary
measured flat at ~49 MB.

---

## Smaller, with a reason

- **#149** — per-channel RF-quality aggregates collided across 5 GHz
  and 6 GHz channel numbers. Now keyed by `(channel, band)` from the
  frame's real radiotap frequency, not a channel number out of an IE.
- **#167** — six copies of the frequency-to-channel plan, two of which
  disagreed with each other. `src/wifi_freq.{c,h}` is now the single
  implementation, round-tripped across all 393 assignable channels
  rather than sampled. `RT_BAND_*` renamed `WIFI_BAND_*` (53 mechanical
  sites) because an nl80211 scan result's band has nothing to do with
  radiotap.
- **#148** — `BEACONING` fired one finding per strong track per tick.
  Capped at `bd.max_findings` findings plus one `beacon-overflow`
  finding, with additive `displaced` and `drained` lifecycle reasons.
- **#165** — PTR responses reached the JSONL stream with `answer==""`,
  so slothweb's `passive_ptr` cache never filled. RDATA is now decoded
  as a domain name per RFC 1035 §3.3.12/§4.1.4; a malformed target is
  discarded without aborting the RR walk.
- **#108** — `make mutate` had been dead since #73 because the sandbox
  omitted `research/`. Fixed first, then every mutation claim that
  relied on it was re-checked.
- **#96** — SECURITY.md said 1.4.x while the code was 1.8.0. The
  supported-version line is now checked strictly against
  `SLOTH_VERSION` by `tests/test_docs_consistency.c`, and
  `agents/FACTORY.md` ties the two to the same commit.
- **#100** — `WITH_TLS=1` for the data socket: design captured, not
  scheduled, and CI now fails the build if sloth ever links a TLS
  library.
- **#103** — wiki link integrity and alert rule-row coverage are
  enforced; the wiki is synced to GitHub on every push to `main`.

---

## Verification

Every variant built warning-clean and the suite green on `origin/main`
at `ae8d495`, before the version bump:

```
make                  rc=0   0 warnings
make WITH_NCURSES=0   rc=0   0 warnings
make embedded         rc=0   0 warnings
make WITH_SQLITE=0    rc=0   0 warnings
make test             rc=0   33398 assertions passed, 0 failed
```

CI on `ae8d495` was green across CI, CodeQL, wiki-sync and the Code
Review job, including the blocking `sanitize`, `tsan`, `cppcheck`,
`harden`, `replay-check` and `check-deps` jobs.

`make web-test` is slothweb's own suite and is counted separately; its
three `test_server.c` failures in a sandbox without AF_INET6 are
pre-existing and unrelated to this tag.

Still no `.pcap` files in `tests/` — the capture-path suite builds its
libpcap savefile in memory from the format spec, and every detector
test, including the BLE HCI cases and the Bluetooth stream decoders, is
hand-built bytes per the relevant IEEE, Bluetooth Core or RFC clause.
