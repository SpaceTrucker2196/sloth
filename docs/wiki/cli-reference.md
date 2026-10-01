---
name: cli-reference
description: Complete command, flag, argument, keybinding and environment reference for the sloth binary — the authoritative CLI page
type: reference
---

# CLI reference

**Summary**: Every command-line flag, its argument, default, and effect;
every runtime keybinding; the environment variables; and exit codes.
Source of truth is `print_usage()` and the argv loop in `src/main.c`, and
`view_labels[]` / `handle_key()` for the keys. If this page and the
binary disagree, the binary is right — and this page is out of sync, which
is a bug ([[docs-drift-judge]], and the wiki-sync duty in `agents/AGENTS.md`).

**Sources**: `src/main.c` (`print_usage`, `main` argv loop, `handle_key`),
`src/view_labels.c`, `include/sloth.h`.

**Last updated**: 2026-10-01.

---

## Synopsis

```
sloth [output] [handshakes] [stream] [wifi] [correlation] [db]
      [inventory] [posture] [runtime] [--help] [--version]
```

Run as root (or with `CAP_NET_ADMIN` + `CAP_NET_RAW`) for capture. The
test binary `sloth_test` takes no flags. No subcommands — sloth is a
single mode driven by flags.

## Flags, by group

### Output — forensic log & format

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `-o`, `--out` | `FILE` | off | Append a JSONL forensic log of all observed events. Created `0600`; an existing file must be private, owned by you, not a symlink. → [[jsonl-schema]] |
| `--out-format` | `FORMAT` | `jsonl` | Format for `-o` **and** `--data-socket`. One of `jsonl`, `cef` (ArcSight CEF), `syslog` (RFC 5424, PRI 134). |
| `--pcap-dir` | `DIR` | off | On a critical alert with a known flow, write the matching packets to a fresh pcap under `DIR`. Dir `0700`, files `0600`. → [[pcap-export]] |
| `--eapol-dir` | `DIR` | off | Append captured PMKIDs / 4-way handshakes to `DIR/eapol.22000` (hashcat 22000) **and** a per-handshake `DIR/<bssid>_<sta>.pcap`. **Crackable material** — strict perms, refused not repaired. **Requires `--collect-handshakes`**: without it this flag exits `2` and no directory is created. → [[wifi-sigint]] |
| `--collect-handshakes` | — | **off** | Opt in to writing crackable material to disk. A PMKID or a paired M1+M2 supports offline password guessing, so exporting one is a separate decision from observing one. Gates the `.22000` lines and the per-handshake pcaps **only** — detection, alerting, the `[e]` view and the JSONL/DB records are unaffected. sloth never cracks anything itself (MISSION §2.2). → [[retention]] |
| `--handshake-retention` | `DAYS` | `7` | Age-out window for the artifacts above. Swept at startup and once a day while running; artifacts last written before the window are deleted. `0` = keep forever. Whole-file granularity by mtime, so `eapol.22000` goes only once nothing has been appended for the whole window. A failed delete is counted and shown in the `[e]` header, never silent. → [[retention]] |
| `--report` | `FILE.md` | off | On exit, write a Markdown posture report (alerts by severity + MITRE technique, cleartext creds, high-risk devices). → [[posture-report]] |
| `--report-json` | `FILE.json` | off | Same rollup, structured for SIEM diff. |

### Stream — the read-only data socket

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--data-socket` | `[SPEC]` | off | Stream the same records over a **read-only** socket. `SPEC` = `unix:/path` or `tcp:HOST:PORT`. Bare flag → `tcp:127.0.0.1:8765` (loopback). Nothing is ever read from it. → [[data-socket-exposure]] |
| `--data-socket-allow-remote` | — | off | Permit a non-loopback bind (incl. `0.0.0.0`). Every observation becomes readable by anyone who can reach the port. Prefer an SSH tunnel. |
| `--no-discovery` | — | advertises | Suppress the mDNS advert of a routable data socket. Loopback/unix never advertise regardless. |

### Wi-Fi — capture scope & active behaviour

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--iface` | `NAME` | all | Restrict the stream to `NAME` (repeatable, max `MAX_IFACES`). Logical only — OS iface state untouched. |
| `--monitor-only` | — | off | Restrict capture to the auto-discovered monitor interface. **Fail-closed**: exits non-zero if none found or it can't be enforced. |
| `--hop` | — | off | Passive channel-hopping: retune sloth's own monitor interface across a 2.4/5 GHz list, dwelling on activity. One of two kernel-state writes. Needs monitor mode + `CAP_NET_ADMIN`. No frame transmitted. → [[monitor-mode]] |
| `--allow-active` | — | off | Opt in to the two active behaviours: (1) reverse-DNS PTR queries on cache miss; (2) nl80211 **passive** scan triggers (no SSID list, no probe transmitted). Prints one stderr line naming what it enabled; never silent. |
| `--strict` | — | off | Lock: refuses any later attempt to enable active behaviour this run (`--strict --allow-active` exits non-zero). Suppresses the mDNS advert. Does **not** refuse `--hop`, and does **not** close a routable `--data-socket`. Records operator intent where `ps(1)`/audit can see it. |

### Correlation — MAC deanonymisation

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--no-correlate` | — | on (correlation enabled) | Disable longitudinal device correlation. Seqnum `[j]` still shows each MAC's own trail, but no pair is linked and no `seqnum_correlation` record is exported/stored. → [[mac-randomisation]] |
| `--correlate-retain` | `SECS` | `300` | Evidence window: a pair is reported only while **both** addresses were heard inside this window, counted from now. |

### Persistent state — SQLite

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--db` | `FILE` | off | Persist entity state to SQLite. Bounded by fixed tables, not uptime (upsert per entity, not append per tick). Read with `sqlite3`; sloth exposes no query surface. → [[sqlite-schema]] |
| `--db-interval-secs` | `N` | `1` | Seconds between DB write ticks. Raise on slow storage. |
| `--db-retain-days` | `N` | `30` | Age-out window for observation rows. Tiered: entities keep 3×, alerts/credential exposures keep 12×. → [[retention]] |
| `--db-max-mb` | `N` | `512` | Size target (MiB), a pruning trigger not a hard cap. `0` = unlimited. Oldest observation rows go first; entity/alert/credential rows never dropped. |

### Inventory & ownership — trust anchors

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--inventory` | `FILE` | off | Load approved-inventory JSON (which BSSIDs are authorised for which SSID, #89). The only evil-twin trust input not from the air. All-or-nothing: a malformed file exits. → [[inventory]] |
| `--site` | `TEXT` | off | Operator label for this sensor's location; part of the evil-twin dedup key. Overrides the inventory file's `site`. Config only — never derived from RF. |
| `--my-ssid` | `SSID` | off | Designate your own network (repeatable, max 16). Label only; unlocks `MY_NET_RECON`. |
| `--my-bssid` | `BSSID` | off | Designate your own AP (repeatable, max 16). Floods at it escalate WARN→CRIT; never named the impostor half of a twin. |
| `--known-mac` | `MAC` | off | Add a MAC to the known-device roster (repeatable, max 512). |
| `--known-macs` | `FILE` | off | Load a roster (one MAC/line, `#` comments). With a roster **and** a `--my-ssid`/`--my-bssid`, an associated device not on the roster raises `UNKNOWN_DEVICE`. |

### Posture — snapshots & research

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--snapshot-out` | `FILE` | off | On exit, write a passive AP-inventory snapshot (BSSID/SSID/security/channel/vendor) for repeat site assessments. Normalised text, no pcap. → [[posture-report]] |
| `--baseline-in` | `FILE` | off | On exit, diff the current AP inventory against a prior `--snapshot-out` (new/gone/changed APs). |
| `--site-label` | `TEXT` | off | Operator label stamped into `--snapshot-out`. Distinct from `--site`. |
| `--with-research` | `research.db` | off | Load the research corpus so `--report` cites the source behind each fired alert. Additive: unreadable corpus warns and continues. → [[research-corpus]] |
| `--check-manifest` | `FILE` | off | Read a locally-populated release manifest (JSON); show "update available" in Help when `latest` > `SLOTH_VERSION`. sloth never fetches — populate `FILE` via cron/systemd. → [[manifest-format]] |

### Runtime & meta

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--refresh-ms` | `N` | `250` (~4 Hz) | Dashboard refresh interval, ms. Floor 50. The loop also wakes early on alert fires, so it is an upper bound. |
| `--headless` | — | off | Draw nothing, never touch the terminal (no clears, no escape sequences, no raw-mode termios). For appliance/systemd. Capture, alerting and every sink run normally. |
| `--no-color`, `--no-colour` | — | color on | Suppress colour escapes, keep drawing. Also honoured via `NO_COLOR` env. |
| `--version`, `-V` | — | — | Print version to stdout and exit `0`. |
| `--help`, `-h` | — | — | Print usage and exit `0`. |

## Keybindings (runtime TUI)

### View selection

| Key | View | Key | View | Key | View |
|-----|------|-----|------|-----|------|
| `1` Interfaces | `d` DHCP | `u` QUIC | `l` OSI stack |
| `2` Connections | `s` SSDP | `r` DNS | `x` Twins |
| `3` WiFi | `b` Beacons | `p` NTP | `y` KARMA |
| `4` Packets | `a` Deauth | `i` ICMP | `z` Rogue RADIUS |
| `5` Processes | `h` HTTP | `v` Alerts | `c` FragAttacks |
| `6` Stats | `t` TLS | `g` Devices | `f` Research |
| `7` Probe | `k` PNL | `o` Dashboard | `?` Help |
| `8` ARP | `e` EAPOL | `m` Channel | |
| `9` mDNS | `j` Seqnum | `w` Assoc | |
| `0` NBNS | | | |

Full map with descriptions: [[views-catalog]].

### Global keys

| Key | Action |
|-----|--------|
| `Tab` | Cycle views forward |
| `n` | Toggle DNS hostname resolution (conn/proc/stats views) |
| `/` | Filter current log view — type to refine, `Enter` commit, `Esc` cancel |
| `\` | Clear filter |
| `q` / `Q` | Quit |
| `?` | Toggle Help |

### Per-view keys

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate rows |
| `c` | Clear the current log view's ring buffer |
| `t` | (Interfaces) toggle iface visibility (display-only) |
| `y` | (Interfaces) toggle iface data-stream selection — drops its packets pre-decode |
| `m` | (Interfaces) retarget the 802.11 monitor radio onto the selected iface; refused, leaving a running radio alone, when a non-empty `--iface` allow-list excludes it — the reason shows as the probe error |
| `Enter` | (Interfaces / Packets) open detail panel |
| `f` | (Conns / Packets) cycle filter |
| `s` | (Conns) cycle sort |

A view can *claim* a key the global switch also uses; see
`src/view_route.c` and the "add a view" checklist in `AGENTS.md`.

## Environment variables

| Var | Effect |
|-----|--------|
| `NO_COLOR` | Any non-empty value disables colour (read before flags). |
| `RISK_THRESHOLD` | Converge-loop risk gate threshold (default 50) — tooling, not the binary. See `agents/FACTORY.md`. |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean exit (incl. `--version`, `--help`). |
| `2` | Bad argument, or a fail-closed refusal (`--monitor-only` with no monitor iface, malformed `--inventory`/`--known-macs`, a refused output path, `--strict --allow-active`, `--eapol-dir` without `--collect-handshakes`, a `--handshake-retention` value outside `0..36500`). |

## Build variants (Makefile)

Not runtime flags, but part of the command surface:

```sh
make                 # full: ncurses + pcap + nl80211
make WITH_NCURSES=0  # headless / embedded (ANSI fallback)
make WITH_PCAP=0     # no capture, no probe view
make WITH_WIFI=0     # no nl80211
make WITH_SQLITE=0   # no --db
make embedded        # shortcut: no ncurses, no pcap
make test            # sloth_test — 9304 assertions, no root/tty/net
make mutate          # mutation-test the suite (opt-in, offline)
```

All six build variants must be warning-clean; CI enforces `-Werror`
across the matrix (`AGENTS.md` Discipline).

## Related pages

- [[what-sloth-does]] — what each output actually contains.
- [[monitor-mode]] — the `--hop` / `--monitor-only` substrate.
- [[jsonl-schema]] · [[data-socket-exposure]] · [[sqlite-schema]] · [[pcap-export]].
- [[views-catalog]] — the keys, with per-view detail.
