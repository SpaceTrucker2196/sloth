# FACTORY.md — Build & Infrastructure Runbook

Operating manual for an agent (or human) bringing sloth up from a cold
clone. Charter and ethics live in [`MISSION.md`](MISSION.md); pattern
in [`docs/dark-factory.md`](docs/dark-factory.md); working rules in
[`CLAUDE.md`](CLAUDE.md); concept depth in [`docs/wiki/`](docs/wiki/);
per-view detail in [`docs/views/`](docs/views/).

This file answers one question: *what do I need to install, run, and
ship the binary?*

---

## 0. TL;DR

```sh
# Linux (Debian/Ubuntu)
sudo apt-get install -y build-essential libpcap-dev libncursesw5-dev
git clone https://github.com/SpaceTrucker2196/sloth.git
cd sloth
make test    # green ⇒ env is sound (no root, no terminal, no network)
make         # builds ./sloth
sudo ./sloth # needs CAP_NET_RAW + CAP_NET_ADMIN for pcap + nl80211
```

If `make test` passes and `make` produces no warnings, the factory is
operational.

---

## 1. Supported platforms

| Platform | Build | Run | Notes |
|----------|-------|-----|-------|
| Linux    | yes (primary) | yes (full)   | rtnetlink, nl80211, INET_DIAG, /proc, libpcap |
| macOS / Darwin | yes (build & test) | partial | BSD platform stub; for development only — fake platform drives all tests |
| *BSD     | yes (build only)   | stub    | `src/platform/bsd.c` is minimal |
| Windows  | not maintained     | n/a     | `src/platform/win32.c` exists but is a stub |
| Other    | yes (stub build)   | n/a     | `src/platform/stub.c` returns empty data |

The production target is Linux. Other platforms exist so the test
binary can build anywhere; they are not feature-complete.

---

## 2. Toolchain

| Tool | Minimum | Why |
|------|---------|-----|
| C compiler | C99 (`gcc` ≥ 4.6 or `clang` ≥ 3.3) | code is `-std=c99 -D_DEFAULT_SOURCE` |
| `make`     | GNU make                            | `Makefile` uses GNU conditional syntax |
| `pkg-config` | optional | not used by the Makefile; CMake path uses it |
| `git`      | any modern               | clone + commit |
| `pthread`, `libm` | system               | linked unconditionally |

No autotools, no meson, no bazel. A `CMakeLists.txt` exists at root but
is a stale alternate build path that hardcodes the old `ntop` name —
**use the Makefile**.

---

## 3. Runtime dependencies

For the **full build** (default):

- `libpcap` — packet capture (capture thread, BPF filter, pcap export).
- `libncurses` (Linux: `libncursesw`, macOS: unified `libncurses`) — TUI.

For the **test build**: none beyond `pthread` and `libm`. Tests run
headless and offline.

For the **embedded build** (`make embedded`): none beyond `pthread`
and `libm`. No capture, no TUI; useful for headless data collectors.

### Install per distro

```sh
# Debian / Ubuntu
sudo apt-get install -y build-essential libpcap-dev libncursesw5-dev

# Fedora / RHEL
sudo dnf install -y gcc make libpcap-devel ncurses-devel

# Alpine
apk add build-base libpcap-dev ncurses-dev

# Arch
sudo pacman -S --needed base-devel libpcap ncurses

# macOS (development only — runs against fake platform)
xcode-select --install
brew install libpcap ncurses
```

---

## 4. Build matrix

All targets driven by the root [`Makefile`](Makefile).

| Command | What you get |
|---------|--------------|
| `make`                       | full build → `./sloth` (ncurses + pcap + nl80211) |
| `make WITH_PCAP=0`           | no capture; the packets/probe views render a disabled message |
| `make WITH_NCURSES=0`        | headless; `TPRINT` falls back to `printf` |
| `make WITH_WIFI=0`           | drops nl80211 source on Linux |
| `make embedded`              | shortcut: `WITH_NCURSES=0 WITH_PCAP=0` |
| `make test`                  | builds `./sloth_test`, runs all assertions |
| `make clean`                 | removes objects, `sloth`, `sloth_test` |
| `make install PREFIX=...`    | installs to `$PREFIX/bin/sloth` (default `/usr/local`) |

**Override knobs** (env or `make CC=clang ...`):

- `CC` — compiler (default `cc`)
- `CFLAGS` — default `-O2 -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE`
- `LDFLAGS` — extra linker flags
- `PREFIX` — install root (default `/usr/local`)

**Hard rules** (from [`CLAUDE.md`](CLAUDE.md)):

- `make` must be **warning-clean**. Treat any new warning as a failed build.
- `make test` must return 0. **Never commit a red test**.
- `VIEW_COUNT` in `include/sloth.h` must stay in sync with the assertions
  in `tests/test_state.c` and `tests/test_arp.c` whenever a view is
  added or removed.

---

## 5. Test discipline

- ~1664 assertions across `tests/*.c`.
- No root required. No terminal required. No network required.
- All kernel-facing code is replaced by `tests/fake_platform.c` (see
  [[platform-vtable]] in the wiki).
- TUI render functions execute their full code path against
  `tests/null_tui.c` (ncurses no-ops; `TPRINT` becomes `printf`).
- Protocol parsers (DNS, TLS, JA3, QUIC, HTTP, NTP, ICMP, mDNS, NBNS,
  DHCP, SSDP) are tested with **hand-crafted byte arrays** built from
  the relevant RFCs. Parsers never feed themselves their own output.
- `src/md5.c` is validated against every RFC 1321 test vector.

Adding a feature without adding a test is a regression in the
factory's review capability. Do not skip.

---

## 6. Running sloth

### 6.1 Capabilities

| Need | Capability | Effect if missing |
|------|------------|-------------------|
| libpcap capture       | `CAP_NET_RAW`   | no packets, no L7 logs |
| nl80211 scan / stations | `CAP_NET_ADMIN` | WiFi view empty |
| `/proc/<pid>/fd/*` of other users | root (or same uid) | sockets show no PID/process |
| Monitor-mode capture  | `CAP_NET_ADMIN` on the iface | no probes, no beacons, no EAPOL |

Easiest path during development: `sudo ./sloth`. For unattended
deployment, prefer file-grant caps:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip ./sloth
./sloth   # runs unprivileged
```

### 6.2 Invocation forms

```sh
./sloth                                  # TUI on default iface
./sloth -i eth0                          # pin capture iface
./sloth -o /var/log/sloth.jsonl          # JSONL forensic stream
./sloth --pcap-dir /var/sloth/pcap       # per-alert pcap dumps
./sloth --eapol-dir /var/sloth/eapol     # PMKID + handshake export (hashcat 22000)
```

Flags compose. The JSONL schema is documented in [`README.md`](README.md#jsonl-schema).

### 6.3 WiFi SIGINT prep (out-of-band)

Sloth **never** touches link state. Monitor mode must be set up
externally before sloth starts:

```sh
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
sudo ./sloth --eapol-dir /tmp/sloth-eapol
```

Tested chipset: `rtl88XXau`. Any card whose driver supports
`ARPHRD_IEEE80211_RADIOTAP` should work.

### 6.4 Minimum terminal

100×33 for the [[dashboard]] composite view. Below that, the tiling
collapses and panels become unreadable.

---

## 7. Deployment

Sloth is **one binary**, no config file, no daemon manager required.

- `sudo make install` drops `/usr/local/bin/sloth`.
- For systemd, write a unit that runs `sloth -o ... --pcap-dir ... --eapol-dir ...`
  with `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`. No template
  shipped — keep deployment under operator control.
- The binary has **no telemetry, no phone-home, no auto-update**.
  Anything that talks back to a remote violates [`MISSION.md`](MISSION.md) §2.

---

## 8. CI

`.github/workflows/ci.yml` runs on every push and PR:

```yaml
runs-on: ubuntu-latest
steps:
  - actions/checkout@v4
  - apt-get install libncurses-dev libpcap-dev
  - make
  - make test
```

That's the gate. Both steps must be green for a PR to be considered
mergeable by the factory's review loop.

---

## 9. Code layout (where to put things)

| Path | Contains |
|------|----------|
| `include/sloth.h`            | shared structs, `view_t` enum, `VIEW_COUNT`, `platform_ops_t` |
| `src/main.c`                 | CLI, signal handlers, main poll loop |
| `src/tui.c`                  | ncurses rendering, key polling, ANSI fallback |
| `src/platform/linux*.c`      | rtnetlink, nl80211, /proc readers, INET_DIAG |
| `src/platform/{bsd,win32,stub}.c` | non-Linux backends |
| `src/capture/capture.c`      | libpcap thread, per-protocol parser dispatch |
| `src/capture/probe.c`        | 802.11 probe / beacon capture |
| `src/{dns,tls,quic,http,ntp,icmp,dns}_log.c` | ring buffers + snapshot helpers |
| `src/{alerts,beacon_detect,devices,threat_intel,filter,jsonl,alert_pcap,top_hosts,ip_color,ip_owner,host_cache,probe_pnl,eapol_log,seqnum_track,assoc_track}.c` | synthesis + export |
| `src/views/<name>.c`         | one file per VIEW_* |
| `src/md5.c`                  | embedded MD5 for JA3 (RFC 1321 verified) |
| `tests/`                     | unit tests, fake platform, scenarios |
| `docs/views/<name>.md`       | per-view protocol/observation reference |
| `docs/wiki/<name>.md`        | concept-oriented knowledge base |

**Hard rules**:

- No new files at repo root. Everything has a home.
- Never `git add -A` / `git add .`. Stage by specific path. A local
  `wifi-sigint/` may exist and **must never** be staged or pushed.
- Don't commit the `sloth` or `sloth_test` binaries.
- Never reintroduce coloured row backgrounds (see [[ip-palette]]).

---

## 10. Adding work (agent-facing recipes)

### 10.1 Add a view

See [`CLAUDE.md`](CLAUDE.md) "How to add a new view" — 11-step
checklist that keeps `VIEW_COUNT` synced, lays out the file, wires a
keybind, and demands a test + a per-view doc.

### 10.2 Add an alert rule

See [`CLAUDE.md`](CLAUDE.md) "How to add an alert rule" — 6 steps,
ending in a `find_alert(type) >= 0` assertion. Concept page:
[`docs/wiki/alerts.md`](docs/wiki/alerts.md).

### 10.3 Add a platform op

1. Add the function pointer to `platform_ops_t` in `include/sloth.h`.
2. Implement it in every backend: `linux*.c`, `bsd.c`, `win32.c`, `stub.c`.
3. Implement it in `tests/fake_platform.c` with controllable in-memory data.
4. Write the test that drives the new fake.
5. Views read from `sloth_state_t`. Views must never call platform ops directly.

---

## 11. Common failures and fixes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `fatal error: pcap.h: No such file` | missing libpcap headers | `apt-get install libpcap-dev` (or `make WITH_PCAP=0`) |
| `cannot find -lncursesw` (Linux) | missing wide-char ncurses | `apt-get install libncursesw5-dev` |
| `cannot find -lncurses` (macOS) | shouldn't happen — macOS ships it; check Xcode CLT | `xcode-select --install` |
| Empty connections view | no `CAP_NET_RAW` or wrong uid | `sudo` or `setcap` |
| No process names on sockets | sockets owned by other uids | run as root |
| Empty WiFi view on Linux | missing `CAP_NET_ADMIN` or no wifi iface | check `iw dev`; run with caps |
| No probes / beacons / EAPOL | iface not in monitor mode | see §6.3 |
| `make test` fails on a fresh clone | toolchain too old, or local mod | `make clean && make test`; verify `gcc --version` is ≥ 4.6 |
| Build warnings | regression in the factory's quality gate | **fix before commit** — warnings are not negotiable |
| `VIEW_COUNT mismatch` test failure | added a view without bumping the constant | update `include/sloth.h`, `tests/test_state.c`, `tests/test_arp.c` |

---

## 12. Git & release workflow

From [`CLAUDE.md`](CLAUDE.md):

- Branches: work on `main`. No long-running feature branches.
- Commits: imperative subject, blank line, body explaining the *why*,
  `Co-Authored-By` trailer.
- Push after each green commit. Human reviews on GitHub.
- Never `git push --force` to `main`. Never `--no-verify`. Never
  `git reset --hard` without explicit user authorisation.

CI gates merge: `make` + `make test`. If either fails, the commit
doesn't go in.

---

## 13. Cold-start sanity loop

To verify an agent's environment is wired correctly from scratch:

```sh
# 1. Source of truth
git clone https://github.com/SpaceTrucker2196/sloth.git
cd sloth

# 2. Build, then test
make test      # must exit 0 with all assertions green
make           # must exit 0 with zero warnings

# 3. Smoke run (Linux, with caps)
sudo ./sloth   # press [?] for help, [o] for dashboard, [q] to quit
```

If steps 2–3 succeed, the factory is fully operational and the agent
can start taking work from [`MISSION.md`](MISSION.md) §6 ("Direction").

---

## 14. Where to read next

| If you want… | Read |
|--------------|------|
| The non-negotiable charter | [`MISSION.md`](MISSION.md) |
| The dark-factory pattern itself | [`docs/dark-factory.md`](docs/dark-factory.md) |
| Working rules for the repo | [`CLAUDE.md`](CLAUDE.md) |
| Concept-level wiki | [`docs/wiki/index.md`](docs/wiki/index.md) |
| Per-view protocol reference | [`docs/views/README.md`](docs/views/README.md) |
| User-facing release notes | [`README.md`](README.md) |
