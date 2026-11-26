CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE
LDFLAGS ?=
PREFIX  ?= /usr/local

# Feature flags — disable with: make WITH_PCAP=0
WITH_NCURSES ?= 1
WITH_PCAP    ?= 1
WITH_WIFI    ?= 1
WITH_SQLITE  ?= 1

# ── Source lists (#115) ─────────────────────────────────────────────────────
# Every binary this Makefile builds is derived from these lists; none keeps
# its own. The split is the issue's:
#
#   APP_SRCS   what only the shipped `sloth` links: the CLI and poll loop,
#              the ncurses renderer, and the real platform vtable. The test
#              build links the renderer too (#116) but swaps in
#              tests/fake_platform.c for the platform.
#   CORE_SRCS  everything else the current configuration compiles. It is
#              archived as libsloth_core.a, so each binary's linker pulls
#              only the members something it links actually references —
#              which is what keeps a fuzz target narrow without a hand-kept
#              list beside it (the inline fuzz lists rotted and failed CI on
#              2026-10-14).
#
# A new module goes in exactly one list, once, and `make`, `make test`
# and `make fuzz` all pick it up. Which list (#212, for the sloth-wifi /
# sloth-rf split of #211, ADR 0010):
#
#   RF_SRCS         only ADS-B, APRS, rtl_433 or Victron (and, later,
#                   Meshtastic): a decoder, its reader thread, its rules,
#                   its poll stages, its records and source rows. sloth-rf
#                   owns them; sloth-wifi links none of them since the
#                   cutover (#216), and check_wifi_no_rf holds its link
#                   to that.
#   GNSS_SRCS       only the --gps / --location receiver: the parsers, the
#                   reader, the position track, the GNSS rules and view,
#                   its poll stages. Both daemons link the reader; the
#                   view is sloth-wifi's alone and the rules sloth-rf's
#                   alone (rule_gnss_* is on check_wifi_no_rf's list).
#   CORE_BASE_SRCS  everything else that is built in every configuration:
#                   the Wi-Fi, wired and BLE modules and the services both
#                   daemons share (the alert engine, JSONL, the clock, the
#                   run flag, the poll runner). When in doubt, here.
#   a feature group below (PCAP_CORE_SRCS, SQLITE_CORE_SRCS, the Linux
#                   lists) if a WITH_* flag or the platform gates it.
#
# The test for RF_SRCS and GNSS_SRCS is the include graph, not the topic:
# a file belongs there only if nothing in CORE_BASE_SRCS would have to
# move with it. src/sys_status.c reads every source and stays in the
# base; so does src/alerts/rules_sensor.c.
#
# CORE_COMMON_SRCS is the union of the three and is what every consumer
# below reads. It all goes into one archive, and each binary's linker
# takes the members something it links references: sloth-wifi and
# sloth-rf differ by what their own objects name, not by a second list.
CORE_BASE_SRCS = \
       src/view_route.c    \
       src/worker_thread.c \
       src/view_labels.c   \
       src/tui_palette.c   \
       src/tui_glyph.c     \
       src/dev_how.c       \
       src/ownership.c     \
       src/inventory.c     \
       src/wired_attach.c  \
       src/presence.c      \
       src/transit.c       \
       src/radiotap.c      \
       src/wifi_freq.c     \
       src/rf_quality.c    \
       src/rf_model.c      \
       src/rf_distance.c   \
       src/db_schema.c     \
       src/history.c       \
       src/bandwidth.c     \
       src/dns.c           \
       src/dns_snoop.c     \
       src/dns_wire.c      \
       src/ftp_snoop.c     \
       src/pop3_snoop.c    \
       src/imap_snoop.c    \
       src/smtp_snoop.c    \
       src/cleartext_creds.c \
       src/device_risk.c   \
       src/posture.c       \
       src/posture_coverage.c \
       src/version.c       \
       src/libver.c        \
       src/libver_pcap.c   \
       src/updater.c       \
       src/oui.c           \
       src/services.c      \
       src/views/iface.c   \
       src/views/conns.c   \
       src/views/wifi.c    \
       src/views/packets.c \
       src/views/procs.c   \
       src/views/stats.c   \
       src/views/probe.c   \
       src/views/arp.c     \
       src/mdns_snoop.c    \
       src/nbns_snoop.c    \
       src/dhcp_snoop.c    \
       src/ndp_snoop.c     \
       src/smb_snoop.c     \
       src/kerb_snoop.c    \
       src/ldap_snoop.c    \
       src/bgp_snoop.c     \
       src/ssh_snoop.c     \
       src/rdp_snoop.c     \
       src/snmp_snoop.c    \
       src/mqtt_snoop.c    \
       src/event_wake.c    \
       src/quic_snoop.c    \
       src/views/mdns.c    \
       src/views/nbns.c    \
       src/views/dhcp_snoop.c \
       src/ssdp_snoop.c      \
       src/views/ssdp.c      \
       src/onvif_discovery.c \
       src/rtsp_snoop.c      \
       src/reg_ie.c          \
       src/reg_6g.c          \
       src/reg_obs.c         \
       src/beacon_snoop.c    \
       src/views/beacon.c    \
       src/deauth_snoop.c    \
       src/flood_window.c    \
       src/sloth_clock.c     \
       src/views/deauth.c    \
       src/http_log.c        \
       src/views/http.c      \
       src/tls_log.c         \
       src/views/tls.c       \
       src/quic_log.c        \
       src/views/quic.c      \
       src/dns_log.c         \
       src/views/dns_log.c   \
       src/ntp_log.c         \
       src/views/ntp.c       \
       src/icmp_log.c        \
       src/views/icmp.c      \
       src/threat_intel.c    \
       src/vendor_watchlist.c \
       src/dga.c             \
       src/wifi_oui_attacker.c \
       src/wifi_chanhop.c    \
       src/df.c              \
       src/capture/df_radio.c \
       src/mon_radios.c      \
       src/capture/mon_radio.c \
       src/auth_track.c      \
       src/action_snoop.c    \
       src/ctrl_frames.c     \
       src/dot11_data.c      \
       src/dot11_frame.c     \
       src/dot11_ie.c        \
       src/rsn_ie.c          \
       src/netstr.c          \
       src/mle.c             \
       src/tool_fingerprint.c \
       src/attack_hw.c       \
       src/captive_portal.c  \
       src/wifi_snapshot.c   \
       src/sweep.c           \
       src/sweep_cov.c       \
       src/wifi_assess.c     \
       src/wifi_baseline.c   \
       src/sensors.c         \
       src/sensor_health.c   \
       src/sys_status.c      \
       src/sys_status_capture.c \
       src/capture_side.c    \
       src/stab.c            \
       src/persist_health.c  \
       src/wps_track.c       \
       src/pm_forge.c        \
       src/queue_evict.c     \
       src/wifi_merge.c      \
       src/twins.c           \
       src/views/twins.c     \
       src/karma_detect.c    \
       src/probe_latency.c   \
       src/harvest_track.c   \
       src/views/karma.c     \
       src/views/rogue_radius.c \
       src/alerts/engine.c   \
       src/alert_lifecycle.c \
       src/alerts/rules_table.c \
       src/alerts/rules_mle.c \
       src/alerts/rules_enterprise.c \
       src/alerts/rules_wired.c \
       src/alerts/rules_wifi_mgmt.c \
       src/alerts/rules_twin.c \
       src/alerts/twin_field.c \
       src/alerts/rules_camera.c \
       src/alerts/rules_harvest.c \
       src/tune.c src/fs_capacity.c            \
       src/views/alerts.c    \
       src/md5.c             \
       src/sha256.c          \
       src/devices.c         \
       src/views/devices.c   \
       src/beacon_detect.c   \
       src/jsonl.c           \
       src/jsonl_core.c      \
       src/jsonl_chain.c     \
       src/formatter.c       \
       src/data_socket.c     \
       src/discovery.c       \
       src/observe.c         \
       src/views/help.c      \
       src/filter.c          \
       src/alert_pcap.c      \
       src/secure_file.c     \
       src/ip_owner.c        \
       src/ip_color.c        \
       src/top_hosts.c       \
       src/host_cache.c      \
       src/probe_pnl.c       \
       src/views/pnl.c       \
       src/eapol_log.c       \
       src/eap_parse.c       \
       src/eap_track.c       \
       src/views/eapol.c     \
       src/seqnum_track.c    \
       src/views/seqnum.c    \
       src/assoc_track.c     \
       src/views/assoc.c     \
       src/views/channel.c   \
       src/views/dashboard.c            \
       src/views/dashboard_primitives.c \
       src/views/dashboard_bands.c      \
       src/views/dashboard_grid.c       \
       src/views/osi.c

# Unconditional: capture.c is almost entirely inside its own WITH_PCAP
# guard, but the pure datalink/return-code classifiers above that guard
# are compiled and linked in every configuration — main.c calls
# capture_dlt_has_ifindex() to report inactive scoping even in a build
# with no capture at all (#46, #57).
CORE_BASE_SRCS += src/capture/capture.c
# The pcap-edge gate (#141) is libpcap-free so the test and fuzz builds
# link it whatever WITH_PCAP says; both capture callbacks call it first.
CORE_BASE_SRCS += src/capture/frame_edge.c
# --replay (#119). Same split as capture.c: the route table, the list
# parser and the empty platform are pure and built everywhere; the
# savefile reader sits inside WITH_PCAP.
CORE_BASE_SRCS += src/capture/replay.c
CORE_BASE_SRCS += src/fragattack.c
CORE_BASE_SRCS += src/views/research.c
CORE_BASE_SRCS += src/views/fragattack.c
CORE_BASE_SRCS += research/coverage.c
CORE_BASE_SRCS += src/pcap_format.c src/pcap_write.c
CORE_BASE_SRCS += src/evidence_ring.c src/evidence_export.c
CORE_BASE_SRCS += src/evidence_manifest.c
CORE_BASE_SRCS += src/geo.c
# #101 slice A: the compiled-in 5 GHz channel table and the rules that read it.
CORE_BASE_SRCS += src/reg_table.c src/alerts/rules_regulatory.c
# Coverage assessment (#242): pure tables, no capture or 802.11 symbol.
CORE_BASE_SRCS += src/rule_coverage.c src/rule_coverage_live.c
# The capture side's filler: named by capture_side.c only.
CORE_BASE_SRCS += src/rule_coverage_capture.c
# What the site reveals (#243): the exposure report section and the
# exposure_summary record; reads alerts, designations and coverage.
CORE_BASE_SRCS += src/exposure.c
# The per-interval coverage record (#242 item 2): the record and its
# writers (cov_interval.c, which db.c reads and which names no capture
# module) and the capture side's sampler (named by poll.c's wifi table
# and probe.c only).
CORE_BASE_SRCS += src/cov_interval.c src/cov_interval_capture.c
# Quality fields on each finding (#246): the judgement and the dwell
# and drop history (alert_quality.c, cov_timeline.c; no capture symbol,
# engine.c and jsonl_core.c name the first), and the reader of the cited
# frames (alert_quality_capture.c, named by the wifi rule table only, so
# sloth-rf's link pulls neither it nor the evidence ring).
CORE_BASE_SRCS += src/alert_quality.c src/cov_timeline.c src/alert_quality_capture.c
# sloth --preflight (#247): the pure checks and the read-only gatherer,
# named by src/main.c only, so sloth-rf's link pulls neither.
CORE_BASE_SRCS += src/preflight.c src/preflight_gather.c
# sloth --handoff and --interference-report (#250): sloth.db read-only
# (src/site_db.c), the packet and the report.
CORE_BASE_SRCS += src/site_db.c src/handoff.c src/interference.c
# Passive cueing (#248): the policy (chancue.c, pure) and sloth-wifi's
# side (cue_live.c), named by src/main.c's hop stage only, so sloth-rf's
# link pulls neither.
CORE_BASE_SRCS += src/chancue.c src/cue_live.c
# sloth --verify (#251): the reader of the -o hash chain and of the
# evidence manifests, named by src/main.c only; the writer,
# src/jsonl_chain.c, is with jsonl_core.c above.
CORE_BASE_SRCS += src/jsonl_verify.c
CORE_BASE_SRCS += src/ble_snoop.c
# #144 slice 2: the HCI monitor decoder and the own-transmission rule are
# pure; the libpcap worker that feeds them is in PCAP_CORE_SRCS.
CORE_BASE_SRCS += src/ble_hci.c src/alerts/rules_ble.c
CORE_BASE_SRCS += src/alerts/rules_sensor.c
# #144 slice 3: the Ubertooth stream's framer and its two link-layer
# parsers are pure; the reader that feeds them is in PCAP_CORE_SRCS.
CORE_BASE_SRCS += src/btle_ll.c src/bredr_bb.c src/bt_stream.c
# #144 slice 4: the flood windows, the watchlist matcher (shipped empty),
# the three BLE detector lanes and the [*] BLE view. All pure.
CORE_BASE_SRCS += src/ble_flood.c src/ble_watchlist.c src/ble_detect.c
# #156 item 2: address-rotation hints, off unless --ble-rotation-hints, and
# the keyed hash their digests use. Pure.
CORE_BASE_SRCS += src/ble_rotation.c src/siphash.c
CORE_BASE_SRCS += src/views/ble.c
CORE_BASE_SRCS += src/scan.c
CORE_BASE_SRCS += src/alert_key.c
CORE_BASE_SRCS += src/camera_vendor.c
CORE_BASE_SRCS += src/camera_join.c
# #231: the intel-pack snapshot the tables were generated from, which
# sensor_health and the consulting alerts report as `intel_pack`.
CORE_BASE_SRCS += src/intel_pack.c
# #155: router-role observations (DHCP server, DNS responder) the camera
# classifier vetoes a mixed-vendor OUI from.
CORE_BASE_SRCS += src/lan_role.c
CORE_BASE_SRCS += src/privdrop.c
# The poll table (#113, #212): the Wi-Fi stages and `sloth`'s table, then
# the runner and the stages every table shares. The GNSS and RF stages
# are in their groups below.
CORE_BASE_SRCS += src/poll.c src/poll_core.c
# The worker run flag (#95), out of capture.c since #212 so a reader
# thread does not need the capture module to have a stop flag.
CORE_BASE_SRCS += src/run_flag.c
# #213: the start-up steps both daemons take alike (--tune, the
# privilege drop, the three sinks), out of src/main.c.
CORE_BASE_SRCS += src/daemon_start.c
# #216: the six decoder flags sloth-wifi refuses, and the line it says.
CORE_BASE_SRCS += src/rf_moved.c

# ── The GNSS group (#212) ───────────────────────────────────────────────────
# --location / --gps (2026-10-27): the parsers and the arbitration state
# are pure; the reader opens a serial device or a gpsd TCP stream and
# needs neither libpcap nor SQLite, so it is common too.
GNSS_SRCS  = src/gps.c src/capture/gps_reader.c src/position_track.c
GNSS_SRCS += src/alerts/rules_gnss.c
# GNSS observation (2026-11-02): the [#] view over the --gps receiver's sky.
GNSS_SRCS += src/views/gnss.c
GNSS_SRCS += src/poll_gnss.c
# #213: the --location / --gps flags' checks, out of src/main.c so both
# daemons' mains call one copy.
GNSS_SRCS += src/gnss_flags.c

# ── The RF group (#212) ─────────────────────────────────────────────────────
# --adsb (#26 slice 1, 2026-11-05): the aircraft.json parser and table are
# pure; the reader re-reads a local file and needs neither libpcap nor
# SQLite.
RF_SRCS  = src/adsb.c src/adsb_beast.c src/capture/adsb_reader.c
# #186: ADSB_EMERGENCY, read off the ADS-B table.
RF_SRCS += src/alerts/rules_adsb.c
# --aprs (2026-11-05): Dire Wolf's packet-log parser and the station
# table are pure; the reader tails a local file and needs neither
# libpcap nor SQLite.
RF_SRCS += src/aprs.c src/capture/aprs_reader.c
# --rtl433 (#208, 2026-11-14): rtl_433's JSON event-log parser and the
# device table are pure; the reader tails a local file and needs neither
# libpcap nor SQLite.
RF_SRCS += src/rtl433.c src/capture/rtl433_reader.c
# --victron (2026-11-15): sloth-va's JSONL (docs/wiki/victron.md). The
# parser and table are pure; the reader tails a local file. Not sloth-va:
# nothing under src/va/ is named here (tests/test_va.c).
RF_SRCS += src/victron.c src/capture/victron_reader.c
# The RF poll stages and the table sloth-rf passes (#212, #213).
RF_SRCS += src/poll_rf.c
# #213: the receiver's and the decoders' JSONL records, out of
# src/jsonl.c so a daemon with no capture links them, and the rule table
# sloth-rf selects.
RF_SRCS += src/jsonl_rf.c src/alerts/rules_table_rf.c
# #213: the decoder flags' checks, out of src/main.c for the same reason.
RF_SRCS += src/rf_flags.c
# #216: the four decoder source rows, out of src/sys_status.c, and the
# one call that hands sloth-rf's side to the shared services.
RF_SRCS += src/sys_status_rf.c src/rf_side.c
# 2026-11-18: the startup trim - decoder inputs whose SDR is not on USB
# are not started (src/rf_trim.h).
RF_SRCS += src/rf_trim.c

# The union every consumer reads. Order is base, GNSS, RF; nothing
# depends on it (the objects go into an archive).
CORE_COMMON_SRCS = $(CORE_BASE_SRCS) $(GNSS_SRCS) $(RF_SRCS)

# Feature-gated core sources, grouped by the flag that gates them.
# CORE_SRCS_ALL is their union with the common list: the test and fuzz
# builds link it whatever WITH_* says (they set their own -D flags), and a
# shipped config takes CORE_SRCS, the union minus the groups its flags
# turn off. One list, filtered — not one list per consumer.
#
# The Linux helpers are pure parsers and readers; off Linux they compile
# to empty translation units, which is why the test build links them on
# every host while the shipped build leaves them out.
LINUX_PLATFORM_SRCS = src/platform/linux_parse.c   \
                      src/platform/linux_pid.c     \
                      src/platform/linux_dhcp.c    \
                      src/platform/linux_tcpdiag.c \
                      src/platform/linux_neigh.c   \
                      src/platform/linux_self.c
LINUX_WIFI_SRCS     = src/platform/linux_wifi.c

# probe.c exists only with WITH_PCAP: without it probe.h's inline stubs
# stand in. The evidence ring and its exporter (#92) used to sit here
# too, on the grounds that only on_probe_frame() fills the ring. Since
# #92 slice 1 the alert engine calls the exporter, and the engine is in
# every build — so both are in CORE_BASE_SRCS now. In a no-pcap build
# the ring is never initialised (main.c calls evidence_ring_init_default()
# only under WITH_PCAP), so it holds no arena and costs code, not memory.
PCAP_CORE_SRCS      = src/capture/probe.c src/capture/bt_monitor.c \
                      src/capture/bt_capture.c

# Embedded SQLite sink (#42). The research corpus (#73) is an FTS5 index,
# so it goes wherever SQLite goes. query.h stubs to no-ops without it, and
# every caller already tolerates a NULL handle — the additive contract
# means the no-SQLite build simply never has research context.
SQLITE_CORE_SRCS    = src/db.c research/query.c

CORE_SRCS_ALL = $(CORE_COMMON_SRCS) $(LINUX_PLATFORM_SRCS) $(LINUX_WIFI_SRCS) \
                $(PCAP_CORE_SRCS) $(SQLITE_CORE_SRCS)

# The groups the current configuration turns off; appended to below.
CORE_OFF =

UNAME := $(shell uname -s 2>/dev/null || echo Unknown)
ifeq ($(UNAME),Linux)
    PLATFORM_SRC = src/platform/linux.c
    CFLAGS += -DPLATFORM_LINUX
    ifneq ($(WITH_WIFI),1)
        CORE_OFF += $(LINUX_WIFI_SRCS)
    endif
else
    CORE_OFF += $(LINUX_PLATFORM_SRCS) $(LINUX_WIFI_SRCS)
    ifeq ($(UNAME),Darwin)
        PLATFORM_SRC = src/platform/bsd.c
        CFLAGS += -DPLATFORM_BSD
    else ifneq ($(findstring BSD,$(UNAME)),)
        PLATFORM_SRC = src/platform/bsd.c
        CFLAGS += -DPLATFORM_BSD
    else ifeq ($(OS),Windows_NT)
        PLATFORM_SRC = src/platform/win32.c
        CFLAGS += -DPLATFORM_WIN32
    else
        PLATFORM_SRC = src/platform/stub.c
        CFLAGS += -DPLATFORM_STUB
    endif
endif

ifeq ($(WITH_NCURSES),1)
    CFLAGS  += -DWITH_NCURSES
    # macOS ships a unified wide-char-capable libncurses (no separate ncursesw).
    ifeq ($(UNAME),Darwin)
        LDFLAGS += -lncurses
    else
        LDFLAGS += -lncursesw
    endif
endif

LDFLAGS += -lpthread -lm

ifeq ($(WITH_PCAP),1)
    CFLAGS  += -DWITH_PCAP
    LDFLAGS += -lpcap
else
    CORE_OFF += $(PCAP_CORE_SRCS)
endif

# Embedded SQLite sink (#42). Disable with: make WITH_SQLITE=0
ifeq ($(WITH_SQLITE),1)
    CFLAGS  += -DWITH_SQLITE
    LDFLAGS += -lsqlite3
else
    CORE_OFF += $(SQLITE_CORE_SRCS)
endif

APP_SRCS  = src/main.c src/tui.c $(PLATFORM_SRC)
CORE_SRCS = $(filter-out $(CORE_OFF),$(CORE_SRCS_ALL))
SRCS      = $(APP_SRCS) $(CORE_SRCS)

ifeq ($(WITH_WIFI),1)
    CFLAGS += -DWITH_WIFI
endif

# Hardened build flags (#95, wave 6). PIE, stack protector and fortified
# libc calls on the shipped `sloth` binary (and `embedded`, which reuses
# this same rule). _FORTIFY_SOURCE needs optimisation to do anything at
# runtime; -O2 above already satisfies that.
#
# Requesting level **3**, not the level 2 the issue names: this repo's own
# dev/CI host (Ubuntu 24.04, gcc 13) already defaults to
# -D_FORTIFY_SOURCE=3 via its distro-patched gcc spec — confirmed with
# `gcc -E -dM` on a throwaway TU — so hardcoding =2 would have been a
# silent *downgrade* on the one platform this Makefile is verified on.
# glibc's own <features.h> degrades a requested level 3 to 2 (or 0) on a
# compiler/glibc pair that can't support it — verified the same way, with
# an older-looking probe compiler invocation — so =3 is never worse than
# =2 and is sometimes better. -fPIE/-fstack-protector-strong are portable
# across gcc and clang, Linux and Darwin (and inert on musl, which never
# defines the _chk symbols _FORTIFY_SOURCE expands to). Full RELRO
# (-Wl,-z,relro,-z,now) and -pie are ELF/GNU-ld syntax that ld64 on
# Darwin rejects outright, so — same call as the ncursesw/ncurses split
# above — they are gated to Linux, which is also PIE-by-default there.
#
# On that same Ubuntu host every one of these is *already* gcc's default
# (verified: reverting this whole block still yields a PIE/full-RELRO/SSP
# /FORTIFY=3 binary). The explicit flags are not a no-op everywhere,
# though — a from-source gcc, an older distro, or a musl/Alpine-class
# toolchain defaults to none of this. Restating it here makes the
# guarantee a property of the build recipe, not of whichever toolchain
# happens to run it; see the `harden` CI job, which greps the actual
# compile/link command lines for these flags (a check of the *emitted
# binary* would pass on this host with the whole block deleted).
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE
ifeq ($(UNAME),Linux)
    LDFLAGS += -pie -Wl,-z,relro,-z,now
endif

# Appended last so a caller can tighten the build without restating CFLAGS.
# CFLAGS uses ?=, so overriding it wholesale silently drops -Wall -Wextra -std=c99;
# CI passes EXTRA_CFLAGS=-Werror instead. Propagates into `embedded` through
# MAKEFLAGS like any other command-line variable.
CFLAGS += $(EXTRA_CFLAGS)

# ── Intelligence pack (#231, Stage 2 of #184) ──────────────────────────────
# The rows of sloth's six intelligence tables (src/oui.c,
# src/wifi_oui_attacker.c, src/camera_vendor.c, src/vendor_watchlist.c,
# src/tool_fingerprint.c, src/ble_watchlist.c) are not kept by hand: they
# are generated from the pinned pack snapshot in intel/ (six pack
# directories, each with its manifest.json and SOURCE.md, and intel/LOCK
# naming the pack version, the snapshot hash and the sloth-comint commit
# it came from). tools/intel_gen, sloth's own generator written against
# docs/wiki/pack-schema.md, verifies every pack against its manifest
# (length, SHA-256, row count, no unlisted file, a known schema_version)
# and LOCK against the packs, checks every value against the C type it
# lands in, and writes one initialiser file per array into build/intel/;
# the array definitions stay in src/ and #include them. Build output,
# never committed, the same for every configuration: every object
# directory's compile waits on it (order-only; -MMD then tracks which
# objects include which file) and searches it ($(INTEL_INC)).
# `make update-intel PACK=<dir>` refreshes intel/ from a pack root;
# nothing else changes it, and nothing here reaches the network.
INTEL_DIR      = intel
INTEL_GEN_DIR  = build/intel
INTEL_GEN      = $(INTEL_GEN_DIR)/intel_gen
INTEL_GEN_SRCS = tools/intel_gen.c tools/intel_read.c src/sha256.c
INTEL_GEN_HDRS = tools/intel_read.h src/sha256.h src/tool_fingerprint.h \
                 src/ble_watchlist.h src/ble_snoop.h include/sloth.h
INTEL_STAMP    = $(INTEL_GEN_DIR)/.generated
INTEL_INC      = -I$(INTEL_GEN_DIR)
# The pack directories too: a file deleted from one changes no other
# file's time, only its directory's, and the generator must see it.
INTEL_FILES    = $(INTEL_DIR)/LOCK $(wildcard $(INTEL_DIR)/*/*) \
                 $(patsubst %/,%,$(wildcard $(INTEL_DIR)/*/))

# The rules are below `all`, so that `all` stays the default goal.

# ── Object directories (#115) ───────────────────────────────────────────────
# One object directory per configuration, so a config switch never links
# an object compiled under another one — the stale-object link failure
# behind the "make clean between configs" rule. CFG_TAG spells the four
# feature flags; `embedded` is n0p0w1s0.
#
# Each directory also carries a flags stamp. Its objects depend on it,
# and it is rewritten only when the compile command it records changes,
# so `make EXTRA_CFLAGS=-Werror` after a plain `make` recompiles instead
# of reusing objects no -Werror ever saw — without that, keeping objects
# per config would make the -Werror gate vacuous on a warm tree. A
# second stamp records each archive's member list, so dropping a source
# rebuilds the archive rather than leaving the old member in it.
CFG_TAG   = n$(WITH_NCURSES)p$(WITH_PCAP)w$(WITH_WIFI)s$(WITH_SQLITE)
OBJDIR    = build/$(CFG_TAG)
CORE_LIB  = $(OBJDIR)/libsloth_core.a
APP_OBJS  = $(APP_SRCS:%.c=$(OBJDIR)/%.o)
CORE_OBJS = $(CORE_SRCS:%.c=$(OBJDIR)/%.o)
OBJS      = $(APP_OBJS) $(CORE_LIB)
# The Wi-Fi daemon (#216, ADR 0010). It was `sloth` until the cutover
# and still answers to that name: `sloth` is a symlink to it, in the
# build tree (below) and beside it where `make install` puts it, with no
# end date (owner ruling 2026-11-15). One program under two names:
# nothing in it reads argv[0] to decide what it is.
TARGET       = sloth-wifi
TARGET_ALIAS = sloth

# The shipped binary is relinked when the config or link command changes,
# not only when an object is newer: going back to a config whose objects
# predate the current `sloth` would otherwise leave the other config's
# binary in place and call it up to date.
LINK_STAMP = build/sloth-wifi.link

# Rewrite the stamp only when what it records differs, so its mtime moves
# exactly when the recorded text does. STAMP is set per target below.
write_stamp = @mkdir -p $(@D) && { printf '%s\n' '$(STAMP)' | cmp -s - $@ || printf '%s\n' '$(STAMP)' > $@; }

$(OBJDIR)/.flags:   STAMP = $(CC) $(CFLAGS)
$(OBJDIR)/.members: STAMP = $(CORE_SRCS)
$(LINK_STAMP):      STAMP = $(OBJDIR) $(CC) $(CFLAGS) $(LDFLAGS)

.PHONY: all clean install embedded check-deps sbom

all: check-deps $(TARGET) $(TARGET_ALIAS)

# ── Intelligence pack rules (#231; the variables and why are above) ──────
$(INTEL_GEN_DIR)/.flags: STAMP = $(CC) $(CFLAGS)
$(INTEL_GEN_DIR)/.flags: FORCE
	$(write_stamp)

$(INTEL_GEN): $(INTEL_GEN_SRCS) $(INTEL_GEN_HDRS) $(INTEL_GEN_DIR)/.flags
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Iinclude -Isrc -Itools -o $@ $(INTEL_GEN_SRCS)

# One run writes every file; each is rewritten only when its bytes
# change, so a rebuilt generator recompiles nothing.
$(INTEL_STAMP): $(INTEL_GEN) $(INTEL_FILES)
	$(INTEL_GEN) gen $(INTEL_DIR) $(INTEL_GEN_DIR)
	@touch $@

# Refresh intel/ from a pack root (PACK=<dir>: sloth-comint's packs/, or
# an unpacked sloth-intel-pack-<ver>/). Copies the six packs' listed
# files only, verifies them, and rewrites intel/LOCK; on any refusal
# intel/ is left as it was. The version comes from PACK/VERSION or
# PACK/MANIFEST.json, the commit from PACK's git tree or COMMIT=<sha>.
.PHONY: update-intel intel-parity
update-intel: $(INTEL_GEN)
	@[ -n "$(PACK)" ] || { echo "usage: make update-intel PACK=<dir> [COMMIT=<sha>]" >&2; exit 2; }
	sh tools/update_intel.sh "$(PACK)" $(INTEL_DIR) $(INTEL_GEN) "$(COMMIT)"

# The parity proof (#231): the generated tables against the hand-kept
# rows the six sources held at PARITY_REF (the last commit before Stage 2
# replaced them), element by element. Needs git; not part of `make test`.
# PARITY_INC=<dir> runs it against another generator's output instead.
PARITY_REF ?= 1c207a0a
PARITY_INC ?= $(INTEL_GEN_DIR)
PARITY_DIR  = build/intel-parity
PARITY_TABLES = oui wifi_oui_attacker camera_vendor vendor_watchlist tool_fingerprint ble_watchlist
PARITY_SRC    = tools/intel_parity.c
intel-parity: $(INTEL_STAMP)
	@rm -rf $(PARITY_DIR) && mkdir -p $(PARITY_DIR)/old
	@for f in $(PARITY_TABLES); do \
	  git show $(PARITY_REF):src/$$f.c > $(PARITY_DIR)/old/$$f.c || exit 1; done
	@for t in OUI ATTACKER CAMERA WATCHLIST TOOL BLE MAIN; do \
	  $(CC) $(CFLAGS) -DPARITY_$$t -I$(PARITY_DIR)/old -I$(PARITY_INC) -Iinclude -Isrc \
	    -c -o $(PARITY_DIR)/$$t.o $(PARITY_SRC) || exit 1; done
	$(CC) $(CFLAGS) -o $(PARITY_DIR)/intel_parity $(PARITY_DIR)/*.o
	./$(PARITY_DIR)/intel_parity

# ── Dependency floors (#142) ────────────────────────────────────────────────
# The minimum library versions, checked before compiling rather than
# discovered as an #error halfway through. sqlite 3.31.0 is the release
# that added SQLITE_OPEN_NOFOLLOW and SQLITE_DBCONFIG_TRUSTED_SCHEMA,
# which src/db.c and research/query.c depend on (#134); libpcap 1.9 is
# the oldest release the capture path is exercised against, and
# capture.c degrades rather than refuses below the features it probes.
#
# Only the libraries this configuration links are checked. Fatal when
# pkg-config is present and reports a version below the floor; skipped
# with a one-line notice when pkg-config is absent (embedded hosts often
# have none) or has no .pc file for the library, because "cannot tell"
# is not "too old" — the compile-time #error and the runtime refusal in
# db_open()/rq_open() still stand behind it. Vendoring either library
# was rejected: the distro is the patch channel (#142).
SQLITE_FLOOR  = 3.31.0
LIBPCAP_FLOOR = 1.9.0
DEP_FLOORS    =
ifeq ($(WITH_SQLITE),1)
    DEP_FLOORS += sqlite3:$(SQLITE_FLOOR)
endif
ifeq ($(WITH_PCAP),1)
    DEP_FLOORS += libpcap:$(LIBPCAP_FLOOR)
endif
PKG_CONFIG ?= pkg-config

check-deps:
	@if [ -z "$(strip $(DEP_FLOORS))" ]; then :; \
	elif ! command -v $(PKG_CONFIG) >/dev/null 2>&1; then \
	  echo "check-deps: $(PKG_CONFIG) not found -- dependency floors not checked ($(strip $(DEP_FLOORS)))"; \
	else \
	  fail=0; \
	  for d in $(DEP_FLOORS); do \
	    pkg=$${d%%:*}; floor=$${d#*:}; \
	    if ! $(PKG_CONFIG) --exists "$$pkg"; then \
	      echo "check-deps: no pkg-config data for $$pkg -- floor $$floor not checked"; \
	    elif ! $(PKG_CONFIG) --atleast-version="$$floor" "$$pkg"; then \
	      echo "check-deps: $$pkg `$(PKG_CONFIG) --modversion $$pkg` is below the $$floor floor" >&2; \
	      fail=1; \
	    fi; \
	  done; \
	  exit $$fail; \
	fi

# ── SBOM fallback (#142) ────────────────────────────────────────────────────
# CI produces the SBOM with anchore/sbom-action. This is the fallback for
# a host without it: a CycloneDX 1.5 document naming sloth itself and the
# five libraries the default build links, each at the version
# pkg-config (or the C library) reports. Written to stdout; redirect it.
sbom:
	@SLOTH_VERSION="`sed -n 's/^#define SLOTH_VERSION "\(.*\)"$$/\1/p' include/sloth.h`" \
	  PKG_CONFIG="$(PKG_CONFIG)" sh tools/sbom.sh

# CFLAGS on the *link* line, not just the compile line. Several flags are
# not compile-only: -fsanitize=... has to reach the driver at link time or
# the sanitizer runtime is never pulled in, and -fPIE pairs with -pie. Before
# this, `make EXTRA_CFLAGS=-fsanitize=address,undefined` compiled every
# object instrumented and then failed at ld with undefined references to
# __asan_init / __asan_report_* — so the shipped binary had never once been
# linked under a sanitizer, and main.c, the pcap capture path and the ncurses
# renderer (none of which `sloth_test` contains) were uninstrumented in every
# CI job. `sloth_test` was unaffected because its rule already compiles and
# links in one $(CC) invocation carrying TEST_CFLAGS.
#
# Appending $(LDFLAGS) after the objects is deliberate and unchanged: -l
# libraries must follow the objects that reference them.
#
# The core library follows the app objects for the same reason: an archive
# member is pulled in only to satisfy a reference already seen.
$(TARGET): $(OBJS) $(LINK_STAMP)
	$(CC) $(CFLAGS) -o $@ $(filter-out $(LINK_STAMP),$^) $(LDFLAGS)
	$(check_no_hci_builder)
	$(check_wifi_no_rf)

# ./sloth, so `./sloth --headless ...` and every script that names it
# keep working in a build tree. A relative symlink, remade whenever it is
# not one pointing at $(TARGET): a tree built before the cutover has a
# regular file called sloth here, the old binary, and leaving that in
# place would run pre-split code under the old name. Order-only on the
# binary, so the link is not remade when the binary is relinked; the
# recipe always runs and does nothing when the link is already right.
.PHONY: FORCE_ALIAS
FORCE_ALIAS:
$(TARGET_ALIAS): FORCE_ALIAS | $(TARGET)
	@[ "$$(readlink $@ 2>/dev/null)" = "$(TARGET)" ] || { ln -sfn $(TARGET) $@ && echo "ln -sfn $(TARGET) $@"; }

# MISSION.md §2: sloth sends no HCI command, so sloth-ble-scan's builder
# (src/ble_scan/, every symbol `bles_`) must never be in it. Checked on
# the linked binary, in every configuration that links one: a Makefile
# text scan cannot see `CORE_COMMON_SRCS += $$(BLE_SCAN_SRCS)` or a
# source that includes the header, and an archive member nothing calls
# is not linked anyway, so what matters is what `nm` finds. The source
# scan beside it catches an include before any call exists. A failure
# deletes the binary, so the next `make` cannot call it up to date.
define check_no_hci_builder
	@syms=$$(nm $@) || { echo "$@: nm failed; cannot check for the HCI builder" >&2; rm -f $@; exit 1; }; \
	 bad=$$(printf '%s\n' "$$syms" | awk '$$NF ~ /^_?bles_/ { print $$NF }' | head -n 3 | tr '\n' ' '); \
	 [ -z "$$bad" ] || { echo "$@: links sloth-ble-scan's HCI builder ($$bad); MISSION.md §2: sloth sends no HCI command" >&2; rm -f $@; exit 1; }; \
	 inc=$$(grep -lE 'ble_scan_cmd|ble_scan/' $(APP_SRCS) $(RF_APP_SRCS) $(CORE_SRCS) /dev/null); \
	 [ -z "$$inc" ] || { echo "$@: $$inc names sloth-ble-scan's builder; MISSION.md §2: sloth sends no HCI command" >&2; rm -f $@; exit 1; }
endef

$(OBJDIR)/%.o: %.c $(OBJDIR)/.flags | $(INTEL_STAMP)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -MP -Iinclude -Isrc -Iresearch $(INTEL_INC) -c -o $@ $<

$(CORE_LIB): $(CORE_OBJS) $(OBJDIR)/.members

# ── sloth-ble-scan ─────────────────────────────────────────────────────────
# The operator's passive-scan helper for --bt-monitor (docs/wiki/ble.md):
# holds a PASSIVE LE scan on hciN through the HCI user channel. A separate
# binary on purpose, like sloth-monitor-up: sloth sends no HCI command
# (MISSION.md §2), so nothing under src/ble_scan/ is in any list `sloth`
# links, and tests/test_ble_scan.c checks that it stays out. Linux only
# (AF_BLUETOOTH); in `all` there so every matrix config compiles it under
# -Werror. Rebuilt when the config's flag stamp moves, like an object,
# so a warm tree cannot hand -Werror a binary it never compiled.
BLE_SCAN_SRCS = src/ble_scan/main.c src/ble_scan/ble_scan_cmd.c src/sloth_clock.c
BLE_SCAN_HDRS = src/ble_scan/ble_scan_cmd.h src/sloth_clock.h
ifeq ($(UNAME),Linux)
    BLE_SCAN_BIN = sloth-ble-scan
endif

sloth-ble-scan: $(BLE_SCAN_SRCS) $(BLE_SCAN_HDRS) $(OBJDIR)/.flags
	$(CC) $(CFLAGS) -iquote src -o $@ $(BLE_SCAN_SRCS) $(filter -pie -Wl%,$(LDFLAGS))

# ── sloth-sdrsweep ─────────────────────────────────────────────────────────
# The SDR sweep helper behind slothweb's Spectrum tab (slothweb is
# sloth-mesh's since #235; docs/wiki/sdr-sweep.md): tunes a receiver the
# operator dedicated across its range for a minute and writes
# /var/lib/sloth-sdrsweep. A separate binary on purpose, like
# sloth-ble-scan: sloth never drives a radio and links no SoapySDR, so
# nothing under src/sdrsweep/ is in a list sloth is built from, and
# tests/test_sdrsweep.c checks that it stays out. Its pure half
# (sdrsweep_dsp.c) is linked into sloth_test through TEST_ONLY_SRCS.
#
# Built when pkg-config finds SoapySDR (WITH_SOAPY=auto), so a host
# without libsoapysdr-dev builds everything else as before; WITH_SOAPY=0
# skips it, WITH_SOAPY=1 makes a missing SoapySDR an error. In `all`
# when built, so every matrix config compiles it under -Werror where CI
# installs the library. Rebuilt when the config's flag stamp moves.
WITH_SOAPY ?= auto
SDRSWEEP_SRCS = src/sdrsweep/main.c src/sdrsweep/sdrsweep_dsp.c src/sloth_clock.c
SDRSWEEP_HDRS = src/sdrsweep/sdrsweep_dsp.h src/sloth_clock.h
ifeq ($(WITH_SOAPY),auto)
    override WITH_SOAPY := $(shell $(PKG_CONFIG) --exists SoapySDR 2>/dev/null && echo 1 || echo 0)
endif
ifeq ($(WITH_SOAPY),1)
    SDRSWEEP_BIN    = sloth-sdrsweep
    SOAPY_CFLAGS   := $(shell $(PKG_CONFIG) --cflags SoapySDR 2>/dev/null)
    SOAPY_LIBS     := $(shell $(PKG_CONFIG) --libs SoapySDR 2>/dev/null || echo -lSoapySDR)
endif

sloth-sdrsweep: $(SDRSWEEP_SRCS) $(SDRSWEEP_HDRS) $(OBJDIR)/.flags
	$(CC) $(CFLAGS) -iquote src $(SOAPY_CFLAGS) -o $@ $(SDRSWEEP_SRCS) \
	      $(filter -pie -Wl%,$(LDFLAGS)) $(SOAPY_LIBS) -lm

# ── sloth-va ───────────────────────────────────────────────────────────────
# The Victron reader (docs/wiki/victron.md, ADR 0011): decodes the owner's
# Victron Instant Readout advertisements and holds short GATT sessions
# with them through BlueZ, appending JSONL that sloth reads with
# --victron. It TRANSMITS (LE connections, pairing), so it is a separate
# binary under its own account, like sloth-ble-scan: nothing under
# src/va/ is in a list `sloth` is built from, and
# tests/test_va.c checks that it stays out. Its pure half (decode, AES,
# parsers, record) is linked into sloth_test through TEST_ONLY_SRCS.
#
# Built when pkg-config finds libsystemd (sd-bus; WITH_SDBUS=auto);
# WITH_SDBUS=0 skips it, WITH_SDBUS=1 makes a missing libsystemd an
# error. Rebuilt when the config's flag stamp moves.
WITH_SDBUS ?= auto
VA_SRCS = src/va/main.c src/va/va_victron.c src/va/va_conf.c src/va/va_aes.c src/sloth_clock.c
VA_HDRS = src/va/va_victron.h src/va/va_conf.h src/va/va_aes.h src/sloth_clock.h
ifeq ($(UNAME),Linux)
ifeq ($(WITH_SDBUS),auto)
    override WITH_SDBUS := $(shell $(PKG_CONFIG) --exists libsystemd 2>/dev/null && echo 1 || echo 0)
endif
endif
ifeq ($(WITH_SDBUS),1)
    VA_BIN        = sloth-va
    SDBUS_CFLAGS := $(shell $(PKG_CONFIG) --cflags libsystemd 2>/dev/null)
    SDBUS_LIBS   := $(shell $(PKG_CONFIG) --libs libsystemd 2>/dev/null || echo -lsystemd)
endif

sloth-va: $(VA_SRCS) $(VA_HDRS) $(OBJDIR)/.flags
	$(CC) $(CFLAGS) -iquote src $(SDBUS_CFLAGS) -o $@ $(VA_SRCS) \
	      $(filter -pie -Wl%,$(LDFLAGS)) $(SDBUS_LIBS)
# ── sloth-rf (#213, ADR 0010) ──────────────────────────────────────────────
# The RF half of the sensor as a daemon of its own: the GNSS receiver and
# the ADS-B, APRS and rtl_433 decoders' files, with the alert engine, the
# JSONL writer and the database sloth-wifi uses for its own. Built
# beside sloth-wifi by a plain `make` and installed by `make install`
# (#215). Since the cutover (#216) it is the only daemon that links the
# decoders: check_wifi_no_rf, below, holds sloth-wifi to that.
#
# Its three own sources are compiled like any object (per config, behind
# the flag stamp), and everything else comes out of libsloth_core.a, so
# only the members something references are linked. That is the whole
# mechanism: there is no second source list to keep in step, and what
# keeps the capture out is that nothing sloth-rf references leads to it.
# check_rf_no_capture, below, holds the link to that.
#
# No -lpcap and no ncurses on its link line, whatever the config: it
# references neither, and naming them would put them in DT_NEEDED.
RF_APP_SRCS   = src/rf/main.c src/rf/rf_args.c src/rf/platform_rf.c
RF_APP_OBJS   = $(RF_APP_SRCS:%.c=$(OBJDIR)/%.o)
RF_TARGET     = sloth-rf
RF_LINK_STAMP = build/sloth-rf.link
RF_LDFLAGS    = $(filter-out -lpcap -lncursesw -lncurses,$(LDFLAGS))

$(RF_LINK_STAMP): STAMP = $(OBJDIR) $(CC) $(CFLAGS) $(RF_LDFLAGS)

$(RF_TARGET): $(RF_APP_OBJS) $(CORE_LIB) $(RF_LINK_STAMP)
	$(CC) $(CFLAGS) -o $@ $(filter-out $(RF_LINK_STAMP),$^) $(RF_LDFLAGS)
	$(check_no_hci_builder)
	$(check_rf_no_capture)

# MISSION.md §2 and ADR 0010: sloth-rf opens no radio and links no
# capture. Checked on the linked binary, as check_no_hci_builder is and
# for the same reason: what a Makefile list says is not what the linker
# did, and one new call from a shared file (src/sys_status.c,
# src/jsonl_core.c, src/db.c, src/alerts/engine.c, a rule file) into a
# capture module would pull that module, and through it the rest, into
# this binary without a line of this file changing. That is not
# hypothetical: before #213 cut the seams, linking these same roots
# pulled 159 archive members and libpcap; after, 49 and none (51 with
# --victron's victron.o and victron_reader.o, which name no capture).
#
# Three lists, all explicit.
#   RF_FORBID_IMPORTS: dynamic symbols it must not import. Any libpcap
#     call; every resolver entry (getnameinfo is the one src/dns.c
#     uses, the one module that can put a query on the wire; the
#     forward calls are here so a second resolver cannot arrive by
#     another name); ncurses, which a headless daemon has no use for;
#     and the calls the netlink and raw-socket modules are made of
#     (sendto, sendmsg, recv*, ioctl, if_nametoindex), none of which
#     this daemon's own sockets use: it read()s them, and its one
#     write to a peer is send() of gpsd's ?WATCH. A module the two
#     lists below miss still trips here if it talks to the kernel.
#   RF_FORBID_DEFS: sloth's own entry points, one or two per module
#     that must stay out, chosen because nothing can use the module
#     without them - the IP capture, the 802.11 monitor and its frame
#     decoders, the Bluetooth HCI monitor and the Ubertooth stream, the
#     savefile replay, the evidence ring and the two pcap exporters, the
#     platform backend member by member (nl80211, rtnetlink, INET_DIAG,
#     the neighbour, lease, pid and self-MAC readers; sloth-rf's own
#     g_platform, src/rf/platform_rf.c, reads files and nothing else),
#     the mDNS advertisement, the resolver and the terminal.
#   RF_FORBID_DEF_PATTERNS: the same by family, so a member added to
#     one later is held without a line here: every linux_* backend
#     function, every dot11_* helper, every *_observe_frame and
#     *_parse_frame decoder, the Bluetooth sources, the evidence and
#     handshake stores, the advertisement, every view and the terminal.
# The gate works per archive member: a name guards the member that
# defines it. That is why the platform backend and the 802.11 decoders
# are listed member by member and not by one name each (review of
# #213: linux_tcpdiag.o, linux_neigh.o, discovery.o and seven frame
# decoders define none of the names the first list had).
#
# What it does not claim: that no file about 802.11 is linked.
# wifi_assess.o, attack_hw.o and wifi_oui_attacker.o are, as tables and
# labels over state this daemon never fills
# (docs/wiki/architecture-rf-split.md section 10). What is held out is
# everything that opens, decodes or captures.
#
# A name on the second list that is renamed stops guarding, so
# tests/test_rf_build.c holds every one of them to being defined in the
# tree today, and every pattern to matching a definition it names.
#
# A failure deletes the binary, so the next `make` cannot call it up to
# date.
RF_FORBID_IMPORTS = pcap_[a-z_]+ getnameinfo getaddrinfo \
                    gethostbyname[0-9a-z_]* gethostbyaddr[a-z_]* \
                    (__)?res_[a-z]+ \
                    sendto sendmsg sendmmsg \
                    recv recvfrom recvmsg recvmmsg \
                    __recv_chk __recvfrom_chk \
                    ioctl if_nametoindex if_indextoname \
                    initscr newterm
RF_FORBID_DEFS    = capture_open capture_run capture_start \
                    probe_open probe_run \
                    bt_monitor_open bt_capture_run ble_mon_ingest \
                    bt_stream_feed btle_ll_parse \
                    replay_run \
                    dot11_frame_decode radiotap_parse beacon_parse_frame \
                    deauth_parse_frame eapol_observe_frame \
                    action_observe_frame frag_observe_frame \
                    ctrl_observe_frame karma_observe_frame \
                    assoc_request_parse_frame pm_forge_observe_frame \
                    mle_bss_observe_frame dot11_ie_find dot11_data_addrs \
                    evidence_ring_init alert_pcap_dump \
                    evidence_export_pcap_unique \
                    linux_wifi_scan linux_wifi_set_channel \
                    linux_wifi_get_stations \
                    linux_get_ifaces linux_get_conns \
                    linux_tcpdiag_fill linux_neigh6_fill linux_get_dhcp \
                    linux_get_self_macs resolve_pids \
                    discovery_publish \
                    dns_init dns_resolve \
                    tui_init
RF_FORBID_DEF_PATTERNS = linux_[a-z0-9_]+ dot11_[a-z0-9_]+ \
                    [a-z0-9_]+_observe_frame [a-z0-9_]+_parse_frame \
                    bt_[a-z0-9_]+ ble_[a-z0-9_]+ btle_[a-z0-9_]+ \
                    evidence_[a-z0-9_]+ eapol_[a-z0-9_]+ \
                    discovery_[a-z0-9_]+ view_[a-z0-9_]+ tui_[a-z0-9_]+
rf_empty :=
rf_space := $(rf_empty) $(rf_empty)
RF_FORBID_IMPORTS_RE = ^_?($(subst $(rf_space),|,$(strip $(RF_FORBID_IMPORTS))))$$
RF_FORBID_DEFS_RE    = ^_?($(subst $(rf_space),|,$(strip $(RF_FORBID_DEFS) $(RF_FORBID_DEF_PATTERNS))))$$
define check_rf_no_capture
	@syms=$$(nm $@) || { echo "$@: nm failed; cannot check for the capture" >&2; rm -f $@; exit 1; }; \
	 bad=$$(printf '%s\n' "$$syms" | awk 'NF == 2 && $$1 == "U" { sub(/@.*/, "", $$2); if ($$2 ~ /$(RF_FORBID_IMPORTS_RE)/) print $$2 }' | sort -u | head -n 4 | tr '\n' ' '); \
	 [ -z "$$bad" ] || { echo "$@: imports $$bad- sloth-rf links no libpcap, no resolver, no terminal and no netlink or raw-socket call (MISSION.md §2, ADR 0010); a shared file has grown a call into a capture or platform module" >&2; rm -f $@; exit 1; }; \
	 bad=$$(printf '%s\n' "$$syms" | awk 'NF == 3 && $$2 != "U" && $$3 ~ /$(RF_FORBID_DEFS_RE)/ { print $$3 }' | sort -u | head -n 4 | tr '\n' ' '); \
	 [ -z "$$bad" ] || { echo "$@: links $$bad- sloth-rf links no capture, 802.11 frame decoder, Bluetooth source, platform backend (nl80211, rtnetlink, INET_DIAG), mDNS advertisement, resolver, view or terminal code (MISSION.md §2, ADR 0010); cut the dependency, do not shorten this list" >&2; rm -f $@; exit 1; }
endef

# The mirror for the other daemon (#216, ADR 0010): sloth-wifi reads no
# SDR decoder. Until the cutover every RF file was linked into the one
# binary; what keeps them out now is, as for sloth-rf, only that nothing
# sloth-wifi references leads to them - so one new call from a shared
# file (src/sys_status.c, src/db.c, src/jsonl.c, a view) into
# src/adsb.c would put the decoder, its reader thread and its records
# back without a line of this file changing. Checked on the linked
# binary, file-local symbols included, by family:
#   the decoders and their readers        adsb_* (the Beast decoder is
#                                         adsb_beast_*) aprs_* rtl433_*
#                                         victron_*
#   their rules and the receiver's rules  rule_adsb_* rule_gnss_*
#                                         rules_adsb_* rules_gnss_*
#   their records and health blocks       jsonl_emit_{gnss,adsb,aprs,
#                                         rtl433,victron}, jsonl_sh_{adsb,
#                                         aprs,rtl433,victron,rf}*,
#                                         jsonl_emit_state_rf,
#                                         jsonl_emit_sensor_health_rf
#   sloth-rf's stages, tables and side    poll_st_*_rf, g_poll_rf,
#                                         g_alert_table_rf, rf_flags_*,
#                                         rf_flag_*, rf_side_install,
#                                         rf_trim_*, sys_status_rf_fill
# It is a list of names, so it holds RF files out of the link and not
# RF code in a shared file: src/db.c's writers for the gnss_*, adsb_*,
# aprs_* and victron_* tables are in both daemons and are kept off in
# sloth-wifi at run time (db_set_rf_side(), tests/test_rf_db.c).
# The GNSS reader, the position track and the GNSS view are not on it:
# sloth-wifi keeps them (owner ruling 2026-11-15). rf_moved_* is this
# daemon's own refusal of the six flags and is not matched (the list
# says rf_flag, not rf_). tests/test_rf_build.c holds every family to
# matching a definition in the tree today, so a renamed module cannot
# leave a pattern guarding nothing. A failure deletes the binary, so the
# next `make` cannot call it up to date.
WIFI_FORBID_DEF_PATTERNS = adsb_[a-z0-9_]+ aprs_[a-z0-9_]+ \
                    rtl433_[a-z0-9_]+ victron_[a-z0-9_]+ \
                    rule_adsb_[a-z0-9_]+ rule_gnss_[a-z0-9_]+ \
                    rules_adsb_[a-z0-9_]+ rules_gnss_[a-z0-9_]+ \
                    jsonl_emit_(gnss|adsb|aprs|rtl433|victron) \
                    jsonl_sh_(adsb|aprs|rtl433|victron|rf)[a-z0-9_]* \
                    jsonl_emit_state_rf jsonl_emit_sensor_health_rf \
                    poll_st_[a-z0-9_]+_rf g_poll_rf g_alert_table_rf \
                    rf_flags_[a-z0-9_]+ rf_flag_[a-z0-9_]+ rf_side_install \
                    rf_trim_[a-z0-9_]+ \
                    sys_status_rf_fill
WIFI_FORBID_DEFS_RE = ^_?($(subst $(rf_space),|,$(strip $(WIFI_FORBID_DEF_PATTERNS))))$$
define check_wifi_no_rf
	@syms=$$(nm $@) || { echo "$@: nm failed; cannot check for the RF decoders" >&2; rm -f $@; exit 1; }; \
	 bad=$$(printf '%s\n' "$$syms" | awk 'NF == 3 && $$2 != "U" && $$3 ~ /$(WIFI_FORBID_DEFS_RE)/ { print $$3 }' | sort -u | head -n 4 | tr '\n' ' '); \
	 [ -z "$$bad" ] || { echo "$@: links $$bad- sloth-wifi links no ADS-B, APRS, rtl_433 or Victron decoder, none of their records or source rows, and no GNSS or ADS-B rule: those are sloth-rf's (ADR 0010, #216); cut the dependency, do not shorten this list" >&2; rm -f $@; exit 1; }
endef

all: $(RF_TARGET)

# The helpers join `all` here, below their definitions: make expands a
# rule's prerequisites when it reads the rule, so naming them on the
# `all:` line above, before BLE_SCAN_BIN was set, added nothing, and
# sloth-ble-scan was built only by `install` until 2026-11-13.
all: $(BLE_SCAN_BIN) $(SDRSWEEP_BIN) $(VA_BIN)

# Minimal build for embedded targets (no ncurses, no pcap, no sqlite)
embedded:
	$(MAKE) WITH_NCURSES=0 WITH_PCAP=0 WITH_SQLITE=0

# ── Generated prose counts (#117) ─────────────────────────────────────────
# The view and alert-rule counts in the docs sit inside
# <!-- count:NAME -->N<!-- /count --> markers; this rewrites them from
# include/sloth_views.def and include/sloth_alerts.def. A count that drifts
# fails test_docs_consistency.c, and this is the fix.
.PHONY: docs-counts
docs-counts:
	sh tools/docs_counts.sh

# ── Research corpus (#73) ───────────────────────────────────────────────────
# research.db is committed: it is small, deterministic (documents are
# visited in sorted path order, so a rebuild with the same SQLite is
# byte-identical; tools/gate.sh compares by content across versions), and
# committing it means --with-research works from a fresh clone with no
# build step. Regenerate after editing anything under research/.
RESEARCH_SRCS = research/ingest/main.c research/ingest/research_ingest.c

.PHONY: research-index
research-index:
	$(CC) $(CFLAGS) -Iresearch/ingest -o research_ingest $(RESEARCH_SRCS) -lsqlite3
	./research_ingest research research.db

# The MCP server is a separate binary on purpose. sloth links the query
# layer directly (see research/query.h); this exists for the external
# consumers MCP is actually for, and keeping it out of `all` means the
# monitor never grows a JSON-RPC surface it does not use.
#
# src/libver.c rides along because rq_open() applies the runtime sqlite
# floor (#142). -UWITH_PCAP because CFLAGS carries the shipped build's
# -DWITH_PCAP and this binary links no libpcap: libver then reports
# "none" for it, which is true.
MCP_SRCS = research/mcp/main.c research/mcp/mcp.c research/mcp/json.c \
           research/query.c src/libver.c

.PHONY: research-mcp
research-mcp:
	$(CC) $(CFLAGS) -UWITH_PCAP -DWITH_SQLITE -Iinclude -Isrc -Iresearch -Iresearch/mcp \
	      -o sloth-research-mcp $(MCP_SRCS) -lsqlite3

# ── Test build ───────────────────────────────────────────────────────────────
# Built the way the program ships (#116): WITH_NCURSES and WITH_PCAP, the
# real renderer (src/tui.c) and the real probe (src/capture/probe.c).
# Until #116 the suite was compiled without either flag, so every view
# ran its `#ifndef WITH_NCURSES` printf fallback, ~2,200 ncurses-only view
# lines compiled to nothing, and on_packet()/decode_frame() lived in a
# second binary. A configuration no operator runs is not the one to test.
#
# Views draw into an offscreen ncurses SCREEN (tui_init_offscreen(), its
# output to /dev/null) and tests read the cells back with tui_test_line().
# The platform stays the fake one: tests/fake_platform.c stands in for
# src/platform/linux.c, and main.c is not linked.
#
# PLATFORM_LINUX is only defined on Linux; on Darwin the Linux-only
# platform sources become empty translation units (their tests use the
# fake platform).
TEST_FEATURES = -DWITH_WIFI -DWITH_SQLITE
TEST_CFLAGS = -O0 -g -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE $(TEST_FEATURES)
ifeq ($(UNAME),Linux)
    TEST_CFLAGS += -DPLATFORM_LINUX
endif
TEST_CFLAGS += -DTEST_TMP_DIR_MAX=$(TEST_TMP_DIR_MAX)
TEST_CFLAGS += $(EXTRA_CFLAGS)
TEST_SHIP_DEFS = -DWITH_NCURSES -DWITH_PCAP
ifeq ($(UNAME),Darwin)
    TEST_CURSES_LIB = -lncurses
else
    TEST_CURSES_LIB = -lncursesw
endif

# What the test binary links, derived rather than listed (#115):
#
#   TEST_SRCS        every tests/*.c. A new test file is linked by
#                    existing; its run_*_tests() still has to be called
#                    from main_test.c, which
#                    test_every_run_tests_fn_is_declared_and_called checks.
#   TEST_CORE_SRCS   the full core (whatever WITH_* says — the test build
#                    sets its own flags) plus the renderer, plus the sources
#                    only the tests link: the reset registry (#114) and the
#                    library halves of the research tools, taken from those
#                    tools' own source lists minus their main().
#
# The core is archived as for `sloth`, in its own object directory because
# TEST_CFLAGS is not CFLAGS. TEST_INCS is the include set every test-build
# translation unit has always been compiled with.
TEST_SRCS        = $(wildcard tests/*.c)
TEST_ONLY_SRCS   = src/reset_all.c src/ble_scan/ble_scan_cmd.c tools/intel_read.c \
                   src/sdrsweep/sdrsweep_dsp.c src/rf/rf_args.c \
                   src/va/va_victron.c src/va/va_conf.c src/va/va_aes.c \
                   $(filter-out %/main.c research/query.c src/libver.c,$(RESEARCH_SRCS) $(MCP_SRCS))
TEST_CORE_SRCS   = $(CORE_SRCS_ALL) src/tui.c $(TEST_ONLY_SRCS)
TEST_INCS        = -Iinclude -Isrc -Itests -Iresearch/ingest -Iresearch -Iresearch/mcp \
                   $(INTEL_INC)

TEST_OBJDIR      = build/test
TEST_CORE_LIB    = $(TEST_OBJDIR)/libsloth_core.a
TEST_OBJS        = $(TEST_SRCS:%.c=$(TEST_OBJDIR)/%.o)
TEST_CORE_OBJS   = $(TEST_CORE_SRCS:%.c=$(TEST_OBJDIR)/%.o)

$(TEST_OBJDIR)/.flags:   STAMP = $(CC) $(TEST_CFLAGS) $(TEST_SHIP_DEFS) $(TEST_INCS)
$(TEST_OBJDIR)/.members: STAMP = $(TEST_CORE_SRCS)

$(TEST_OBJDIR)/%.o: %.c $(TEST_OBJDIR)/.flags | $(INTEL_STAMP)
	@mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(TEST_SHIP_DEFS) $(TEST_INCS) -MMD -MP -c -o $@ $<

$(TEST_CORE_LIB): $(TEST_CORE_OBJS) $(TEST_OBJDIR)/.members

TEST_BIN = sloth_test

# Temporary files (docs/wiki/architecture.md, "Temporary files"): each
# runner makes a private run directory under $TMPDIR, points TMPDIR at
# it, removes it at exit (and on SIGINT/SIGTERM/SIGHUP) and fails the run
# on anything a test left in it. This outer directory is for the exits
# the binary never sees - a sanitizer abort, a SIGSEGV, a SIGKILL - and
# its trap removes it when the recipe shell itself is interrupted with
# the binary (Ctrl-C reaches the whole process group). A second Ctrl-C
# may make make SIGKILL the recipe, and nothing survives that.
#
# The runner falls back to /tmp when $TMPDIR plus its "/<prefix>.XXXXXX"
# (at most 21, the room slothweb_test's took before #235 moved it to
# sloth-mesh, kept) is over TEST_TMP_DIR_MAX, which would put its directory outside
# this one. So the outer base is $TMPDIR only when it leaves room for
# "/sloth_mk.XXXXXX" (16) as well, else /tmp: the runner's directory is
# always inside the outer one. TEST_TMP_DIR_MAX reaches the runners as
# -D, so the two checks cannot drift. SLOTH_TEST_KEEP_TMP=1 keeps both.
TEST_TMP_DIR_MAX = 56
TEST_IN_TMPDIR = base=$${TMPDIR:-/tmp}; \
	[ $$(printf %s "$$base" | wc -c) -le $$(( $(TEST_TMP_DIR_MAX) - 37 )) ] || base=/tmp; \
	d=$$(mktemp -d "$$base/sloth_mk.XXXXXX") || exit 1; \
	if [ -n "$$SLOTH_TEST_KEEP_TMP" ] && [ "$$SLOTH_TEST_KEEP_TMP" != 0 ]; \
	then trap 'echo "kept $$d (SLOTH_TEST_KEEP_TMP)"' EXIT; \
	else trap 'rm -rf "$$d"' EXIT; fi; \
	trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP; \
	echo "TMPDIR=$$d $(1)"; TMPDIR=$$d $(1); rc=$$?; exit $$rc

.PHONY: test test-capture-path
test: $(TEST_BIN)
	@$(call TEST_IN_TMPDIR,./$(TEST_BIN))

# The capture-path suite used to be its own binary, sloth_test_pcap,
# because sloth_test had no WITH_PCAP. It is part of `make test` now
# (#116); this alias is kept for one release so scripts and muscle memory
# that call it still run the capture path rather than failing on a
# missing target.
test-capture-path: test
	@echo "test-capture-path: the capture path is part of 'make test' since #116;" \
	      "this alias goes away next release"

# ── Max-occupancy bench (#91) ───────────────────────────────────────────────
# Times seqnum correlation and the PNL union with their tables full and
# the early-outs defeated; tests/bench/bench_occupancy.c says how. Linked
# against this configuration's -O2 core archive and the real renderer and
# platform objects, so it measures the code `sloth` ships rather than the
# -O0 test build. Deliberately not a `make test` dependency: it reports a
# time and a slow runner is not a defect. It does fail when a table is
# short of capacity. The recorded figure lives in docs/wiki/ring-buffers.md.
# tests/bench/bench_manifest.c (#92 slice 3) times one manifest line
# against a growing eapol.22000, under and outside the EAPOL lock;
# recorded in docs/wiki/pcap-export.md §5.
# The binary lives under $(OBJDIR) like the objects it links: a shared
# build/bench/ would let `make bench` in one configuration see its own
# objects older than a binary last linked by another, and run that one.
BENCH_SRCS  = $(wildcard tests/bench/bench_*.c)
BENCH_BINS  = $(BENCH_SRCS:tests/bench/%.c=$(OBJDIR)/bench/%)
BENCH_ITERS ?= 50
BENCH_OBJS  = $(filter-out $(OBJDIR)/src/main.o,$(APP_OBJS))

$(OBJDIR)/bench/%: tests/bench/%.c $(BENCH_OBJS) $(CORE_LIB) $(OBJDIR)/.flags
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Iinclude -Isrc -Iresearch -o $@ $< \
	      $(BENCH_OBJS) $(CORE_LIB) $(LDFLAGS)

.PHONY: bench
bench: $(BENCH_BINS)
	@$(call TEST_IN_TMPDIR,sh -c 'for b in $(BENCH_BINS); do ./$$b $(BENCH_ITERS) || exit 1; done')

# ── Headless replay integration (#119) ──────────────────────────────────────
# The one gate that runs the shipped `sloth` binary: main()'s argv
# handling, the poll loop, the alert engine and the JSONL and SQLite
# sinks, end to end. `sloth_test` has its own main() and links none of
# that; before this, CI only ever linked `sloth`.
#
# Inputs are generated, never committed (agents/AGENTS.md, "No pcap
# fixtures"): gen_replay writes two savefiles from tests/frame_build.h
# byte arrays into REPLAY_DIR, sloth replays them for REPLAY_TICKS
# ticks, and normalise.sh strips what varies per run and per host. What
# is committed is tests/replay/golden.jsonl, the normalised output, so a
# behaviour change is a reviewable diff of records in the PR that made
# it. `make replay-golden` rewrites the golden from the current tree;
# run it only when the diff `make replay-check` shows is the intended
# one, and say so in the commit.
#
# replay-check also runs sloth-rf (#213) beside sloth-wifi on the
# command lines both refuse - the receiver's flags, --tune, --ticks,
# --strict with a routable --data-socket - and fails unless both exit 2
# with the same words; on the six decoder flags, which sloth-wifi
# refuses with its one guidance line and sloth-rf takes (#216); and on
# `sloth`, which must be a symlink that answers as sloth-wifi does
# (tests/replay/rf_refusals.sh).
#
# --refresh-ms 100 only shortens the wait between ticks. The normalised
# output was checked identical at 100 and 1000 ms before this was set.
REPLAY_DIR    ?= build/replay
REPLAY_TICKS  ?= 3
REPLAY_GEN     = $(REPLAY_DIR)/gen_replay
REPLAY_RUN     = $(REPLAY_DIR)/run
REPLAY_GOLDEN  = tests/replay/golden.jsonl
# The generator is a host tool: its own sources plus the shared savefile
# writer, compiled with the test flags (it is test code, and -Werror and
# the sanitizers reach it through EXTRA_CFLAGS like everything else).
REPLAY_GEN_SRCS = $(wildcard tests/replay/*.c) src/pcap_format.c

$(REPLAY_GEN): $(REPLAY_GEN_SRCS) src/pcap_format.h tests/frame_build.h
	@mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(TEST_INCS) -o $@ $(filter %.c,$^)

.PHONY: replay-run replay-check replay-golden
replay-run: $(TARGET) $(TARGET_ALIAS) $(REPLAY_GEN)
	rm -rf $(REPLAY_RUN)
	mkdir -p $(REPLAY_RUN)
	$(REPLAY_GEN) $(REPLAY_RUN)
	./$(TARGET) --headless \
	    --replay $(REPLAY_RUN)/wired.pcap,$(REPLAY_RUN)/monitor.pcap,$(REPLAY_RUN)/bt.pcap \
	    -o $(REPLAY_RUN)/out.jsonl --db $(REPLAY_RUN)/replay.db \
	    --ticks $(REPLAY_TICKS) --refresh-ms 100
	sh tests/replay/normalise.sh < $(REPLAY_RUN)/out.jsonl > $(REPLAY_RUN)/norm.jsonl

replay-check: replay-run $(RF_TARGET)
	diff -u $(REPLAY_GOLDEN) $(REPLAY_RUN)/norm.jsonl
	@# #251: the same replay under --jsonl-chain verifies, and with its
	@# chain records taken out is the run above, line for line: the
	@# chain adds records and changes none.
	@rm -f $(REPLAY_RUN)/chain.jsonl $(REPLAY_RUN)/chain.db
	@./$(TARGET) --headless \
	    --replay $(REPLAY_RUN)/wired.pcap,$(REPLAY_RUN)/monitor.pcap,$(REPLAY_RUN)/bt.pcap \
	    -o $(REPLAY_RUN)/chain.jsonl --db $(REPLAY_RUN)/chain.db --jsonl-chain 7 \
	    --ticks $(REPLAY_TICKS) --refresh-ms 100 >/dev/null 2>&1 || \
	  { echo "replay-check: the --jsonl-chain replay failed" >&2; exit 1; }
	@./$(TARGET) --verify $(REPLAY_RUN)/chain.jsonl >$(REPLAY_RUN)/chain.verify || \
	  { cat $(REPLAY_RUN)/chain.verify >&2; echo "replay-check: --verify on the chained replay did not pass" >&2; exit 1; }
	@grep -v '^{"type":"chain",' $(REPLAY_RUN)/chain.jsonl | sh tests/replay/normalise.sh > $(REPLAY_RUN)/chain_norm.jsonl
	@diff -u $(REPLAY_RUN)/norm.jsonl $(REPLAY_RUN)/chain_norm.jsonl || \
	  { echo "replay-check: --jsonl-chain changed a record other than its own" >&2; exit 1; }
	@# #245: with --no-preliminary the stream is the one before the
	@# finding lifecycle: the golden with `state` and `value_period_s`
	@# taken out (and no alert.preliminary or alert_lifecycle record),
	@# line for line.
	@rm -f $(REPLAY_RUN)/off.jsonl $(REPLAY_RUN)/off.db
	@./$(TARGET) --headless \
	    --replay $(REPLAY_RUN)/wired.pcap,$(REPLAY_RUN)/monitor.pcap,$(REPLAY_RUN)/bt.pcap \
	    -o $(REPLAY_RUN)/off.jsonl --db $(REPLAY_RUN)/off.db --no-preliminary \
	    --ticks $(REPLAY_TICKS) --refresh-ms 100 >/dev/null 2>&1 || \
	  { echo "replay-check: the --no-preliminary replay failed" >&2; exit 1; }
	@sh tests/replay/normalise.sh < $(REPLAY_RUN)/off.jsonl > $(REPLAY_RUN)/off_norm.jsonl
	@grep -v -e '^{"type":"alert\.preliminary",' -e '^{"type":"alert_lifecycle",' $(REPLAY_GOLDEN) | \
	  LC_ALL=C sed -E 's/,"state":"[a-z]+","value_period_s":[0-9]+//' > $(REPLAY_RUN)/off_want.jsonl
	@diff -u $(REPLAY_RUN)/off_want.jsonl $(REPLAY_RUN)/off_norm.jsonl || \
	  { echo "replay-check: --no-preliminary is not the stream before #245" >&2; exit 1; }
	@./$(TARGET) --headless --ticks 1 --jsonl-chain 7 >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --jsonl-chain without -o exited $$rc, want 2 (refused)" >&2; exit 1; fi
	@./$(TARGET) --headless --ticks 1 -o $(REPLAY_RUN)/cef.out --out-format cef --jsonl-chain 7 >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --jsonl-chain with --out-format cef exited $$rc, want 2 (refused)" >&2; exit 1; fi
	@./$(RF_TARGET) --ticks 1 --jsonl-chain 7 >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: sloth-rf --jsonl-chain without -o exited $$rc, want 2 (refused)" >&2; exit 1; fi
	@./$(TARGET) --headless --replay /nonexistent.pcap --allow-active >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --replay --allow-active exited $$rc, want 2 (refused)" >&2; exit 1; fi
	@./$(TARGET) --headless --ticks 1 --iface bluetooth0 >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --iface bluetooth0 exited $$rc, want 2 (raw HCI refused)" >&2; exit 1; fi
	@./$(TARGET) --headless --replay /nonexistent.pcap --bt-monitor >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --replay --bt-monitor exited $$rc, want 2 (refused)" >&2; exit 1; fi
	@./$(TARGET) --headless --replay /nonexistent.pcap --bt-capture /nonexistent >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --replay --bt-capture exited $$rc, want 2 (refused)" >&2; exit 1; fi
	@./$(TARGET) --headless --replay /nonexistent.pcap --gps gpsd:// >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --replay --gps exited $$rc, want 2 (refused)" >&2; exit 1; fi
	@./$(TARGET) --headless --ticks 1 --no-privdrop --gps gpsd://192.0.2.1 >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --gps to a remote gpsd exited $$rc, want 2 (refused)" >&2; exit 1; fi
	@./$(TARGET) --headless --ticks 1 --no-privdrop --location 91,0 >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --location 91,0 exited $$rc, want 2 (refused)" >&2; exit 1; fi
	@./$(TARGET) --headless --ticks 1 --no-privdrop --bt-capture $(REPLAY_RUN) >/dev/null 2>&1; \
	  rc=$$?; if [ $$rc -ne 2 ]; then \
	    echo "replay-check: --bt-capture DIR exited $$rc, want 2 (not a file or FIFO)" >&2; exit 1; fi
	@sh tests/replay/rf_refusals.sh ./$(TARGET) ./$(RF_TARGET) ./$(TARGET_ALIAS)
	@sh tests/replay/preflight_cli.sh ./$(TARGET) $(REPLAY_RUN)/preflight
	@sh tests/replay/handoff_cli.sh ./$(TARGET) $(REPLAY_RUN)
	@echo "replay-check: $$(wc -l < $(REPLAY_GOLDEN)) records match $(REPLAY_GOLDEN)"

replay-golden: replay-run
	cp $(REPLAY_RUN)/norm.jsonl $(REPLAY_GOLDEN)
	@echo "replay-golden: wrote $$(wc -l < $(REPLAY_GOLDEN)) records; review the diff before committing"

# Headers are dependencies too. Without them a header-only change — a
# new struct field, a bumped constant — leaves the test binary stale,
# and the suite reports on code that is no longer there. That is worse
# than a slow build: it looks like a passing test. Every compile above
# writes its own header list with -MMD; the .d files are included at the
# end of this Makefile.
$(TEST_BIN): $(TEST_OBJS) $(TEST_CORE_LIB)
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_OBJS) $(TEST_CORE_LIB) \
	      $(TEST_CURSES_LIB) -lm -lpthread -lsqlite3 -lpcap

# ── No-flag test build: link-only (#116) ────────────────────────────────────
# The same suite compiled without WITH_NCURSES and WITH_PCAP, against the
# ANSI renderer and probe.h's inline stubs. It is built, never run: the
# assertions are written for the shipped configuration and do not hold
# here. What it proves is that the `#ifndef` halves of every source the
# suite reaches still compile and link — the property the old default
# test build gave for free and the one `make WITH_NCURSES=0` alone does
# not cover for tests/.
NOFLAGS_OBJDIR    = build/test-noflags
NOFLAGS_CORE_SRCS = $(filter-out src/capture/probe.c,$(CORE_SRCS_ALL)) src/tui.c $(TEST_ONLY_SRCS)
NOFLAGS_CORE_LIB  = $(NOFLAGS_OBJDIR)/libsloth_core.a
NOFLAGS_OBJS      = $(TEST_SRCS:%.c=$(NOFLAGS_OBJDIR)/%.o)
NOFLAGS_CORE_OBJS = $(NOFLAGS_CORE_SRCS:%.c=$(NOFLAGS_OBJDIR)/%.o)
NOFLAGS_BIN       = sloth_test_noflags

$(NOFLAGS_OBJDIR)/.flags:   STAMP = $(CC) $(TEST_CFLAGS) $(TEST_INCS)
$(NOFLAGS_OBJDIR)/.members: STAMP = $(NOFLAGS_CORE_SRCS)

$(NOFLAGS_OBJDIR)/%.o: %.c $(NOFLAGS_OBJDIR)/.flags | $(INTEL_STAMP)
	@mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(TEST_INCS) -MMD -MP -c -o $@ $<

$(NOFLAGS_CORE_LIB): $(NOFLAGS_CORE_OBJS) $(NOFLAGS_OBJDIR)/.members

$(NOFLAGS_BIN): $(NOFLAGS_OBJS) $(NOFLAGS_CORE_LIB)
	$(CC) $(TEST_CFLAGS) -o $@ $(NOFLAGS_OBJS) $(NOFLAGS_CORE_LIB) -lm -lpthread -lsqlite3

# ── libFuzzer smoke targets (#95) ───────────────────────────────────────────
# "fuzzing through the capture path" was named open on #95 since its first
# triage comment (2026-09-22) and never picked up. `capture_test_dispatch()`
# / `probe_test_dispatch()` (also #95) already drive the real callback path
# with hand-built frames under ASan/UBSan/TSan in CI — that proves specific
# cases, the way every test here does. A fuzzer searches for a case nobody
# wrote, which is a different kind of coverage and the gap this closes.
#
# `-fsanitize=fuzzer` is clang-only (gcc has no libFuzzer runtime), so this
# target uses $(FUZZ_CC) rather than $(CC) and is not part of `make`, `make
# test` or the six-config matrix — none of those may assume clang is
# installed. It is deliberately a SMOKE check, not a fuzzing campaign: no
# corpus is kept in-tree (AGENTS.md's "no fixtures" rule applies here too —
# a saved corpus is a captured input by another name) and there is no
# crash-triage process. `FUZZ_SECONDS` bounds each target so CI gets a
# bounded memory-safety check rather than an open-ended job.
#
# fuzz_deauth_parse landed first, over deauth_parse() (src/deauth_snoop.c)
# — a pure byte parser with no global state, so it needed no harness
# scaffolding beyond the bytes themselves. fuzz_eapol_observe lands
# second, over eapol_observe_dot11() (src/eapol_log.c), which reaches
# parse_eapol_key() plus the shared eap_track/wps_track/assoc_track/
# src/alerts/ machinery it feeds — named as a follow-up because
# parse_eapol_key is `static` and reaching it means fuzzing the whole
# 802.11-data-frame-to-EAPOL-key shape, not the key field alone. Like
# fuzz_deauth_parse it takes the frame directly with no libpcap in
# between, so the fuzzer's own tightly-redzoned input buffer is what the
# parser reads — the monitor-decode path (radiotap, the IE walk) does
# go through libpcap's offline reader, whose internal buffer is sized
# well past any one record's caplen (verified empirically: a 10-byte
# frame still reports malloc_usable_size 2048 at the record pointer),
# so a fuzz harness built on that seam cannot catch a modest overread
# with ASan the way this one can. That is why this slice targets
# eapol_observe_dot11() rather than probe_test_dispatch() for the
# "radiotap/LLC" half of the original ask: the latter would have looked
# like coverage without delivering it.
#
# fuzz_radiotap_parse and fuzz_beacon_parse_ies land third and fourth,
# and they are the answer to the paragraph above rather than a change of
# mind about it. The objection there was to fuzzing the monitor decode
# path THROUGH libpcap's offline reader, whose buffer is sized well past
# any one record, so ASan has no redzone at the frame's end. Calling
# radiotap_parse() and beacon_parse_ies() directly removes libpcap from
# the picture entirely: the fuzzer's own tightly-redzoned buffer is what
# each parser reads, which is the property the earlier slice said was
# missing. So the "radiotap / IE walk" half of #95's original ask is now
# covered at the only seam where ASan can actually see an overread.
#
# Both are pure parsers — no global state, no lock, no clock — so like
# fuzz_deauth_parse they need no harness beyond the bytes.
#
# Each target used to link a hand-kept source list, and the lists rotted:
# on 2026-10-14 deauth_snoop.c and beacon_snoop.c started calling
# dot11_mgmt_hdr_len() and both targets failed to LINK in CI, after
# `make test`, `make test-capture-path` and all six -Werror configs had
# passed locally. Since #115 there is one rule and no list: every
# tests/fuzz/fuzz_<name>.c is a target, linked against a libsloth_core.a
# built from the test build's core sources with the fuzz flags. The
# archive is what keeps each target narrow — the linker pulls only the
# members the harness's call tree references, which is what the
# hand-kept lists approximated — so a new dependency is picked up instead
# of failing the link, and a new harness needs no Makefile edit.
#
# The archive also carries the test build's stand-ins — tests/*.c that are
# neither a suite nor the runner: the fake platform and the scenarios.
# eapol_observe_dot11() reaches src/alerts/ and from there code that draws,
# so the fuzz targets resolve tui_* against src/tui.c's ANSI backend —
# the fuzz flags carry no WITH_NCURSES, so no fuzz binary links ncurses
# (the null renderer that used to stand in here went with #116). A target
# whose call tree stops short of that simply never pulls those members in.
TEST_SUPPORT_SRCS = $(filter-out tests/main_test.c tests/test_%.c,$(wildcard tests/*.c))

# One flag set for every target: the union the eapol harness always
# needed (WITH_WIFI, WITH_SQLITE, the test include set). It must also
# carry the platform define TEST_CFLAGS adds: without it, src/platform/
# linux_wifi.c compiles to an empty translation unit — same as on Darwin
# — and anything that calls one of its functions unconditionally
# (sloth_reset_all(), #114) fails to link on a Linux build host, where
# every other gate defines it.
FUZZ_CC      ?= clang
FUZZ_SECONDS ?= 20
FUZZ_FLAGS    = -g -O1 -fsanitize=fuzzer,address,undefined \
                -Iinclude -Isrc -Itests/fuzz $(INTEL_INC)
FUZZ_PLATFORM_DEFS =
ifeq ($(UNAME),Linux)
    FUZZ_PLATFORM_DEFS += -DPLATFORM_LINUX
endif
FUZZ_DEFS     = -DWITH_WIFI -DWITH_SQLITE $(FUZZ_PLATFORM_DEFS) \
                -Itests -Iresearch/ingest -Iresearch -Iresearch/mcp

# Harnesses that need -DWITH_PCAP: decode_frame() and everything it
# reaches sit inside capture.c's WITH_PCAP guard, so its target cannot
# link against the archive above. Named here — a harness is a pcap one
# because of the seam it calls, which a file name cannot say — and
# tests/test_docs_consistency.c holds the list to the files: every name
# here has a harness, and every harness calling a WITH_PCAP-only seam is
# named here (#125). Everything else is picked up by the wildcard.
FUZZ_PCAP_TARGETS = decode_frame
FUZZ_PCAP_SRCS = $(FUZZ_PCAP_TARGETS:%=tests/fuzz/fuzz_%.c)

FUZZ_SRCS      = $(filter-out $(FUZZ_PCAP_SRCS),$(wildcard tests/fuzz/fuzz_*.c))
FUZZ_CORE_SRCS = $(NOFLAGS_CORE_SRCS) $(TEST_SUPPORT_SRCS)
FUZZ_OBJDIR    = build/fuzz
FUZZ_CORE_LIB  = $(FUZZ_OBJDIR)/libsloth_core.a
FUZZ_CORE_OBJS = $(FUZZ_CORE_SRCS:%.c=$(FUZZ_OBJDIR)/%.o)
FUZZ_BINS      = $(FUZZ_SRCS:tests/fuzz/%.c=$(FUZZ_OBJDIR)/bin/%)

$(FUZZ_OBJDIR)/.flags:   STAMP = $(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS)
$(FUZZ_OBJDIR)/.members: STAMP = $(FUZZ_CORE_SRCS)

# libFuzzer needs clang; say so once, before the first compile fails.
.PHONY: fuzz-cc-check
fuzz-cc-check:
	@command -v $(FUZZ_CC) >/dev/null 2>&1 || { \
	  echo "fuzz: $(FUZZ_CC) not found -- libFuzzer needs clang, not gcc" >&2; \
	  exit 1; }

$(FUZZ_OBJDIR)/.flags: | fuzz-cc-check

$(FUZZ_OBJDIR)/%.o: %.c $(FUZZ_OBJDIR)/.flags | $(INTEL_STAMP)
	@mkdir -p $(@D)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) -MMD -MP -c -o $@ $<

$(FUZZ_CORE_LIB): $(FUZZ_CORE_OBJS) $(FUZZ_OBJDIR)/.members

$(FUZZ_OBJDIR)/bin/fuzz_%: tests/fuzz/fuzz_%.c $(FUZZ_CORE_LIB) $(FUZZ_OBJDIR)/.flags
	@mkdir -p $(@D)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) -o $@ $< $(FUZZ_CORE_LIB) -lm -lpthread -lsqlite3

# The WITH_PCAP twin of the archive above (#125): the test core with
# probe.c back in (TEST_CORE_SRCS, as sloth_test links it) plus the same
# stand-ins,
# compiled with the fuzz flags and -DWITH_PCAP in their own object
# directory, because -DWITH_PCAP changes what the headers declare.
FUZZ_PCAP_CORE_SRCS = $(TEST_CORE_SRCS) $(TEST_SUPPORT_SRCS)
FUZZ_PCAP_OBJDIR    = build/fuzz-pcap
FUZZ_PCAP_CORE_LIB  = $(FUZZ_PCAP_OBJDIR)/libsloth_core.a
FUZZ_PCAP_CORE_OBJS = $(FUZZ_PCAP_CORE_SRCS:%.c=$(FUZZ_PCAP_OBJDIR)/%.o)
FUZZ_PCAP_BINS      = $(FUZZ_PCAP_SRCS:tests/fuzz/%.c=$(FUZZ_PCAP_OBJDIR)/bin/%)

$(FUZZ_PCAP_OBJDIR)/.flags:   STAMP = $(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) -DWITH_PCAP
$(FUZZ_PCAP_OBJDIR)/.members: STAMP = $(FUZZ_PCAP_CORE_SRCS)

$(FUZZ_PCAP_OBJDIR)/.flags: | fuzz-cc-check

$(FUZZ_PCAP_OBJDIR)/%.o: %.c $(FUZZ_PCAP_OBJDIR)/.flags | $(INTEL_STAMP)
	@mkdir -p $(@D)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) -DWITH_PCAP -MMD -MP -c -o $@ $<

$(FUZZ_PCAP_CORE_LIB): $(FUZZ_PCAP_CORE_OBJS) $(FUZZ_PCAP_OBJDIR)/.members

$(FUZZ_PCAP_OBJDIR)/bin/fuzz_%: tests/fuzz/fuzz_%.c $(FUZZ_PCAP_CORE_LIB) $(FUZZ_PCAP_OBJDIR)/.flags
	@mkdir -p $(@D)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) -DWITH_PCAP -o $@ $< $(FUZZ_PCAP_CORE_LIB) \
	      -lm -lpthread -lsqlite3 -lpcap

# `make fuzz` runs every target. The pcap half needs libpcap's headers,
# which the CI fuzz job does not install today (its runner image ships
# libsqlite3-dev but not libpcap-dev, and adding the package is a
# .github change outside #125). So FUZZ_PCAP decides what a missing
# header means:
#
#   FUZZ_PCAP=auto  (default) run the pcap targets when <pcap.h> is
#                   there; otherwise print a SKIPPED line naming each one
#                   and carry on — loud, so a reader of the log can see
#                   what did not run, rather than a silent pass.
#   FUZZ_PCAP=1     a missing header is a failure. What CI should pass
#                   once its fuzz job installs libpcap-dev.
#   FUZZ_PCAP=0     never run them.
FUZZ_PCAP ?= auto

FUZZ_RUN = for f in $(1); do \
	  echo "$$f -max_total_time=$(FUZZ_SECONDS) -close_fd_mask=3"; \
	  $$f -max_total_time=$(FUZZ_SECONDS) -close_fd_mask=3 || exit 1; \
	done

.PHONY: fuzz fuzz-pcap
fuzz: $(FUZZ_BINS)
	@$(call FUZZ_RUN,$(FUZZ_BINS))
	@if [ "$(FUZZ_PCAP)" = 0 ]; then \
	  echo "fuzz: FUZZ_PCAP=0 -- SKIPPED $(FUZZ_PCAP_BINS)"; \
	elif printf '#include <pcap.h>\n' | \
	     $(FUZZ_CC) -fsyntax-only -x c - >/dev/null 2>&1; then \
	  $(MAKE) --no-print-directory fuzz-pcap; \
	elif [ "$(FUZZ_PCAP)" = 1 ]; then \
	  echo "fuzz: FUZZ_PCAP=1 but <pcap.h> not found -- install libpcap-dev" >&2; \
	  exit 1; \
	else \
	  echo "fuzz: <pcap.h> not found -- SKIPPED $(FUZZ_PCAP_BINS)" \
	       "(install libpcap-dev, or FUZZ_PCAP=1 to make this fatal)"; \
	fi

fuzz-pcap: $(FUZZ_PCAP_BINS)
	@$(call FUZZ_RUN,$(FUZZ_PCAP_BINS))

# ── Static analysis (#95) ───────────────────────────────────────────────────
# Runs CI's cppcheck command, byte for byte, with CI's version guard.
# This is not an approximation: `make cppcheck` green means the cppcheck
# job will be green.
#
# The version is the whole point, so the guard is a hard failure rather
# than a warning. tests/cppcheck.supp is baselined against 2.13.0, and
# each release adds and retires checks, so a different version reports a
# different set and cannot tell you whether the baseline still holds.
# Measured on 2.21.0: nine suppressions report unmatched because the
# checks behind them were retired, and a bare `#` in the suppression
# list — which 2.13 rejects outright, failing the run before analysis —
# is accepted silently. A newer checker is not a stricter one.
#
# No distro ships 2.13.0 (Kali offers 2.21), so it is built from source:
#
#   git clone --depth 1 --branch 2.13.0 https://github.com/danmar/cppcheck
#   cmake -S cppcheck -B cppcheck/build -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
#         -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$$HOME/.local \
#         -DFILESDIR=$$HOME/.local/share/cppcheck
#   cmake --build cppcheck/build -j"$$(nproc)" && cmake --install cppcheck/build
#
# CMAKE_POLICY_VERSION_MINIMUM is required on CMake 4, which refuses
# cppcheck 2.13's declared minimum of 2.8.12. FILESDIR matters: without
# it --library=posix cannot find cfg/posix.cfg. Install under
# ~/.local/bin, which precedes /usr/bin, so it wins over any packaged
# cppcheck without removing it.
CPPCHECK_DEFS = -D__linux__ -D__GNUC__ -D_DEFAULT_SOURCE -DPLATFORM_LINUX \
                -DWITH_NCURSES -DWITH_PCAP -DWITH_WIFI -DWITH_SQLITE
CPPCHECK_CI_VERSION = Cppcheck 2.13.0

.PHONY: cppcheck
cppcheck: $(INTEL_STAMP)
	@command -v cppcheck >/dev/null 2>&1 || { \
	  echo "cppcheck not installed; need $(CPPCHECK_CI_VERSION) — see the" >&2; \
	  echo "build recipe in the comment above this target in the Makefile." >&2; \
	  exit 1; }
	@v=`cppcheck --version`; \
	 if [ "$$v" != "$(CPPCHECK_CI_VERSION)" ]; then \
	   echo "cppcheck is $$v; this gate needs $(CPPCHECK_CI_VERSION)." >&2; \
	   echo "A different version checks a different set and cannot" >&2; \
	   echo "validate tests/cppcheck.supp. Recipe above this target." >&2; \
	   exit 1; \
	 fi
	cppcheck -q -j `nproc` --std=c99 --platform=unix64 --library=posix \
	  --enable=warning,portability,performance,information \
	  --error-exitcode=1 \
	  --suppressions-list=tests/cppcheck.supp \
	  $(CPPCHECK_DEFS) -Iinclude -Isrc -Iresearch \
	  $(INTEL_INC) \
	  -i src/platform/bsd.c -i src/platform/win32.c -i src/platform/stub.c \
	  src research tools/intel_read.c tools/intel_gen.c tools/contract_parity.c \
	  tools/contract_palette.c

# ── Contract artifact (#185 item 4; #184 §2 C1-C5, C9) ─────────────────────
# `make contract` builds dist/sloth-contract-<SLOTH_VERSION>.tar, what a
# repository split off this one (sloth-mesh, sloth-comint) builds and
# tests against instead of reaching into this tree: libsloth-wire.a
# (exactly CONTRACT_WIRE_SRCS) with its headers and sloth-wire.pc, schema.sql
# as `sloth-wifi --print-schema` prints it, jsonl-schema.md,
# palette.json, the alert knowledge bundle, and the golden fixtures.
# Reproducible: two builds of one commit with one toolchain are the same
# bytes, and `make contract-check` builds twice and compares. Contents,
# decisions and the release step: docs/wiki/contract.md. dist/ is not
# committed; the release workflow attaches the tar to a v* tag.
CONTRACT_VERSION   = $(shell sed -n 's/^\#define SLOTH_VERSION "\(.*\)"/\1/p' include/sloth.h)
CONTRACT_TAR       = dist/sloth-contract-$(CONTRACT_VERSION).tar
# sloth's leaf parsers, the ones slothweb (sloth-mesh) links so that the
# page and the sensor cannot disagree about a frame: radiotap, the
# 802.11 frame and its elements, a DNS name, the band plan, the RF model.
# Each includes only its own header and the leaf headers beside it; the
# one call out of them, dot11_ie.c's sh_parse_fault_note(), is the
# consumer's to answer (sloth-mesh's src/web_sh_stub.c). Until #235 this
# was the Makefile's WEB_CORE_SRCS, the same seven files.
CONTRACT_WIRE_SRCS = src/dot11_frame.c src/radiotap.c src/wifi_freq.c src/dns_wire.c \
                     src/dot11_ie.c src/netstr.c src/rf_model.c
# The headers a consumer of CONTRACT_WIRE_SRCS needs: each public header and
# the leaf headers they include, plus sensor_health.h for the one hook
# the archive calls and does not define (sh_parse_fault_note()).
# src/bytes.h is included by the .c files only and is not shipped.
# sensor_health.h declares functions the archive does not define;
# contract-check pins that list (tests/contract/declared-not-defined.txt,
# docs/wiki/contract.md Gaps). dot11_frame.h takes dot11_data_status_t
# from dot11_data_status.h, so dot11_data.h does not ship (#185).
CONTRACT_WIRE_HDRS = src/dot11_frame.h src/dot11_data_status.h src/radiotap.h src/wifi_freq.h \
                     src/dns_wire.h src/dot11_ie.h src/netstr.h src/rf_model.h \
                     src/sensor_health.h
# Fixed flags, not CFLAGS: a sanitizer or a hardening flag of this
# tree's build would become a link requirement of every consumer.
# -fPIC so the archive can go into a shared object; no -g, and the tree's
# path mapped away, so the objects do not depend on where it was built.
# EXTRA_CFLAGS contributes its warning flags (-Werror) only.
CONTRACT_CFLAGS    = -O2 -std=c99 -D_DEFAULT_SOURCE -Wall -Wextra -fPIC \
                     -ffile-prefix-map=$(CURDIR)/= $(filter -W%,$(EXTRA_CFLAGS))
CONTRACT_DB        = build/contract-tools/contract-db
CONTRACT_DB_SRCS   = tools/contract_db.c
# palette/palette.json: the TUI's data colours as data, written by
# tools/contract_palette.c, which links src/tui_palette.c and reads
# src/tui.c's brand table (the json half of what was web/tools/palette.c
# until #235; the same bytes).
CONTRACT_PALETTE      = build/contract-tools/contract-palette
CONTRACT_PALETTE_SRCS = tools/contract_palette.c src/tui_palette.c
# parity/ (sloth#233): the facts sloth-mesh's tests hold slothweb's
# copies to, compiled against this tree's headers and the two leaf
# sources whose answers it records (tools/contract_parity.c).
CONTRACT_PARITY      = build/contract-tools/contract-parity
CONTRACT_PARITY_SRCS = tools/contract_parity.c src/ip_color.c src/rsn_ie.c

$(CONTRACT_DB): $(CONTRACT_DB_SRCS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $(CONTRACT_DB_SRCS) -lsqlite3

$(CONTRACT_PALETTE): $(CONTRACT_PALETTE_SRCS) src/tui_palette.h src/tui.h src/ip_color.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Iinclude -Isrc -o $@ $(CONTRACT_PALETTE_SRCS)

$(CONTRACT_PARITY): $(CONTRACT_PARITY_SRCS) include/sloth.h src/ip_color.h src/rsn_ie.h | $(INTEL_STAMP)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Iinclude -Isrc $(INTEL_INC) -o $@ $(CONTRACT_PARITY_SRCS)

.PHONY: contract contract-check
contract: $(TARGET) $(CONTRACT_PALETTE) $(CONTRACT_DB) $(CONTRACT_PARITY)
	@[ "$(WITH_SQLITE)" = 1 ] || { echo "contract: needs WITH_SQLITE=1 (the golden sloth.db)" >&2; exit 1; }
	CC='$(CC)' AR='$(AR)' CONTRACT_CFLAGS='$(CONTRACT_CFLAGS)' sh tools/contract.sh \
	    '$(CONTRACT_VERSION)' ./$(TARGET) $(CONTRACT_PALETTE) $(CONTRACT_DB) \
	    '$(CONTRACT_WIRE_SRCS)' '$(CONTRACT_WIRE_HDRS)' $(CONTRACT_PARITY)

# Unpack, verify, compile a consumer against the unpacked archive alone,
# check the schema and the golden db, then build again and compare
# (tests/contract/check.sh). The consumer is a test program and is
# compiled with this tree's CFLAGS (and -Werror); the archive it links
# was not. Needs pkg-config; no network, temporary files under
# mktemp -d only.
contract-check: contract $(RF_TARGET)
	MAKE='$(MAKE)' CC='$(CC)' CFLAGS='$(CFLAGS)' sh tests/contract/check.sh $(CONTRACT_TAR) \
	    ./$(TARGET) ./$(RF_TARGET) $(CONTRACT_DB) $(CONTRACT_PARITY)

# ── Mutation testing ────────────────────────────────────────────────────────
# Verifies the test suite itself: introduces small faults into src/ files,
# rebuilds, runs `make test`, and reports surviving mutants. See
# docs/wiki/mutation-testing.md for what to do with the report.
# Pass extra flags via MUTATE_FLAGS, e.g.:
#   make mutate MUTATE_FLAGS="--files src/threat_intel.c --limit 50"
.PHONY: mutate
mutate:
	python3 .github/scripts/mutate.py $(MUTATE_FLAGS)

# ── Housekeeping ──────────────────────────────────────────────────────────────
# Every object, archive, stamp and fuzz binary lives under build/. The
# second rm sweeps objects the pre-#115 layout compiled beside their
# sources, so a tree upgraded across that change does not keep them.
clean:
	rm -rf build dist
	rm -f $(TARGET) $(TARGET_ALIAS) $(TEST_BIN) $(NOFLAGS_BIN) research_ingest sloth-research-mcp
	rm -f sloth-ble-scan sloth-sdrsweep sloth-va
	rm -f sloth-rf
	rm -f sloth_test_pcap   # the pre-#116 capture-path binary
	rm -f $(patsubst %.c,%.o,$(CORE_SRCS_ALL) $(APP_SRCS) $(TEST_ONLY_SRCS) $(wildcard tests/*.c))

# ── Shared build machinery (#115) ───────────────────────────────────────────
# One archive recipe for every libsloth_core.a; each variant above adds
# its members and its .members stamp as prerequisites. Rebuilt from
# scratch rather than updated in place, so a member dropped from the list
# leaves the archive with it.
%/libsloth_core.a:
	@rm -f $@
	$(AR) rcs $@ $(filter %.o,$^)

STAMPS = $(LINK_STAMP) $(RF_LINK_STAMP) \
         $(foreach d,$(OBJDIR) $(TEST_OBJDIR) $(NOFLAGS_OBJDIR) $(FUZZ_OBJDIR) $(FUZZ_PCAP_OBJDIR),$(d)/.flags $(d)/.members)

.PHONY: FORCE
$(STAMPS): FORCE
	$(write_stamp)

# Header dependencies written by -MMD. Absent until the first compile,
# which has to rebuild everything anyway.
-include $(wildcard $(patsubst %.o,%.d,$(APP_OBJS) $(RF_APP_OBJS) $(CORE_OBJS) $(TEST_OBJS) $(TEST_CORE_OBJS) \
                    $(NOFLAGS_OBJS) $(NOFLAGS_CORE_OBJS) $(FUZZ_CORE_OBJS) \
                    $(FUZZ_PCAP_CORE_OBJS)))

# ── Install (#139) ───────────────────────────────────────────────────────────
# `install` places what the binary and the shipped units reference, all
# root-owned under $(PREFIX): the binary, the monitor-mode helper the unit
# runs as ExecStartPre (sloth never sets monitor mode itself — MISSION §2),
# the research corpus for --with-research (0644: read-only data, opened
# SQLITE_OPEN_READONLY, so ownership does not matter to secure_file.c), and
# the per-type alert assessments (docs/wiki/alert-assessments/<TYPE>.md,
# 0644 data) in share/sloth/alert-assessments: they are the research
# corpus's and stay with it (#184 ADR 2), and slothweb.service passes
# that directory as --web-assessments for "follow recommended". slothweb
# itself, its unit and /etc/default/slothweb install from sloth-mesh
# since #235 (its `make install` and `make install-service`, carrying
# the refusals this file had for them). sloth-ble-scan, the
# passive-scan helper sloth-ble-scan.service runs, goes to sbin beside
# sloth-monitor-up: both are operator tools that prepare a receiver, and
# neither is ever started by sloth.
# DESTDIR is honoured throughout so CI can stage into a scratch root and
# `systemd-analyze verify` the result without touching the runner.
#
# `install-service` is separate because it writes outside $(PREFIX): the
# unit, the sysusers fragment and the site defaults. The sloth account is
# created by `systemd-sysusers`, never by make — a Makefile has no business
# running useradd. The units and the sysusers fragment are the shipped
# artefact and are replaced on every install: a site's changes to a unit
# belong in a drop-in (`systemctl edit`), which make never touches. The
# defaults files are the site's, not the artefact's, so each goes in only
# where there is none (no-clobber): /etc/default/sloth holds SLOTH_ARGS.
# `install -b` used to
# put the shipped /etc/default/sloth over an edited one, keeping the edit
# only as sloth~ — the next restart ran the sensor with the stock
# arguments, which is a silent loss of the site's flags, not a backup.
# A new default in packaging/default/ is the operator's to merge by hand.
# sloth-ble-scan.service is installed like the other two units and is
# never enabled here: it takes the controller away from bluetoothd, which
# is the operator's decision (docs/wiki/deployment.md §7). It
# has no defaults file; its one setting is a drop-in. The sensor's
# AF_BLUETOOTH drop-in for --bt-monitor goes to share/sloth, inert: only
# the operator, or sloth-migrate-sensor for a unit with the flag, puts
# it in sloth-sensor.service.d/, because the family lets a compromised
# sensor make hciN transmit.
# sloth-rf (#215, ADR 0010) is installed when the tree has built one
# (`[ ! -x sloth-rf ] ||`: the binary is #213's, and a tree without it
# still installs), with sloth-migrate-rf beside the other operator tools
# in sbin. sloth-rf.service is never enabled here, and goes in only
# where `make install` has placed the binary it runs
# (`[ ! -x $(DESTDIR)$(PREFIX)/bin/sloth-rf ] ||`): slothweb.service
# (sloth-mesh's) Wants= it, and Wants= starts any unit that is
# installed, enabled or not, so a unit with no binary behind it would
# fail 203/EXEC at every start of slothweb and leave the host degraded.
# Its defaults file is no-clobber like the others, and its AF_INET /
# serial drop-in goes to share/sloth inert as the sensor's gps.conf does.
# The units are written for PREFIX=/usr/local; a different prefix is
# substituted at install time so the text in packaging/ stays the one
# tests/test_unit_file.c scans.
# The sensor's unit and its binary are held the same way since the
# cutover (#216 review): the unit names bin/sloth-wifi, a pre-cutover
# host has only bin/sloth, and `install-service` run alone (or after a
# `make install` that failed) would replace a unit that starts with one
# that does not. It refuses, before it writes anything, when bin/sloth
# is there and bin/sloth-wifi is not; with neither there is nothing
# installed to disagree with (a staged tree, a first install).
# Upgrade safety (#216). sloth-wifi refuses the six decoder flags, so a
# host whose /etc/default/sloth still carries one has a sensor that will
# not start after this build is installed. install-service never
# rewrites that file (see above), so it says so instead, twice: before
# the summary and as the last thing printed, where a scrolled terminal
# still shows it. Only uncommented lines count; the shipped file names
# the flags in its comments. Never fatal: the units are installed either
# way, and the fix is the operator's one command.
RF_MOVED_FLAGS_RE = --(adsb|aprs|aprs-freq|aprs-silent-hours|rtl433|victron)([[:space:]=]|$$)
define warn_rf_flags_in_default
f=$(DESTDIR)$(DEFAULTDIR)/sloth; \
	 [ ! -f "$$f" ] || ! grep -v '^[[:space:]]*[#]' "$$f" | grep -Eq -e '$(RF_MOVED_FLAGS_RE)' || { \
	   echo ""; \
	   echo "  ************************************************************************"; \
	   echo "  WARNING: $$f still passes an SDR decoder flag:"; \
	   grep -v '^[[:space:]]*[#]' "$$f" | grep -Eo -e '$(RF_MOVED_FLAGS_RE)' | sed -e 's/[[:space:]=]$$//' | sort -u | sed 's/^/      /'; \
	   echo "  sloth-wifi REFUSES these (exit 2): sloth-sensor.service WILL NOT START"; \
	   echo "  with this file. They are sloth-rf's now. Before restarting the sensor:"; \
	   echo "      sloth-migrate-rf            (dry run: shows what it would move)"; \
	   echo "      sloth-migrate-rf --apply    (moves them to $(DEFAULTDIR)/sloth-rf)"; \
	   echo "  then the commands it prints. docs/wiki/deployment.md section 11.4"; \
	   echo "  ************************************************************************"; \
	   echo ""; }
endef

# The same upgrade, the quiet half (#216 review). --gps is not one of
# the six: sloth-wifi takes it (the position stamp and the receiver's
# health are its own), so the sensor starts and the warning above has
# nothing to say. But the four GNSS_* rules, the gnss_fix / gnss_sky /
# gnss_sat records and the gnss_fixes / gnss_sightings tables are
# sloth-rf's alone, so a host whose sensor has --gps and whose sloth-rf
# has none stops raising and recording them, and nothing fails. Said
# once, before the summary, as a note: uncommented lines only, and
# --gps-baud is not --gps. Never fatal, and no file is edited.
GPS_FLAG_RE = --gps([[:space:]=]|$$)
define note_gps_without_rf
f=$(DESTDIR)$(DEFAULTDIR)/sloth; r=$(DESTDIR)$(DEFAULTDIR)/sloth-rf; \
	 [ ! -f "$$f" ] || ! grep -v '^[[:space:]]*[#]' "$$f" | grep -Eq -e '$(GPS_FLAG_RE)' || \
	 { [ -f "$$r" ] && grep -v '^[[:space:]]*[#]' "$$r" | grep -Eq -e '$(GPS_FLAG_RE)'; } || { \
	   echo ""; \
	   echo "  NOTE: $$f passes --gps and $$r does not."; \
	   echo "  sloth-wifi keeps the receiver for the position stamp and its health, and starts."; \
	   echo "  It no longer raises GNSS_JAMMING, GNSS_SPOOF_SUSPECT, GNSS_TIME_JUMP or"; \
	   echo "  GNSS_POSITION_JUMP and no longer writes gnss_fix / gnss_sky / gnss_sat or the"; \
	   echo "  gnss_* tables: those are sloth-rf's now, and only with a --gps of its own."; \
	   echo "  To keep them (the receiver must be on gpsd; a serial device opens once):"; \
	   echo "      sloth-migrate-rf            (dry run: shows --gps and --location copied)"; \
	   echo "      sloth-migrate-rf --apply    (copies them to $(DEFAULTDIR)/sloth-rf)"; \
	   echo "  then the commands it prints. docs/wiki/deployment.md section 11.4"; \
	   echo ""; }
endef

DESTDIR     ?=
UNITDIR     ?= /etc/systemd/system
SYSUSERSDIR ?= /usr/lib/sysusers.d
DEFAULTDIR  ?= /etc/default

# The Wi-Fi daemon is installed as sloth-wifi, and `sloth` beside it is
# a relative symlink to it (#216; it stays, owner ruling 2026-11-15):
# `ln -sfn` so a pre-cutover /usr/local/bin/sloth, a regular file and
# the old binary, is replaced by the link and not left running under
# the old name. Anything that executes or names /usr/local/bin/sloth
# keeps working; sloth-sensor.service names sloth-wifi.
install: $(TARGET) $(BLE_SCAN_BIN) $(SDRSWEEP_BIN) $(VA_BIN)
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/share/sloth
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	ln -sfn $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET_ALIAS)
	install -m 755 packaging/bin/sloth-monitor-up $(DESTDIR)$(PREFIX)/sbin/sloth-monitor-up
	[ ! -x sloth-rf ] || install -m 755 sloth-rf $(DESTDIR)$(PREFIX)/bin/sloth-rf
	install -m 755 packaging/bin/sloth-migrate-rf $(DESTDIR)$(PREFIX)/sbin/sloth-migrate-rf
	[ -z "$(BLE_SCAN_BIN)" ] || install -m 755 sloth-ble-scan $(DESTDIR)$(PREFIX)/sbin/sloth-ble-scan
	[ -z "$(SDRSWEEP_BIN)" ] || install -m 755 sloth-sdrsweep $(DESTDIR)$(PREFIX)/sbin/sloth-sdrsweep
	[ -z "$(VA_BIN)" ] || install -m 755 sloth-va $(DESTDIR)$(PREFIX)/sbin/sloth-va
	install -m 644 research.db $(DESTDIR)$(PREFIX)/share/sloth/research.db
	install -d $(DESTDIR)$(PREFIX)/share/sloth/alert-assessments
	install -m 644 $(filter-out %/README.md,$(wildcard docs/wiki/alert-assessments/*.md)) $(DESTDIR)$(PREFIX)/share/sloth/alert-assessments/

.PHONY: install-service
install-service:
	@d=$(DESTDIR)$(PREFIX)/bin; [ ! -e "$$d/$(TARGET_ALIAS)" ] && [ ! -L "$$d/$(TARGET_ALIAS)" ] || [ -x "$$d/$(TARGET)" ] || { \
	    echo "install-service: $$d/$(TARGET_ALIAS) is installed and $$d/$(TARGET) is not: this is a pre-cutover install (#216), and the new sloth-sensor.service runs $$d/$(TARGET); the sensor would fail to start (203/EXEC) at its next restart. Nothing was installed: run 'sudo make install' from this tree first" >&2; exit 1; }
	install -d $(DESTDIR)$(UNITDIR) $(DESTDIR)$(SYSUSERSDIR) $(DESTDIR)$(DEFAULTDIR)
	sed -e 's|/usr/local/|$(PREFIX)/|g' packaging/systemd/sloth-sensor.service \
	    > $(DESTDIR)$(UNITDIR)/sloth-sensor.service.tmp
	install -m 644 $(DESTDIR)$(UNITDIR)/sloth-sensor.service.tmp $(DESTDIR)$(UNITDIR)/sloth-sensor.service
	rm -f $(DESTDIR)$(UNITDIR)/sloth-sensor.service.tmp
	install -m 644 packaging/systemd/sloth.sysusers.conf $(DESTDIR)$(SYSUSERSDIR)/sloth.conf
	[ -e $(DESTDIR)$(DEFAULTDIR)/sloth ] || \
	    install -m 644 packaging/default/sloth $(DESTDIR)$(DEFAULTDIR)/sloth
	sed -e 's|/usr/local/|$(PREFIX)/|g' packaging/systemd/sloth-ble-scan.service \
	    > $(DESTDIR)$(UNITDIR)/sloth-ble-scan.service.tmp
	install -m 644 $(DESTDIR)$(UNITDIR)/sloth-ble-scan.service.tmp $(DESTDIR)$(UNITDIR)/sloth-ble-scan.service
	rm -f $(DESTDIR)$(UNITDIR)/sloth-ble-scan.service.tmp
	sed -e 's|/usr/local/|$(PREFIX)/|g' packaging/systemd/sloth-sdrsweep.service \
	    > $(DESTDIR)$(UNITDIR)/sloth-sdrsweep.service.tmp
	install -m 644 $(DESTDIR)$(UNITDIR)/sloth-sdrsweep.service.tmp $(DESTDIR)$(UNITDIR)/sloth-sdrsweep.service
	rm -f $(DESTDIR)$(UNITDIR)/sloth-sdrsweep.service.tmp
	install -m 644 packaging/systemd/sloth-sdrsweep.path $(DESTDIR)$(UNITDIR)/sloth-sdrsweep.path
	install -m 644 packaging/systemd/sloth-sdrsweep-auto.timer $(DESTDIR)$(UNITDIR)/sloth-sdrsweep-auto.timer
	install -m 644 packaging/systemd/sloth-sdrsweep.sysusers.conf $(DESTDIR)$(SYSUSERSDIR)/sloth-sdrsweep.conf
	[ -e $(DESTDIR)$(DEFAULTDIR)/sloth-sdrsweep ] || \
	    install -m 644 packaging/default/sloth-sdrsweep $(DESTDIR)$(DEFAULTDIR)/sloth-sdrsweep
	sed -e 's|/usr/local/|$(PREFIX)/|g' packaging/systemd/sloth-va.service \
	    > $(DESTDIR)$(UNITDIR)/sloth-va.service.tmp
	install -m 644 $(DESTDIR)$(UNITDIR)/sloth-va.service.tmp $(DESTDIR)$(UNITDIR)/sloth-va.service
	rm -f $(DESTDIR)$(UNITDIR)/sloth-va.service.tmp
	install -m 644 packaging/systemd/sloth-va.sysusers.conf $(DESTDIR)$(SYSUSERSDIR)/sloth-va.conf
	[ -e $(DESTDIR)$(DEFAULTDIR)/sloth-va ] || \
	    install -m 644 packaging/default/sloth-va $(DESTDIR)$(DEFAULTDIR)/sloth-va
	install -D -m 644 packaging/systemd/sloth-sensor.service.d/bt-monitor.conf \
	    $(DESTDIR)$(PREFIX)/share/sloth/sloth-sensor-bt-monitor.conf
	install -D -m 644 packaging/systemd/sloth-sensor.service.d/gps.conf \
	    $(DESTDIR)$(PREFIX)/share/sloth/sloth-sensor-gps.conf
	[ ! -x $(DESTDIR)$(PREFIX)/bin/sloth-rf ] || { \
	    sed -e 's|/usr/local/|$(PREFIX)/|g' packaging/systemd/sloth-rf.service \
	        > $(DESTDIR)$(UNITDIR)/sloth-rf.service.tmp && \
	    install -m 644 $(DESTDIR)$(UNITDIR)/sloth-rf.service.tmp $(DESTDIR)$(UNITDIR)/sloth-rf.service && \
	    rm -f $(DESTDIR)$(UNITDIR)/sloth-rf.service.tmp; }
	[ -e $(DESTDIR)$(DEFAULTDIR)/sloth-rf ] || \
	    install -m 644 packaging/default/sloth-rf $(DESTDIR)$(DEFAULTDIR)/sloth-rf
	install -D -m 644 packaging/systemd/sloth-rf.service.d/gps.conf \
	    $(DESTDIR)$(PREFIX)/share/sloth/sloth-rf-gps.conf
	@$(warn_rf_flags_in_default)
	@$(note_gps_without_rf)
	@echo "installed units and sysusers fragment; the /etc/default files only where absent; next:"
	@echo "  systemd-sysusers && systemctl daemon-reload && systemctl enable --now sloth-sensor"
	@echo "  slothweb (the web UI) installs from sloth-mesh: 'make', 'sudo make install' and"
	@echo "  'sudo make install-service' there"
	@echo "  sloth-ble-scan.service is installed, not enabled; --bt-monitor's AF_BLUETOOTH drop-in"
	@echo "  is at $(PREFIX)/share/sloth/sloth-sensor-bt-monitor.conf, not active: docs/wiki/deployment.md §7"
	@echo "  --gps's device/AF_INET drop-in is at $(PREFIX)/share/sloth/sloth-sensor-gps.conf, inert"
	@echo "  until edited and copied: docs/wiki/deployment.md §7.2"
	@echo "  sloth-sdrsweep.{service,path} are installed, not enabled; the Spectrum tab's button"
	@echo "  needs systemd-sysusers and 'systemctl enable --now sloth-sdrsweep.path':"
	@echo "  docs/wiki/deployment.md, SDR sweep (a shared receiver needs a drop-in there)"
	@echo "  sloth-sdrsweep-auto.timer (a sweep every 5 min, for the Spectrum ranges) is installed,"
	@echo "  not enabled: 'systemctl enable --now sloth-sdrsweep-auto.timer'"
	@echo "  sloth-va.service (Victron reader; TRANSMITS) is installed, not enabled; it needs"
	@echo "  bluetoothd and its own controller: docs/wiki/deployment.md, Victron (sloth-va),"
	@echo "  then 'systemd-sysusers && systemctl enable --now sloth-va'"
	@[ -x $(DESTDIR)$(PREFIX)/bin/sloth-rf ] || \
	    echo "  sloth-rf.service was NOT installed: no $(DESTDIR)$(PREFIX)/bin/sloth-rf ('sudo make install' first)"
	@echo "  sloth-rf.service, where installed, is not enabled. sloth-sensor.service"
	@echo "  runs $(PREFIX)/bin/sloth-wifi, which REFUSES --adsb, --aprs, --aprs-freq, --aprs-silent-hours,"
	@echo "  --rtl433 and --victron (exit 2): they are sloth-rf's. A host whose /etc/default/sloth has one"
	@echo "  moves it before restarting the sensor: sloth-migrate-rf (dry run), then sloth-migrate-rf --apply"
	@echo "  and the commands it prints: docs/wiki/deployment.md §11.4"
	@echo "  (migration from a build-tree unit: docs/wiki/deployment.md)"
	@$(warn_rf_flags_in_default)

# ── Deploy tooling test (#153) ───────────────────────────────────────────────
# packaging/bin/sloth-migrate-sensor against a scratch root with stub
# systemctl / systemd-sysusers / chown / socat: unprivileged, touches no
# real service, reads nothing under /etc. Not a `make test` dependency
# because it is shell, not the C suite; shellcheck runs when installed.
# tests/deploy/test_three_repos.sh is linted here and run by CI's
# three-repos job, not here: it needs sloth-mesh and sloth-comint
# checkouts beside this one (#236; docs/wiki/deployment.md §12).
DEPLOY_SCRIPTS = packaging/bin/sloth-migrate-sensor packaging/bin/sloth-monitor-up \
                 tests/deploy/test_migrate_sensor.sh \
                 packaging/bin/sloth-migrate-rf tests/deploy/test_migrate_rf.sh \
                 .github/scripts/wiki_sync.sh tests/deploy/test_wiki_sync.sh \
                 tests/deploy/test_install_service.sh tools/gate.sh \
                 tools/lab/lab_capture.sh tools/lab/expect.sh \
                 tools/update_intel.sh \
                 tests/deploy/test_lab_tools.sh \
                 tools/contract.sh tests/contract/check.sh \
                 tests/deploy/test_three_repos.sh

# The whole build surface in one measured run (agents/AGENTS.md
# "Discipline"); one run per tree, refuses a full TMPDIR, prints the
# toolchain, cleans before each sanitized step. GATE_SHELLCHECKS adds
# the other-shellcheck steps.
.PHONY: gate
gate:
	sh tools/gate.sh .

.PHONY: deploy-test
deploy-test:
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -s sh $(DEPLOY_SCRIPTS); \
	else \
	  echo "deploy-test: shellcheck not installed, skipping lint"; \
	fi
	sh tests/deploy/test_migrate_sensor.sh
	sh tests/deploy/test_migrate_rf.sh
	sh tests/deploy/test_wiki_sync.sh
	sh tests/deploy/test_install_service.sh
	sh tests/deploy/test_lab_tools.sh
