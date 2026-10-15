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
#              build swaps in tests/null_tui.c and tests/fake_platform.c.
#   CORE_SRCS  everything else the current configuration compiles. It is
#              archived as libsloth_core.a, so each binary's linker pulls
#              only the members something it links actually references —
#              which is what keeps a fuzz target narrow without a hand-kept
#              list beside it (the inline fuzz lists rotted and failed CI on
#              2026-10-14).
#
# A new module goes in CORE_COMMON_SRCS (or a feature group below) once,
# and `make`, `make test`, `make test-capture-path` and `make fuzz` all
# pick it up.
CORE_COMMON_SRCS = \
       src/view_route.c    \
       src/view_labels.c   \
       src/tui_palette.c   \
       src/ownership.c     \
       src/inventory.c     \
       src/wired_attach.c  \
       src/presence.c      \
       src/transit.c       \
       src/radiotap.c      \
       src/rf_quality.c    \
       src/db_schema.c     \
       src/history.c       \
       src/bandwidth.c     \
       src/dns.c           \
       src/dns_snoop.c     \
       src/sni_snoop.c     \
       src/http_snoop.c    \
       src/ftp_snoop.c     \
       src/pop3_snoop.c    \
       src/imap_snoop.c    \
       src/smtp_snoop.c    \
       src/cleartext_creds.c \
       src/device_risk.c   \
       src/posture.c       \
       src/version.c       \
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
       src/reg_ie.c          \
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
       src/auth_track.c      \
       src/action_snoop.c    \
       src/ctrl_frames.c     \
       src/dot11_data.c      \
       src/dot11_frame.c     \
       src/mle.c             \
       src/tool_fingerprint.c \
       src/captive_portal.c  \
       src/wifi_snapshot.c   \
       src/wifi_assess.c     \
       src/wifi_baseline.c   \
       src/sensors.c         \
       src/sensor_health.c   \
       src/stab.c            \
       src/persist_health.c  \
       src/wps_track.c       \
       src/pm_forge.c        \
       src/queue_evict.c     \
       src/wifi_merge.c      \
       src/twins.c           \
       src/views/twins.c     \
       src/karma_detect.c    \
       src/views/karma.c     \
       src/views/rogue_radius.c \
       src/alerts.c          \
       src/tune.c src/fs_capacity.c            \
       src/views/alerts.c    \
       src/md5.c             \
       src/sha256.c          \
       src/devices.c         \
       src/views/devices.c   \
       src/beacon_detect.c   \
       src/jsonl.c           \
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
CORE_COMMON_SRCS += src/capture/capture.c
CORE_COMMON_SRCS += src/fragattack.c
CORE_COMMON_SRCS += src/views/research.c
CORE_COMMON_SRCS += src/views/fragattack.c
CORE_COMMON_SRCS += research/coverage.c
CORE_COMMON_SRCS += src/pcap_format.c src/pcap_write.c
CORE_COMMON_SRCS += src/geo.c
CORE_COMMON_SRCS += src/scan.c
CORE_COMMON_SRCS += src/alert_key.c
CORE_COMMON_SRCS += src/privdrop.c
CORE_COMMON_SRCS += src/poll.c

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
                      src/platform/linux_tcpdiag.c
LINUX_WIFI_SRCS     = src/platform/linux_wifi.c

# probe.c exists only with WITH_PCAP: without it probe.h's inline stubs
# stand in. The evidence ring (#92) is fed only by on_probe_frame(), so a
# no-pcap build would link an arena nothing can ever fill; the exporter
# goes with it for the same reason — it reads the ring and nothing else
# fills the ring. Neither has a libpcap dependency of its own, which is
# what lets the ordinary (WITH_PCAP-less) test binary unit-test both: the
# test build drops probe.c alone.
PCAP_CORE_SRCS      = src/capture/probe.c        \
                      src/evidence_ring.c        \
                      src/evidence_export.c

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
TARGET    = sloth

# The shipped binary is relinked when the config or link command changes,
# not only when an object is newer: going back to a config whose objects
# predate the current `sloth` would otherwise leave the other config's
# binary in place and call it up to date.
LINK_STAMP = build/sloth.link

# Rewrite the stamp only when what it records differs, so its mtime moves
# exactly when the recorded text does. STAMP is set per target below.
write_stamp = @mkdir -p $(@D) && { printf '%s\n' '$(STAMP)' | cmp -s - $@ || printf '%s\n' '$(STAMP)' > $@; }

$(OBJDIR)/.flags:   STAMP = $(CC) $(CFLAGS)
$(OBJDIR)/.members: STAMP = $(CORE_SRCS)
$(LINK_STAMP):      STAMP = $(OBJDIR) $(CC) $(CFLAGS) $(LDFLAGS)

.PHONY: all clean install embedded

all: $(TARGET)

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

$(OBJDIR)/%.o: %.c $(OBJDIR)/.flags
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -MP -Iinclude -Isrc -Iresearch -c -o $@ $<

$(CORE_LIB): $(CORE_OBJS) $(OBJDIR)/.members

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
# visited in sorted path order, so a rebuild is byte-identical), and
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
MCP_SRCS = research/mcp/main.c research/mcp/mcp.c research/mcp/json.c \
           research/query.c

.PHONY: research-mcp
research-mcp:
	$(CC) $(CFLAGS) -DWITH_SQLITE -Iinclude -Iresearch -Iresearch/mcp \
	      -o sloth-research-mcp $(MCP_SRCS) -lsqlite3

# ── Test build ───────────────────────────────────────────────────────────────
# Compiled without ncurses/pcap — TPRINT falls back to printf, no terminal needed.
# PLATFORM_LINUX is only defined on Linux; on Darwin the Linux-only platform
# sources become empty translation units (their tests use the fake platform).
TEST_CFLAGS = -O0 -g -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE -DWITH_WIFI -DWITH_SQLITE
ifeq ($(UNAME),Linux)
    TEST_CFLAGS += -DPLATFORM_LINUX
endif
TEST_CFLAGS += $(EXTRA_CFLAGS)
# No WITH_NCURSES: TPRINT expands to printf in view files
# No WITH_PCAP:    packets view shows disabled message

# What the test binary links, derived rather than listed (#115):
#
#   TEST_SRCS        every tests/*.c except the capture-path pair, which
#                    belong to the WITH_PCAP binary below. A new test file
#                    is linked by existing; its run_*_tests() still has to
#                    be called from main_test.c, which
#                    test_every_run_tests_fn_is_declared_and_called checks.
#   TEST_CORE_SRCS   the full core (whatever WITH_* says — TEST_CFLAGS sets
#                    its own) minus probe.c, plus the sources only the tests
#                    link: the reset registry (#114) and the library halves
#                    of the research tools, taken from those tools' own
#                    source lists minus their main().
#
# The core is archived as for `sloth`, in its own object directory because
# TEST_CFLAGS is not CFLAGS. TEST_INCS is the include set every test-build
# translation unit has always been compiled with.
TEST_SRCS        = $(filter-out tests/test_capture_path%.c,$(wildcard tests/*.c))
TEST_ONLY_SRCS   = src/reset_all.c \
                   $(filter-out %/main.c research/query.c,$(RESEARCH_SRCS) $(MCP_SRCS))
TEST_CORE_SRCS   = $(filter-out src/capture/probe.c,$(CORE_SRCS_ALL)) $(TEST_ONLY_SRCS)
TEST_INCS        = -Iinclude -Isrc -Itests -Iresearch/ingest -Iresearch -Iresearch/mcp

TEST_OBJDIR      = build/test
TEST_CORE_LIB    = $(TEST_OBJDIR)/libsloth_core.a
TEST_OBJS        = $(TEST_SRCS:%.c=$(TEST_OBJDIR)/%.o)
TEST_CORE_OBJS   = $(TEST_CORE_SRCS:%.c=$(TEST_OBJDIR)/%.o)

$(TEST_OBJDIR)/.flags:   STAMP = $(CC) $(TEST_CFLAGS) $(TEST_INCS)
$(TEST_OBJDIR)/.members: STAMP = $(TEST_CORE_SRCS)

$(TEST_OBJDIR)/%.o: %.c $(TEST_OBJDIR)/.flags
	@mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) $(TEST_INCS) -MMD -MP -c -o $@ $<

$(TEST_CORE_LIB): $(TEST_CORE_OBJS) $(TEST_OBJDIR)/.members

TEST_BIN = sloth_test

.PHONY: test
test: $(TEST_BIN)
	./$(TEST_BIN)

# Headers are dependencies too. Without them a header-only change — a
# new struct field, a bumped constant — leaves the test binary stale,
# and the suite reports on code that is no longer there. That is worse
# than a slow build: it looks like a passing test. Every compile above
# writes its own header list with -MMD; the .d files are included at the
# end of this Makefile.
$(TEST_BIN): $(TEST_OBJS) $(TEST_CORE_LIB)
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_OBJS) $(TEST_CORE_LIB) -lm -lpthread -lsqlite3

# ── Capture-path test binary (#95) ──────────────────────────────────────────
# `sloth_test` is built without WITH_PCAP on purpose (the packets view
# renders a disabled message, and the scope helpers are compiled outside
# the guard so they stay testable). The cost was that on_packet(),
# decode_frame() and every protocol parser they reach — the code that
# consumes attacker-controlled bytes — were absent from every sanitizer
# run, which is exactly what #95 asks to close.
#
# This second binary links libpcap and drives the real pcap_dispatch()
# callback over an in-memory savefile (see capture_test_dispatch() in
# src/capture/capture.c). It is deliberately narrow: only the sources
# the capture path needs, so a failure names the parser rather than the
# whole suite. Run under the same EXTRA_CFLAGS as everything else, which
# is how the CI sanitize job reaches it.
# Reuses the test build's lists rather than enumerating capture.c's
# dependency tree by hand: it pulls in every protocol snooper, and a
# hand-kept list would rot on the first new one. main_test.c is swapped
# for a main that runs only this suite, so the other run_*_tests() stay
# linked but unentered — they assert the no-WITH_PCAP behaviour and would
# not hold in this build. Every test file is recompiled here, in its own
# object directory, because -DWITH_PCAP changes what the headers declare.
# probe.c rejoins the core because WITH_PCAP turns probe.h's inline stubs
# into real declarations — the same source the main build adds.
CAPTURE_PATH_SRCS      = $(filter-out tests/main_test.c,$(wildcard tests/*.c))
CAPTURE_PATH_CORE_SRCS = $(CORE_SRCS_ALL) $(TEST_ONLY_SRCS)

CAPTURE_PATH_OBJDIR    = build/test-pcap
CAPTURE_PATH_CORE_LIB  = $(CAPTURE_PATH_OBJDIR)/libsloth_core.a
CAPTURE_PATH_OBJS      = $(CAPTURE_PATH_SRCS:%.c=$(CAPTURE_PATH_OBJDIR)/%.o)
CAPTURE_PATH_CORE_OBJS = $(CAPTURE_PATH_CORE_SRCS:%.c=$(CAPTURE_PATH_OBJDIR)/%.o)

CAPTURE_PATH_BIN = sloth_test_pcap

$(CAPTURE_PATH_OBJDIR)/.flags:   STAMP = $(CC) $(TEST_CFLAGS) -DWITH_PCAP $(TEST_INCS)
$(CAPTURE_PATH_OBJDIR)/.members: STAMP = $(CAPTURE_PATH_CORE_SRCS)

$(CAPTURE_PATH_OBJDIR)/%.o: %.c $(CAPTURE_PATH_OBJDIR)/.flags
	@mkdir -p $(@D)
	$(CC) $(TEST_CFLAGS) -DWITH_PCAP $(TEST_INCS) -MMD -MP -c -o $@ $<

$(CAPTURE_PATH_CORE_LIB): $(CAPTURE_PATH_CORE_OBJS) $(CAPTURE_PATH_OBJDIR)/.members

.PHONY: test-capture-path
test-capture-path: $(CAPTURE_PATH_BIN)
	./$(CAPTURE_PATH_BIN)

$(CAPTURE_PATH_BIN): $(CAPTURE_PATH_OBJS) $(CAPTURE_PATH_CORE_LIB)
	$(CC) $(TEST_CFLAGS) -DWITH_PCAP -o $@ $(CAPTURE_PATH_OBJS) \
	      $(CAPTURE_PATH_CORE_LIB) -lm -lpthread -lsqlite3 -lpcap

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
# alerts.c machinery it feeds — named as a follow-up because
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
# neither a suite nor the runner: the null renderer and the fake platform.
# eapol_observe_dot11() reaches alerts.c and from there code that draws,
# so like sloth_test the fuzz targets resolve tui_* against the null
# renderer, never ncurses; a target whose call tree stops short of that
# simply never pulls those members in.
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
                -Iinclude -Isrc -Itests/fuzz
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
FUZZ_CORE_SRCS = $(TEST_CORE_SRCS) $(TEST_SUPPORT_SRCS)
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

$(FUZZ_OBJDIR)/%.o: %.c $(FUZZ_OBJDIR)/.flags
	@mkdir -p $(@D)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) -MMD -MP -c -o $@ $<

$(FUZZ_CORE_LIB): $(FUZZ_CORE_OBJS) $(FUZZ_OBJDIR)/.members

$(FUZZ_OBJDIR)/bin/fuzz_%: tests/fuzz/fuzz_%.c $(FUZZ_CORE_LIB) $(FUZZ_OBJDIR)/.flags
	@mkdir -p $(@D)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) -o $@ $< $(FUZZ_CORE_LIB) -lm -lpthread -lsqlite3

# The WITH_PCAP twin of the archive above (#125): the capture-path core
# (probe.c back in, as for sloth_test_pcap) plus the same stand-ins,
# compiled with the fuzz flags and -DWITH_PCAP in their own object
# directory, because -DWITH_PCAP changes what the headers declare.
FUZZ_PCAP_CORE_SRCS = $(CORE_SRCS_ALL) $(TEST_ONLY_SRCS) $(TEST_SUPPORT_SRCS)
FUZZ_PCAP_OBJDIR    = build/fuzz-pcap
FUZZ_PCAP_CORE_LIB  = $(FUZZ_PCAP_OBJDIR)/libsloth_core.a
FUZZ_PCAP_CORE_OBJS = $(FUZZ_PCAP_CORE_SRCS:%.c=$(FUZZ_PCAP_OBJDIR)/%.o)
FUZZ_PCAP_BINS      = $(FUZZ_PCAP_SRCS:tests/fuzz/%.c=$(FUZZ_PCAP_OBJDIR)/bin/%)

$(FUZZ_PCAP_OBJDIR)/.flags:   STAMP = $(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) -DWITH_PCAP
$(FUZZ_PCAP_OBJDIR)/.members: STAMP = $(FUZZ_PCAP_CORE_SRCS)

$(FUZZ_PCAP_OBJDIR)/.flags: | fuzz-cc-check

$(FUZZ_PCAP_OBJDIR)/%.o: %.c $(FUZZ_PCAP_OBJDIR)/.flags
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
cppcheck:
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
	  -i src/platform/bsd.c -i src/platform/win32.c -i src/platform/stub.c \
	  src research

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
	rm -rf build
	rm -f $(TARGET) $(TEST_BIN) $(CAPTURE_PATH_BIN) research_ingest sloth-research-mcp
	rm -f $(patsubst %.c,%.o,$(CORE_SRCS_ALL) $(APP_SRCS) $(TEST_ONLY_SRCS) $(wildcard tests/*.c))

# ── Shared build machinery (#115) ───────────────────────────────────────────
# One archive recipe for every libsloth_core.a; each variant above adds
# its members and its .members stamp as prerequisites. Rebuilt from
# scratch rather than updated in place, so a member dropped from the list
# leaves the archive with it.
%/libsloth_core.a:
	@rm -f $@
	$(AR) rcs $@ $(filter %.o,$^)

STAMPS = $(LINK_STAMP) \
         $(foreach d,$(OBJDIR) $(TEST_OBJDIR) $(CAPTURE_PATH_OBJDIR) $(FUZZ_OBJDIR) $(FUZZ_PCAP_OBJDIR),$(d)/.flags $(d)/.members)

.PHONY: FORCE
$(STAMPS): FORCE
	$(write_stamp)

# Header dependencies written by -MMD. Absent until the first compile,
# which has to rebuild everything anyway.
-include $(wildcard $(patsubst %.o,%.d,$(APP_OBJS) $(CORE_OBJS) $(TEST_OBJS) $(TEST_CORE_OBJS) \
                    $(CAPTURE_PATH_OBJS) $(CAPTURE_PATH_CORE_OBJS) $(FUZZ_CORE_OBJS) \
                    $(FUZZ_PCAP_CORE_OBJS)))

# ── Install (#139) ───────────────────────────────────────────────────────────
# `install` places what the binary and the shipped unit reference, all
# root-owned under $(PREFIX): the binary, the monitor-mode helper the unit
# runs as ExecStartPre (sloth never sets monitor mode itself — MISSION §2),
# and the research corpus for --with-research (0644: read-only data, opened
# SQLITE_OPEN_READONLY, so ownership does not matter to secure_file.c).
# DESTDIR is honoured throughout so CI can stage into a scratch root and
# `systemd-analyze verify` the result without touching the runner.
#
# `install-service` is separate because it writes outside $(PREFIX): the
# unit, the sysusers fragment and the site defaults. The sloth account is
# created by `systemd-sysusers`, never by make — a Makefile has no business
# running useradd. The defaults file goes in with `install -b` so an edited
# /etc/default/sloth survives as /etc/default/sloth~ rather than being
# silently replaced. The unit is written for PREFIX=/usr/local; a different
# prefix is substituted at install time so the text in packaging/ stays the
# one tests/test_unit_file.c scans.
DESTDIR     ?=
UNITDIR     ?= /etc/systemd/system
SYSUSERSDIR ?= /usr/lib/sysusers.d
DEFAULTDIR  ?= /etc/default

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/share/sloth
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	install -m 755 packaging/bin/sloth-monitor-up $(DESTDIR)$(PREFIX)/sbin/sloth-monitor-up
	install -m 644 research.db $(DESTDIR)$(PREFIX)/share/sloth/research.db

.PHONY: install-service
install-service:
	install -d $(DESTDIR)$(UNITDIR) $(DESTDIR)$(SYSUSERSDIR) $(DESTDIR)$(DEFAULTDIR)
	sed -e 's|/usr/local/|$(PREFIX)/|g' packaging/systemd/sloth-sensor.service \
	    > $(DESTDIR)$(UNITDIR)/sloth-sensor.service.tmp
	install -m 644 $(DESTDIR)$(UNITDIR)/sloth-sensor.service.tmp $(DESTDIR)$(UNITDIR)/sloth-sensor.service
	rm -f $(DESTDIR)$(UNITDIR)/sloth-sensor.service.tmp
	install -m 644 packaging/systemd/sloth.sysusers.conf $(DESTDIR)$(SYSUSERSDIR)/sloth.conf
	install -b -m 644 packaging/default/sloth $(DESTDIR)$(DEFAULTDIR)/sloth
	@echo "installed unit, sysusers fragment and defaults; next:"
	@echo "  systemd-sysusers && systemctl daemon-reload && systemctl enable --now sloth-sensor"
	@echo "  (migration from a build-tree unit: docs/wiki/deployment.md)"
