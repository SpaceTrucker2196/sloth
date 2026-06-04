CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE
LDFLAGS ?=
PREFIX  ?= /usr/local

# Feature flags — disable with: make WITH_PCAP=0
WITH_NCURSES ?= 1
WITH_PCAP    ?= 1
WITH_WIFI    ?= 1

SRCS = src/main.c          \
       src/tui.c           \
       src/history.c       \
       src/bandwidth.c     \
       src/dns.c           \
       src/dns_snoop.c     \
       src/sni_snoop.c     \
       src/http_snoop.c    \
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
       src/quic_snoop.c    \
       src/views/mdns.c    \
       src/views/nbns.c    \
       src/views/dhcp_snoop.c \
       src/ssdp_snoop.c      \
       src/views/ssdp.c      \
       src/beacon_snoop.c    \
       src/views/beacon.c    \
       src/deauth_snoop.c    \
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
       src/dga.c             \
       src/wifi_oui_attacker.c \
       src/twins.c           \
       src/views/twins.c     \
       src/alerts.c          \
       src/views/alerts.c    \
       src/md5.c             \
       src/devices.c         \
       src/views/devices.c   \
       src/beacon_detect.c   \
       src/jsonl.c           \
       src/formatter.c       \
       src/data_socket.c     \
       src/views/help.c      \
       src/filter.c          \
       src/alert_pcap.c      \
       src/ip_owner.c        \
       src/ip_color.c        \
       src/top_hosts.c       \
       src/host_cache.c      \
       src/probe_pnl.c       \
       src/views/pnl.c       \
       src/eapol_log.c       \
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

UNAME := $(shell uname -s 2>/dev/null || echo Unknown)
ifeq ($(UNAME),Linux)
    SRCS   += src/platform/linux.c
    SRCS   += src/platform/linux_parse.c
    SRCS   += src/platform/linux_pid.c
    SRCS   += src/platform/linux_dhcp.c
    SRCS   += src/platform/linux_tcpdiag.c
    CFLAGS += -DPLATFORM_LINUX
    ifeq ($(WITH_WIFI),1)
        SRCS += src/platform/linux_wifi.c
    endif
else ifeq ($(UNAME),Darwin)
    SRCS   += src/platform/bsd.c
    CFLAGS += -DPLATFORM_BSD
else ifneq ($(findstring BSD,$(UNAME)),)
    SRCS   += src/platform/bsd.c
    CFLAGS += -DPLATFORM_BSD
else ifeq ($(OS),Windows_NT)
    SRCS   += src/platform/win32.c
    CFLAGS += -DPLATFORM_WIN32
else
    SRCS   += src/platform/stub.c
    CFLAGS += -DPLATFORM_STUB
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
    SRCS    += src/capture/capture.c
    SRCS    += src/capture/probe.c
endif

SRCS += src/pcap_write.c
SRCS += src/geo.c
SRCS += src/scan.c

ifeq ($(WITH_WIFI),1)
    CFLAGS += -DWITH_WIFI
endif

OBJS   = $(SRCS:.c=.o)
TARGET = sloth

.PHONY: all clean install embedded

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -Iinclude -Isrc -c -o $@ $<

# Minimal build for embedded targets (no ncurses, no pcap)
embedded:
	$(MAKE) WITH_NCURSES=0 WITH_PCAP=0

# ── Test build ───────────────────────────────────────────────────────────────
# Compiled without ncurses/pcap — TPRINT falls back to printf, no terminal needed.
# PLATFORM_LINUX is only defined on Linux; on Darwin the Linux-only platform
# sources become empty translation units (their tests use the fake platform).
TEST_CFLAGS = -O0 -g -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE -DWITH_WIFI
ifeq ($(UNAME),Linux)
    TEST_CFLAGS += -DPLATFORM_LINUX
endif
# No WITH_NCURSES: TPRINT expands to printf in view files
# No WITH_PCAP:    packets view shows disabled message

TEST_SRCS = tests/main_test.c          \
            tests/null_tui.c           \
            tests/fake_platform.c      \
            tests/scenarios.c          \
            tests/test_parse.c         \
            tests/test_rates.c         \
            tests/test_state.c         \
            tests/test_scenario.c      \
            src/history.c              \
            src/bandwidth.c            \
            src/dns.c                  \
            src/dns_snoop.c            \
            src/sni_snoop.c            \
            src/http_snoop.c           \
            src/oui.c                  \
            src/services.c             \
            src/platform/linux_parse.c \
            src/platform/linux_pid.c   \
            src/platform/linux_wifi.c  \
            src/views/iface.c          \
            tests/test_conns.c         \
            tests/test_wifi.c          \
            tests/test_packets.c       \
            tests/test_procs.c         \
            tests/test_bw.c            \
            tests/test_dns.c           \
            tests/test_stats.c         \
            tests/test_probe.c         \
            tests/test_oui.c           \
            tests/test_services.c      \
            tests/test_arp.c           \
            tests/test_pcap_write.c    \
            tests/test_iface_graph.c   \
            tests/test_geo.c           \
            src/geo.c                  \
            src/pcap_write.c           \
            src/views/conns.c          \
            src/views/wifi.c           \
            src/views/packets.c        \
            src/views/procs.c          \
            src/views/stats.c          \
            src/views/probe.c          \
            src/views/arp.c                \
            tests/test_dhcp.c              \
            src/platform/linux_dhcp.c      \
            tests/test_rtt.c               \
            src/platform/linux_tcpdiag.c   \
            tests/test_tree.c              \
            src/scan.c                     \
            tests/test_scan.c              \
            tests/test_dns_snoop.c         \
            tests/test_sni_snoop.c         \
            src/mdns_snoop.c               \
            src/nbns_snoop.c               \
            src/dhcp_snoop.c               \
            src/ndp_snoop.c                \
            tests/test_ndp_snoop.c         \
            src/smb_snoop.c                \
            tests/test_smb_snoop.c         \
            src/kerb_snoop.c               \
            tests/test_kerb_snoop.c        \
            src/ldap_snoop.c               \
            tests/test_ldap_snoop.c        \
            src/bgp_snoop.c                \
            tests/test_bgp_snoop.c         \
            src/quic_snoop.c               \
            src/views/mdns.c               \
            src/views/nbns.c               \
            src/views/dhcp_snoop.c         \
            tests/test_mdns_snoop.c        \
            tests/test_http_snoop.c        \
            tests/test_nbns_snoop.c        \
            tests/test_dhcp_snoop.c        \
            tests/test_quic_snoop.c        \
            src/ssdp_snoop.c               \
            src/views/ssdp.c               \
            tests/test_ssdp_snoop.c        \
            src/beacon_snoop.c             \
            src/views/beacon.c             \
            tests/test_beacon_snoop.c      \
            src/deauth_snoop.c             \
            src/views/deauth.c             \
            tests/test_deauth_snoop.c      \
            src/http_log.c                 \
            src/views/http.c               \
            tests/test_http_log.c          \
            src/tls_log.c                  \
            src/views/tls.c                \
            tests/test_tls_log.c           \
            src/quic_log.c                 \
            src/views/quic.c               \
            tests/test_quic_log.c          \
            src/dns_log.c                  \
            src/views/dns_log.c            \
            tests/test_dns_log.c           \
            src/ntp_log.c                  \
            src/views/ntp.c                \
            tests/test_ntp_log.c           \
            src/icmp_log.c                 \
            src/views/icmp.c               \
            tests/test_icmp_log.c          \
            src/threat_intel.c             \
            tests/test_threat_intel.c      \
            src/dga.c                      \
            tests/test_dga.c               \
            src/wifi_oui_attacker.c        \
            tests/test_wifi_oui_attacker.c \
            src/twins.c                    \
            src/views/twins.c              \
            tests/test_twins.c             \
            src/alerts.c                   \
            src/views/alerts.c             \
            tests/test_alerts.c            \
            src/md5.c                      \
            tests/test_md5.c               \
            src/devices.c                  \
            src/views/devices.c            \
            tests/test_devices.c           \
            src/beacon_detect.c            \
            tests/test_beacon_detect.c     \
            src/jsonl.c                    \
            tests/test_jsonl.c             \
            src/formatter.c                \
            tests/test_formatter.c         \
            src/data_socket.c              \
            tests/test_data_socket.c       \
            src/views/help.c               \
            src/filter.c                   \
            tests/test_filter.c            \
            src/alert_pcap.c               \
            tests/test_alert_pcap.c        \
            src/ip_owner.c                 \
            tests/test_ip_owner.c          \
            src/ip_color.c                 \
            tests/test_ip_color.c          \
            src/top_hosts.c                \
            tests/test_top_hosts.c         \
            src/host_cache.c               \
            tests/test_host_cache.c        \
            src/probe_pnl.c                \
            src/views/pnl.c                \
            tests/test_probe_pnl.c         \
            src/eapol_log.c                \
            src/views/eapol.c              \
            tests/test_eapol_log.c         \
            src/seqnum_track.c             \
            src/views/seqnum.c             \
            tests/test_seqnum_track.c      \
            src/assoc_track.c              \
            src/views/assoc.c              \
            tests/test_assoc_track.c       \
            src/views/channel.c            \
            tests/test_channel.c           \
            src/views/dashboard.c             \
            src/views/dashboard_primitives.c  \
            src/views/dashboard_bands.c       \
            src/views/dashboard_grid.c        \
            tests/test_dashboard.c            \
            src/views/osi.c                   \
            tests/test_osi.c

TEST_BIN = sloth_test

.PHONY: test
test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRCS)
	$(CC) $(TEST_CFLAGS) -Iinclude -Isrc -Itests -o $@ $^ -lm -lpthread

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
clean:
	rm -f $(OBJS) $(TARGET) $(TEST_BIN)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/bin/$(TARGET)
