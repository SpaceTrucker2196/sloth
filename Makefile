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
       src/oui.c           \
       src/services.c      \
       src/views/iface.c   \
       src/views/conns.c   \
       src/views/wifi.c    \
       src/views/packets.c \
       src/views/procs.c   \
       src/views/stats.c   \
       src/views/probe.c   \
       src/views/arp.c

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
    LDFLAGS += -lncursesw
endif

LDFLAGS += -lpthread

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
TARGET = ntop

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
TEST_CFLAGS = -O0 -g -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE \
              -DPLATFORM_LINUX -DWITH_WIFI
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
            tests/test_scan.c

TEST_BIN = ntop_test

.PHONY: test
test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRCS)
	$(CC) $(TEST_CFLAGS) -Iinclude -Isrc -Itests -o $@ $^ -lm -lpthread

# ── Housekeeping ──────────────────────────────────────────────────────────────
clean:
	rm -f $(OBJS) $(TARGET) $(TEST_BIN)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/bin/$(TARGET)
