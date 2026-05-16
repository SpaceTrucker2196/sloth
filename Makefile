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
       src/views/iface.c   \
       src/views/conns.c   \
       src/views/wifi.c    \
       src/views/packets.c

UNAME := $(shell uname -s 2>/dev/null || echo Unknown)
ifeq ($(UNAME),Linux)
    SRCS   += src/platform/linux.c
    SRCS   += src/platform/linux_parse.c
    CFLAGS += -DPLATFORM_LINUX
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
    LDFLAGS += -lncurses
endif

ifeq ($(WITH_PCAP),1)
    CFLAGS  += -DWITH_PCAP
    LDFLAGS += -lpcap
endif

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
            src/platform/linux_parse.c \
            src/views/iface.c          \
            src/views/conns.c          \
            src/views/wifi.c           \
            src/views/packets.c

TEST_BIN = ntop_test

.PHONY: test
test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRCS)
	$(CC) $(TEST_CFLAGS) -Iinclude -Isrc -Itests -o $@ $^ -lm

# ── Housekeeping ──────────────────────────────────────────────────────────────
clean:
	rm -f $(OBJS) $(TARGET) $(TEST_BIN)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/bin/$(TARGET)
