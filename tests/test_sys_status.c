#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "runner.h"
#include "tmp_dir.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "fake_platform.h"
#include "jsonl.h"
#include "poll.h"
#include "sys_status.h"

/* ── Host status and the receiver inventory (src/sys_status.h) ───────
 *
 * The /proc and /sys text below is written by hand from the kernel's
 * own description of each file (proc(5); Documentation/hwmon/
 * sysfs-interface: tempN_input in millidegrees C, inN_input in
 * millivolts; Documentation/ABI/testing/sysfs-class-power:
 * voltage_now in microvolts; sysfs-bus-usb: idVendor / idProduct as
 * four hex digits). None of it was produced by the code under test. */

static time_t   g_w;
static uint64_t g_m;
static time_t   t_wall(void) { return g_w; }
static uint64_t t_mono(void) { return g_m; }

static void clock_at(uint64_t ms) {
    g_m = ms;
    g_w = 1800000000 + (time_t)(ms / 1000u);
    sloth_clock_test_set(t_mono, t_wall);
}

static char g_jl[TEST_TMP_MAX];

static void jl_open(void) {
    int fd = mkstemp(test_tmp_tpl(g_jl, sizeof(g_jl), "sloth_sys_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_jl);
    ASSERT(jsonl_open(g_jl));
}

static char *jl_read(void) {
    static char buf[131072];
    jsonl_close();
    FILE *fp = fopen(g_jl, "r");
    buf[0] = '\0';
    if (!fp) return buf;
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    unlink(g_jl);
    return buf;
}

static int count_of(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* The one line of `type` whose text contains `has` (NULL: the first of
 * that type), copied out; "" when there is none. */
static const char *line_of(const char *hay, const char *type, const char *has) {
    static char line[4096];
    char want[64];
    snprintf(want, sizeof(want), "{\"type\":\"%s\",", type);
    line[0] = '\0';
    for (const char *p = hay; (p = strstr(p, want)) != NULL; p++) {
        const char *e = strchr(p, '\n');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n >= sizeof(line)) n = sizeof(line) - 1;
        memcpy(line, p, n);
        line[n] = '\0';
        if (!has || strstr(line, has)) return line;
        line[0] = '\0';
    }
    return line;
}

/* One tick of the two hooks, the way the poll table runs them. */
static void tick(sloth_state_t *s, uint64_t ms) {
    clock_at(ms);
    sys_status_poll(s, g_w, g_m);
    sys_status_emit(s);
}

static void fresh(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    fake_net_reset();
    sys_status_reset();
    clock_at(0);
}

static void done(void) {
    jsonl_close();
    unlink(g_jl);
    fake_net_reset();
    sys_status_reset();
    sloth_clock_test_set(NULL, NULL);
}

#define PROC_STAT_A \
    "cpu  1000 0 500 8000 400 50 50 0 0 0\n" \
    "cpu0 500 0 250 4000 200 25 25 0 0 0\n" \
    "intr 12345 0 0\nctxt 999\nbtime 1700000000\n"
/* 2000 jiffies later: 300 busy (user +200, system +100), 1500 idle,
 * 200 iowait. */
#define PROC_STAT_B \
    "cpu  1200 0 600 9500 600 50 50 0 0 0\n" \
    "cpu0 600 0 300 4750 300 25 25 0 0 0\n"
/* The same shares again, 2000 jiffies after B. */
#define PROC_STAT_C \
    "cpu  1400 0 700 11000 800 50 50 0 0 0\n"
#define PROC_MEMINFO \
    "MemTotal:        3884328 kB\n" \
    "MemFree:          213456 kB\n" \
    "MemAvailable:    2913246 kB\n" \
    "Buffers:          101010 kB\n"

/* ── parsers ─────────────────────────────────────────────────────── */

static void test_parse_cpu(void) {
    sys_cpu_t c;
    ASSERT_EQ(sys_parse_cpu(PROC_STAT_A, (int)strlen(PROC_STAT_A), &c), 0);
    ASSERT_EQ(c.total, 10000u);
    ASSERT_EQ(c.idle, 8000u);
    ASSERT_EQ(c.iowait, 400u);
    /* No trailing newline. */
    const char *one = "cpu  10 20 30 40 5";
    ASSERT_EQ(sys_parse_cpu(one, (int)strlen(one), &c), 0);
    ASSERT_EQ(c.total, 105u);
    ASSERT_EQ(c.iowait, 5u);
    /* A kernel with only the four original fields: no iowait column. */
    const char *four = "cpu  10 20 30 40\n";
    ASSERT_EQ(sys_parse_cpu(four, (int)strlen(four), &c), 0);
    ASSERT_EQ(c.total, 100u);
    ASSERT_EQ(c.iowait, 0u);
    /* Only per-core lines: "cpu0" is not the aggregate. */
    const char *core = "cpu0 500 0 250 4000 200 25 25 0 0 0\n";
    ASSERT_EQ(sys_parse_cpu(core, (int)strlen(core), &c), -1);
    /* Truncated mid-line: fewer than four fields. */
    const char *cut = "cpu  1000 0 5";
    ASSERT_EQ(sys_parse_cpu(cut, (int)strlen(cut), &c), -1);
    ASSERT_EQ(sys_parse_cpu("cpu  ", 5, &c), -1);
    /* Negative, non-numeric, binary. */
    const char *neg = "cpu  -1000 0 500 8000 400\n";
    ASSERT_EQ(sys_parse_cpu(neg, (int)strlen(neg), &c), -1);
    const char *txt = "cpu  lots none some idle\n";
    ASSERT_EQ(sys_parse_cpu(txt, (int)strlen(txt), &c), -1);
    const char bin[] = { 'c', 'p', 'u', ' ', 0x00, (char)0xff, 0x01, '\n' };
    ASSERT_EQ(sys_parse_cpu(bin, (int)sizeof(bin), &c), -1);
    /* One field past uint64, and four that only overflow when summed. */
    const char *huge = "cpu  99999999999999999999 0 0 0\n";
    ASSERT_EQ(sys_parse_cpu(huge, (int)strlen(huge), &c), -1);
    const char *sum = "cpu  9000000000000000000 9000000000000000000 9000000000000000000 1\n";
    ASSERT_EQ(sys_parse_cpu(sum, (int)strlen(sum), &c), -1);
    ASSERT_EQ(sys_parse_cpu("", 0, &c), -1);
    ASSERT_EQ(sys_parse_cpu(NULL, 10, &c), -1);
    /* len is honoured: the same text cut before its fourth field. */
    ASSERT_EQ(sys_parse_cpu(PROC_STAT_A, 14, &c), -1);
}

static void test_cpu_delta(void) {
    sys_cpu_t a, b;
    double busy = -1, io = -1;
    ASSERT_EQ(sys_parse_cpu(PROC_STAT_A, (int)strlen(PROC_STAT_A), &a), 0);
    ASSERT_EQ(sys_parse_cpu(PROC_STAT_B, (int)strlen(PROC_STAT_B), &b), 0);
    ASSERT_EQ(sys_cpu_delta(&a, &b, &busy, &io), 0);
    ASSERT_NEAR(busy, 15.0, 1e-9);     /* 300 of 2000 */
    ASSERT_NEAR(io, 10.0, 1e-9);       /* 200 of 2000 */
    /* Backwards (a counter reset), and no advance at all. */
    ASSERT_EQ(sys_cpu_delta(&b, &a, &busy, &io), -1);
    ASSERT_EQ(sys_cpu_delta(&a, &a, &busy, &io), -1);
    /* Idle grew by more than the total did: not an interval. */
    sys_cpu_t c = a;
    c.total += 10; c.idle += 500;
    ASSERT_EQ(sys_cpu_delta(&a, &c, &busy, &io), -1);
}

static void test_parse_loadavg(void) {
    double a = -1, b = -1, c = -1;
    const char *ok = "0.20 0.18 0.12 1/80 11206\n";
    ASSERT_EQ(sys_parse_loadavg(ok, (int)strlen(ok), &a, &b, &c), 0);
    ASSERT_NEAR(a, 0.20, 1e-9);
    ASSERT_NEAR(b, 0.18, 1e-9);
    ASSERT_NEAR(c, 0.12, 1e-9);
    const char *busy = "12.50 3.00 104.75 9/400 1\n";
    ASSERT_EQ(sys_parse_loadavg(busy, (int)strlen(busy), &a, &b, &c), 0);
    ASSERT_NEAR(c, 104.75, 1e-9);
    const char *bad[] = {
        "0.20 0.18",                      /* truncated */
        "0.20 0.18 0.12",                 /* cut before the field ends */
        "-0.20 0.18 0.12 1/80 1\n",       /* negative */
        "0.20abc 0.18 0.12 1/80 1\n",
        "nan nan nan 1/80 1\n",
        "0. 0.18 0.12 1/80 1\n",          /* a point with nothing after */
        "99999999999999999999.0 0.1 0.1 1/1 1\n",
        "1e9 0.1 0.1 1/1 1\n",
        "",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        a = b = c = -7;
        ASSERT_EQ(sys_parse_loadavg(bad[i], (int)strlen(bad[i]), &a, &b, &c), -1);
        ASSERT_NEAR(a, -7, 1e-9);         /* outputs untouched */
    }
    const char bin[] = { 0x00, 0x01, (char)0xfe, ' ', '1' };
    ASSERT_EQ(sys_parse_loadavg(bin, (int)sizeof(bin), &a, &b, &c), -1);
}

static void test_parse_meminfo(void) {
    long long t = -1, a = -1;
    ASSERT_EQ(sys_parse_meminfo(PROC_MEMINFO, (int)strlen(PROC_MEMINFO), &t, &a), 0);
    ASSERT_EQ(t, 3884328);
    ASSERT_EQ(a, 2913246);
    /* No trailing newline on the last line that matters. */
    const char *nonl = "MemTotal: 1000 kB\nMemAvailable: 250 kB";
    ASSERT_EQ(sys_parse_meminfo(nonl, (int)strlen(nonl), &t, &a), 0);
    ASSERT_EQ(a, 250);
    const char *bad[] = {
        "MemTotal:        3884328 kB\nMemFree: 1 kB\n",        /* no MemAvailable */
        "MemAvailable: 5 kB\n",                                  /* no MemTotal */
        "MemTotal: 100 kB\nMemAvailable: 101 kB\n",              /* more than there is */
        "MemTotal: -100 kB\nMemAvailable: 5 kB\n",
        "MemTotal: 0 kB\nMemAvailable: 0 kB\n",
        "MemTotal: 99999999999999999999 kB\nMemAvailable: 5 kB\n",
        "MemTotal: lots kB\nMemAvailable: 5 kB\n",
        "MemTotalX: 100 kB\nMemAvailableX: 5 kB\n",
        "MemTotal:",
        "",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ASSERT_EQ(sys_parse_meminfo(bad[i], (int)strlen(bad[i]), &t, &a), -1);
    /* Truncated inside the MemAvailable figure's line: the key is gone. */
    ASSERT_EQ(sys_parse_meminfo(PROC_MEMINFO, 60, &t, &a), -1);
}

static void test_parse_uptime_and_int(void) {
    long long v = -1;
    ASSERT_EQ(sys_parse_uptime("350735.47 234388.90\n", 20, &v), 0);
    ASSERT_EQ(v, 350735);
    ASSERT_EQ(sys_parse_uptime("7", 1, &v), 0);
    ASSERT_EQ(v, 7);
    ASSERT_EQ(sys_parse_uptime("", 0, &v), -1);
    ASSERT_EQ(sys_parse_uptime("up 3 days", 9, &v), -1);
    ASSERT_EQ(sys_parse_uptime("12.", 3, &v), -1);
    ASSERT_EQ(sys_parse_uptime("-5.0 1.0\n", 9, &v), -1);

    ASSERT_EQ(sys_parse_int("48312\n", 6, -100000, 250000, &v), 0);
    ASSERT_EQ(v, 48312);
    ASSERT_EQ(sys_parse_int("-5000\n", 6, -100000, 250000, &v), 0);
    ASSERT_EQ(v, -5000);
    ASSERT_EQ(sys_parse_int("42", 2, 0, 100, &v), 0);          /* no newline */
    ASSERT_EQ(sys_parse_int(" 42 \n", 5, 0, 100, &v), 0);
    v = 77;
    const char *bad[] = { "", "\n", "-", "- 5", "42abc", "4 2", "0x2a", "+42", "4.2",
                          "999999999999999999999999999999", "9223372036854775808",
                          "250001", "-100001" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ASSERT_EQ(sys_parse_int(bad[i], (int)strlen(bad[i]), -100000, 250000, &v), -1);
    ASSERT_EQ(v, 77);                                           /* untouched */
    const char bin[] = { 0x00, 0x01, '4', '2' };
    ASSERT_EQ(sys_parse_int(bin, (int)sizeof(bin), 0, 100, &v), -1);
    const char nul[] = { '4', '2', 0x00, '9' };                 /* NUL mid-number */
    ASSERT_EQ(sys_parse_int(nul, (int)sizeof(nul), 0, 100, &v), -1);
}

static void test_clean_str_uevent_hex(void) {
    char o[16];
    sys_clean_str("Realtek\n", 8, o, (int)sizeof(o));
    ASSERT_STR(o, "Realtek");
    sys_clean_str("  spaced out  \n", 15, o, (int)sizeof(o));
    ASSERT_STR(o, "spaced out");
    /* ESC, a UTF-8 pair and DEL: each byte becomes '?'. */
    const char hostile[] = { 'a', 0x1b, '[', (char)0xc3, (char)0xa9, 0x7f, 'z', '\n' };
    sys_clean_str(hostile, (int)sizeof(hostile), o, (int)sizeof(o));
    ASSERT_STR(o, "a?[???z");
    /* Only the first line, and nothing past a NUL. */
    sys_clean_str("one\ntwo\n", 8, o, (int)sizeof(o));
    ASSERT_STR(o, "one");
    const char nul[] = { 'a', 'b', 0x00, 'c', 'd' };
    sys_clean_str(nul, (int)sizeof(nul), o, (int)sizeof(o));
    ASSERT_STR(o, "ab");
    /* Bounded: 40 bytes into a 16-byte buffer. */
    sys_clean_str("0123456789012345678901234567890123456789", 40, o, (int)sizeof(o));
    ASSERT_EQ(strlen(o), 15u);
    sys_clean_str(NULL, 5, o, (int)sizeof(o));
    ASSERT_STR(o, "");

    const char *ue = "DRIVER=iwlwifi\nPCI_CLASS=28000\nPCI_ID=8086:2723\nPCI_SLOT_NAME=0000:00:14.3";
    char v[24];
    ASSERT_EQ(sys_parse_uevent(ue, (int)strlen(ue), "DRIVER", v, (int)sizeof(v)), 0);
    ASSERT_STR(v, "iwlwifi");
    ASSERT_EQ(sys_parse_uevent(ue, (int)strlen(ue), "PCI_SLOT_NAME", v, (int)sizeof(v)), 0);
    ASSERT_STR(v, "0000:00:14.3");                              /* no newline */
    /* A key that is only a prefix of another, a missing key, an empty value. */
    ASSERT_EQ(sys_parse_uevent(ue, (int)strlen(ue), "PCI", v, (int)sizeof(v)), -1);
    ASSERT_EQ(sys_parse_uevent(ue, (int)strlen(ue), "SDIO_ID", v, (int)sizeof(v)), -1);
    ASSERT_EQ(sys_parse_uevent("DRIVER=\n", 8, "DRIVER", v, (int)sizeof(v)), -1);
    ASSERT_EQ(sys_parse_uevent("", 0, "DRIVER", v, (int)sizeof(v)), -1);

    char h[5];
    ASSERT_EQ(sys_parse_hex4("0bda\n", 5, h), 0);
    ASSERT_STR(h, "0bda");
    ASSERT_EQ(sys_parse_hex4("0BDA", 4, h), 0);
    ASSERT_STR(h, "0bda");
    ASSERT_EQ(sys_parse_hex4("0bd", 3, h), -1);
    ASSERT_EQ(sys_parse_hex4("0bdg\n", 5, h), -1);
    ASSERT_EQ(sys_parse_hex4("0bda5\n", 6, h), -1);
    ASSERT_EQ(sys_parse_hex4("-bda\n", 5, h), -1);
}

static void test_bands(void) {
    const double e[] = { 60.0, 70.0, 80.0 };
    ASSERT_EQ(sys_held_band(-1, 59.9, e, 3, 2.0), 0);
    ASSERT_EQ(sys_held_band(-1, 60.0, e, 3, 2.0), 1);
    ASSERT_EQ(sys_held_band(-1, 95.0, e, 3, 2.0), 3);
    /* Up is taken at once, however far. */
    ASSERT_EQ(sys_held_band(0, 85.0, e, 3, 2.0), 3);
    /* Down only once clear of the edge by the margin. */
    ASSERT_EQ(sys_held_band(1, 59.0, e, 3, 2.0), 1);
    ASSERT_EQ(sys_held_band(1, 58.0, e, 3, 2.0), 1);
    ASSERT_EQ(sys_held_band(1, 57.9, e, 3, 2.0), 0);
    ASSERT_EQ(sys_held_band(3, 79.0, e, 3, 2.0), 3);
    ASSERT_EQ(sys_held_band(3, 77.9, e, 3, 2.0), 2);
    ASSERT_EQ(sys_held_band(3, 50.0, e, 3, 2.0), 0);
    /* A value sitting on an edge and wobbling does not move the band. */
    int b = 1, moves = 0;
    for (int i = 0; i < 40; i++) {
        int n = sys_held_band(b, (i & 1) ? 60.4 : 59.6, e, 3, 2.0);
        if (n != b) moves++;
        b = n;
    }
    ASSERT_EQ(moves, 0);

    ASSERT_EQ(sys_age_band(-1), -1);
    ASSERT_EQ(sys_age_band(0), 0);
    ASSERT_EQ(sys_age_band(SYS_SRC_STALE_S), 0);
    ASSERT_EQ(sys_age_band(SYS_SRC_STALE_S + 1), 1);
    ASSERT_EQ(sys_age_band(SYS_SRC_OLD_S), 1);
    ASSERT_EQ(sys_age_band(SYS_SRC_OLD_S + 1), 2);
    ASSERT_STR(sys_age_band_name(-1), "never");
    ASSERT_STR(sys_age_band_name(2), "old");
    ASSERT_STR(sys_src_state_name(SYS_ST_NOT_CONFIGURED), "not_configured");
    ASSERT_STR(sys_src_state_name(SYS_ST_DOWN), "down");
}

static void test_usb_table(void) {
    const sys_usb_id_t *e = sys_usb_lookup(0x0bda, 0x2838);
    ASSERT(e != NULL);
    if (e) ASSERT_STR(e->kind, "sdr");
    e = sys_usb_lookup(0x1546, 0x01a7);
    ASSERT(e != NULL);
    if (e) ASSERT_STR(e->kind, "gnss");
    ASSERT(sys_usb_lookup(0x046d, 0xc31c) == NULL);   /* a keyboard */
    ASSERT(sys_usb_lookup(0, 0) == NULL);
    static const char *const kinds[] = { "sdr", "gnss", "serial", "wifi", "bluetooth",
                                         "bluetooth-sniffer" };
    ASSERT_GT(sys_usb_table_count, 0);
    for (int i = 0; i < sys_usb_table_count; i++) {
        int known = 0;
        for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++)
            known |= !strcmp(sys_usb_table[i].kind, kinds[k]);
        ASSERT(known);
        ASSERT(sys_usb_table[i].name[0] != '\0');
        ASSERT(strlen(sys_usb_table[i].name) < sizeof(((sys_hw_t *)0)->desc));
        for (int j = i + 1; j < sys_usb_table_count; j++)
            ASSERT(sys_usb_table[i].vid != sys_usb_table[j].vid ||
                   sys_usb_table[i].pid != sys_usb_table[j].pid);
    }
}

static void test_path_guard(void) {
    ASSERT_EQ(sys_path_ok("/proc/stat"), 1);
    ASSERT_EQ(sys_path_ok("/sys/class/thermal/thermal_zone0/temp"), 1);
    ASSERT_EQ(sys_path_ok("/sys/bus/usb/devices/1-1.2:1.0/net"), 1);
    ASSERT_EQ(sys_path_ok("/sys/class/net/..foo/wireless"), 1);  /* a name, not a component */
    ASSERT_EQ(sys_path_ok("/dev/ttyUSB0"), 0);
    ASSERT_EQ(sys_path_ok("/etc/passwd"), 0);
    ASSERT_EQ(sys_path_ok("proc/stat"), 0);
    ASSERT_EQ(sys_path_ok("/sysfoo/x"), 0);
    ASSERT_EQ(sys_path_ok("/proc/../dev/ttyUSB0"), 0);
    ASSERT_EQ(sys_path_ok("/sys/class/net/.."), 0);
    ASSERT_EQ(sys_path_ok(""), 0);
    ASSERT_EQ(sys_path_ok(NULL), 0);
}

/* ── the real readers, on a real directory ───────────────────────── */

static void test_real_readers_take_regular_files_only(void) {
    char dir[TEST_TMP_MAX] = "", path[TEST_TMP_MAX + 32], buf[64];
    ASSERT(mkdtemp(test_tmp_tpl(dir, sizeof(dir), "sloth_sysio_XXXXXX")) != NULL);
    snprintf(path, sizeof(path), "%s/temp", dir);
    FILE *fp = fopen(path, "w");
    ASSERT(fp != NULL);
    if (fp) { fputs("48312\n", fp); fclose(fp); }
    int n = sys_io_read_file(path, buf, (int)sizeof(buf));
    ASSERT_EQ(n, 6);
    ASSERT(n == 6 && memcmp(buf, "48312\n", 6) == 0);
    /* A cap shorter than the file: cap bytes, no overrun. */
    memset(buf, 'x', sizeof(buf));
    ASSERT_EQ(sys_io_read_file(path, buf, 3), 3);
    ASSERT_EQ(buf[3], 'x');
    /* Missing, a directory, a FIFO: refused, and the FIFO without a
     * read that would wait for a writer. */
    snprintf(path, sizeof(path), "%s/absent", dir);
    ASSERT_EQ(sys_io_read_file(path, buf, (int)sizeof(buf)), -1);
    ASSERT_EQ(sys_io_read_file(dir, buf, (int)sizeof(buf)), -1);
    snprintf(path, sizeof(path), "%s/fifo", dir);
    ASSERT_EQ(mkfifo(path, 0600), 0);
    ASSERT_EQ(sys_io_read_file(path, buf, (int)sizeof(buf)), -1);

    char names[8][16];
    n = sys_io_list_dir(dir, &names[0][0], 16, 8);
    ASSERT_EQ(n, 2);                                   /* temp and fifo; no . or .. */
    int saw_temp = 0, saw_fifo = 0;
    for (int i = 0; i < n; i++) {
        saw_temp |= !strcmp(names[i], "temp");
        saw_fifo |= !strcmp(names[i], "fifo");
    }
    ASSERT(saw_temp && saw_fifo);
    ASSERT_EQ(sys_io_list_dir(dir, &names[0][0], 16, 1), 1);   /* max honoured */
    snprintf(path, sizeof(path), "%s/absent", dir);
    ASSERT_EQ(sys_io_list_dir(path, &names[0][0], 16, 8), -1);
    test_rm_tree(dir);
}

/* ── a host with neither tree ────────────────────────────────────── */

/* A VM, a container, a platform with no /proc: every reading is absent
 * and nothing is written as zero. Seen red with cpu_pct, load1,
 * uptime_s, rss_kb and undervolt written unconditionally in
 * emit_batch(), and the per-source age_s / count absences with the
 * not_configured guard in emit_source() removed. The mem_, temp_max
 * and disk_ absences were not mutated the same way: their fields sit
 * beside a band name indexed by a band that is -1 when absent, so the
 * mutation is undefined behaviour rather than a wrong record. */
static void test_bare_host_reports_nothing_as_zero(void) {
    TEST_STATE(s);
    fresh(&s);
    jl_open();
    tick(&s, 0);
    const sys_snapshot_t *sn = sys_status_get();
    ASSERT_EQ(sn->valid, 1);
    ASSERT_EQ(sn->has_cpu, 0);
    ASSERT_EQ(sn->has_load, 0);
    ASSERT_EQ(sn->has_mem, 0);
    ASSERT_EQ(sn->ntemp, 0);
    ASSERT_EQ(sn->hottest, -1);
    ASSERT_EQ(sn->nhw, 0);
    char *b = jl_read();
    ASSERT_EQ(count_of(b, "\"type\":\"sys_status\""), 1);
    const char *l = line_of(b, "sys_status", NULL);
    ASSERT(strstr(l, "\"seq\":1,\"interval_s\":60,") != NULL);
    ASSERT(strstr(l, "\"temps\":0,\"volts\":0,\"power\":0,\"sources\":7,"
                     "\"sources_configured\":0,\"sources_ok\":0,\"sources_down\":0,"
                     "\"receivers\":0}") != NULL);
    ASSERT(strstr(l, "cpu_pct") == NULL);
    ASSERT(strstr(l, "cpu_band") == NULL);
    ASSERT(strstr(l, "load1") == NULL);
    ASSERT(strstr(l, "mem_") == NULL);
    ASSERT(strstr(l, "uptime_s") == NULL);
    ASSERT(strstr(l, "rss_kb") == NULL);
    ASSERT(strstr(l, "temp_max") == NULL);
    ASSERT(strstr(l, "undervolt") == NULL);
    ASSERT(strstr(l, "disk_") == NULL);
    ASSERT_EQ(count_of(b, "\"type\":\"sys_sensor\""), 0);
    ASSERT_EQ(count_of(b, "\"type\":\"receiver_hw\""), 0);
    /* The whole set of sources all the same, each not configured. */
    ASSERT_EQ(count_of(b, "\"type\":\"source_status\""), SYS_SRC_COUNT);
    ASSERT_EQ(count_of(b, "\"state\":\"not_configured\""), SYS_SRC_COUNT);
    static const char *const names[] = { "capture", "monitor", "btmon", "btcap",
                                         "gnss", "adsb", "aprs" };
    for (int i = 0; i < SYS_SRC_COUNT; i++) {
        char want[40];
        snprintf(want, sizeof(want), "\"name\":\"%s\"", names[i]);
        l = line_of(b, "source_status", want);
        ASSERT(l[0] != '\0');
        /* Not configured: no age, count or rate to misread as "idle". */
        ASSERT(strstr(l, "age_s") == NULL);
        ASSERT(strstr(l, "\"count\"") == NULL);
        ASSERT(strstr(l, "\"rate\"") == NULL);
    }
    done();
}

/* A platform with no sys_read at all (bsd, win32, the embedded stub). */
static void test_null_ops_are_a_bare_host(void) {
    TEST_STATE(s);
    fresh(&s);
    fake_sys_put("/proc/loadavg", "0.20 0.18 0.12 1/80 11206\n");
    platform_ops_t saved = g_platform;
    g_platform.sys_read = NULL;
    g_platform.sys_list = NULL;
    tick(&s, 0);
    g_platform = saved;
    ASSERT_EQ(sys_status_get()->valid, 1);
    ASSERT_EQ(sys_status_get()->has_load, 0);
    ASSERT_EQ(g_fake_net.sys_read_calls, 0);
    done();
}

/* ── a Raspberry Pi shaped host ──────────────────────────────────── */

static void put_pi(void) {
    fake_sys_put("/proc/stat", PROC_STAT_A);
    fake_sys_put("/proc/loadavg", "0.20 0.18 0.12 1/80 11206\n");
    fake_sys_put("/proc/meminfo", PROC_MEMINFO);
    fake_sys_put("/proc/uptime", "350735.47 234388.90\n");
    fake_sys_put("/proc/self/status",
                 "Name:\tsloth\nVmPeak:\t  90000 kB\nVmHWM:\t   13000 kB\nVmRSS:\t   12276 kB\n");
    fake_sys_put("/sys/class/thermal/thermal_zone0/temp", "48312\n");
    fake_sys_put("/sys/class/thermal/thermal_zone0/type", "cpu-thermal\n");
    fake_sys_put("/sys/class/hwmon/hwmon0/name", "cpu_thermal\n");
    fake_sys_put("/sys/class/hwmon/hwmon0/temp1_input", "48850\n");
    /* The firmware's under-voltage flag: an alarm, no reading. */
    fake_sys_put("/sys/class/hwmon/hwmon1/name", "rpi_volt\n");
    fake_sys_put("/sys/class/hwmon/hwmon1/in0_lcrit_alarm", "0\n");
    /* An ADC with two rails, one labelled. */
    fake_sys_put("/sys/class/hwmon/hwmon3/name", "rp1_adc\n");
    fake_sys_put("/sys/class/hwmon/hwmon3/in1_input", "5103\n");
    fake_sys_put("/sys/class/hwmon/hwmon3/in1_label", "VBUS\n");
    fake_sys_put("/sys/class/hwmon/hwmon3/in2_input", "3312\n");
    fake_sys_put("/sys/class/hwmon/hwmon3/temp1_input", "51000\n");
}

static void test_pi_sample_and_records(void) {
    TEST_STATE(s);
    fresh(&s);
    put_pi();
    jl_open();
    tick(&s, 0);
    const sys_snapshot_t *sn = sys_status_get();
    ASSERT_EQ(sn->has_cpu, 0);                    /* one sample is not an interval */
    ASSERT_EQ(sn->has_load, 1);
    ASSERT_NEAR(sn->load15, 0.12, 1e-9);
    ASSERT_EQ(sn->mem_total_kb, 3884328);
    ASSERT_EQ(sn->uptime_s, 350735);
    ASSERT_EQ(sn->rss_kb, 12276);
    ASSERT_EQ(sn->ntemp, 3);
    ASSERT_STR(sn->temp[0].id, "thermal_zone0");
    ASSERT_STR(sn->temp[0].label, "cpu-thermal");
    ASSERT_NEAR(sn->temp[0].val, 48.312, 1e-9);
    ASSERT_STR(sn->temp[1].id, "hwmon0/temp1");
    ASSERT_STR(sn->temp[1].label, "cpu_thermal");
    ASSERT_STR(sn->temp[2].id, "hwmon3/temp1");
    ASSERT_EQ(sn->hottest, 2);                    /* 51.0 */
    ASSERT_EQ(sn->temp_band, 0);
    ASSERT_EQ(sn->nvolt, 3);
    ASSERT_STR(sn->volt[0].id, "hwmon1/in0");
    ASSERT_EQ(sn->volt[0].has_val, 0);            /* an alarm with no reading */
    ASSERT_EQ(sn->volt[0].has_alarm, 1);
    ASSERT_STR(sn->volt[1].label, "rp1_adc VBUS");
    ASSERT_NEAR(sn->volt[1].val, 5.103, 1e-9);
    ASSERT_STR(sn->volt[2].label, "rp1_adc");
    ASSERT_EQ(sn->has_undervolt, 1);
    ASSERT_EQ(sn->undervolt, 0);

    /* The next sample, 10 s on: the interval's CPU share. */
    fake_sys_put("/proc/stat", PROC_STAT_B);
    tick(&s, 10000);
    ASSERT_EQ(sn->has_cpu, 1);
    ASSERT_NEAR(sn->cpu_pct, 15.0, 1e-9);
    ASSERT_NEAR(sn->iowait_pct, 10.0, 1e-9);
    /* The first CPU figure appearing is not a band crossing: no batch
     * of its own. */
    ASSERT_EQ(sn->seq, 1u);
    fake_sys_put("/proc/stat", PROC_STAT_C);
    tick(&s, 60000);

    char *b = jl_read();
    ASSERT_EQ(count_of(b, "\"type\":\"sys_status\""), 2);
    const char *l = line_of(b, "sys_status", "\"seq\":1,");
    ASSERT(strstr(l, "{\"type\":\"sys_status\",\"ts\":1800000000,\"seq\":1,\"interval_s\":60,"
                     "\"load1\":0.20,\"load5\":0.18,\"load15\":0.12,"
                     "\"mem_total_kb\":3884328,\"mem_avail_kb\":2913246,\"mem_band\":\"ok\","
                     "\"uptime_s\":350735,\"rss_kb\":12276,"
                     "\"temps\":3,\"temp_max_c\":51.0,\"temp_max_id\":\"hwmon3/temp1\","
                     "\"temp_band\":\"ok\",\"volts\":3,\"undervolt\":0,\"power\":0,") != NULL);
    l = line_of(b, "sys_status", "\"seq\":2,");
    ASSERT(strstr(l, "\"ts\":1800000060,\"seq\":2,\"interval_s\":60,\"cpu_pct\":15.0,"
                     "\"cpu_iowait_pct\":10.0,\"cpu_band\":\"low\",") != NULL);
    ASSERT_EQ(count_of(b, "\"type\":\"sys_sensor\""), 12);      /* 6 readings, 2 batches */
    ASSERT(strstr(b, "{\"type\":\"sys_sensor\",\"ts\":1800000000,\"seq\":1,\"class\":\"temp\","
                     "\"id\":\"thermal_zone0\",\"label\":\"cpu-thermal\",\"c\":48.3}") != NULL);
    ASSERT(strstr(b, "\"class\":\"volt\",\"id\":\"hwmon3/in1\",\"label\":\"rp1_adc VBUS\","
                     "\"v\":5.103}") != NULL);
    /* The alarm-only rail: an alarm, and no "v" beside it. */
    l = line_of(b, "sys_sensor", "\"id\":\"hwmon1/in0\"");
    ASSERT(strstr(l, "\"label\":\"rpi_volt\",\"alarm\":0}") != NULL);
    ASSERT(strstr(l, "\"v\":") == NULL);
    done();
}

/* Truncated, malformed and hostile sensor text is absent, never zero
 * and never a row. */
static void test_hostile_sensor_text_is_absent(void) {
    TEST_STATE(s);
    fresh(&s);
    fake_sys_put("/sys/class/thermal/thermal_zone0/type", "cpu-thermal\n");
    fake_sys_put("/sys/class/thermal/thermal_zone0/temp", "garbage\n");
    fake_sys_put("/sys/class/thermal/thermal_zone1/type", "gpu\n");
    fake_sys_put("/sys/class/thermal/thermal_zone1/temp", "999999999\n");     /* a million C */
    fake_sys_put("/sys/class/thermal/thermal_zone2/type", "soc\n");
    fake_sys_put("/sys/class/thermal/thermal_zone2/temp", "-150000\n");       /* below range */
    fake_sys_put("/sys/class/thermal/thermal_zone3/type", "ok\n");
    fake_sys_put("/sys/class/thermal/thermal_zone3/temp", "40000");           /* no newline */
    const char bin[] = { 0x00, (char)0xff, 0x07, '\n' };
    fake_sys_put("/sys/class/thermal/thermal_zone4/type", "bin\n");
    fake_sys_put_n("/sys/class/thermal/thermal_zone4/temp", bin, (int)sizeof(bin));
    fake_sys_put("/sys/class/thermal/thermal_zone5/type", "empty\n");
    fake_sys_put_n("/sys/class/thermal/thermal_zone5/temp", "", 0);
    fake_sys_put("/sys/class/hwmon/hwmon0/name", "weird\n");
    fake_sys_put("/sys/class/hwmon/hwmon0/temp1_input", "99999999999999999999999\n");
    fake_sys_put("/sys/class/hwmon/hwmon0/in0_input", "5v\n");
    fake_sys_put("/sys/class/hwmon/hwmon0/in1_input", "-200000\n");
    fake_sys_put("/sys/class/hwmon/hwmon0/in2_lcrit_alarm", "2\n");           /* not 0 or 1 */
    fake_sys_put("/proc/stat", "cpu  1000 0 5");                              /* truncated */
    fake_sys_put("/proc/meminfo", "MemTotal: 100 kB\nMemAvailable: 900 kB\n");
    fake_sys_put("/proc/loadavg", "0.20 0.18");
    fake_sys_put("/proc/uptime", "soon\n");
    tick(&s, 0);
    const sys_snapshot_t *sn = sys_status_get();
    ASSERT_EQ(sn->ntemp, 1);
    ASSERT_STR(sn->temp[0].id, "thermal_zone3");
    ASSERT_NEAR(sn->temp[0].val, 40.0, 1e-9);
    ASSERT_EQ(sn->nvolt, 0);
    ASSERT_EQ(sn->has_undervolt, 0);
    ASSERT_EQ(sn->has_cpu, 0);
    ASSERT_EQ(sn->has_mem, 0);
    ASSERT_EQ(sn->has_load, 0);
    ASSERT_EQ(sn->has_uptime, 0);
    /* And a second truncated /proc/stat is still not an interval. */
    tick(&s, 10000);
    ASSERT_EQ(sn->has_cpu, 0);
    done();
}

static void test_power_supply(void) {
    TEST_STATE(s);
    fresh(&s);
    fake_sys_put("/sys/class/power_supply/BAT0/type", "Battery\n");
    fake_sys_put("/sys/class/power_supply/BAT0/voltage_now", "12011000\n");
    fake_sys_put("/sys/class/power_supply/BAT0/capacity", "87\n");
    fake_sys_put("/sys/class/power_supply/BAT0/status", "Discharging\n");
    /* A supply whose every figure is out of range or hostile. */
    fake_sys_put("/sys/class/power_supply/ups/type", "UPS\n");
    fake_sys_put("/sys/class/power_supply/ups/capacity", "250\n");
    fake_sys_put("/sys/class/power_supply/ups/voltage_now", "-5\n");
    const char st[] = { 'O', 'K', '"', 0x1b, '[', '2', 'J', '\n' };
    fake_sys_put_n("/sys/class/power_supply/ups/status", st, (int)sizeof(st));
    /* One that says nothing: not a row. */
    fake_sys_put("/sys/class/power_supply/ac/online", "1\n");
    jl_open();
    tick(&s, 0);
    const sys_snapshot_t *sn = sys_status_get();
    ASSERT_EQ(sn->npower, 2);
    char *b = jl_read();
    ASSERT(strstr(b, "\"class\":\"power\",\"id\":\"BAT0\",\"label\":\"Battery\",\"v\":12.011,"
                     "\"capacity\":87,\"status\":\"Discharging\"}") != NULL);
    const char *l = line_of(b, "sys_sensor", "\"id\":\"ups\"");
    /* The escape byte became '?' and the quote is escaped: one valid
     * JSON string, no control byte reaching a terminal that tails the
     * log. */
    ASSERT(strstr(l, "\"label\":\"UPS\",\"status\":\"OK\\\"?[2J\"}") != NULL);
    ASSERT(strstr(l, "capacity") == NULL);
    ASSERT(strstr(l, "\"v\":") == NULL);
    ASSERT(strchr(b, 0x1b) == NULL);
    ASSERT_EQ(count_of(b, "\"id\":\"ac\""), 0);
    done();
}

/* ── receivers ───────────────────────────────────────────────────── */

#define USB "/sys/bus/usb/devices/"

static void put_receivers(void) {
    /* An RTL-SDR, with the serial number a real one carries. */
    fake_sys_put(USB "1-1.2/idVendor", "0bda\n");
    fake_sys_put(USB "1-1.2/idProduct", "2838\n");
    fake_sys_put(USB "1-1.2/manufacturer", "Realtek\n");
    fake_sys_put(USB "1-1.2/product", "RTL2838UHIDIR\n");
    fake_sys_put(USB "1-1.2/serial", "00000001\n");
    fake_sys_put(USB "1-1.2:1.0/uevent", "DEVTYPE=usb_interface\nDRIVER=dvb_usb_rtl28xxu\n");
    /* A keyboard: attached, and none of sloth's business. */
    fake_sys_put(USB "1-1.3/idVendor", "046d\n");
    fake_sys_put(USB "1-1.3/idProduct", "c31c\n");
    fake_sys_put(USB "1-1.3/product", "USB Keyboard\n");
    /* A monitor-mode Wi-Fi adapter with its netdev and a monitor vif. */
    fake_sys_put(USB "1-1.4/idVendor", "0bda\n");
    fake_sys_put(USB "1-1.4/idProduct", "8812\n");
    fake_sys_put(USB "1-1.4/product", "802.11n NIC\n");
    fake_sys_put(USB "1-1.4:1.0/uevent", "DRIVER=rtl88XXau\n");
    fake_sys_put(USB "1-1.4:1.0/net/wlan1/address", "02:00:00:00:00:01\n");
    fake_sys_put(USB "1-1.4:1.0/net/wlan1mon/address", "02:00:00:00:00:01\n");
    /* A u-blox on cdc_acm. */
    fake_sys_put(USB "1-1.1/idVendor", "1546\n");
    fake_sys_put(USB "1-1.1/idProduct", "01a7\n");
    fake_sys_put(USB "1-1.1/product", "u-blox 7 - GPS/GNSS Receiver\n");
    fake_sys_put(USB "1-1.1:1.0/uevent", "DRIVER=cdc_acm\n");
    fake_sys_put(USB "1-1.1:1.0/tty/ttyACM0/dev", "166:0\n");
    /* A root hub and a device whose ID is cut short or not hex. */
    fake_sys_put(USB "usb1/idVendor", "1d6b\n");
    fake_sys_put(USB "usb1/idProduct", "0002\n");
    fake_sys_put(USB "1-1.5/idVendor", "0b");
    fake_sys_put(USB "1-1.5/idProduct", "2838\n");
    fake_sys_put(USB "1-1.6/idVendor", "zzzz\n");
    fake_sys_put(USB "1-1.6/idProduct", "2838\n");
    /* The class directories: the USB adapter's two netdevs again, the
     * on-board SDIO radio, a wired port, and an on-board controller. */
    fake_sys_put("/sys/class/net/wlan1/phy80211/index", "1\n");
    fake_sys_put("/sys/class/net/wlan1mon/phy80211/index", "1\n");
    fake_sys_put("/sys/class/net/wlan0/phy80211/index", "0\n");
    fake_sys_put("/sys/class/net/wlan0/device/uevent",
                 "DRIVER=brcmfmac\nSDIO_CLASS=00\nSDIO_ID=02D0:A9A6\n");
    fake_sys_put("/sys/class/net/eth0/device/uevent", "DRIVER=bcmgenet\n");
    fake_sys_put("/sys/class/bluetooth/hci0/device/uevent", "DRIVER=hci_uart_bcm\n");
    fake_sys_put("/sys/class/bluetooth/hci0:11/uevent", "DEVTYPE=link\n");
}

static const sys_hw_t *hw_by_key(const char *key) {
    const sys_snapshot_t *sn = sys_status_get();
    for (int i = 0; i < sn->nhw; i++)
        if (!strcmp(sn->hw[i].key, key)) return &sn->hw[i];
    return NULL;
}

static void test_receiver_inventory(void) {
    TEST_STATE(s);
    fresh(&s);
    put_receivers();
    snprintf(g_fake_net.sys_watch, sizeof(g_fake_net.sys_watch), "serial");
    jl_open();
    tick(&s, 0);
    const sys_snapshot_t *sn = sys_status_get();
    ASSERT_EQ(sn->nhw, 5);          /* sdr, wifi, gnss, on-board wifi, on-board bt */
    const sys_hw_t *h = hw_by_key("usb:1-1.2");
    ASSERT(h != NULL);
    if (h) {
        ASSERT_STR(h->kind, "sdr");
        ASSERT_STR(h->id, "0bda:2838");
        ASSERT_STR(h->desc, "Realtek RTL2838 DVB-T (RTL-SDR)");
        ASSERT_STR(h->vendor, "Realtek");
        ASSERT_STR(h->product, "RTL2838UHIDIR");
        ASSERT_STR(h->driver, "dvb_usb_rtl28xxu");
        ASSERT_STR(h->ifaces, "");
    }
    h = hw_by_key("usb:1-1.4");
    ASSERT(h != NULL);
    if (h) {
        ASSERT_STR(h->kind, "wifi");
        ASSERT(strstr(h->ifaces, "wlan1mon") != NULL);
        ASSERT(!strncmp(h->ifaces, "wlan1", 5));
        ASSERT_STR(h->driver, "rtl88XXau");
    }
    h = hw_by_key("usb:1-1.1");
    ASSERT(h != NULL);
    if (h) { ASSERT_STR(h->kind, "gnss"); ASSERT_STR(h->ifaces, "ttyACM0"); }
    h = hw_by_key("net:wlan0");
    ASSERT(h != NULL);
    if (h) {
        ASSERT_STR(h->kind, "wifi");
        ASSERT_STR(h->bus, "sdio");
        ASSERT_STR(h->id, "02d0:a9a6");
        ASSERT_STR(h->driver, "brcmfmac");
        ASSERT_EQ(h->known, 0);
    }
    h = hw_by_key("bt:hci0");
    ASSERT(h != NULL);
    if (h) { ASSERT_STR(h->kind, "bluetooth"); ASSERT_STR(h->driver, "hci_uart_bcm"); }
    /* Not listed: the keyboard, the root hub, the wired port, the two
     * malformed IDs, the link entry, and the USB adapter's netdevs a
     * second time. Seen red with scan_usb() listing a device that is
     * not in the table (the keyboard becomes a row). */
    ASSERT(hw_by_key("usb:1-1.3") == NULL);
    ASSERT(hw_by_key("usb:usb1") == NULL);
    ASSERT(hw_by_key("usb:1-1.5") == NULL);
    ASSERT(hw_by_key("usb:1-1.6") == NULL);
    ASSERT(hw_by_key("net:eth0") == NULL);
    ASSERT(hw_by_key("net:wlan1") == NULL);
    ASSERT(hw_by_key("net:wlan1mon") == NULL);
    ASSERT(hw_by_key("bt:hci0:11") == NULL);
    /* The serial number is on the fake host and is never asked for.
     * Seen red with a read of <device>/serial added beside the product
     * string's. */
    ASSERT_EQ(g_fake_net.sys_watch_hits, 0);
    ASSERT_EQ(g_fake_net.sys_outside_calls, 0);
    char *b = jl_read();
    ASSERT_EQ(count_of(b, "\"type\":\"receiver_hw\""), 5);
    ASSERT(strstr(b, "{\"type\":\"receiver_hw\",\"ts\":1800000000,\"seq\":1,\"key\":\"usb:1-1.2\","
                     "\"kind\":\"sdr\",\"bus\":\"usb\",\"id\":\"0bda:2838\",\"known\":1,"
                     "\"desc\":\"Realtek RTL2838 DVB-T (RTL-SDR)\",\"vendor\":\"Realtek\","
                     "\"product\":\"RTL2838UHIDIR\",\"driver\":\"dvb_usb_rtl28xxu\","
                     "\"ifaces\":\"\"}") != NULL);
    ASSERT(strstr(b, "00000001") == NULL);
    ASSERT(strstr(b, "serial") == NULL);
    ASSERT(strstr(b, "Keyboard") == NULL);
    done();
}

/* A receiver's row says the table's name for it, whole. scan_usb()
 * wrote it through "%.31s", so the five names longer than that lost
 * their ends ("Realtek RTL2832U DVB-T (RTL-SDR" without its bracket,
 * "Cambridge Silicon Radio Bluetoo"), while the same device reached
 * through a class directory's uevent kept it. Seen red with that
 * format: this test, for each of the five. */
static void test_receiver_name_is_the_tables_whole(void) {
    TEST_STATE(s);
    int longer = 0;
    for (int i = 0; i < sys_usb_table_count; i++) {
        const sys_usb_id_t *e = &sys_usb_table[i];
        char v[8], p[8];
        fresh(&s);
        snprintf(v, sizeof(v), "%04x\n", (unsigned)e->vid);
        snprintf(p, sizeof(p), "%04x\n", (unsigned)e->pid);
        fake_sys_put(USB "1-1/idVendor", v);
        fake_sys_put(USB "1-1/idProduct", p);
        tick(&s, 0);
        const sys_hw_t *h = hw_by_key("usb:1-1");
        ASSERT(h != NULL);
        if (h) {
            ASSERT_STR(h->desc, e->name);
            ASSERT_STR(h->kind, e->kind);
        }
        longer += strlen(e->name) > 31;
    }
    ASSERT_GT(longer, 0);          /* the table still has a name that long */
}

/* The /proc and /sys text parsers and the two lookups under generated
 * input, from a fixed seed: real files' text with bytes flipped, cut
 * and spliced, and plain noise, every length from none to past any
 * buffer here, NUL and bytes over 0x7f included. The text is handed in
 * a block of exactly its length (no terminator: none is promised) and
 * every output goes into a block of exactly its capacity, so a read or
 * a write past either is the sanitizer's to report; what is asserted
 * is what a caller relies on when a parser says yes. What it found on
 * 2026-11-11: nothing. */
static void test_parsers_under_generated_text(void) {
    static const char *const REAL[] = {
        "cpu  4705 150 1120 16250 520 0 30 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n",
        "0.42 0.36 0.30 1/345 12345\n",
        "MemTotal:        3884388 kB\nMemFree:          112340 kB\n"
        "MemAvailable:    2011420 kB\n",
        "350735.47 1388860.38\n",
        "48312\n", "-1500\n", "1\n",
        "DRIVER=iwlwifi\nPCI_CLASS=28000\nPCI_ID=8086:2723\nPCI_SLOT_NAME=0000:00:14.3\n",
        "PRODUCT=bda/8812/0\nDRIVER=rtl88XXau\n", "SDIO_ID=02D0:A9A6\n",
        "0bda\n", "Realtek Semiconductor Corp.\n",
        "18446744073709551615 99999999999999999999 1e308 -0 +5 0x10\n",
    };
    static const char NOISE[] = "0123456789 .\n\t-=:/abcdefxMemTotalcpuDRIVERPCI_ID\0\x01\x7f\x80\xff";
    uint32_t x = 0x5107b0a7;
    int yes = 0;
#define NEXT() (x = x * 1664525u + 1013904223u, x >> 8)
    for (int it = 0; it < 6000; it++) {
        char src[400];
        int len = 0;
        const char *r = REAL[NEXT() % (sizeof(REAL) / sizeof(REAL[0]))];
        int rl = (int)strlen(r);
        switch (NEXT() % 4) {
        case 0:                                 /* a real file, cut anywhere */
            len = (int)(NEXT() % (unsigned)(rl + 1));
            memcpy(src, r, (size_t)len);
            break;
        case 1:                                 /* a real file, a few bytes flipped */
            len = rl;
            memcpy(src, r, (size_t)len);
            for (int k = 0, n = 1 + (int)(NEXT() % 4); k < n && len; k++) {
                unsigned at = NEXT() % (unsigned)len;
                src[at] = NOISE[NEXT() % (sizeof(NOISE) - 1)];
            }
            break;
        case 2:                                 /* two real files end to end */
            len = rl;
            memcpy(src, r, (size_t)len);
            r = REAL[NEXT() % (sizeof(REAL) / sizeof(REAL[0]))];
            rl = (int)strlen(r);
            memcpy(src + len, r, (size_t)rl);
            len += rl;
            break;
        default:                                /* noise, none to 300 bytes */
            len = (int)(NEXT() % 301);
            for (int k = 0; k < len; k++) src[k] = NOISE[NEXT() % (sizeof(NOISE) - 1)];
        }
        char *t = malloc(len ? (size_t)len : 1);
        ASSERT(t != NULL);
        if (!t) return;
        memcpy(t, src, (size_t)len);

        sys_cpu_t c = { 0, 0, 0 };
        if (sys_parse_cpu(t, len, &c) == 0) { yes++; ASSERT(c.idle <= c.total && c.iowait <= c.total); }
        double l1 = -1, l5 = -1, l15 = -1;
        if (sys_parse_loadavg(t, len, &l1, &l5, &l15) == 0) { yes++; ASSERT(l1 >= 0 && l5 >= 0 && l15 >= 0); }
        long long mt = -1, ma = -1, up = -1, iv = 0;
        if (sys_parse_meminfo(t, len, &mt, &ma) == 0) { yes++; ASSERT(mt > 0 && ma >= 0 && ma <= mt); }
        if (sys_parse_uptime(t, len, &up) == 0) { yes++; ASSERT(up >= 0 && up <= 1000000000000LL); }
        if (sys_parse_int(t, len, -100000, 250000, &iv) == 0) { yes++; ASSERT(iv >= -100000 && iv <= 250000); }
        char h4[5] = "zzzz";
        if (sys_parse_hex4(t, len, h4) == 0) {
            yes++;
            ASSERT_EQ(strlen(h4), 4u);
            ASSERT_EQ(strspn(h4, "0123456789abcdef"), 4u);
        }
        static const char *const KEYS[] = { "DRIVER", "PCI_ID", "PRODUCT", "SDIO_ID", "" };
        int cap = 1 + (int)(NEXT() % 40);
        char *o = malloc((size_t)cap);
        ASSERT(o != NULL);
        if (!o) { free(t); return; }
        for (size_t k = 0; k < sizeof(KEYS) / sizeof(KEYS[0]); k++) {
            memset(o, 'Z', (size_t)cap);
            if (sys_parse_uevent(t, len, KEYS[k], o, cap) == 0) {
                yes++;
                ASSERT(o[0] != '\0' && memchr(o, '\0', (size_t)cap) != NULL);
            }
        }
        memset(o, 'Z', (size_t)cap);
        sys_clean_str(t, len, o, cap);
        const char *e = memchr(o, '\0', (size_t)cap);
        ASSERT(e != NULL);
        for (const char *q = o; e && q < e; q++) ASSERT(*q >= 0x20 && *q <= 0x7e);
        free(o);
        free(t);

        /* The receiver table: an ID is found exactly when a row has it. */
        unsigned vid = NEXT() & 0x1ffffu, pid = NEXT() & 0x1ffffu;
        if (NEXT() % 3 == 0) {
            const sys_usb_id_t *row = &sys_usb_table[NEXT() % (unsigned)sys_usb_table_count];
            vid = row->vid; pid = row->pid;
            if (NEXT() % 4 == 0) vid |= 0x10000u;       /* past sixteen bits: no row's */
        }
        const sys_usb_id_t *hit = sys_usb_lookup(vid, pid);
        int in_table = 0;
        for (int k = 0; k < sys_usb_table_count; k++)
            in_table |= sys_usb_table[k].vid == vid && sys_usb_table[k].pid == pid;
        ASSERT_EQ(hit != NULL, in_table);
        if (hit) ASSERT(hit->vid == vid && hit->pid == pid);

        /* The path guard: what it lets through is under one of the two
         * trees and has no ".." component. */
        static const char *const PARTS[] = { "/proc", "/sys", "/", "..", ".", "/..", "/../",
                                             "class", "/etc/passwd", "/dev/ttyUSB0", "...", "/.../" };
        char path[128] = "";
        for (int k = 0, n = (int)(NEXT() % 6); k < n; k++) {
            const char *part = PARTS[NEXT() % (sizeof(PARTS) / sizeof(PARTS[0]))];
            if (strlen(path) + strlen(part) < sizeof(path)) strcat(path, part);
        }
        if (sys_path_ok(path)) {
            size_t pl = strlen(path);
            ASSERT(!strncmp(path, "/proc/", 6) || !strncmp(path, "/sys/", 5));
            ASSERT(strstr(path, "/../") == NULL);
            ASSERT(pl < 3 || strcmp(path + pl - 3, "/..") != 0);
        }
    }
#undef NEXT
    ASSERT_GT(yes, 500);            /* the generator does reach the accepting side */
}

/* Two interfaces of one PCI chip are one receiver; two chips are two. */
static void test_class_rows_merge_by_device(void) {
    TEST_STATE(s);
    fresh(&s);
    const char *ue = "DRIVER=iwlwifi\nPCI_ID=8086:2723\nPCI_SLOT_NAME=0000:00:14.3\n";
    fake_sys_put("/sys/class/net/wlp2s0/wireless/x", "\n");
    fake_sys_put("/sys/class/net/wlp2s0/device/uevent", ue);
    fake_sys_put("/sys/class/net/mon0/wireless/x", "\n");
    fake_sys_put("/sys/class/net/mon0/device/uevent", ue);
    fake_sys_put("/sys/class/net/wlp3s0/wireless/x", "\n");
    fake_sys_put("/sys/class/net/wlp3s0/device/uevent",
                 "DRIVER=iwlwifi\nPCI_ID=8086:2723\nPCI_SLOT_NAME=0000:03:00.0\n");
    tick(&s, 0);
    ASSERT_EQ(sys_status_get()->nhw, 2);
    int two = 0, one = 0;
    for (int i = 0; i < sys_status_get()->nhw; i++) {
        const sys_hw_t *h = &sys_status_get()->hw[i];
        ASSERT_STR(h->bus, "pci");
        ASSERT_STR(h->id, "8086:2723");
        if (strchr(h->ifaces, ',')) two++; else one++;
    }
    ASSERT_EQ(two, 1);
    ASSERT_EQ(one, 1);
    done();
}

/* A device-supplied string is whatever the device says. */
static void test_hostile_device_strings(void) {
    TEST_STATE(s);
    fresh(&s);
    fake_sys_put(USB "2-1/idVendor", "1d50\n");
    fake_sys_put(USB "2-1/idProduct", "6089\n");
    const char prod[] = { 'H', '"', '}', ',', '{', '\\', 0x1b, ']', '0', ';', (char)0x9b,
                          (char)0xe2, (char)0x80, (char)0xa8, 'x', '\n', 'n', 'e', 'x', 't' };
    fake_sys_put_n(USB "2-1/product", prod, (int)sizeof(prod));
    char longm[300];
    memset(longm, 'A', sizeof(longm));
    fake_sys_put_n(USB "2-1/manufacturer", longm, (int)sizeof(longm));
    jl_open();
    tick(&s, 0);
    const sys_hw_t *h = hw_by_key("usb:2-1");
    ASSERT(h != NULL);
    if (h) {
        ASSERT_STR(h->product, "H\"},{\\?]0;????x");
        ASSERT_EQ(strlen(h->vendor), sizeof(h->vendor) - 1);     /* bounded */
    }
    char *b = jl_read();
    const char *l = line_of(b, "receiver_hw", NULL);
    ASSERT(strstr(l, "\"product\":\"H\\\"},{\\\\?]0;????x\",") != NULL);
    for (const char *p = b; *p; p++)
        ASSERT((unsigned char)*p >= 0x20 || *p == '\n');         /* no raw control byte */
    done();
}

/* ── sources ─────────────────────────────────────────────────────── */

static const sys_source_t *src(int i) { return &sys_status_get()->src[i]; }

static void test_source_states(void) {
    TEST_STATE(s);
    fresh(&s);
    /* The pcap streams. */
    snprintf(s.pkt_iface, sizeof(s.pkt_iface), "eth0");
    s.pkt_linktype = 1;
    s.cap_health.open = 1; s.cap_health.running = 1; s.cap_health.stale_secs = 5;
    s.cap_health.ps_recv = 1000; s.cap_health.ps_drop = 3; s.cap_health.ps_ifdrop = 4;
    tick(&s, 0);
    ASSERT_EQ(src(SYS_SRC_CAPTURE)->state, SYS_ST_OK);
    ASSERT_STR(src(SYS_SRC_CAPTURE)->kind, "ip-capture");
    ASSERT_EQ(src(SYS_SRC_CAPTURE)->count, 1000u);
    ASSERT_EQ(src(SYS_SRC_CAPTURE)->errors, 7u);
    s.cap_health.stale_secs = SYS_SRC_STALE_S;
    tick(&s, 1000);
    ASSERT_EQ(src(SYS_SRC_CAPTURE)->state, SYS_ST_OK);
    s.cap_health.stale_secs = SYS_SRC_STALE_S + 1;
    tick(&s, 2000);
    ASSERT_EQ(src(SYS_SRC_CAPTURE)->state, SYS_ST_STALE);
    s.cap_health.stale_secs = -1;
    tick(&s, 3000);
    ASSERT_EQ(src(SYS_SRC_CAPTURE)->state, SYS_ST_STALE);
    ASSERT_STR(src(SYS_SRC_CAPTURE)->detail, "no frame yet");
    s.cap_health.running = 0;
    s.cap_health.exit_reason = CAPTURE_EXIT_IFACE_GONE;
    snprintf(s.cap_health.exit_detail, sizeof(s.cap_health.exit_detail), "No such device");
    tick(&s, 4000);
    ASSERT_EQ(src(SYS_SRC_CAPTURE)->state, SYS_ST_DOWN);
    ASSERT_STR(src(SYS_SRC_CAPTURE)->detail, "exit: iface_gone: No such device");
    s.cap_health.open = 0;
    tick(&s, 5000);
    ASSERT_EQ(src(SYS_SRC_CAPTURE)->state, SYS_ST_DOWN);
    ASSERT_STR(src(SYS_SRC_CAPTURE)->detail, "not open");
    /* Radiotap on the IP handle is a monitor radio. */
    s.pkt_linktype = 127;
    tick(&s, 6000);
    ASSERT_STR(src(SYS_SRC_CAPTURE)->kind, "wifi-monitor");

    /* The monitor radio, not found. */
    ASSERT_EQ(src(SYS_SRC_MONITOR)->state, SYS_ST_NOT_CONFIGURED);

    /* The Ubertooth stream. */
    s.btcap.configured = 1;
    s.btcap.state = BT_CAP_WAITING; s.btcap.stale_secs = -1;
    tick(&s, 7000);
    ASSERT_EQ(src(SYS_SRC_BTCAP)->state, SYS_ST_STALE);
    ASSERT_STR(src(SYS_SRC_BTCAP)->detail, "waiting");
    s.btcap.state = BT_CAP_STREAMING; s.btcap.stale_secs = 2;
    tick(&s, 8000);
    ASSERT_EQ(src(SYS_SRC_BTCAP)->state, SYS_ST_OK);
    s.btcap.state = BT_CAP_REFUSED;
    snprintf(s.btcap.err, sizeof(s.btcap.err), "link type 1");
    tick(&s, 9000);
    ASSERT_EQ(src(SYS_SRC_BTCAP)->state, SYS_ST_DOWN);
    ASSERT_STR(src(SYS_SRC_BTCAP)->detail, "refused: link type 1");

    /* ADS-B takes the decoder's own word. */
    s.adsb.configured = 1;
    snprintf(s.adsb.src, sizeof(s.adsb.src), "beast:127.0.0.1:30005");
    s.adsb.state = ADSB_LIVE; s.adsb.age_s = 1; s.adsb.messages = 500;
    tick(&s, 10000);
    ASSERT_EQ(src(SYS_SRC_ADSB)->state, SYS_ST_OK);
    ASSERT_STR(src(SYS_SRC_ADSB)->endpoint, "beast:127.0.0.1:30005");
    s.adsb.state = ADSB_STALE; s.adsb.age_s = 90;
    tick(&s, 11000);
    ASSERT_EQ(src(SYS_SRC_ADSB)->state, SYS_ST_STALE);
    s.adsb.state = ADSB_ERROR;
    snprintf(s.adsb.err, sizeof(s.adsb.err), "connection refused");
    tick(&s, 12000);
    ASSERT_EQ(src(SYS_SRC_ADSB)->state, SYS_ST_DOWN);
    ASSERT_STR(src(SYS_SRC_ADSB)->detail, "error: connection refused");

    /* A --location alone is a setting, not a receiver. */
    s.gps.configured = 1; s.gps.has_fixed = 1;
    tick(&s, 13000);
    ASSERT_EQ(src(SYS_SRC_GNSS)->state, SYS_ST_NOT_CONFIGURED);
    ASSERT(strstr(src(SYS_SRC_GNSS)->detail, "no receiver") != NULL);
    done();
}

/* gnss and aprs keep no arrival clock: their age is the count
 * advancing. A GNSS receiver searching for a fix is a working source;
 * an APRS channel that is quiet is not a fault. */
static void test_source_age_from_count(void) {
    TEST_STATE(s);
    fresh(&s);
    s.gps.configured = 1; s.gps.has_gps = 1; s.gps.state = GPS_SEARCHING;
    snprintf(s.gps.src, sizeof(s.gps.src), "gpsd:127.0.0.1:2947");
    s.aprs.configured = 1; s.aprs.state = APRS_LIVE;
    snprintf(s.aprs.src, sizeof(s.aprs.src), "file:/var/lib/direwolf/aprs.log");
    tick(&s, 0);
    ASSERT_EQ(src(SYS_SRC_GNSS)->age_s, -1);
    ASSERT_EQ(src(SYS_SRC_GNSS)->state, SYS_ST_STALE);          /* nothing heard yet */
    ASSERT_EQ(src(SYS_SRC_APRS)->age_s, -1);
    ASSERT_EQ(src(SYS_SRC_APRS)->state, SYS_ST_OK);             /* live, and quiet */
    s.gps.sentences = 40;
    s.aprs.packets = 1;
    tick(&s, 5000);
    ASSERT_EQ(src(SYS_SRC_GNSS)->age_s, 0);
    ASSERT_EQ(src(SYS_SRC_GNSS)->state, SYS_ST_OK);
    ASSERT_STR(src(SYS_SRC_GNSS)->detail, "searching");
    tick(&s, 5000 + 60000);
    ASSERT_EQ(src(SYS_SRC_GNSS)->age_s, 60);
    ASSERT_EQ(src(SYS_SRC_GNSS)->state, SYS_ST_OK);
    tick(&s, 5000 + 61000);
    ASSERT_EQ(src(SYS_SRC_GNSS)->state, SYS_ST_STALE);
    tick(&s, 5000 + 3601000);
    ASSERT_EQ(src(SYS_SRC_APRS)->state, SYS_ST_OK);
    ASSERT_EQ(sys_age_band(src(SYS_SRC_APRS)->age_s), 2);       /* old, and still ok */
    snprintf(s.gps.err, sizeof(s.gps.err), "read: Input/output error");
    tick(&s, 5000 + 3602000);
    ASSERT_EQ(src(SYS_SRC_GNSS)->state, SYS_ST_DOWN);
    ASSERT_EQ(src(SYS_SRC_GNSS)->has_reconnects, 1);
    done();
}

/* A source is tied to a receiver only where sysfs says so. */
static void test_source_ties(void) {
    TEST_STATE(s);
    fresh(&s);
    put_receivers();
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    s.mon_health.open = 1; s.mon_health.running = 1; s.mon_health.stale_secs = 0;
    snprintf(s.pkt_iface, sizeof(s.pkt_iface), "wlan0");
    s.pkt_linktype = 1;
    s.cap_health.open = 1; s.cap_health.running = 1; s.cap_health.stale_secs = 0;
    s.gps.configured = 1; s.gps.has_gps = 1; s.gps.sentences = 1;
    snprintf(s.gps.src, sizeof(s.gps.src), "nmea:/dev/ttyACM0");
    s.adsb.configured = 1; s.adsb.state = ADSB_LIVE;
    snprintf(s.adsb.src, sizeof(s.adsb.src), "beast:127.0.0.1:30005");
    jl_open();
    tick(&s, 0);
    ASSERT_STR(src(SYS_SRC_MONITOR)->hw, "usb:1-1.4");
    ASSERT_STR(src(SYS_SRC_MONITOR)->desc, "Realtek RTL8812AU 802.11ac");
    ASSERT_STR(src(SYS_SRC_MONITOR)->driver, "rtl88XXau");
    ASSERT_STR(src(SYS_SRC_CAPTURE)->hw, "net:wlan0");
    ASSERT_STR(src(SYS_SRC_CAPTURE)->kind, "wifi-managed");
    ASSERT_STR(src(SYS_SRC_GNSS)->hw, "usb:1-1.1");
    /* An RTL-SDR is attached and readsb is very likely what owns it -
     * and sloth sees a TCP endpoint, so it does not say so. Seen red
     * with fill_sources() tying adsb to the first "sdr" receiver. */
    ASSERT_STR(src(SYS_SRC_ADSB)->hw, "");
    char *b = jl_read();
    const char *l = line_of(b, "source_status", "\"name\":\"adsb\"");
    ASSERT(strstr(l, "\"hw\"") == NULL);
    ASSERT(strstr(l, "\"desc\"") == NULL);
    l = line_of(b, "source_status", "\"name\":\"monitor\"");
    ASSERT(strstr(l, "\"kind\":\"wifi-monitor\",\"flag\":\"a monitor-mode interface\","
                     "\"state\":\"ok\",\"detail\":\"\",\"endpoint\":\"wlan1mon\","
                     "\"hw\":\"usb:1-1.4\",\"desc\":\"Realtek RTL8812AU 802.11ac\","
                     "\"driver\":\"rtl88XXau\",\"age_s\":0,\"age_band\":\"fresh\","
                     "\"unit\":\"frames\",\"count\":0,\"errors\":0}") != NULL);
    /* gpsd is an endpoint too. */
    snprintf(s.gps.src, sizeof(s.gps.src), "gpsd:127.0.0.1:2947");
    tick(&s, 1000);
    ASSERT_STR(src(SYS_SRC_GNSS)->hw, "");
    done();
}

/* An interface name is operator- or kernel-supplied text that goes
 * into a path. Seen red with both name_ok() and sys_path_ok() made to
 * return 1 (the fake is then asked for a path with ".." in it). */
static void test_no_path_outside_proc_and_sys(void) {
    TEST_STATE(s);
    fresh(&s);
    put_pi();
    put_receivers();
    snprintf(s.pkt_iface, sizeof(s.pkt_iface), "a/../../../dev/x");
    tick(&s, 0);
    snprintf(s.pkt_iface, sizeof(s.pkt_iface), "..");
    tick(&s, 60000);
    ASSERT_GT(g_fake_net.sys_read_calls, 20);
    ASSERT_GT(g_fake_net.sys_list_calls, 3);
    ASSERT_EQ(g_fake_net.sys_outside_calls, 0);
    ASSERT_STR(src(SYS_SRC_CAPTURE)->kind, "ip-capture");
    done();
}

/* ── cadence ─────────────────────────────────────────────────────── */

/* One batch a minute on a steady host, and figures moving inside their
 * bands add none. Seen red with a batch marked due on every sample in
 * sys_status_poll(), and its source rows with the raw age_s in the
 * source signature. */
static void test_cadence_is_a_minute_not_a_firehose(void) {
    TEST_STATE(s);
    fresh(&s);
    put_pi();
    s.adsb.configured = 1; s.adsb.state = ADSB_LIVE;
    jl_open();
    char t[16], st[96];
    for (int sec = 0; sec <= 180; sec++) {
        /* The temperature wanders 48..52 C, CPU 10..20 %, the decoder's
         * age and count move every second. */
        snprintf(t, sizeof(t), "%d\n", 48000 + ((sec / 10) % 5) * 1000);
        fake_sys_put("/sys/class/thermal/thermal_zone0/temp", t);
        snprintf(st, sizeof(st), "cpu  %d 0 0 %d 0 0 0 0 0 0\n",
                 1000 + sec * 15 + ((sec / 10) % 2) * 20, 100000 + sec * 85);
        fake_sys_put("/proc/stat", st);
        s.adsb.age_s = sec % 3;
        s.adsb.messages = (uint64_t)sec * 40u;
        tick(&s, (uint64_t)sec * 1000u);
    }
    char *b = jl_read();
    ASSERT_EQ(count_of(b, "\"type\":\"sys_status\""), 4);        /* 0, 60, 120, 180 s */
    ASSERT_EQ(count_of(b, "\"type\":\"source_status\""), 4 * SYS_SRC_COUNT);
    /* The rate is the count over the minute between two rows. */
    const char *l = line_of(b, "source_status", "\"seq\":2,\"name\":\"adsb\"");
    ASSERT(strstr(l, "\"count\":2400,\"rate\":40.00,") != NULL);
    l = line_of(b, "source_status", "\"seq\":1,\"name\":\"adsb\"");
    ASSERT(strstr(l, "\"count\":0,") != NULL);
    ASSERT(strstr(l, "\"rate\"") == NULL);                       /* no interval yet */
    done();
}

/* A band getting worse does not wait for the minute; the under-voltage
 * alarm is the case that matters, and it is caught within one sample. */
static void test_band_change_writes_a_batch_at_once(void) {
    TEST_STATE(s);
    fresh(&s);
    put_pi();
    jl_open();
    tick(&s, 0);
    tick(&s, 10000);
    fake_sys_put("/sys/class/hwmon/hwmon1/in0_lcrit_alarm", "1\n");
    tick(&s, 15000);                     /* between samples: not read yet */
    ASSERT_EQ(sys_status_get()->seq, 1u);
    tick(&s, 20000);
    ASSERT_EQ(sys_status_get()->seq, 2u);
    ASSERT_EQ(sys_status_get()->undervolt, 1);
    /* Hot: 81 C is band 3 at once. */
    fake_sys_put("/sys/class/thermal/thermal_zone0/temp", "81000\n");
    tick(&s, 30000);
    ASSERT_EQ(sys_status_get()->seq, 3u);
    /* Cooling to 79 C is still inside the held band: no batch. */
    fake_sys_put("/sys/class/thermal/thermal_zone0/temp", "79000\n");
    tick(&s, 40000);
    ASSERT_EQ(sys_status_get()->seq, 3u);
    char *b = jl_read();
    const char *l = line_of(b, "sys_status", "\"seq\":2,");
    ASSERT(strstr(l, "\"ts\":1800000020,") != NULL);
    ASSERT(strstr(l, "\"undervolt\":1,") != NULL);
    l = line_of(b, "sys_sensor", "\"seq\":2,\"class\":\"volt\",\"id\":\"hwmon1/in0\"");
    ASSERT(strstr(l, "\"alarm\":1}") != NULL);
    l = line_of(b, "sys_status", "\"seq\":3,");
    ASSERT(strstr(l, "\"temp_max_c\":81.0,\"temp_max_id\":\"thermal_zone0\","
                     "\"temp_band\":\"critical\"") != NULL);
    done();
}

/* A recovery waits for the minute, so a value swinging across an edge
 * cannot write a batch per swing: an alarm toggling on every sample for
 * two minutes adds one batch per minute, not one per toggle. Seen red
 * (13 batches) with the trigger in sys_status_poll() taking any change
 * of band in place of a worse one. */
static void test_flapping_band_is_bounded(void) {
    TEST_STATE(s);
    fresh(&s);
    put_pi();
    jl_open();
    tick(&s, 0);
    ASSERT_EQ(sys_status_get()->seq, 1u);
    /* Clear at 0 s, then set on the odd samples, clear on the even. */
    for (int k = 1; k <= 12; k++) {
        fake_sys_put("/sys/class/hwmon/hwmon1/in0_lcrit_alarm", (k & 1) ? "1\n" : "0\n");
        tick(&s, (uint64_t)k * 10000u);
    }
    /* 10 s: set, a batch at once (2). 20..60 s: clear, set, clear, set,
     * clear - none: the recovery waits and the next "set" is no worse
     * than what was written. 70 s: the minute's batch (3), alarm set.
     * 80..120 s: nothing. */
    ASSERT_EQ(sys_status_get()->seq, 3u);
    char *b = jl_read();
    ASSERT_EQ(count_of(b, "\"type\":\"sys_status\""), 3);
    const char *l = line_of(b, "sys_status", "\"seq\":2,");
    ASSERT(strstr(l, "\"ts\":1800000010,") != NULL);
    ASSERT(strstr(l, "\"undervolt\":1,") != NULL);
    l = line_of(b, "sys_status", "\"seq\":3,");
    ASSERT(strstr(l, "\"ts\":1800000070,") != NULL);
    done();
}

/* A source's row goes out alone when its state changes, and not when
 * only its figures do. Seen red (a row every tick) with age_s hashed
 * into the source signature in place of its band. */
static void test_source_change_is_one_row(void) {
    TEST_STATE(s);
    fresh(&s);
    s.adsb.configured = 1; s.adsb.state = ADSB_LIVE; s.adsb.age_s = 0;
    s.adsb.messages = 100;
    snprintf(s.adsb.src, sizeof(s.adsb.src), "sbs:127.0.0.1:30003");
    jl_open();
    tick(&s, 0);
    for (int sec = 1; sec <= 20; sec++) {
        s.adsb.age_s = sec % 4;
        s.adsb.messages += 50;
        tick(&s, (uint64_t)sec * 1000u);
    }
    s.adsb.state = ADSB_STALE; s.adsb.age_s = 61;
    tick(&s, 21000);
    tick(&s, 22000);
    /* The decoder restarted: its count ran backwards. */
    s.adsb.state = ADSB_LIVE; s.adsb.age_s = 0; s.adsb.messages = 7;
    tick(&s, 30000);
    char *b = jl_read();
    ASSERT_EQ(count_of(b, "\"type\":\"sys_status\""), 1);
    ASSERT_EQ(count_of(b, "\"type\":\"source_status\""), SYS_SRC_COUNT + 2);
    ASSERT_EQ(count_of(b, "\"name\":\"adsb\""), 3);
    const char *l = line_of(b, "source_status", "\"state\":\"stale\"");
    ASSERT(strstr(l, "\"ts\":1800000021,\"seq\":1,\"name\":\"adsb\"") != NULL);
    ASSERT(strstr(l, "\"age_s\":61,\"age_band\":\"stale\",\"unit\":\"messages\","
                     "\"count\":1100,\"rate\":47.62,") != NULL);     /* 1000 in 21 s */
    l = line_of(b, "source_status", "\"ts\":1800000030,");
    ASSERT(strstr(l, "\"state\":\"ok\"") != NULL);
    ASSERT(strstr(l, "\"count\":7,") != NULL);
    ASSERT(strstr(l, "\"rate\"") == NULL);        /* backwards: not measured, not zero */
    done();
}

/* The filesystem the output lands on, from a real one. */
static void test_disk_of_the_output_path(void) {
    TEST_STATE(s);
    fresh(&s);
    char path[TEST_TMP_MAX + 16];
    snprintf(path, sizeof(path), "%s/sloth.db", test_tmpdir());
    sys_status_set_disk_path(path, "db");
    jl_open();
    tick(&s, 0);
    const sys_snapshot_t *sn = sys_status_get();
    ASSERT_EQ(sn->has_disk, 1);
    ASSERT_GT(sn->disk_total_mb, 0);
    ASSERT(sn->disk_free_mb >= 0 && sn->disk_free_mb <= sn->disk_total_mb);
    ASSERT_STR(sn->disk_for, "db");
    char *b = jl_read();
    ASSERT(strstr(b, "\"disk_for\":\"db\",\"disk_free_mb\":") != NULL);
    /* A path whose directory is not there: absent. */
    sys_status_reset();
    sys_status_set_disk_path("/nonexistent-sloth-dir/x.db", "db");
    tick(&s, 0);
    ASSERT_EQ(sys_status_get()->has_disk, 0);
    done();
}

/* The poll table runs both hooks: a real tick writes a batch, and
 * sensor_health is still the last record of it. */
static void test_poll_tick_writes_the_batch(void) {
    TEST_STATE(s);
    fresh(&s);
    put_pi();
    jl_open();
    poll_ctx_t ctx;
    clock_at(0);
    poll_ctx_init(&ctx);
    poll_tick(&s, &ctx);
    char *b = jl_read();
    ASSERT_EQ(count_of(b, "\"type\":\"sys_status\""), 1);
    ASSERT_EQ(count_of(b, "\"type\":\"source_status\""), SYS_SRC_COUNT);
    const char *ss = strstr(b, "\"type\":\"sys_status\"");
    const char *sh = strstr(b, "\"type\":\"sensor_health\"");
    ASSERT(ss != NULL && sh != NULL && ss < sh);
    if (sh) ASSERT(strstr(sh, "\n{") == NULL);
    ASSERT(poll_stage_index("health") >= 0);
    done();
}

/* The contract page names the four records. */
static void test_schema_doc_names_the_records(void) {
    FILE *fp = fopen("docs/wiki/jsonl-schema.md", "r");
    ASSERT(fp != NULL);
    if (!fp) return;
    static char doc[400000];
    size_t n = fread(doc, 1, sizeof(doc) - 1, fp);
    doc[n] = '\0';
    fclose(fp);
    ASSERT(strstr(doc, "### `sys_status`") != NULL);
    ASSERT(strstr(doc, "### `sys_sensor`") != NULL);
    ASSERT(strstr(doc, "### `source_status`") != NULL);
    ASSERT(strstr(doc, "### `receiver_hw`") != NULL);
}

void run_sys_status_tests(void) {
    TEST_SUITE("sys_status (host status, sources, receivers)");
    RUN_TEST(test_parse_cpu);
    RUN_TEST(test_cpu_delta);
    RUN_TEST(test_parse_loadavg);
    RUN_TEST(test_parse_meminfo);
    RUN_TEST(test_parse_uptime_and_int);
    RUN_TEST(test_clean_str_uevent_hex);
    RUN_TEST(test_bands);
    RUN_TEST(test_usb_table);
    RUN_TEST(test_path_guard);
    RUN_TEST(test_real_readers_take_regular_files_only);
    RUN_TEST(test_bare_host_reports_nothing_as_zero);
    RUN_TEST(test_null_ops_are_a_bare_host);
    RUN_TEST(test_pi_sample_and_records);
    RUN_TEST(test_hostile_sensor_text_is_absent);
    RUN_TEST(test_power_supply);
    RUN_TEST(test_receiver_inventory);
    RUN_TEST(test_receiver_name_is_the_tables_whole);
    RUN_TEST(test_parsers_under_generated_text);
    RUN_TEST(test_class_rows_merge_by_device);
    RUN_TEST(test_hostile_device_strings);
    RUN_TEST(test_source_states);
    RUN_TEST(test_source_age_from_count);
    RUN_TEST(test_source_ties);
    RUN_TEST(test_no_path_outside_proc_and_sys);
    RUN_TEST(test_cadence_is_a_minute_not_a_firehose);
    RUN_TEST(test_band_change_writes_a_batch_at_once);
    RUN_TEST(test_flapping_band_is_bounded);
    RUN_TEST(test_source_change_is_one_row);
    RUN_TEST(test_disk_of_the_output_path);
    RUN_TEST(test_poll_tick_writes_the_batch);
    RUN_TEST(test_schema_doc_names_the_records);
}
