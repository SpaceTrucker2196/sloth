#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "quic_log.h"
#include "views/quic.h"

/* Minimal QUIC Long Header Initial builder (same as test_quic_snoop.c). */
static int make_quic_initial(uint32_t version, uint8_t type_bits,
                              uint8_t dcil, uint8_t *buf, int bufsz) {
    int need = 6 + (int)dcil + 1;
    if (bufsz < need + 1) return 0;
    buf[0] = (uint8_t)(0xC0 | type_bits | 0x03);
    buf[1] = (uint8_t)(version >> 24);
    buf[2] = (uint8_t)(version >> 16);
    buf[3] = (uint8_t)(version >>  8);
    buf[4] = (uint8_t)(version);
    buf[5] = dcil;
    for (int i = 0; i < (int)dcil; i++) buf[6 + i] = (uint8_t)(0xAA + i);
    buf[6 + dcil] = 0x00;
    return need;
}

/* ── quic_log_parse tests ────────────────────────────────── */

static void test_parse_v1(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x00, 8, buf, sizeof(buf));
    quic_log_entry_t e;
    int r = quic_log_parse(buf, len, "192.168.1.5", "142.250.80.46", NULL, &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.ver,  "v1");
    ASSERT_STR(e.src,  "192.168.1.5");
    ASSERT_STR(e.dst,  "142.250.80.46");
    ASSERT_EQ((int)e.host[0], 0);   /* no host provided */
}

static void test_parse_v1_with_host(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x00, 4, buf, sizeof(buf));
    quic_log_entry_t e;
    int r = quic_log_parse(buf, len, "10.0.0.1", "8.8.8.8", "dns.google", &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.ver,  "v1");
    ASSERT_STR(e.host, "dns.google");
}

static void test_parse_v2(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0x6b3343cfu, 0x10, 8, buf, sizeof(buf));
    quic_log_entry_t e;
    ASSERT_EQ(quic_log_parse(buf, len, "1.2.3.4", "5.6.7.8", NULL, &e), 1);
    ASSERT_STR(e.ver, "v2");
}

static void test_parse_draft(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0xff00001du, 0x00, 4, buf, sizeof(buf));
    quic_log_entry_t e;
    ASSERT_EQ(quic_log_parse(buf, len, "1.1.1.1", "2.2.2.2", NULL, &e), 1);
    ASSERT_STR(e.ver, "draft");
}

static void test_parse_rejects_non_quic(void) {
    /* TLS record — not QUIC */
    uint8_t buf[] = {0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01};
    quic_log_entry_t e;
    ASSERT_EQ(quic_log_parse(buf, (int)sizeof(buf), "1.2.3.4", "5.6.7.8", NULL, &e), 0);
}

static void test_parse_rejects_short(void) {
    uint8_t buf[4] = {0xC3, 0x00, 0x00, 0x01};
    quic_log_entry_t e;
    ASSERT_EQ(quic_log_parse(buf, 4, "1.2.3.4", "5.6.7.8", NULL, &e), 0);
}

static void test_parse_null_ips_ok(void) {
    uint8_t buf[32];
    int len = make_quic_initial(0x00000001u, 0x00, 8, buf, sizeof(buf));
    quic_log_entry_t e;
    ASSERT_EQ(quic_log_parse(buf, len, NULL, NULL, NULL, &e), 1);
    ASSERT_EQ((int)e.src[0], 0);
    ASSERT_EQ((int)e.dst[0], 0);
}

/* ── ring buffer tests ───────────────────────────────────── */

static quic_log_entry_t make_entry(const char *src, const char *dst,
                                   const char *host, const char *ver)
{
    quic_log_entry_t e;
    memset(&e, 0, sizeof(e));
    if (src)  snprintf(e.src,  sizeof(e.src),  "%s", src);
    if (dst)  snprintf(e.dst,  sizeof(e.dst),  "%s", dst);
    if (host) snprintf(e.host, sizeof(e.host), "%s", host);
    if (ver)  snprintf(e.ver,  sizeof(e.ver),  "%s", ver);
    e.ts = 1000;
    return e;
}

static void test_record_and_snapshot(void) {
    quic_log_clear();
    quic_log_entry_t e = make_entry("10.0.0.1", "142.250.80.46", "google.com", "v1");
    quic_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    quic_log_snapshot(&s);

    ASSERT_EQ(s.quic_log_count, 1);
    ASSERT_STR(s.quic_log[0].host, "google.com");
    ASSERT_STR(s.quic_log[0].ver,  "v1");
}

static void test_snapshot_newest_first(void) {
    quic_log_clear();
    quic_log_entry_t a = make_entry("1.1.1.1", "8.8.8.8",       "first.com",  "v1");
    quic_log_entry_t b = make_entry("1.1.1.2", "1.1.1.1",       "second.com", "v2");
    quic_log_record(&a);
    quic_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    quic_log_snapshot(&s);

    ASSERT_EQ(s.quic_log_count, 2);
    ASSERT_STR(s.quic_log[0].host, "second.com");
    ASSERT_STR(s.quic_log[1].host, "first.com");
}

static void test_clear_empties_log(void) {
    quic_log_entry_t e = make_entry("1.1.1.1", "2.2.2.2", "x.com", "v1");
    quic_log_record(&e);
    quic_log_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    quic_log_snapshot(&s);
    ASSERT_EQ(s.quic_log_count, 0);
}

static void test_snapshot_clamps_sel(void) {
    quic_log_clear();
    quic_log_entry_t e = make_entry("1.1.1.1", "2.2.2.2", "a.com", "v1");
    quic_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.quic_log_sel = 99;
    quic_log_snapshot(&s);
    ASSERT_EQ(s.quic_log_sel, 0);
}

/* Boundary at sel == n (kills `>=` → `>`) and empty-log (kills
 * `n > 0` → `n >= 0`, which would set sel to -1). */
static void test_snapshot_clamps_sel_at_boundary_and_empty(void) {
    quic_log_clear();
    quic_log_entry_t e = make_entry("1.1.1.1", "2.2.2.2", "a.com", "v1");
    quic_log_record(&e);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.quic_log_sel = 1;            /* sel == n exactly */
    quic_log_snapshot(&s);
    ASSERT_EQ(s.quic_log_sel, 0);

    /* Empty log: sel must reset to 0, not -1. */
    quic_log_clear();
    memset(&s, 0, sizeof(s));
    s.quic_log_sel = 5;
    quic_log_snapshot(&s);
    ASSERT_EQ(s.quic_log_sel, 0);
}

/* ── view_quic_draw smoke tests ──────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_quic_draw(&s);
    ASSERT(1);
}

static void test_view_draw_populated(void) {
    quic_log_clear();
    quic_log_entry_t e1 = make_entry("192.168.1.5",  "142.250.80.46", "google.com",   "v1");
    quic_log_entry_t e2 = make_entry("192.168.1.10", "31.13.71.36",   "facebook.com", "v2");
    quic_log_entry_t e3 = make_entry("192.168.1.5",  "151.101.1.140", "",             "draft");
    quic_log_record(&e1);
    quic_log_record(&e2);
    quic_log_record(&e3);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    quic_log_snapshot(&s);
    view_quic_draw(&s);
    ASSERT(1);
}

/* ── view_quic_key tests ─────────────────────────────────── */

static void test_view_key_nav(void) {
    quic_log_clear();
    quic_log_entry_t a = make_entry("1.1.1.1", "2.2.2.2", "a.com", "v1");
    quic_log_entry_t b = make_entry("1.1.1.2", "2.2.2.2", "b.com", "v1");
    quic_log_record(&a);
    quic_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    quic_log_snapshot(&s);
    s.quic_log_sel = 0;

    view_quic_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.quic_log_sel, 1);

    view_quic_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.quic_log_sel, 1);   /* clamped */

    view_quic_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.quic_log_sel, 0);

    view_quic_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.quic_log_sel, 0);   /* clamped */
}

static void test_view_key_clear(void) {
    quic_log_clear();
    quic_log_entry_t e = make_entry("1.1.1.1", "2.2.2.2", "x.com", "v1");
    quic_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    quic_log_snapshot(&s);
    ASSERT_EQ(s.quic_log_count, 1);

    view_quic_key(&s, 'c');
    ASSERT_EQ(s.quic_log_count, 0);
    ASSERT_EQ(s.quic_log_sel,   0);
}

/* ── Suite entry point ───────────────────────────────────── */

void run_quic_log_tests(void) {
    TEST_SUITE("quic_log parse");
    RUN_TEST(test_parse_v1);
    RUN_TEST(test_parse_v1_with_host);
    RUN_TEST(test_parse_v2);
    RUN_TEST(test_parse_draft);
    RUN_TEST(test_parse_rejects_non_quic);
    RUN_TEST(test_parse_rejects_short);
    RUN_TEST(test_parse_null_ips_ok);

    TEST_SUITE("quic_log ring buffer");
    RUN_TEST(test_record_and_snapshot);
    RUN_TEST(test_snapshot_newest_first);
    RUN_TEST(test_clear_empties_log);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_snapshot_clamps_sel_at_boundary_and_empty);

    TEST_SUITE("view_quic draw");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);

    TEST_SUITE("view_quic key");
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
}
