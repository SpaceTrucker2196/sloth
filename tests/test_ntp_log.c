#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "ntp_log.h"
#include "views/ntp.h"

/* Hand-crafted NTP datagrams (48-byte header).
 *
 * Byte 0: LI (2 bits) | Version (3 bits) | Mode (3 bits)
 *   LI=0, V=4, Mode=3 (client) -> 0b00 100 011 = 0x23
 *   LI=0, V=4, Mode=4 (server) -> 0b00 100 100 = 0x24
 * Byte 1:  Stratum
 * Byte 2:  Poll
 * Byte 3:  Precision (signed)
 * Bytes 4..7:   Root Delay
 * Bytes 8..11:  Root Dispersion
 * Bytes 12..15: Reference ID
 * Bytes 16..47: Timestamps (zeroed for tests)
 */

static void build_ntp(uint8_t *buf, int flags, uint8_t stratum,
                       const uint8_t *ref4) {
    memset(buf, 0, 48);
    buf[0] = (uint8_t)flags;
    buf[1] = stratum;
    buf[2] = 6;       /* poll */
    buf[3] = (uint8_t)(-23);  /* precision = -23 → ~119ns */
    memcpy(buf + 12, ref4, 4);
}

/* ── parse tests ─────────────────────────────────────────── */

static void test_parse_client_v4(void) {
    uint8_t pkt[48];
    /* V=4, Mode=3 (client) */
    build_ntp(pkt, 0x23, 0, (const uint8_t *)"\0\0\0\0");

    ntp_log_entry_t e;
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "192.168.1.5", "pool.ntp.org", &e));
    ASSERT_EQ((int)e.version, 4);
    ASSERT_STR(e.mode, "client");
    ASSERT_EQ((int)e.stratum, 0);
    ASSERT_STR(e.src, "192.168.1.5");
    ASSERT_STR(e.dst, "pool.ntp.org");
}

static void test_parse_server_stratum1_ref(void) {
    uint8_t pkt[48];
    /* V=4, Mode=4 (server), stratum=1, ref = "GPS\0" */
    build_ntp(pkt, 0x24, 1, (const uint8_t *)"GPS");

    ntp_log_entry_t e;
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "10.0.0.1", "192.168.1.5", &e));
    ASSERT_STR(e.mode, "server");
    ASSERT_EQ((int)e.stratum, 1);
    ASSERT_STR(e.ref, "GPS");
}

static void test_parse_server_stratum3_ref_is_ip(void) {
    uint8_t pkt[48];
    uint8_t ref[4] = { 17, 253, 14, 251 };  /* time.apple.com */
    build_ntp(pkt, 0x24, 3, ref);

    ntp_log_entry_t e;
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "1.1.1.1", "1.2.3.4", &e));
    ASSERT_STR(e.mode, "server");
    ASSERT_EQ((int)e.stratum, 3);
    ASSERT_STR(e.ref, "17.253.14.251");
}

static void test_parse_version_3(void) {
    uint8_t pkt[48];
    /* V=3, Mode=3 (client) -> 0b00 011 011 = 0x1b */
    build_ntp(pkt, 0x1b, 2, (const uint8_t *)"\1\2\3\4");

    ntp_log_entry_t e;
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "10.0.0.5", "10.0.0.1", &e));
    ASSERT_EQ((int)e.version, 3);
    ASSERT_STR(e.mode, "client");
    ASSERT_STR(e.ref, "1.2.3.4");
}

static void test_parse_sym_active(void) {
    uint8_t pkt[48];
    /* V=4, Mode=1 (symmetric active) -> 0b00 100 001 = 0x21 */
    build_ntp(pkt, 0x21, 2, (const uint8_t *)"\0\0\0\0");
    ntp_log_entry_t e;
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "a", "b", &e));
    ASSERT_STR(e.mode, "sym-act");
}

static void test_parse_rejects_short(void) {
    uint8_t pkt[20] = {0};
    pkt[0] = 0x23;
    ntp_log_entry_t e;
    ASSERT(!ntp_log_parse(pkt, sizeof(pkt), "a", "b", &e));
}

static void test_parse_rejects_bad_version(void) {
    uint8_t pkt[48] = {0};
    /* V=0, Mode=3 -> 0b00 000 011 = 0x03 */
    pkt[0] = 0x03;
    ntp_log_entry_t e;
    ASSERT(!ntp_log_parse(pkt, sizeof(pkt), "a", "b", &e));
}

static void test_parse_null_ips_ok(void) {
    uint8_t pkt[48];
    build_ntp(pkt, 0x24, 1, (const uint8_t *)"PPS");
    ntp_log_entry_t e;
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), NULL, NULL, &e));
    ASSERT_EQ((int)e.src[0], 0);
    ASSERT_EQ((int)e.dst[0], 0);
    ASSERT_STR(e.ref, "PPS");
}

static void test_parse_unspec_stratum(void) {
    uint8_t pkt[48];
    /* V=4, Mode=4 (server), stratum=16 (unsync) */
    build_ntp(pkt, 0x24, 16, (const uint8_t *)"INIT");
    ntp_log_entry_t e;
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "a", "b", &e));
    ASSERT_EQ((int)e.stratum, 16);
    ASSERT_STR(e.ref, "INIT");
}

/* ── ring buffer tests ───────────────────────────────────── */

static void test_record_and_snapshot(void) {
    ntp_log_clear();

    uint8_t pkt[48];
    for (int i = 0; i < 3; i++) {
        build_ntp(pkt, 0x24, (uint8_t)(i + 1), (const uint8_t *)"GPS");
        ntp_log_entry_t e;
        ASSERT(ntp_log_parse(pkt, sizeof(pkt), "10.0.0.1", "192.168.1.5", &e));
        ntp_log_record(&e);
    }

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ntp_log_snapshot(&s);
    ASSERT_EQ(s.ntp_log_count, 3);
}

static void test_snapshot_newest_first(void) {
    ntp_log_clear();

    uint8_t pkt[48];
    /* push three with stratums 1, 5, 9 */
    uint8_t strata[3] = { 1, 5, 9 };
    for (int i = 0; i < 3; i++) {
        build_ntp(pkt, 0x24, strata[i], (const uint8_t *)"GPS");
        ntp_log_entry_t e;
        ASSERT(ntp_log_parse(pkt, sizeof(pkt), "a", "b", &e));
        ntp_log_record(&e);
    }

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ntp_log_snapshot(&s);
    ASSERT_EQ(s.ntp_log_count, 3);
    ASSERT_EQ((int)s.ntp_log[0].stratum, 9);  /* newest */
    ASSERT_EQ((int)s.ntp_log[2].stratum, 1);  /* oldest */
}

static void test_clear_empties(void) {
    ntp_log_clear();
    uint8_t pkt[48];
    build_ntp(pkt, 0x23, 1, (const uint8_t *)"GPS");
    ntp_log_entry_t e;
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "a", "b", &e));
    ntp_log_record(&e);

    ntp_log_clear();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ntp_log_snapshot(&s);
    ASSERT_EQ(s.ntp_log_count, 0);
}

/* ── view tests ──────────────────────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_ntp_draw(&s);
    ASSERT(1);
}

static void test_view_draw_populated(void) {
    ntp_log_clear();
    uint8_t pkt[48];

    /* a client query (stratum 0), a stratum-1 server with GPS,
       a stratum-3 server */
    build_ntp(pkt, 0x23, 0, (const uint8_t *)"\0\0\0\0");
    ntp_log_entry_t e;
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "192.168.1.5", "pool.ntp.org", &e));
    ntp_log_record(&e);

    build_ntp(pkt, 0x24, 1, (const uint8_t *)"GPS");
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "10.0.0.1", "192.168.1.5", &e));
    ntp_log_record(&e);

    uint8_t ip[4] = { 17, 253, 14, 251 };
    build_ntp(pkt, 0x24, 3, ip);
    ASSERT(ntp_log_parse(pkt, sizeof(pkt), "1.2.3.4", "192.168.1.5", &e));
    ntp_log_record(&e);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ntp_log_snapshot(&s);
    ASSERT_EQ(s.ntp_log_count, 3);
    view_ntp_draw(&s);
}

static void test_view_key_nav_and_clear(void) {
    ntp_log_clear();
    uint8_t pkt[48];
    for (int i = 0; i < 3; i++) {
        build_ntp(pkt, 0x24, (uint8_t)(i + 1), (const uint8_t *)"GPS");
        ntp_log_entry_t e;
        ASSERT(ntp_log_parse(pkt, sizeof(pkt), "a", "b", &e));
        ntp_log_record(&e);
    }

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ntp_log_snapshot(&s);
    ASSERT_EQ(s.ntp_log_sel, 0);
    view_ntp_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.ntp_log_sel, 1);
    view_ntp_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.ntp_log_sel, 0);

    view_ntp_key(&s, 'c');
    ASSERT_EQ(s.ntp_log_count, 0);
    ASSERT_EQ(s.ntp_log_sel, 0);

    /* underlying ring is also cleared */
    sloth_state_t s2;
    memset(&s2, 0, sizeof(s2));
    ntp_log_snapshot(&s2);
    ASSERT_EQ(s2.ntp_log_count, 0);
}

void run_ntp_log_tests(void) {
    TEST_SUITE("ntp_log parse");
    RUN_TEST(test_parse_client_v4);
    RUN_TEST(test_parse_server_stratum1_ref);
    RUN_TEST(test_parse_server_stratum3_ref_is_ip);
    RUN_TEST(test_parse_version_3);
    RUN_TEST(test_parse_sym_active);
    RUN_TEST(test_parse_rejects_short);
    RUN_TEST(test_parse_rejects_bad_version);
    RUN_TEST(test_parse_null_ips_ok);
    RUN_TEST(test_parse_unspec_stratum);

    TEST_SUITE("ntp_log ring buffer");
    RUN_TEST(test_record_and_snapshot);
    RUN_TEST(test_snapshot_newest_first);
    RUN_TEST(test_clear_empties);

    TEST_SUITE("view_ntp draw");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);

    TEST_SUITE("view_ntp key");
    RUN_TEST(test_view_key_nav_and_clear);
}
