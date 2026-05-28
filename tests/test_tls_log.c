#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "tls_log.h"
#include "views/tls.h"

/* ── Hand-crafted TLS ClientHello frames ─────────────────────
   TLS record:   16 03 01 <rec_len:2>
   Handshake:    01 <ch_len:3>
   ClientHello:  <legacy_version:2> <random:32> <sid_len:1>
                 <cs_len:2> <cs:2> <cm_len:1> <cm:1>
                 <ext_len:2> [extensions...]
   ──────────────────────────────────────────────────────────── */

/*
 * TLS 1.3 ClientHello with SNI "example.com" (79 bytes)
 * Contains: SNI ext (0x0000) + supported_versions ext (0x002b = TLS 1.3)
 */
static const uint8_t tls13_sni[] = {
    /* TLS record header */
    0x16, 0x03, 0x01, 0x00, 0x4a,   /* type=handshake, ver=3.1, len=74 */
    /* Handshake header */
    0x01, 0x00, 0x00, 0x46,         /* ClientHello, ch_len=70 */
    /* ClientHello */
    0x03, 0x03,                     /* legacy_version = TLS 1.2 */
    /* random (32 bytes) */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0x00,                           /* session_id_len = 0 */
    0x00, 0x02,                     /* cipher_suites_len = 2 */
    0x00, 0x2f,                     /* TLS_RSA_WITH_AES_128_CBC_SHA */
    0x01,                           /* compression_methods_len = 1 */
    0x00,                           /* no compression */
    0x00, 0x1b,                     /* extensions_len = 27 */
    /* SNI extension (type=0x0000, len=16) */
    0x00, 0x00, 0x00, 0x10,
    0x00, 0x0e,                     /* list_len = 14 */
    0x00,                           /* name_type = host_name */
    0x00, 0x0b,                     /* name_len = 11 */
    'e','x','a','m','p','l','e','.','c','o','m',
    /* supported_versions extension (type=0x002b, len=3) */
    0x00, 0x2b, 0x00, 0x03,
    0x02,                           /* versions_list_len = 2 */
    0x03, 0x04,                     /* TLS 1.3 */
};

/*
 * TLS 1.2 ClientHello, no SNI, no supported_versions (52 bytes)
 * uses legacy_version 0x0303 → "TLS 1.2"
 */
static const uint8_t tls12_nosni[] = {
    0x16, 0x03, 0x01, 0x00, 0x2f,
    0x01, 0x00, 0x00, 0x2b,
    0x03, 0x03,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    0x00, 0x00,                     /* extensions_len = 0 */
};

/*
 * TLS 1.1 ClientHello, legacy_version 0x0302 (52 bytes)
 */
static const uint8_t tls11_legacy[] = {
    0x16, 0x03, 0x01, 0x00, 0x2f,
    0x01, 0x00, 0x00, 0x2b,
    0x03, 0x02,                     /* legacy_version = TLS 1.1 */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    0x00, 0x00,
};

/* ── tls_log_parse tests ─────────────────────────────────── */

static void test_parse_tls13_sni(void) {
    tls_log_entry_t e;
    int r = tls_log_parse(tls13_sni, (int)sizeof(tls13_sni),
                          "192.168.1.5", "93.184.216.34", &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.tls_ver, "TLS 1.3");
    ASSERT_STR(e.host,    "example.com");
    ASSERT_STR(e.src,     "192.168.1.5");
    ASSERT_STR(e.dst,     "93.184.216.34");
}

static void test_parse_tls12_nosni(void) {
    tls_log_entry_t e;
    int r = tls_log_parse(tls12_nosni, (int)sizeof(tls12_nosni),
                          "10.0.0.1", "8.8.8.8", &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.tls_ver, "TLS 1.2");
    ASSERT_EQ((int)e.host[0], 0);   /* no SNI */
}

static void test_parse_tls11_legacy(void) {
    tls_log_entry_t e;
    int r = tls_log_parse(tls11_legacy, (int)sizeof(tls11_legacy),
                          "10.0.0.2", "10.0.0.1", &e);
    ASSERT_EQ(r, 1);
    ASSERT_STR(e.tls_ver, "TLS 1.1");
}

static void test_parse_rejects_wrong_type(void) {
    /* record type 0x17 (application data), not handshake */
    uint8_t buf[sizeof(tls12_nosni)];
    memcpy(buf, tls12_nosni, sizeof(buf));
    buf[0] = 0x17;
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(buf, (int)sizeof(buf), "1.2.3.4", "5.6.7.8", &e), 0);
}

static void test_parse_rejects_server_hello(void) {
    /* handshake type 0x02 (ServerHello), not ClientHello */
    uint8_t buf[sizeof(tls12_nosni)];
    memcpy(buf, tls12_nosni, sizeof(buf));
    buf[5] = 0x02;
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(buf, (int)sizeof(buf), "1.2.3.4", "5.6.7.8", &e), 0);
}

static void test_parse_rejects_short(void) {
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(tls12_nosni, 8, "1.2.3.4", "5.6.7.8", &e), 0);
}

static void test_parse_rejects_truncated(void) {
    /* partial frame — len in header says 74 but data is only 20 bytes */
    tls_log_entry_t e;
    ASSERT_EQ(tls_log_parse(tls13_sni, 20, "1.2.3.4", "5.6.7.8", &e), 0);
}

static void test_parse_null_ips_ok(void) {
    /* NULL IPs should not crash */
    tls_log_entry_t e;
    int r = tls_log_parse(tls12_nosni, (int)sizeof(tls12_nosni), NULL, NULL, &e);
    ASSERT_EQ(r, 1);
    ASSERT_EQ((int)e.src[0], 0);
    ASSERT_EQ((int)e.dst[0], 0);
}

/* ── JA3 fingerprint tests ───────────────────────────────── */

/* A ClientHello with cipher 0x003c, ext SNI + supported_versions, supported
 * groups [0x001d, 0x0017], and ec_point_formats [0x00]. Exercises all five
 * JA3 sections.
 *
 * Length fields:
 *   extensions body: 4 (SNI) + 10 (groups) + 6 (formats) + 7 (versions) = 27 = 0x1b
 *   ch body: 2+32+1+2+2+1+1+2+27 = 70 = 0x46
 *   rec body: 4 (hs hdr) + 70 = 74 = 0x4a
 */
static const uint8_t ja3_clienthello[] = {
    /* TLS record */
    0x16, 0x03, 0x01, 0x00, 0x4a,
    /* Handshake */
    0x01, 0x00, 0x00, 0x46,
    /* legacy_version = TLS 1.2 */
    0x03, 0x03,
    /* random */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* session_id_len */
    0x00,
    /* cipher_suites len + entry 0x003c */
    0x00, 0x02, 0x00, 0x3c,
    /* compression_methods */
    0x01, 0x00,
    /* extensions_len = 27 */
    0x00, 0x1b,
    /* SNI ext (type 0x0000, len 0) */
    0x00, 0x00, 0x00, 0x00,
    /* supported_groups (0x000a) — list_len(2)=4 + two uint16 */
    0x00, 0x0a, 0x00, 0x06,
    0x00, 0x04,
    0x00, 0x1d, 0x00, 0x17,
    /* ec_point_formats (0x000b) — fmt_list_len(1)=1 + one byte */
    0x00, 0x0b, 0x00, 0x02,
    0x01,
    0x00,
    /* supported_versions (0x002b) — list_len(1)=2 + TLS1.3 */
    0x00, 0x2b, 0x00, 0x03,
    0x02,
    0x03, 0x04,
};

static void test_parse_emits_ja3(void) {
    tls_log_entry_t e;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "1.1.1.1", "2.2.2.2", &e));
    /* JA3 is the lowercase-hex MD5 — exactly 32 characters. */
    ASSERT_EQ((int)strlen(e.ja3), 32);
    for (int i = 0; i < 32; i++) {
        char c = e.ja3[i];
        int ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        ASSERT(ok);
    }
}

static void test_ja3_is_deterministic(void) {
    tls_log_entry_t a, b;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "x", "y", &a));
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "p", "q", &b));
    ASSERT_STR(a.ja3, b.ja3);
}

static void test_ja3_differs_for_different_ciphers(void) {
    /* Same as ja3_clienthello but cipher_suite changed from 0x003c → 0x0035. */
    uint8_t alt[sizeof(ja3_clienthello)];
    memcpy(alt, ja3_clienthello, sizeof(alt));
    /* offset of cipher_suite bytes inside the buffer: 5 (record) +
       4 (handshake) + 2 (legacy_version) + 32 (random) + 1 (sid_len) +
       2 (cipher_suites_len) = 46, then the suite itself spans 46..47. */
    alt[46] = 0x00;
    alt[47] = 0x35;

    tls_log_entry_t e1, e2;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "x", "y", &e1));
    ASSERT(tls_log_parse(alt, (int)sizeof(alt), "x", "y", &e2));
    ASSERT(strcmp(e1.ja3, e2.ja3) != 0);
}

static void test_ja3_skips_grease(void) {
    /* Insert GREASE cipher 0x0a0a alongside 0x003c. Since GREASE is filtered,
     * JA3 should equal that of the cipher-only ja3_clienthello. */
    uint8_t with_grease[sizeof(ja3_clienthello) + 2];
    /* Splice in: bump cipher_suites_len from 2 → 4 and prepend 0a 0a. */
    int prefix = 5 + 4 + 2 + 32 + 1;  /* up to and including sid_len */
    memcpy(with_grease, ja3_clienthello, prefix);
    /* cipher_suites_len */
    with_grease[prefix + 0] = 0x00;
    with_grease[prefix + 1] = 0x04;
    /* the two cipher entries: 0a 0a (GREASE) then 00 3c */
    with_grease[prefix + 2] = 0x0a;
    with_grease[prefix + 3] = 0x0a;
    with_grease[prefix + 4] = 0x00;
    with_grease[prefix + 5] = 0x3c;
    /* rest of the buffer follows. Source offset is prefix+4 (we kept
       cipher_suites_len of size 2 + cipher of size 2 = 4 bytes there). */
    int rest_src = prefix + 4;
    int rest_dst = prefix + 6;
    int rest_len = (int)sizeof(ja3_clienthello) - rest_src;
    memcpy(with_grease + rest_dst, ja3_clienthello + rest_src, (size_t)rest_len);

    /* Fix up the lengths: TLS record length +2, handshake length +2. */
    int new_rec_len = (with_grease[3] << 8 | with_grease[4]) + 2;
    with_grease[3] = (uint8_t)(new_rec_len >> 8);
    with_grease[4] = (uint8_t)(new_rec_len & 0xff);
    int new_ch_len = ((with_grease[6] << 16) | (with_grease[7] << 8) | with_grease[8]) + 2;
    with_grease[6] = (uint8_t)((new_ch_len >> 16) & 0xff);
    with_grease[7] = (uint8_t)((new_ch_len >>  8) & 0xff);
    with_grease[8] = (uint8_t)( new_ch_len        & 0xff);

    tls_log_entry_t base, greased;
    ASSERT(tls_log_parse(ja3_clienthello, (int)sizeof(ja3_clienthello),
                         "x", "y", &base));
    ASSERT(tls_log_parse(with_grease, (int)sizeof(with_grease),
                         "x", "y", &greased));
    ASSERT_STR(base.ja3, greased.ja3);
}

/* ── tls_log_record / tls_log_snapshot tests ─────────────── */

static tls_log_entry_t make_tls_entry(const char *src, const char *dst,
                                      const char *host, const char *ver)
{
    tls_log_entry_t e;
    memset(&e, 0, sizeof(e));
    if (src) strncpy(e.src,     src,  sizeof(e.src)     - 1);
    if (dst) strncpy(e.dst,     dst,  sizeof(e.dst)     - 1);
    if (host)strncpy(e.host,    host, sizeof(e.host)    - 1);
    if (ver) strncpy(e.tls_ver, ver,  sizeof(e.tls_ver) - 1);
    e.ts = 1000;
    return e;
}

static void test_record_and_snapshot(void) {
    tls_log_clear();
    tls_log_entry_t e = make_tls_entry("192.168.1.5", "93.184.216.34",
                                       "example.com", "TLS 1.3");
    tls_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);

    ASSERT_EQ(s.tls_log_count, 1);
    ASSERT_STR(s.tls_log[0].host,    "example.com");
    ASSERT_STR(s.tls_log[0].tls_ver, "TLS 1.3");
}

static void test_snapshot_newest_first(void) {
    tls_log_clear();
    tls_log_entry_t a = make_tls_entry("1.1.1.1", "8.8.8.8", "first.com",  "TLS 1.2");
    tls_log_entry_t b = make_tls_entry("1.1.1.2", "8.8.8.8", "second.com", "TLS 1.3");
    tls_log_record(&a);
    tls_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);

    ASSERT_EQ(s.tls_log_count, 2);
    ASSERT_STR(s.tls_log[0].host, "second.com");   /* newest first */
    ASSERT_STR(s.tls_log[1].host, "first.com");
}

static void test_clear_empties_log(void) {
    tls_log_entry_t e = make_tls_entry("1.1.1.1", "2.2.2.2", "x.com", "TLS 1.2");
    tls_log_record(&e);
    tls_log_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_count, 0);
}

static void test_snapshot_clamps_sel(void) {
    tls_log_clear();
    tls_log_entry_t e = make_tls_entry("1.1.1.1", "2.2.2.2", "a.com", "TLS 1.2");
    tls_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.tls_log_sel = 99;
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_sel, 0);
}

/* Boundary at sel == n + empty-log clamp tests. */
static void test_snapshot_clamps_sel_at_boundary_and_empty(void) {
    tls_log_clear();
    tls_log_entry_t e = make_tls_entry("1.1.1.1", "2.2.2.2", "a.com", "TLS 1.2");
    tls_log_record(&e);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.tls_log_sel = 1;
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_sel, 0);

    tls_log_clear();
    memset(&s, 0, sizeof(s));
    s.tls_log_sel = 5;
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_sel, 0);
}

/* ── view_tls_draw smoke tests ───────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_tls_draw(&s);
    ASSERT(1);
}

static void test_view_draw_populated(void) {
    tls_log_clear();
    tls_log_entry_t e1 = make_tls_entry("192.168.1.5",  "93.184.216.34", "example.com",  "TLS 1.3");
    tls_log_entry_t e2 = make_tls_entry("192.168.1.10", "142.250.80.46", "google.com",   "TLS 1.2");
    tls_log_record(&e1);
    tls_log_record(&e2);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);
    view_tls_draw(&s);
    ASSERT(1);
}

/* ── view_tls_key tests ──────────────────────────────────── */

static void test_view_key_nav(void) {
    tls_log_clear();
    tls_log_entry_t a = make_tls_entry("1.1.1.1", "2.2.2.2", "a.com", "TLS 1.3");
    tls_log_entry_t b = make_tls_entry("1.1.1.2", "2.2.2.2", "b.com", "TLS 1.2");
    tls_log_record(&a);
    tls_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);
    s.tls_log_sel = 0;

    view_tls_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.tls_log_sel, 1);

    view_tls_key(&s, SLOTH_KEY_DOWN);  /* at end */
    ASSERT_EQ(s.tls_log_sel, 1);

    view_tls_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.tls_log_sel, 0);

    view_tls_key(&s, SLOTH_KEY_UP);    /* at top */
    ASSERT_EQ(s.tls_log_sel, 0);
}

static void test_view_key_clear(void) {
    tls_log_clear();
    tls_log_entry_t e = make_tls_entry("1.1.1.1", "2.2.2.2", "x.com", "TLS 1.3");
    tls_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    tls_log_snapshot(&s);
    ASSERT_EQ(s.tls_log_count, 1);

    view_tls_key(&s, 'c');
    ASSERT_EQ(s.tls_log_count, 0);
    ASSERT_EQ(s.tls_log_sel,   0);
}

/* ── Suite entry point ───────────────────────────────────── */

void run_tls_log_tests(void) {
    TEST_SUITE("tls_log parse");
    RUN_TEST(test_parse_tls13_sni);
    RUN_TEST(test_parse_tls12_nosni);
    RUN_TEST(test_parse_tls11_legacy);
    RUN_TEST(test_parse_rejects_wrong_type);
    RUN_TEST(test_parse_rejects_server_hello);
    RUN_TEST(test_parse_rejects_short);
    RUN_TEST(test_parse_rejects_truncated);
    RUN_TEST(test_parse_null_ips_ok);

    TEST_SUITE("tls_log JA3 fingerprint");
    RUN_TEST(test_parse_emits_ja3);
    RUN_TEST(test_ja3_is_deterministic);
    RUN_TEST(test_ja3_differs_for_different_ciphers);
    RUN_TEST(test_ja3_skips_grease);

    TEST_SUITE("tls_log ring buffer");
    RUN_TEST(test_record_and_snapshot);
    RUN_TEST(test_snapshot_newest_first);
    RUN_TEST(test_clear_empties_log);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_snapshot_clamps_sel_at_boundary_and_empty);

    TEST_SUITE("view_tls draw");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);

    TEST_SUITE("view_tls key");
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
}
