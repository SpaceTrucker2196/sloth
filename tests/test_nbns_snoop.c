#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "nbns_snoop.h"
#include "dns.h"
#include "views/nbns.h"

/* ── Packet builder ──────────────────────────────────────── */

/* NetBIOS First Level Encoding: name padded to 15 chars, sfx appended,
   each byte → 2 chars ((nibble>>4)+'A', (nibble&F)+'A').
   out must be 34 bytes: [0]=0x20, [1..32]=encoded, [33]=0x00 */
static void nb_encode(const char *name, uint8_t sfx, uint8_t *out) {
    uint8_t raw[16];
    memset(raw, ' ', 15);
    raw[15] = sfx;
    int n = (int)strlen(name);
    if (n > 15) n = 15;
    memcpy(raw, name, (size_t)n);
    out[0] = 0x20;
    for (int i = 0; i < 16; i++) {
        out[1 + i * 2]     = (uint8_t)((raw[i] >> 4)    + 'A');
        out[1 + i * 2 + 1] = (uint8_t)((raw[i] & 0x0F) + 'A');
    }
    out[33] = 0x00;
}

/* Build a minimal NBNS NAME_QUERY packet (query, no answer). */
static int make_query(const char *name, uint8_t sfx, uint8_t *buf, int bufsz) {
    if (bufsz < 50) return 0;
    memset(buf, 0, (size_t)bufsz);
    buf[0] = 0x01; buf[1] = 0x23;  /* TID */
    buf[2] = 0x01; buf[3] = 0x10;  /* FLAGS: QR=0, RD=1 */
    buf[4] = 0x00; buf[5] = 0x01;  /* QDCOUNT=1 */
    /* ANCOUNT/NSCOUNT/ARCOUNT all zero */
    nb_encode(name, sfx, buf + 12);
    buf[46] = 0x00; buf[47] = 0x20; /* QTYPE  NB  */
    buf[48] = 0x00; buf[49] = 0x01; /* QCLASS IN  */
    return 50;
}

/* Build a NBNS NAME_QUERY response with one NB answer record.
   ip4 is 4 raw bytes (network order). */
static int make_response(const char *name, uint8_t sfx,
                         const uint8_t ip4[4], uint8_t *buf, int bufsz) {
    if (bufsz < 66) return 0;
    memset(buf, 0, (size_t)bufsz);
    buf[0] = 0x01; buf[1] = 0x23;  /* TID */
    buf[2] = 0x85; buf[3] = 0x00;  /* FLAGS: QR=1, AA=1, RD=1 */
    buf[4] = 0x00; buf[5] = 0x00;  /* QDCOUNT=0 */
    buf[6] = 0x00; buf[7] = 0x01;  /* ANCOUNT=1 */
    /* NSCOUNT/ARCOUNT=0 */
    /* Answer RR */
    nb_encode(name, sfx, buf + 12);           /* name = 34 bytes, ends at buf[45] */
    buf[46] = 0x00; buf[47] = 0x20;           /* RTYPE NB  */
    buf[48] = 0x00; buf[49] = 0x01;           /* RCLASS IN */
    /* TTL (4 bytes) */
    buf[50] = 0x00; buf[51] = 0x04;
    buf[52] = 0x93; buf[53] = 0xe0;
    /* RDLENGTH = 6 */
    buf[54] = 0x00; buf[55] = 0x06;
    /* RDATA: 2-byte NB flags + 4-byte IP */
    buf[56] = 0x60; buf[57] = 0x00; /* NB flags: B-node, unique */
    buf[58] = ip4[0]; buf[59] = ip4[1];
    buf[60] = ip4[2]; buf[61] = ip4[3];
    return 62;
}

/* ── Helper to reset between tests ───────────────────────── */
static void reset(void) {
    nbns_clear();
    dns_init();
}

/* ── Protocol tests ──────────────────────────────────────── */

static void test_query_adds_entry(void) {
    reset();
    uint8_t buf[64];
    int len = make_query("DESKTOP1", 0x00, buf, sizeof(buf));
    char info[64] = "";
    int r = nbns_snoop(buf, len, info, sizeof(info));
    ASSERT_EQ(1, r);
    /* info should mention the queried name */
    ASSERT(strstr(info, "DESKTOP1") != NULL);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    ASSERT_EQ(1, s.nbns_count);
    ASSERT_STR("DESKTOP1", s.nbns_names[0].name);
    ASSERT_EQ(0x00, s.nbns_names[0].suffix);
    /* no IP yet — this was just a query */
    ASSERT_EQ(0, s.nbns_names[0].ip[0]);
}

static void test_response_fills_ip(void) {
    reset();
    uint8_t ip4[4] = {192, 168, 1, 50};
    uint8_t buf[128];
    int len = make_response("FILESVR", 0x20, ip4, buf, sizeof(buf));
    char info[64] = "";
    int r = nbns_snoop(buf, len, info, sizeof(info));
    ASSERT_EQ(1, r);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    ASSERT_EQ(1, s.nbns_count);
    ASSERT_STR("FILESVR", s.nbns_names[0].name);
    ASSERT_EQ(0x20, s.nbns_names[0].suffix);
    ASSERT_STR("192.168.1.50", s.nbns_names[0].ip);
}

static void test_response_info_contains_name_and_ip(void) {
    reset();
    uint8_t ip4[4] = {10, 0, 0, 5};
    uint8_t buf[128];
    int len = make_response("SERVER", 0x20, ip4, buf, sizeof(buf));
    char info[64] = "";
    nbns_snoop(buf, len, info, sizeof(info));
    ASSERT(strstr(info, "SERVER") != NULL);
    ASSERT(strstr(info, "10.0.0.5") != NULL);
}

static void test_response_calls_dns_resolved(void) {
    reset();
    uint8_t ip4[4] = {172, 16, 0, 3};
    uint8_t buf[128];
    int len = make_response("WINBOX", 0x00, ip4, buf, sizeof(buf));
    char info[64] = "";
    nbns_snoop(buf, len, info, sizeof(info));
    /* dns cache should resolve this IP to the name */
    const char *resolved = dns_lookup("172.16.0.3");
    ASSERT(resolved != NULL && strcmp(resolved, "WINBOX") == 0);
}

static void test_dedup_same_name_suffix(void) {
    reset();
    uint8_t ip4a[4] = {192, 168, 0, 10};
    uint8_t buf[128];
    int len = make_response("LAPTOP", 0x00, ip4a, buf, sizeof(buf));
    char info[64] = "";
    nbns_snoop(buf, len, info, sizeof(info));

    /* second response same name/suffix updates IP */
    uint8_t ip4b[4] = {192, 168, 0, 20};
    len = make_response("LAPTOP", 0x00, ip4b, buf, sizeof(buf));
    nbns_snoop(buf, len, info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    ASSERT_EQ(1, s.nbns_count);   /* still one entry, not two */
    ASSERT_STR("192.168.0.20", s.nbns_names[0].ip);
}

static void test_different_suffix_separate_entry(void) {
    reset();
    uint8_t ip4[4] = {10, 1, 1, 1};
    uint8_t buf[128];
    char info[64];
    int len = make_response("PC", 0x00, ip4, buf, sizeof(buf));
    nbns_snoop(buf, len, info, sizeof(info));
    len = make_response("PC", 0x20, ip4, buf, sizeof(buf));
    nbns_snoop(buf, len, info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    ASSERT_EQ(2, s.nbns_count);
}

static void test_too_short_rejected(void) {
    reset();
    uint8_t buf[11] = {0};
    char info[64] = "";
    ASSERT_EQ(0, nbns_snoop(buf, 11, info, sizeof(info)));
}

static void test_bad_qdcount_rejected(void) {
    reset();
    uint8_t buf[64]; memset(buf, 0, sizeof(buf));
    buf[4] = 0x00; buf[5] = 0x0F;  /* QDCOUNT=15 — too large */
    buf[2] = 0x01;                  /* QR=0 */
    char info[64] = "";
    ASSERT_EQ(0, nbns_snoop(buf, sizeof(buf), info, sizeof(info)));
}

static void test_last_seen_set(void) {
    reset();
    uint8_t ip4[4] = {1, 2, 3, 4};
    uint8_t buf[128];
    int len = make_response("TS", 0x00, ip4, buf, sizeof(buf));
    char info[64];
    nbns_snoop(buf, len, info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    ASSERT(s.nbns_names[0].last_seen > 0);
}

static void test_clear_empties_table(void) {
    reset();
    uint8_t ip4[4] = {5, 5, 5, 5};
    uint8_t buf[128];
    int len = make_response("CLEAR_ME", 0x00, ip4, buf, sizeof(buf));
    char info[64];
    nbns_snoop(buf, len, info, sizeof(info));
    nbns_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    ASSERT_EQ(0, s.nbns_count);
}

static void test_name_padded_with_spaces(void) {
    /* "A" — should decode to just "A", not "A              " */
    reset();
    uint8_t ip4[4] = {1, 1, 1, 1};
    uint8_t buf[128];
    int len = make_response("A", 0x00, ip4, buf, sizeof(buf));
    char info[64];
    nbns_snoop(buf, len, info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    ASSERT_EQ(1, s.nbns_count);
    ASSERT_STR("A", s.nbns_names[0].name);
}

static void test_query_info_has_question_mark(void) {
    reset();
    uint8_t buf[64];
    int len = make_query("SEARCHME", 0x00, buf, sizeof(buf));
    char info[64] = "";
    nbns_snoop(buf, len, info, sizeof(info));
    ASSERT(strstr(info, "?") != NULL);
}

static void test_file_server_suffix(void) {
    reset();
    uint8_t ip4[4] = {192, 168, 1, 100};
    uint8_t buf[128];
    int len = make_response("NAS", 0x20, ip4, buf, sizeof(buf));
    char info[64];
    nbns_snoop(buf, len, info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    ASSERT_EQ(0x20, s.nbns_names[0].suffix);
}

static void test_multiple_queries_multiple_entries(void) {
    reset();
    uint8_t buf[64];
    char info[64];
    const char *names[] = {"HOST1", "HOST2", "HOST3"};
    for (int i = 0; i < 3; i++) {
        int len = make_query(names[i], 0x00, buf, sizeof(buf));
        nbns_snoop(buf, len, info, sizeof(info));
    }
    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    ASSERT_EQ(3, s.nbns_count);
}

/* ── View draw / nav tests ───────────────────────────────── */

static void test_draw_empty_state(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* should not crash */
    view_nbns_draw(&s);
}

static void test_draw_with_entries(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.nbns_count = 2;
    snprintf(s.nbns_names[0].name, 16, "PC1");
    snprintf(s.nbns_names[0].ip,   46, "10.0.0.1");
    s.nbns_names[0].suffix    = 0x00;
    s.nbns_names[0].last_seen = 1000000;
    snprintf(s.nbns_names[1].name, 16, "SERVER");
    snprintf(s.nbns_names[1].ip,   46, "10.0.0.2");
    s.nbns_names[1].suffix    = 0x20;
    s.nbns_names[1].last_seen = 1000000;
    view_nbns_draw(&s);   /* must not crash */
}

static void test_nav_down_up(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.nbns_count = 3;
    ASSERT_EQ(0, s.nbns_sel);
    view_nbns_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(1, s.nbns_sel);
    view_nbns_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(2, s.nbns_sel);
    view_nbns_key(&s, SLOTH_KEY_DOWN);   /* clamp */
    ASSERT_EQ(2, s.nbns_sel);
    view_nbns_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(1, s.nbns_sel);
    view_nbns_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(0, s.nbns_sel);
    view_nbns_key(&s, SLOTH_KEY_UP);    /* clamp */
    ASSERT_EQ(0, s.nbns_sel);
}

static void test_clear_key_resets_state(void) {
    uint8_t ip4[4] = {1, 2, 3, 4};
    uint8_t buf[128];
    char info[64];
    int len = make_response("CLEARME", 0x00, ip4, buf, sizeof(buf));
    nbns_snoop(buf, len, info, sizeof(info));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    nbns_snapshot(&s);
    s.nbns_sel = 1;
    ASSERT_GT(s.nbns_count, 0);

    view_nbns_key(&s, 'c');
    ASSERT_EQ(0, s.nbns_count);
    ASSERT_EQ(0, s.nbns_sel);
}

static void test_draw_selected_row(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.nbns_count = 2;
    s.nbns_sel   = 1;
    snprintf(s.nbns_names[0].name, 16, "A");
    s.nbns_names[0].last_seen = 1;
    snprintf(s.nbns_names[1].name, 16, "B");
    s.nbns_names[1].last_seen = 1;
    view_nbns_draw(&s);   /* must not crash with sel=1 */
}

/* ── Entry point ────────────────────────────────────────── */

void run_nbns_snoop_tests(void) {
    TEST_SUITE("nbns_snoop protocol");
    RUN_TEST(test_query_adds_entry);
    RUN_TEST(test_response_fills_ip);
    RUN_TEST(test_response_info_contains_name_and_ip);
    RUN_TEST(test_response_calls_dns_resolved);
    RUN_TEST(test_dedup_same_name_suffix);
    RUN_TEST(test_different_suffix_separate_entry);
    RUN_TEST(test_too_short_rejected);
    RUN_TEST(test_bad_qdcount_rejected);
    RUN_TEST(test_last_seen_set);
    RUN_TEST(test_clear_empties_table);
    RUN_TEST(test_name_padded_with_spaces);
    RUN_TEST(test_query_info_has_question_mark);
    RUN_TEST(test_file_server_suffix);
    RUN_TEST(test_multiple_queries_multiple_entries);

    TEST_SUITE("nbns view");
    RUN_TEST(test_draw_empty_state);
    RUN_TEST(test_draw_with_entries);
    RUN_TEST(test_nav_down_up);
    RUN_TEST(test_clear_key_resets_state);
    RUN_TEST(test_draw_selected_row);
}
