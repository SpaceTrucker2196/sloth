#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "dns_log.h"
#include "views/dns_log.h"

/*
 * Hand-crafted DNS messages.
 *
 * DNS header (12 bytes):
 *   ID(2) Flags(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
 *
 * Flags for query:   0x01 0x00  (QR=0, RD=1)
 * Flags for response:0x81 0x80  (QR=1, RD=1, RA=1, RCODE=0)
 * Flags for NXDOMAIN:0x81 0x83  (QR=1, RD=1, RA=1, RCODE=3)
 *
 * Name encoding: \x03foo\x03bar\x00 = "foo.bar"
 *
 * Answer RR with compression ptr: \xc0\x0c (→ offset 12 = start of question)
 */

/* "test.example.com" encoded: 4+1+7+1+3+1+1 = 18 bytes */
static const uint8_t NAME_TEST_EXAMPLE[] = {
    0x04,'t','e','s','t',
    0x07,'e','x','a','m','p','l','e',
    0x03,'c','o','m',
    0x00
};
#define NAME_LEN 18

/* ── helpers ─────────────────────────────────────────────── */

static int build_query(uint8_t *buf, int bufsz,
                       const uint8_t *name, int namelen, uint16_t qtype)
{
    int need = 12 + namelen + 4;
    if (bufsz < need) return 0;
    /* header */
    buf[0]=0x12; buf[1]=0x34;   /* ID */
    buf[2]=0x01; buf[3]=0x00;   /* QR=0, RD=1 */
    buf[4]=0x00; buf[5]=0x01;   /* QDCOUNT=1 */
    buf[6]=0x00; buf[7]=0x00;   /* ANCOUNT=0 */
    buf[8]=0x00; buf[9]=0x00;
    buf[10]=0x00; buf[11]=0x00;
    memcpy(buf + 12, name, (size_t)namelen);
    buf[12 + namelen]     = (uint8_t)(qtype >> 8);
    buf[12 + namelen + 1] = (uint8_t)(qtype & 0xff);
    buf[12 + namelen + 2] = 0x00;
    buf[12 + namelen + 3] = 0x01;   /* QCLASS=IN */
    return need;
}

static int build_response_a(uint8_t *buf, int bufsz,
                             const uint8_t *name, int namelen,
                             const uint8_t ip4[4])
{
    int qsec = namelen + 4;
    int need = 12 + qsec + 2 + 10 + 4;  /* hdr + qsec + ptr + rr_fixed + rdata */
    if (bufsz < need) return 0;
    buf[0]=0x12; buf[1]=0x34;
    buf[2]=0x81; buf[3]=0x80;   /* QR=1, RD=1, RA=1, RCODE=0 */
    buf[4]=0x00; buf[5]=0x01;   /* QDCOUNT=1 */
    buf[6]=0x00; buf[7]=0x01;   /* ANCOUNT=1 */
    buf[8]=0x00; buf[9]=0x00;
    buf[10]=0x00; buf[11]=0x00;
    memcpy(buf + 12, name, (size_t)namelen);
    int off = 12 + namelen;
    buf[off++]=0x00; buf[off++]=0x01;  /* QTYPE A */
    buf[off++]=0x00; buf[off++]=0x01;  /* QCLASS IN */
    /* answer: compression ptr to offset 12 */
    buf[off++]=0xc0; buf[off++]=0x0c;
    buf[off++]=0x00; buf[off++]=0x01;  /* TYPE A */
    buf[off++]=0x00; buf[off++]=0x01;  /* CLASS IN */
    buf[off++]=0x00; buf[off++]=0x00; buf[off++]=0x01; buf[off++]=0x2c; /* TTL 300 */
    buf[off++]=0x00; buf[off++]=0x04;  /* RDLENGTH 4 */
    buf[off++]=ip4[0]; buf[off++]=ip4[1];
    buf[off++]=ip4[2]; buf[off++]=ip4[3];
    return off;
}

static int build_nxdomain(uint8_t *buf, int bufsz,
                           const uint8_t *name, int namelen)
{
    int need = 12 + namelen + 4;
    if (bufsz < need) return 0;
    buf[0]=0x12; buf[1]=0x34;
    buf[2]=0x81; buf[3]=0x83;   /* QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN) */
    buf[4]=0x00; buf[5]=0x01;
    buf[6]=0x00; buf[7]=0x00;   /* ANCOUNT=0 */
    buf[8]=0x00; buf[9]=0x00;
    buf[10]=0x00; buf[11]=0x00;
    memcpy(buf + 12, name, (size_t)namelen);
    int off = 12 + namelen;
    buf[off++]=0x00; buf[off++]=0x01;
    buf[off++]=0x00; buf[off++]=0x01;
    return off;
}

/* ── dns_log_parse tests ─────────────────────────────────── */

static void test_parse_query_a(void) {
    uint8_t buf[64];
    int len = build_query(buf, sizeof(buf), NAME_TEST_EXAMPLE, NAME_LEN, 1);
    dns_log_entry_t e;
    int r = dns_log_parse(buf, len, "192.168.1.5", &e);
    ASSERT_EQ(r, 1);
    ASSERT_EQ(e.is_resp, 0);
    ASSERT_STR(e.qname,  "test.example.com");
    ASSERT_STR(e.qtype,  "A");
    ASSERT_STR(e.src,    "192.168.1.5");
    ASSERT_EQ((int)e.answer[0], 0);   /* no answer for a query */
}

static void test_parse_response_a(void) {
    uint8_t buf[128];
    static const uint8_t ip4[] = {93, 184, 216, 34};
    int len = build_response_a(buf, sizeof(buf), NAME_TEST_EXAMPLE, NAME_LEN, ip4);
    dns_log_entry_t e;
    int r = dns_log_parse(buf, len, "8.8.8.8", &e);
    ASSERT_EQ(r, 1);
    ASSERT_EQ(e.is_resp, 1);
    ASSERT_STR(e.qname,  "test.example.com");
    ASSERT_STR(e.qtype,  "A");
    ASSERT_STR(e.answer, "93.184.216.34");
}

static void test_parse_nxdomain(void) {
    uint8_t buf[64];
    int len = build_nxdomain(buf, sizeof(buf), NAME_TEST_EXAMPLE, NAME_LEN);
    dns_log_entry_t e;
    int r = dns_log_parse(buf, len, "8.8.8.8", &e);
    ASSERT_EQ(r, 1);
    ASSERT_EQ(e.is_resp, 1);
    ASSERT_STR(e.answer, "NXDOMAIN");
}

static void test_parse_query_aaaa(void) {
    uint8_t buf[64];
    int len = build_query(buf, sizeof(buf), NAME_TEST_EXAMPLE, NAME_LEN, 28);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "10.0.0.1", &e), 1);
    ASSERT_STR(e.qtype, "AAAA");
    ASSERT_EQ(e.is_resp, 0);
}

static void test_parse_query_ptr(void) {
    /* PTR query: qtype=12 */
    uint8_t buf[64];
    int len = build_query(buf, sizeof(buf), NAME_TEST_EXAMPLE, NAME_LEN, 12);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "10.0.0.1", &e), 1);
    ASSERT_STR(e.qtype, "PTR");
}

static void test_parse_query_mx(void) {
    uint8_t buf[64];
    int len = build_query(buf, sizeof(buf), NAME_TEST_EXAMPLE, NAME_LEN, 15);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "10.0.0.1", &e), 1);
    ASSERT_STR(e.qtype, "MX");
}

static void test_parse_unknown_qtype(void) {
    uint8_t buf[64];
    int len = build_query(buf, sizeof(buf), NAME_TEST_EXAMPLE, NAME_LEN, 255);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "10.0.0.1", &e), 1);
    ASSERT_STR(e.qtype, "?");
}

static void test_parse_rejects_short(void) {
    uint8_t buf[8] = {0};
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, 8, "1.2.3.4", &e), 0);
}

static void test_parse_rejects_no_question(void) {
    uint8_t buf[12] = {0x12,0x34, 0x01,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00};
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, 12, "1.2.3.4", &e), 0);
}

static void test_parse_null_src_ok(void) {
    uint8_t buf[64];
    int len = build_query(buf, sizeof(buf), NAME_TEST_EXAMPLE, NAME_LEN, 1);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, NULL, &e), 1);
    ASSERT_EQ((int)e.src[0], 0);
}

/* ── ring buffer tests ───────────────────────────────────── */

static dns_log_entry_t make_entry(const char *src, const char *qname,
                                   const char *qtype, const char *answer,
                                   int is_resp)
{
    dns_log_entry_t e;
    memset(&e, 0, sizeof(e));
    if (src)    snprintf(e.src,    sizeof(e.src),    "%s", src);
    if (qname)  snprintf(e.qname,  sizeof(e.qname),  "%s", qname);
    if (qtype)  snprintf(e.qtype,  sizeof(e.qtype),  "%s", qtype);
    if (answer) snprintf(e.answer, sizeof(e.answer), "%s", answer);
    e.is_resp = is_resp;
    e.ts = 1000;
    return e;
}

static void test_record_and_snapshot(void) {
    dns_log_clear();
    dns_log_entry_t e = make_entry("192.168.1.5", "example.com", "A", "93.184.216.34", 1);
    dns_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dns_log_snapshot(&s);

    ASSERT_EQ(s.dns_log_count, 1);
    ASSERT_STR(s.dns_log[0].qname,  "example.com");
    ASSERT_STR(s.dns_log[0].answer, "93.184.216.34");
}

static void test_snapshot_newest_first(void) {
    dns_log_clear();
    dns_log_entry_t a = make_entry("1.1.1.1", "first.com",  "A", "",             0);
    dns_log_entry_t b = make_entry("8.8.8.8", "second.com", "A", "1.2.3.4",      1);
    dns_log_record(&a);
    dns_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dns_log_snapshot(&s);

    ASSERT_EQ(s.dns_log_count, 2);
    ASSERT_STR(s.dns_log[0].qname, "second.com");
    ASSERT_STR(s.dns_log[1].qname, "first.com");
}

static void test_clear_empties_log(void) {
    dns_log_entry_t e = make_entry("1.1.1.1", "x.com", "A", "", 0);
    dns_log_record(&e);
    dns_log_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dns_log_snapshot(&s);
    ASSERT_EQ(s.dns_log_count, 0);
}

static void test_snapshot_clamps_sel(void) {
    dns_log_clear();
    dns_log_entry_t e = make_entry("1.1.1.1", "a.com", "A", "1.2.3.4", 1);
    dns_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.dns_log_sel = 99;
    dns_log_snapshot(&s);
    ASSERT_EQ(s.dns_log_sel, 0);
}

/* Kills the `sel >= n` boundary mutation (`>=` → `>`): if sel
 * equals n exactly (one past the last valid index), the clamp
 * must still trigger. The existing _clamps_sel test seeds
 * sel=99 with n=1 — too far above for the boundary to be
 * exercised. */
static void test_snapshot_clamps_sel_at_exact_boundary(void) {
    dns_log_clear();
    dns_log_entry_t e = make_entry("1.1.1.1", "a.com", "A", "1.2.3.4", 1);
    dns_log_record(&e);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.dns_log_sel = 1;            /* n will be 1; sel==n must clamp */
    dns_log_snapshot(&s);
    ASSERT_EQ(s.dns_log_sel, 0);
}

/* Kills the `n > 0` mutation (`>` → `>=`): when the log is empty
 * (n=0), sel must be reset to 0, not to -1. */
static void test_snapshot_empty_resets_sel_to_zero(void) {
    dns_log_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.dns_log_sel = 5;
    dns_log_snapshot(&s);
    ASSERT_EQ(s.dns_log_sel, 0);
}

/* ── view_dns_draw smoke tests ───────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_dns_draw(&s);
    ASSERT(1);
}

static void test_view_draw_populated(void) {
    dns_log_clear();
    dns_log_entry_t e1 = make_entry("192.168.1.5",  "google.com",  "A",    "142.250.80.46", 1);
    dns_log_entry_t e2 = make_entry("192.168.1.10", "ghost.local", "A",    "NXDOMAIN",      1);
    dns_log_entry_t e3 = make_entry("192.168.1.5",  "reddit.com",  "AAAA", "",              0);
    dns_log_record(&e1);
    dns_log_record(&e2);
    dns_log_record(&e3);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dns_log_snapshot(&s);
    view_dns_draw(&s);
    ASSERT(1);
}

/* ── view_dns_key tests ──────────────────────────────────── */

static void test_view_key_nav(void) {
    dns_log_clear();
    dns_log_entry_t a = make_entry("1.1.1.1", "a.com", "A", "1.2.3.4", 1);
    dns_log_entry_t b = make_entry("1.1.1.2", "b.com", "A", "5.6.7.8", 1);
    dns_log_record(&a);
    dns_log_record(&b);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dns_log_snapshot(&s);
    s.dns_log_sel = 0;

    view_dns_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.dns_log_sel, 1);
    view_dns_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.dns_log_sel, 1);   /* clamped */
    view_dns_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.dns_log_sel, 0);
    view_dns_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.dns_log_sel, 0);   /* clamped */
}

static void test_view_key_clear(void) {
    dns_log_clear();
    dns_log_entry_t e = make_entry("1.1.1.1", "x.com", "A", "1.2.3.4", 1);
    dns_log_record(&e);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    dns_log_snapshot(&s);
    ASSERT_EQ(s.dns_log_count, 1);

    view_dns_key(&s, 'c');
    ASSERT_EQ(s.dns_log_count, 0);
    ASSERT_EQ(s.dns_log_sel,   0);
}

/* ── Suite entry point ───────────────────────────────────── */

void run_dns_log_tests(void) {
    TEST_SUITE("dns_log parse");
    RUN_TEST(test_parse_query_a);
    RUN_TEST(test_parse_response_a);
    RUN_TEST(test_parse_nxdomain);
    RUN_TEST(test_parse_query_aaaa);
    RUN_TEST(test_parse_query_ptr);
    RUN_TEST(test_parse_query_mx);
    RUN_TEST(test_parse_unknown_qtype);
    RUN_TEST(test_parse_rejects_short);
    RUN_TEST(test_parse_rejects_no_question);
    RUN_TEST(test_parse_null_src_ok);

    TEST_SUITE("dns_log ring buffer");
    RUN_TEST(test_record_and_snapshot);
    RUN_TEST(test_snapshot_newest_first);
    RUN_TEST(test_clear_empties_log);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_snapshot_clamps_sel_at_exact_boundary);
    RUN_TEST(test_snapshot_empty_resets_sel_to_zero);

    TEST_SUITE("view_dns draw");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);

    TEST_SUITE("view_dns key");
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
}
