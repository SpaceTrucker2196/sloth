#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "tui.h"
#include "sloth.h"
#include "dns_log.h"
#include "views/dns_log.h"
#include "host_cache.h"

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

/* "host.example.net" encoded: 5+8+4+1 = 18 bytes */
static const uint8_t NAME_HOST_EXAMPLE_NET[] = {
    0x04,'h','o','s','t',
    0x07,'e','x','a','m','p','l','e',
    0x03,'n','e','t',
    0x00
};
#define NAME2_LEN ((int)sizeof(NAME_HOST_EXAMPLE_NET))

/* "1.0.0.10.in-addr.arpa" encoded, a PTR question's reverse name. */
static const uint8_t NAME_PTR_ARPA[] = {
    0x01,'1',
    0x01,'0',
    0x01,'0',
    0x02,'1','0',
    0x07,'i','n','-','a','d','d','r',
    0x04,'a','r','p','a',
    0x00
};
#define PTR_ARPA_LEN ((int)sizeof(NAME_PTR_ARPA))

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

/* ── PTR-answer builders (#165) ──────────────────────────────
 *
 * Each answer RR's owner name is a compression pointer back to the
 * question at offset 12 — the same trick build_response_a already
 * uses, since the owner name is never what these tests are about. */

static int write_dns_header_and_q(uint8_t *buf,
                                  const uint8_t *qname, int qnamelen,
                                  uint16_t qtype, uint16_t ancount)
{
    buf[0]=0x12; buf[1]=0x34;
    buf[2]=0x81; buf[3]=0x80;   /* QR=1, RD=1, RA=1, RCODE=0 */
    buf[4]=0x00; buf[5]=0x01;   /* QDCOUNT=1 */
    buf[6]=(uint8_t)(ancount>>8); buf[7]=(uint8_t)(ancount&0xff);
    buf[8]=0x00; buf[9]=0x00;
    buf[10]=0x00; buf[11]=0x00;
    memcpy(buf + 12, qname, (size_t)qnamelen);
    int off = 12 + qnamelen;
    buf[off++]=(uint8_t)(qtype>>8); buf[off++]=(uint8_t)(qtype&0xff);
    buf[off++]=0x00; buf[off++]=0x01;  /* QCLASS IN */
    return off;
}

/* Appends one RR's fixed 12-byte header (owner-name pointer, type,
 * class, TTL, RDLENGTH). Caller appends rdlen bytes of RDATA (or
 * doesn't, for the "RDATA past the message" case). */
static int append_rr(uint8_t *buf, int off, uint16_t rtype, uint16_t rdlen)
{
    buf[off++]=0xc0; buf[off++]=0x0c;              /* name: ptr to Q */
    buf[off++]=(uint8_t)(rtype>>8); buf[off++]=(uint8_t)(rtype&0xff);
    buf[off++]=0x00; buf[off++]=0x01;               /* CLASS IN */
    buf[off++]=0x00; buf[off++]=0x00; buf[off++]=0x01; buf[off++]=0x2c; /* TTL 300 */
    buf[off++]=(uint8_t)(rdlen>>8); buf[off++]=(uint8_t)(rdlen&0xff);
    return off;
}

/* One PTR answer, target name encoded raw (no compression). */
static int build_response_ptr(uint8_t *buf, int bufsz,
                              const uint8_t *qname, int qnamelen,
                              const uint8_t *target, int targetlen)
{
    int need = 12 + qnamelen + 4 + 12 + targetlen;
    if (bufsz < need) return 0;
    int off = write_dns_header_and_q(buf, qname, qnamelen, 12, 1);
    off = append_rr(buf, off, 12, (uint16_t)targetlen);
    memcpy(buf + off, target, (size_t)targetlen);
    return off + targetlen;
}

/* One PTR answer whose RDATA is a bare compression pointer back to
 * the question name at offset 12. */
static int build_response_ptr_compressed(uint8_t *buf, int bufsz,
                                         const uint8_t *qname, int qnamelen)
{
    int need = 12 + qnamelen + 4 + 12 + 2;
    if (bufsz < need) return 0;
    int off = write_dns_header_and_q(buf, qname, qnamelen, 12, 1);
    off = append_rr(buf, off, 12, 2);
    buf[off++] = 0xc0; buf[off++] = 0x0c;
    return off;
}

/* A malformed PTR RR (RDATA: the 7-byte label "partial" followed by
 * a reserved label-type octet, 0x40 — top bits 01 — per RFC 1035
 * §3.1/§4.1.4; see dns_read_name's rejection of (c & 0xC0) != 0 and
 * != 0xC0) followed by a well-formed PTR RR. dns_read_name has
 * already written "partial" into its output buffer by the time the
 * reserved octet reddens the decode, so a careless caller that used
 * the partial result anyway would leak it into answer; the correct
 * behaviour is to discard it and keep walking to the next RR. */
static const uint8_t PTR_RDATA_MALFORMED[] = {
    0x07,'p','a','r','t','i','a','l', 0x40
};
#define PTR_RDATA_MALFORMED_LEN ((int)sizeof(PTR_RDATA_MALFORMED))

static int build_response_ptr_malformed_then_valid(uint8_t *buf, int bufsz,
                                                    const uint8_t *qname, int qnamelen,
                                                    const uint8_t *target, int targetlen)
{
    int need = 12 + qnamelen + 4
             + 12 + PTR_RDATA_MALFORMED_LEN
             + 12 + targetlen;
    if (bufsz < need) return 0;
    int off = write_dns_header_and_q(buf, qname, qnamelen, 12, 2);
    off = append_rr(buf, off, 12, (uint16_t)PTR_RDATA_MALFORMED_LEN);
    memcpy(buf + off, PTR_RDATA_MALFORMED, (size_t)PTR_RDATA_MALFORMED_LEN);
    off += PTR_RDATA_MALFORMED_LEN;
    off = append_rr(buf, off, 12, (uint16_t)targetlen);
    memcpy(buf + off, target, (size_t)targetlen);
    return off + targetlen;
}

/* One PTR answer whose RDLENGTH claims bytes that were never
 * written, so rdata + rdlen runs past the message. */
static int build_response_ptr_rdata_past_end(uint8_t *buf, int bufsz,
                                             const uint8_t *qname, int qnamelen)
{
    int need = 12 + qnamelen + 4 + 12;
    if (bufsz < need) return 0;
    int off = write_dns_header_and_q(buf, qname, qnamelen, 12, 1);
    return append_rr(buf, off, 12, 50);
}

/* A CNAME RR followed by a PTR RR. */
static int build_response_cname_then_ptr(uint8_t *buf, int bufsz,
                                         const uint8_t *qname, int qnamelen,
                                         const uint8_t *cname_target, int cnamelen,
                                         const uint8_t *ptr_target, int ptrlen)
{
    int need = 12 + qnamelen + 4 + 12 + cnamelen + 12 + ptrlen;
    if (bufsz < need) return 0;
    int off = write_dns_header_and_q(buf, qname, qnamelen, 12, 2);
    off = append_rr(buf, off, 5, (uint16_t)cnamelen);
    memcpy(buf + off, cname_target, (size_t)cnamelen);
    off += cnamelen;
    off = append_rr(buf, off, 12, (uint16_t)ptrlen);
    memcpy(buf + off, ptr_target, (size_t)ptrlen);
    return off + ptrlen;
}

/* An A RR followed by a PTR RR. */
static int build_response_a_then_ptr(uint8_t *buf, int bufsz,
                                     const uint8_t *qname, int qnamelen,
                                     const uint8_t ip4[4],
                                     const uint8_t *ptr_target, int ptrlen)
{
    int need = 12 + qnamelen + 4 + 12 + 4 + 12 + ptrlen;
    if (bufsz < need) return 0;
    int off = write_dns_header_and_q(buf, qname, qnamelen, 12, 2);
    off = append_rr(buf, off, 1, 4);
    memcpy(buf + off, ip4, 4);
    off += 4;
    off = append_rr(buf, off, 12, (uint16_t)ptrlen);
    memcpy(buf + off, ptr_target, (size_t)ptrlen);
    return off + ptrlen;
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

/* #165: a PTR response's RDATA names its target (RFC 1035 §3.3.12).
 * qname stays the reverse arpa name; answer is now the decoded
 * target, where before this it stayed empty. */
static void test_parse_response_ptr_no_compression(void) {
    uint8_t buf[96];
    int len = build_response_ptr(buf, sizeof(buf),
                                  NAME_PTR_ARPA, PTR_ARPA_LEN,
                                  NAME_HOST_EXAMPLE_NET, NAME2_LEN);
    ASSERT(len > 0);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "8.8.8.8", &e), 1);
    ASSERT_EQ(e.is_resp, 1);
    ASSERT_STR(e.qname,  "1.0.0.10.in-addr.arpa");
    ASSERT_STR(e.qtype,  "PTR");
    ASSERT_STR(e.answer, "host.example.net");
}

/* The target name is a bare compression pointer back to the question
 * — dns_read_name must follow it from this call site too. */
static void test_parse_response_ptr_compressed_target(void) {
    uint8_t buf[64];
    int len = build_response_ptr_compressed(buf, sizeof(buf),
                                             NAME_TEST_EXAMPLE, NAME_LEN);
    ASSERT(len > 0);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "8.8.8.8", &e), 1);
    ASSERT_STR(e.answer, "test.example.com");
}

/* RDLENGTH claiming bytes past the end of the message must not be
 * read: the RR is discarded and answer stays empty, same as any other
 * malformed RR (the bound predates #165; this pins it for the PTR
 * branch specifically). */
static void test_parse_response_ptr_rdata_past_message(void) {
    uint8_t buf[64];
    int len = build_response_ptr_rdata_past_end(buf, sizeof(buf),
                                                 NAME_PTR_ARPA, PTR_ARPA_LEN);
    ASSERT(len > 0);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "8.8.8.8", &e), 1);
    ASSERT_EQ((int)e.answer[0], 0);
}

/* A CNAME ahead of the PTR in the answer section must be skipped, not
 * mistaken for a match. */
static void test_parse_response_ptr_after_cname(void) {
    uint8_t buf[128];
    int len = build_response_cname_then_ptr(buf, sizeof(buf),
                                             NAME_PTR_ARPA, PTR_ARPA_LEN,
                                             NAME_TEST_EXAMPLE, NAME_LEN,
                                             NAME_HOST_EXAMPLE_NET, NAME2_LEN);
    ASSERT(len > 0);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "8.8.8.8", &e), 1);
    ASSERT_STR(e.answer, "host.example.net");
}

/* An A record ahead of a PTR record in the same answer section: the
 * existing A/AAAA preference must still win and stop the walk, so
 * adding the PTR branch must not reorder it. */
static void test_parse_response_mixed_a_and_ptr_prefers_a(void) {
    uint8_t buf[128];
    static const uint8_t ip4[] = {10, 0, 0, 99};
    int len = build_response_a_then_ptr(buf, sizeof(buf),
                                        NAME_PTR_ARPA, PTR_ARPA_LEN,
                                        ip4,
                                        NAME_HOST_EXAMPLE_NET, NAME2_LEN);
    ASSERT(len > 0);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "8.8.8.8", &e), 1);
    ASSERT_STR(e.answer, "10.0.0.99");
}

/* ── PTR edge cases (#165 audit) ─────────────────────────────
 *
 * Built per RFC 1035 §4.1 (header, question, RRs per §4.1.3), PTR
 * RDATA per §3.3.12, compression per §4.1.4. The question is always at
 * offset 12; each answer RR's owner is a pointer to it. 192.0.2.0/24
 * and the names below are RFC 5737 / RFC 2606 documentation space. */
typedef struct { uint8_t b[512]; int n; } pm_t;

static void pm_u8(pm_t *m, int v) {
    if (m->n < (int)sizeof m->b) m->b[m->n++] = (uint8_t)v;
}
static void pm_16(pm_t *m, int v) { pm_u8(m, (v >> 8) & 0xff); pm_u8(m, v & 0xff); }
static void pm_raw(pm_t *m, const void *p, int n) {
    for (int i = 0; i < n; i++) pm_u8(m, ((const uint8_t *)p)[i]);
}
/* Dotted text as labels, then the root label ("" is the root alone). */
static void pm_name(pm_t *m, const char *dotted) {
    const char *p = dotted;
    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        pm_u8(m, l);
        pm_raw(m, p, l);
        p += l + (dot ? 1 : 0);
    }
    pm_u8(m, 0);
}
/* Response header (RCODE 0, QDCOUNT 1), then the question. */
static void pm_resp(pm_t *m, int an, const char *qname, int qtype) {
    m->n = 0;
    pm_16(m, 0x1234); pm_16(m, 0x8180);
    pm_16(m, 1); pm_16(m, an); pm_16(m, 0); pm_16(m, 0);
    pm_name(m, qname);
    pm_16(m, qtype); pm_16(m, 1);
}
/* An RR owned by the question, up to and including an RDLENGTH of
 * rdlen; the caller writes the RDATA. */
static void pm_rr(pm_t *m, int type, int rdlen) {
    pm_16(m, 0xC00C);
    pm_16(m, type); pm_16(m, 1);            /* CLASS IN */
    pm_16(m, 0); pm_16(m, 300);             /* TTL */
    pm_16(m, rdlen);
}
/* A PTR RR whose RDATA is exactly the encoded target. */
static void pm_ptr_rr(pm_t *m, const char *target) {
    pm_t t; t.n = 0;
    pm_name(&t, target);
    pm_rr(m, 12, t.n);
    pm_raw(m, t.b, t.n);
}

#define REV_Q "10.2.0.192.in-addr.arpa"

static void pm_parse(const pm_t *m, dns_log_entry_t *e) {
    ASSERT_EQ(dns_log_parse(m->b, m->n, "192.0.2.53", e), 1);
}

/* A PTR RR in the answer to an A question answers nothing that was
 * asked: the A after it is the answer, as it was before #165 added the
 * PTR branch. Taking the PTR target made answer a host name for qtype
 * A, which host_cache_add() keys as an IP and the captive-portal DNS
 * check reads as a sentinel's address. Seen red (answer
 * "host.example.net") with the `&& qtype == 12` gate removed. */
static void test_parse_a_question_ignores_a_ptr_rr(void) {
    static const uint8_t a4[] = { 192, 0, 2, 10 };
    pm_t m;
    pm_resp(&m, 2, "www.example.com", 1);
    pm_ptr_rr(&m, "host.example.net");
    pm_rr(&m, 1, 4);
    pm_raw(&m, a4, 4);
    dns_log_entry_t e;
    pm_parse(&m, &e);
    ASSERT_STR(e.qtype, "A");
    ASSERT_STR(e.answer, "192.0.2.10");
}

/* answer holds qname's 63 bytes: common provider PTR names pass the
 * 45 an address needs, and slothweb's passive_ptr would store a
 * 45-byte cut as the name. Seen red (the 48-byte name cut to 45, the
 * 63-byte one too) with answer put back to 46 bytes in sloth.h. */
static void test_parse_ptr_target_longer_than_an_address_is_whole(void) {
    static const char *const names[] = {
        "ec2-203-0-113-25.us-west-2.compute.amazonaws.com",              /* 48 */
        "aaaaaaaaa.bbbbbbbbb.ccccccccc.ddddddddd.eeeeeeeee.fffffffff.ggg", /* 63 */
    };
    for (int i = 0; i < 2; i++) {
        pm_t m;
        pm_resp(&m, 1, REV_Q, 12);
        pm_ptr_rr(&m, names[i]);
        dns_log_entry_t e;
        pm_parse(&m, &e);
        ASSERT_STR(e.answer, names[i]);
    }
}

/* A target that does not fit in 63 bytes, or whose label holds a NUL
 * octet (legal on the wire, RFC 2181 §11), would store as a prefix of
 * itself; it is skipped and a later PTR answers. Seen red (the
 * prefixes "aaaa…fffffffff.ggg" and "ho" stored) with the
 * `full == plen &&` test removed. */
static void test_parse_ptr_target_that_would_be_cut_is_skipped(void) {
    pm_t m;
    pm_resp(&m, 2, REV_Q, 12);
    pm_ptr_rr(&m, "aaaaaaaaa.bbbbbbbbb.ccccccccc.ddddddddd.eeeeeeeee.fffffffff.gggg");
    pm_ptr_rr(&m, "host.example.net");
    dns_log_entry_t e;
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "host.example.net");

    static const uint8_t nul_name[] = {
        5, 'h', 'o', 0, 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'n', 'e', 't', 0 };
    pm_resp(&m, 2, REV_Q, 12);
    pm_rr(&m, 12, (int)sizeof nul_name);
    pm_raw(&m, nul_name, (int)sizeof nul_name);
    pm_ptr_rr(&m, "host.example.net");
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "host.example.net");
}

/* The target is the RDATA's whole extent (RFC 1035 §3.2.1, §3.3.12):
 * one that runs past RDLENGTH reads bytes outside its RR (RDLENGTH 2
 * over an 18-byte name; RDLENGTH 0, which decodes the next RR's
 * owner), and one shorter than RDLENGTH leaves octets RDATA does not
 * define. None is taken. Seen red (answer "host.example.net" for the
 * first, "www.example.com" for the second via the next RR's owner
 * pointer, "host.example.net" for the third) with the extent test put
 * back to `pn >= 0`. */
static void test_parse_ptr_target_must_be_the_whole_rdata(void) {
    pm_t t; t.n = 0;
    pm_name(&t, "host.example.net");

    pm_t m;
    pm_resp(&m, 1, REV_Q, 12);
    pm_rr(&m, 12, 2);                       /* RDLENGTH short of the name */
    pm_raw(&m, t.b, t.n);
    dns_log_entry_t e;
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "");

    pm_resp(&m, 2, "www.example.com", 12);
    pm_rr(&m, 12, 0);                       /* empty RDATA */
    pm_rr(&m, 16, 1);                       /* a TXT RR follows */
    pm_u8(&m, 0);
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "");

    pm_resp(&m, 1, REV_Q, 12);
    pm_rr(&m, 12, t.n + 2);                 /* two octets past the name */
    pm_raw(&m, t.b, t.n);
    pm_16(&m, 0);
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "");
}

/* A malformed PTR RR must be discarded, not left half-decoded in
 * answer and not treated as fatal to the walk: the next RR's target
 * is used instead. Three shapes: a label run that never reaches the
 * root inside its RDATA, a target that loops (a label, then a pointer
 * back to that label), and one pointing past the end of the message
 * (the shared reader's hop and bounds checks refuse the last two).
 * Seen red with the acceptance test in dns_log_parse replaced by
 * `pn >= -1 && plen > 0`: answer reads "partial" with the second RR
 * never reached, and the loop stores "host.host.…". */
static void test_parse_response_ptr_malformed_rr_is_skipped(void) {
    uint8_t buf[128];
    int len = build_response_ptr_malformed_then_valid(buf, sizeof(buf),
                                                       NAME_PTR_ARPA, PTR_ARPA_LEN,
                                                       NAME_HOST_EXAMPLE_NET, NAME2_LEN);
    ASSERT(len > 0);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "8.8.8.8", &e), 1);
    ASSERT_STR(e.answer, "host.example.net");

    pm_t m;
    pm_resp(&m, 2, REV_Q, 12);
    int at = m.n + 12;                      /* where the RDATA starts */
    pm_rr(&m, 12, 7);
    pm_u8(&m, 4); pm_raw(&m, "host", 4);
    pm_16(&m, 0xC000 | at);                 /* back to "host" */
    pm_ptr_rr(&m, "host.example.net");
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "host.example.net");

    pm_resp(&m, 1, REV_Q, 12);
    pm_rr(&m, 12, 2);
    pm_16(&m, 0xC000 | 0x3FFF);             /* far past the message */
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "");
}

/* The root name (RDATA one zero octet) names no host; it is skipped,
 * not stored as "" with the walk stopped. Seen red (answer "") with
 * the `plen > 0 &&` test removed. */
static void test_parse_ptr_root_target_is_skipped(void) {
    pm_t m;
    pm_resp(&m, 2, REV_Q, 12);
    pm_ptr_rr(&m, "");
    pm_ptr_rr(&m, "host.example.net");
    dns_log_entry_t e;
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "host.example.net");
}

/* A target whose text is "NXDOMAIN" would read as the rcode 3 sentinel
 * to rule_nxdomain_burst and to slothweb's NXDOMAIN counters, so a
 * resolver naming a host that would forge NXDOMAIN counts. Seen red
 * (answer "NXDOMAIN") with the strcmp refusal removed. */
static void test_parse_ptr_nxdomain_text_is_refused(void) {
    pm_t m;
    pm_resp(&m, 1, REV_Q, 12);
    pm_ptr_rr(&m, "NXDOMAIN");
    dns_log_entry_t e;
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "");
}

/* What this adds over test_parse_nxdomain, whose response carries no
 * answer RR: an RCODE 3 response that does carry one (a PTR naming a
 * host) still reads "NXDOMAIN", because the answer section is not
 * walked after the sentinel is set. test_parse_nxdomain passes with
 * the rcode 3 branch's `return 1` removed, since ANCOUNT 0 returns
 * next; this one goes red (answer "host.example.net"). */
static void test_parse_ptr_nxdomain_rcode(void) {
    pm_t m;
    pm_resp(&m, 1, REV_Q, 12);
    m.b[3] = 0x83;                          /* RA, RCODE 3 */
    pm_ptr_rr(&m, "host.example.net");
    dns_log_entry_t e;
    pm_parse(&m, &e);
    ASSERT_STR(e.answer, "NXDOMAIN");
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

/* #105 review: qname holds 63 text bytes, so a longer wire name is
 * kept as a prefix — and the first 63 bytes of
 * "<43 x a>.control.verkada.com.evil.example" read as a Verkada host.
 * qname_trunc records that the stored text is not the whole name.
 * Names are RFC 1035 §3.1 label sequences built here by hand. */
static int put_label(uint8_t *w, int o, const char *lab, int n) {
    w[o++] = (uint8_t)n;
    memcpy(w + o, lab, (size_t)n);
    return o + n;
}

static void test_parse_qname_over_63_sets_trunc(void) {
    uint8_t name[96]; int o = 0;
    char a[43]; memset(a, 'a', sizeof a);
    o = put_label(name, o, a, 43);
    o = put_label(name, o, "control", 7);
    o = put_label(name, o, "verkada", 7);
    o = put_label(name, o, "com", 3);
    o = put_label(name, o, "evil", 4);
    o = put_label(name, o, "example", 7);
    name[o++] = 0x00;
    uint8_t buf[128];
    int len = build_query(buf, sizeof(buf), name, o, 1);
    ASSERT(len > 0);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "10.0.0.5", &e), 1);
    ASSERT_EQ((int)strlen(e.qname), DNS_NAME_LEN - 1);
    ASSERT(strstr(e.qname, ".control.verkada.com") != NULL);
    ASSERT_EQ((int)e.qname_trunc, 1);
}

static void test_parse_qname_of_exactly_63_is_whole(void) {
    uint8_t name[96]; int o = 0;
    char a[43]; memset(a, 'a', sizeof a);
    o = put_label(name, o, a, 43);
    o = put_label(name, o, "control", 7);
    o = put_label(name, o, "verkada", 7);
    o = put_label(name, o, "com", 3);
    name[o++] = 0x00;
    uint8_t buf[128];
    int len = build_query(buf, sizeof(buf), name, o, 1);
    ASSERT(len > 0);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "10.0.0.5", &e), 1);
    ASSERT_EQ((int)strlen(e.qname), DNS_NAME_LEN - 1);
    ASSERT_EQ((int)e.qname_trunc, 0);
}

static void test_parse_qname_with_nul_octet_sets_trunc(void) {
    /* A label may carry any octet (RFC 2181 §11); netstr_copy stops at
     * a NUL, so "com\0x" leaves "api.control.verkada.com" stored. */
    uint8_t name[64]; int o = 0;
    o = put_label(name, o, "api", 3);
    o = put_label(name, o, "control", 7);
    o = put_label(name, o, "verkada", 7);
    o = put_label(name, o, "com\0x", 5);
    name[o++] = 0x00;
    uint8_t buf[96];
    int len = build_query(buf, sizeof(buf), name, o, 1);
    ASSERT(len > 0);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "10.0.0.5", &e), 1);
    ASSERT_STR(e.qname, "api.control.verkada.com");
    ASSERT_EQ((int)e.qname_trunc, 1);
}

static void test_parse_short_qname_is_whole(void) {
    uint8_t buf[64];
    int len = build_query(buf, sizeof(buf), NAME_TEST_EXAMPLE, NAME_LEN, 1);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "192.168.1.5", &e), 1);
    ASSERT_EQ((int)e.qname_trunc, 0);
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

/* #165: a PTR record's (qname, answer) is (reverse-arpa-name,
 * target-host), the opposite of host_cache_add's (ip, host) shape.
 * dns_log_record must not feed it through unchanged, or host_cache
 * would gain an entry keyed on a host name. Seen to fail
 * (host_cache_count grows by one) with the qtype guard in
 * dns_log_record removed. */
static void test_record_ptr_does_not_feed_host_cache_inverted(void) {
    dns_log_clear();
    host_cache_clear();
    dns_log_entry_t e = make_entry("8.8.8.8", "1.0.0.10.in-addr.arpa",
                                   "PTR", "host.example.net", 1);
    dns_log_record(&e);
    ASSERT_EQ(host_cache_count(), 0);
    char out[HOST_CACHE_HOSTLEN];
    ASSERT_EQ(host_cache_lookup("host.example.net", out, sizeof(out)), 0);
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

/* ── view_dns_draw ────────────────────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_dns_draw(&s);
    ASSERT_LINE_HAS(0, "DNS log: 0");
    ASSERT_SCREEN_HAS("(no DNS packets seen");
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
    ASSERT_LINE_HAS(0, "DNS log: 3");
    /* Newest first. The Time column is local time and not asserted. */
    int q  = runner_screen_find("reddit.com");
    int nx = runner_screen_find("ghost.local");
    int a  = runner_screen_find("google.com");
    ASSERT(q >= 0 && q < nx && nx < a);
    ASSERT_LINE_HAS(q,  "192.168.1.5      Q  AAAA");
    ASSERT_LINE_HAS(nx, "NXDOMAIN");
    ASSERT_LINE_HAS(a,  "R  A ");
    /* The Answer column lines up under its header on the selected row
     * (row 0, the query) and on the plain rows alike. The plain rows
     * carry a two-cell DGA-flag slot after the name that the header and
     * the selected row did not, so their answers sat two columns right
     * of "Answer". Seen to fail with the header's slot removed. */
    int col = runner_find_col(1, "Answer");
    ASSERT(col > 0);
    ASSERT_EQ(runner_find_col(a, "142.250.80.46"), col);
    ASSERT_EQ(runner_find_col(nx, "NXDOMAIN"), col);
    ASSERT_EQ(runner_find_col(q, "-"), col);
}

/* #165: a PTR row's answer is a host name in the row's last column,
 * shown whole rather than in an address's 15 cells. The A row is the
 * control: its answer keeps the 15-cell pad. Seen red (the line holds
 * "printer.office." only) with the PTR branch's `%s` put back to the
 * address width. */
static void test_view_draw_ptr_answer_whole(void) {
    dns_log_clear();
    dns_log_entry_t e1 = make_entry("192.0.2.53", "10.2.0.192.in-addr.arpa",
                                    "PTR", "printer.office.example.net", 1);
    dns_log_entry_t e2 = make_entry("192.0.2.53", "a.example", "A",
                                    "192.0.2.77", 1);
    dns_log_record(&e1);
    dns_log_record(&e2);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    dns_log_snapshot(&s);
    s.dns_log_sel = 0;          /* the A row: a selected row prints whole */
    view_dns_draw(&s);
    int y = runner_screen_find("printer.office.example.net");
    ASSERT(y >= 0);
    ASSERT_LINE_HAS(y, "PTR");
    dns_log_clear();
}

/* #165 review: at the 100-column minimum the columns before the
 * answer take 70 cells, so a 48-byte PTR target printed whole wraps
 * and every later row moves down one. The answer is clipped to the
 * row instead, on a plain row and on the selected row. Seen red (the
 * next record on y+2, y+1 holding the target's tail) with each
 * branch's answer_room() put back to a bare "%s", one at a time. */
static void test_view_draw_long_ptr_answer_clips_at_100_cols(void) {
    static const char target[] =
        "ec2-203-0-113-25.us-west-2.compute.amazonaws.com";
    dns_log_clear();
    dns_log_entry_t older = make_entry("192.0.2.53", "after.example", "A",
                                       "192.0.2.77", 1);
    dns_log_entry_t ptr = make_entry("192.0.2.53", "25.113.0.203.in-addr.arpa",
                                     "PTR", target, 1);
    ASSERT_STR(ptr.answer, target);
    dns_log_record(&older);
    dns_log_record(&ptr);
    ASSERT_EQ(tui_init_offscreen(TEST_SCREEN_ROWS, 100), 0);
    for (int sel = 1; sel >= 0; sel--) {     /* the PTR row plain, then selected */
        sloth_state_t s; memset(&s, 0, sizeof(s));
        dns_log_snapshot(&s);
        s.dns_log_sel = sel;
        tui_test_erase();
        view_dns_draw(&s);
        int y = runner_screen_find("in-addr.arpa");
        ASSERT(y >= 0);
        ASSERT_LINE_HAS(y, "ec2-203-0-113-25.us-west");
        ASSERT_EQ(runner_screen_find("after.example"), y + 1);
    }
    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
    dns_log_clear();
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

/* #138: a label may carry any octet (RFC 2181 §11); the stored qname
 * maps C0/DEL to '?'. Mutation-proved: the qname store back to
 * snprintf("%s") reddens it. */
static void test_qname_control_octets_marked(void) {
    static const uint8_t name[] = {
        0x04,'t',0x0a,'s',0x1b,
        0x07,'e','x','a','m','p','l','e',
        0x00
    };
    uint8_t buf[64];
    int len = build_query(buf, sizeof(buf), name, (int)sizeof(name), 1);
    dns_log_entry_t e;
    ASSERT_EQ(dns_log_parse(buf, len, "192.168.1.5", &e), 1);
    ASSERT_STR(e.qname, "t?s?.example");
}

void run_dns_log_tests(void) {
    TEST_SUITE("dns_log parse");
    RUN_TEST(test_parse_query_a);
    RUN_TEST(test_parse_response_a);
    RUN_TEST(test_parse_nxdomain);
    RUN_TEST(test_parse_query_aaaa);
    RUN_TEST(test_parse_query_ptr);
    RUN_TEST(test_parse_response_ptr_no_compression);
    RUN_TEST(test_parse_response_ptr_compressed_target);
    RUN_TEST(test_parse_response_ptr_malformed_rr_is_skipped);
    RUN_TEST(test_parse_response_ptr_rdata_past_message);
    RUN_TEST(test_parse_response_ptr_after_cname);
    RUN_TEST(test_parse_response_mixed_a_and_ptr_prefers_a);
    RUN_TEST(test_parse_a_question_ignores_a_ptr_rr);
    RUN_TEST(test_parse_ptr_target_longer_than_an_address_is_whole);
    RUN_TEST(test_parse_ptr_target_that_would_be_cut_is_skipped);
    RUN_TEST(test_parse_ptr_target_must_be_the_whole_rdata);
    RUN_TEST(test_parse_ptr_root_target_is_skipped);
    RUN_TEST(test_parse_ptr_nxdomain_text_is_refused);
    RUN_TEST(test_parse_ptr_nxdomain_rcode);
    RUN_TEST(test_parse_query_mx);
    RUN_TEST(test_parse_unknown_qtype);
    RUN_TEST(test_parse_rejects_short);
    RUN_TEST(test_parse_rejects_no_question);
    RUN_TEST(test_parse_null_src_ok);
    RUN_TEST(test_parse_qname_over_63_sets_trunc);
    RUN_TEST(test_parse_qname_of_exactly_63_is_whole);
    RUN_TEST(test_parse_qname_with_nul_octet_sets_trunc);
    RUN_TEST(test_parse_short_qname_is_whole);

    TEST_SUITE("dns_log ring buffer");
    RUN_TEST(test_record_and_snapshot);
    RUN_TEST(test_record_ptr_does_not_feed_host_cache_inverted);
    RUN_TEST(test_snapshot_newest_first);
    RUN_TEST(test_clear_empties_log);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_snapshot_clamps_sel_at_exact_boundary);
    RUN_TEST(test_snapshot_empty_resets_sel_to_zero);

    TEST_SUITE("view_dns draw");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);
    RUN_TEST(test_view_draw_ptr_answer_whole);
    RUN_TEST(test_view_draw_long_ptr_answer_clips_at_100_cols);

    TEST_SUITE("view_dns key");
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
    RUN_TEST(test_qname_control_octets_marked);
}
