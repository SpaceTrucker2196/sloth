#include <string.h>
#include "runner.h"
#include "dns_snoop.h"
#include "dns.h"

/*
 * Raw DNS packet helpers.
 *
 * All test vectors are constructed by hand following RFC 1035 §4.
 * Layout reminder:
 *   Header  12 bytes: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
 *   Question: QNAME(variable) QTYPE(2) QCLASS(2)
 *   Answer RR: NAME(variable) TYPE(2) CLASS(2) TTL(4) RDLEN(2) RDATA(rdlen)
 *
 * "example.com" encoded inline:
 *   \x07 e x a m p l e \x03 c o m \x00   (17 bytes, starts at offset 12)
 * Compression pointer back to offset 12:
 *   \xC0 \x0C
 */

/* ── Packet builders ─────────────────────────────────────── */

/* Simple A-record response: example.com → 1.2.3.4 */
static const uint8_t pkt_a[] = {
    /* header */
    0x12, 0x34,             /* ID */
    0x81, 0x80,             /* QR=1, OPCODE=0, RD=1, RA=1 */
    0x00, 0x01,             /* QDCOUNT=1 */
    0x00, 0x01,             /* ANCOUNT=1 */
    0x00, 0x00,             /* NSCOUNT=0 */
    0x00, 0x00,             /* ARCOUNT=0 */
    /* question (offset 12) */
    0x07, 'e','x','a','m','p','l','e',   /* label "example" */
    0x03, 'c','o','m',                   /* label "com" */
    0x00,                                /* end of name */
    0x00, 0x01,             /* QTYPE=A */
    0x00, 0x01,             /* QCLASS=IN */
    /* answer (offset 29) */
    0xC0, 0x0C,             /* compressed name → offset 12 = "example.com" */
    0x00, 0x01,             /* TYPE=A */
    0x00, 0x01,             /* CLASS=IN */
    0x00, 0x00, 0x01, 0x2C, /* TTL=300 */
    0x00, 0x04,             /* RDLENGTH=4 */
    0x01, 0x02, 0x03, 0x04, /* RDATA=1.2.3.4 */
};

/* A-record response with two IPs: example.com → 1.2.3.4, 5.6.7.8 */
static const uint8_t pkt_a_multi[] = {
    0x00, 0x01,
    0x81, 0x80,
    0x00, 0x01,
    0x00, 0x02,   /* ANCOUNT=2 */
    0x00, 0x00,
    0x00, 0x00,
    /* question */
    0x07, 'e','x','a','m','p','l','e',
    0x03, 'c','o','m',
    0x00,
    0x00, 0x01,
    0x00, 0x01,
    /* answer 1 → 1.2.3.4 */
    0xC0, 0x0C,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x2C,
    0x00, 0x04,
    0x01, 0x02, 0x03, 0x04,
    /* answer 2 → 5.6.7.8 */
    0xC0, 0x0C,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x2C,
    0x00, 0x04,
    0x05, 0x06, 0x07, 0x08,
};

/* AAAA response: ipv6.example.com → 2001:db8::1 */
static const uint8_t pkt_aaaa[] = {
    0x00, 0x02,
    0x81, 0x80,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    /* question: "ipv6.example.com" */
    0x04, 'i','p','v','6',
    0x07, 'e','x','a','m','p','l','e',
    0x03, 'c','o','m',
    0x00,
    0x00, 0x1C,   /* QTYPE=AAAA */
    0x00, 0x01,
    /* answer */
    0xC0, 0x0C,   /* compressed → offset 12 */
    0x00, 0x1C,   /* TYPE=AAAA */
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2C,
    0x00, 0x10,   /* RDLENGTH=16 */
    /* 2001:0db8:0000:0000:0000:0000:0000:0001 */
    0x20, 0x01, 0x0d, 0xb8,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
};

/* Query (QR=0): should not inject into cache, info = "DNS qry ..." */
static const uint8_t pkt_query[] = {
    0x00, 0x03,
    0x01, 0x00,   /* QR=0, RD=1 */
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x07, 'e','x','a','m','p','l','e',
    0x03, 'c','o','m',
    0x00,
    0x00, 0x01,
    0x00, 0x01,
};

/* NXDOMAIN response: ANCOUNT=0 */
static const uint8_t pkt_nxdomain[] = {
    0x00, 0x04,
    0x81, 0x83,   /* QR=1, RCODE=3 (NXDOMAIN) */
    0x00, 0x01,
    0x00, 0x00,   /* ANCOUNT=0 */
    0x00, 0x00,
    0x00, 0x00,
    0x07, 'n','o','e','x','i','s','t',
    0x03, 'c','o','m',
    0x00,
    0x00, 0x01,
    0x00, 0x01,
};

/* CNAME-only response: no A record, should not inject IP */
static const uint8_t pkt_cname[] = {
    0x00, 0x05,
    0x81, 0x80,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    /* question: "www.example.com" */
    0x03, 'w','w','w',
    0x07, 'e','x','a','m','p','l','e',
    0x03, 'c','o','m',
    0x00,
    0x00, 0x01,
    0x00, 0x01,
    /* CNAME answer: www.example.com → example.com */
    0xC0, 0x0C,
    0x00, 0x05,   /* TYPE=CNAME */
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2C,
    0x00, 0x02,   /* RDLENGTH=2 (compressed name) */
    0xC0, 0x10,   /* → "example.com" at offset 16 */
};

/* Inline (uncompressed) name in answer RR */
static const uint8_t pkt_inline_name[] = {
    0x00, 0x06,
    0x81, 0x80,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x03, 'f','o','o',
    0x03, 'b','a','r',
    0x00,
    0x00, 0x01,
    0x00, 0x01,
    /* answer with inline name (not compressed) */
    0x03, 'f','o','o',
    0x03, 'b','a','r',
    0x00,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x00, 0x3C,
    0x00, 0x04,
    0x0A, 0x00, 0x00, 0x01,  /* 10.0.0.1 */
};

/* ── Tests ───────────────────────────────────────────────── */

static void test_snoop_a_record_info(void) {
    dns_reset();
    char info[64];
    int r = dns_snoop(pkt_a, (int)sizeof(pkt_a), info, sizeof(info));
    ASSERT_EQ(r, 1);
    /* info should mention "example.com" and "1.2.3.4" */
    ASSERT(strstr(info, "example.com") != NULL);
    ASSERT(strstr(info, "1.2.3.4") != NULL);
}

static void test_snoop_a_record_cache(void) {
    dns_reset();
    char info[64];
    dns_snoop(pkt_a, (int)sizeof(pkt_a), info, sizeof(info));
    /* dns_lookup should now return the snooped hostname */
    const char *host = dns_lookup("1.2.3.4");
    ASSERT_STR(host, "example.com");
}

static void test_snoop_a_multi_both_cached(void) {
    dns_reset();
    char info[64];
    dns_snoop(pkt_a_multi, (int)sizeof(pkt_a_multi), info, sizeof(info));
    ASSERT_STR(dns_lookup("1.2.3.4"), "example.com");
    ASSERT_STR(dns_lookup("5.6.7.8"), "example.com");
}

static void test_snoop_a_multi_info_shows_plus(void) {
    dns_reset();
    char info[64];
    dns_snoop(pkt_a_multi, (int)sizeof(pkt_a_multi), info, sizeof(info));
    /* "+1" should appear to indicate the second IP */
    ASSERT(strstr(info, "+1") != NULL);
}

static void test_snoop_aaaa_record_info(void) {
    dns_reset();
    char info[64];
    int r = dns_snoop(pkt_aaaa, (int)sizeof(pkt_aaaa), info, sizeof(info));
    ASSERT_EQ(r, 1);
    ASSERT(strstr(info, "ipv6.example.com") != NULL);
}

static void test_snoop_aaaa_record_cache(void) {
    dns_reset();
    char info[64];
    dns_snoop(pkt_aaaa, (int)sizeof(pkt_aaaa), info, sizeof(info));
    const char *host = dns_lookup("2001:db8::1");
    ASSERT_STR(host, "ipv6.example.com");
}

static void test_snoop_query_no_inject(void) {
    dns_reset();
    char info[64];
    int r = dns_snoop(pkt_query, (int)sizeof(pkt_query), info, sizeof(info));
    ASSERT_EQ(r, 1);
    /* info should say "qry" */
    ASSERT(strstr(info, "qry") != NULL);
    /* nothing injected into cache */
    const char *host = dns_lookup("1.2.3.4");
    /* still returns the raw IP (not resolved) */
    ASSERT_STR(host, "1.2.3.4");
}

static void test_snoop_query_info_contains_name(void) {
    dns_reset();
    char info[64];
    dns_snoop(pkt_query, (int)sizeof(pkt_query), info, sizeof(info));
    ASSERT(strstr(info, "example.com") != NULL);
}

static void test_snoop_nxdomain_no_inject(void) {
    dns_reset();
    char info[64];
    int r = dns_snoop(pkt_nxdomain, (int)sizeof(pkt_nxdomain), info, sizeof(info));
    ASSERT_EQ(r, 1);
    ASSERT(strstr(info, "noexist.com") != NULL);
    /* no IP injected */
    ASSERT(strstr(info, "→") == NULL);
}

static void test_snoop_cname_no_ip_inject(void) {
    dns_reset();
    char info[64];
    int r = dns_snoop(pkt_cname, (int)sizeof(pkt_cname), info, sizeof(info));
    ASSERT_EQ(r, 1);
    /* CNAME only: no IP → arrow in info */
    ASSERT(strstr(info, "→") == NULL);
}

static void test_snoop_inline_name_answer(void) {
    dns_reset();
    char info[64];
    int r = dns_snoop(pkt_inline_name, (int)sizeof(pkt_inline_name), info, sizeof(info));
    ASSERT_EQ(r, 1);
    ASSERT_STR(dns_lookup("10.0.0.1"), "foo.bar");
}

static void test_snoop_too_short_header(void) {
    dns_reset();
    char info[64] = "unchanged";
    uint8_t tiny[5] = {0x00,0x01,0x81,0x80,0x00};
    int r = dns_snoop(tiny, 5, info, sizeof(info));
    ASSERT_EQ(r, 0);
    /* info should be untouched */
    ASSERT_STR(info, "unchanged");
}

static void test_snoop_empty_buf(void) {
    dns_reset();
    char info[64] = "x";
    int r = dns_snoop(NULL, 0, info, sizeof(info));
    ASSERT_EQ(r, 0);
}

static void test_snoop_truncated_mid_question(void) {
    dns_reset();
    char info[64];
    /* valid header, but question section truncated after first label byte */
    uint8_t trunc[14] = {
        0x00,0x01, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
        0x07, 'e',   /* label length 7 but only 'e' follows — truncated */
    };
    int r = dns_snoop(trunc, 14, info, sizeof(info));
    ASSERT_EQ(r, 0);
}

static void test_snoop_truncated_mid_answer(void) {
    dns_reset();
    char info[64];
    /* complete question, answer truncated after RR name */
    int r = dns_snoop(pkt_a, (int)sizeof(pkt_a) - 4, info, sizeof(info));
    /* may or may not parse; must not crash */
    (void)r;
    ASSERT(1);
}

static void test_snoop_compression_loop_guard(void) {
    dns_reset();
    char info[64];
    /* Two pointers pointing at each other — infinite loop guard must fire */
    uint8_t loop[16] = {
        0x00,0x01, 0x81,0x80, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0xC0, 0x0C, /* question name: pointer → itself (offset 12) */
        0x00, 0x01,
    };
    int r = dns_snoop(loop, 16, info, sizeof(info));
    /* should return 0 (malformed) — crucially must not hang */
    ASSERT_EQ(r, 0);
}

static void test_snoop_info_prefix_response(void) {
    dns_reset();
    char info[64];
    dns_snoop(pkt_a, (int)sizeof(pkt_a), info, sizeof(info));
    /* response: starts with "DNS " not "DNS qry " */
    ASSERT(strncmp(info, "DNS ", 4) == 0);
    ASSERT(strstr(info, "qry") == NULL);
}

static void test_snoop_info_prefix_query(void) {
    dns_reset();
    char info[64];
    dns_snoop(pkt_query, (int)sizeof(pkt_query), info, sizeof(info));
    ASSERT(strncmp(info, "DNS qry ", 8) == 0);
}

static void test_snoop_does_not_overwrite_on_failure(void) {
    dns_reset();
    char info[64];
    strncpy(info, "original", sizeof(info));
    uint8_t bad[4] = {0x00,0x01,0x00,0x00};
    int r = dns_snoop(bad, 4, info, sizeof(info));
    ASSERT_EQ(r, 0);
    ASSERT_STR(info, "original");
}

/* Kills the line-65 `len < 12` header-size boundary (`<` -> `<=` and
 * `12 -> 13`): a 12-byte buffer is the minimum valid DNS message
 * (header only, all counts = 0). Must parse to a no-op success. */
static void test_snoop_header_only_no_questions(void) {
    dns_reset();
    char info[64];
    uint8_t hdr[12] = {
        0x00,0x01, 0x81,0x80,
        0x00,0x00,    /* QDCOUNT=0 */
        0x00,0x00,    /* ANCOUNT=0 */
        0x00,0x00,
        0x00,0x00,
    };
    int r = dns_snoop(hdr, 12, info, sizeof(info));
    /* Returns 1 with no qname; just confirm the length guard accepts
     * exactly-12-byte input. */
    ASSERT_EQ(r, 1);
}

/* Kills the line-113 `type == 1 && rdlen == 4` AND mutation:
 * a record of type != 1 (e.g. NS) with rdlen == 4 must NOT be
 * injected as an A record. Under the `&& -> ||` mutation, any record
 * with rdlen==4 would be misclassified as A. */
static void test_snoop_non_a_record_with_rdlen_4_not_injected(void) {
    dns_reset();
    char info[64];
    /* Forged response: TYPE=2 (NS) but RDLEN=4 (impossible per spec,
     * but the parser must filter by type, not rdlen). */
    uint8_t pkt[] = {
        0x00,0x01, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
        0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01,
        0xC0, 0x0C,
        0x00,0x02,            /* TYPE = NS */
        0x00,0x01,            /* CLASS = IN */
        0x00,0x00,0x01,0x2C,  /* TTL */
        0x00,0x04,            /* RDLEN = 4 */
        0x01,0x02,0x03,0x04,  /* fake "data" */
    };
    int r = dns_snoop(pkt, (int)sizeof(pkt), info, sizeof(info));
    ASSERT_EQ(r, 1);
    /* No "→ 1.2.3.4" suffix — info should contain just the qname. */
    ASSERT(strstr(info, "1.2.3.4") == NULL);
    /* And the DNS cache must not have learnt example.com → 1.2.3.4.
     * (dns_lookup returns the resolved host when RESOLVED, or the
     * IP string itself when PENDING/FAILED, or NULL when no entry.) */
    const char *got = dns_lookup("1.2.3.4");
    /* Either NULL (no entry) or the IP itself (pending state from
     * elsewhere); the resolved hostname "example.com" must not appear. */
    ASSERT(got == NULL || strcmp(got, "example.com") != 0);
}

/* Kills the line-113 AND from the rdlen side: a record of type==1
 * but rdlen != 4 (malformed A record) must not be injected. */
static void test_snoop_a_record_with_wrong_rdlen_not_injected(void) {
    dns_reset();
    char info[64];
    uint8_t pkt[] = {
        0x00,0x01, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
        0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01,
        0xC0, 0x0C,
        0x00,0x01,            /* TYPE = A */
        0x00,0x01,
        0x00,0x00,0x01,0x2C,
        0x00,0x05,            /* RDLEN = 5 (wrong for A) */
        0x01,0x02,0x03,0x04,0x05,
    };
    int r = dns_snoop(pkt, (int)sizeof(pkt), info, sizeof(info));
    ASSERT_EQ(r, 1);
    ASSERT(strstr(info, "1.2.3.4") == NULL);
}

/* Kills the line-125 `type == 28 && rdlen == 16` AND mutation:
 * a record with rdlen==16 but type != 28 must not be injected
 * as AAAA. */
static void test_snoop_non_aaaa_record_with_rdlen_16_not_injected(void) {
    dns_reset();
    char info[64];
    uint8_t pkt[] = {
        0x00,0x01, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
        0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x1C, 0x00,0x01,
        0xC0, 0x0C,
        0x00,0x29,            /* TYPE = OPT (41) -- not AAAA */
        0x00,0x01,
        0x00,0x00,0x01,0x2C,
        0x00,0x10,            /* RDLEN = 16 */
        0x20,0x01,0x0d,0xb8, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01,
    };
    int r = dns_snoop(pkt, (int)sizeof(pkt), info, sizeof(info));
    ASSERT_EQ(r, 1);
    ASSERT(strstr(info, "2001:db8") == NULL);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_dns_snoop_tests(void) {
    TEST_SUITE("dns snoop A record");
    RUN_TEST(test_snoop_a_record_info);
    RUN_TEST(test_snoop_a_record_cache);
    RUN_TEST(test_snoop_a_multi_both_cached);
    RUN_TEST(test_snoop_a_multi_info_shows_plus);

    TEST_SUITE("dns snoop AAAA record");
    RUN_TEST(test_snoop_aaaa_record_info);
    RUN_TEST(test_snoop_aaaa_record_cache);

    TEST_SUITE("dns snoop query / no-answer");
    RUN_TEST(test_snoop_query_no_inject);
    RUN_TEST(test_snoop_query_info_contains_name);
    RUN_TEST(test_snoop_nxdomain_no_inject);
    RUN_TEST(test_snoop_cname_no_ip_inject);

    TEST_SUITE("dns snoop name encoding");
    RUN_TEST(test_snoop_inline_name_answer);
    RUN_TEST(test_snoop_info_prefix_response);
    RUN_TEST(test_snoop_info_prefix_query);

    TEST_SUITE("dns snoop robustness");
    RUN_TEST(test_snoop_too_short_header);
    RUN_TEST(test_snoop_empty_buf);
    RUN_TEST(test_snoop_truncated_mid_question);
    RUN_TEST(test_snoop_truncated_mid_answer);
    RUN_TEST(test_snoop_compression_loop_guard);
    RUN_TEST(test_snoop_does_not_overwrite_on_failure);

    TEST_SUITE("dns snoop boundary");
    RUN_TEST(test_snoop_header_only_no_questions);
    RUN_TEST(test_snoop_non_a_record_with_rdlen_4_not_injected);
    RUN_TEST(test_snoop_a_record_with_wrong_rdlen_not_injected);
    RUN_TEST(test_snoop_non_aaaa_record_with_rdlen_16_not_injected);
}
