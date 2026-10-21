/* The allowed-peer list, on hand-built sockaddrs. No socket is opened
 * here: these are the addresses a test can never originate from
 * (192.168.x, 2001:db8::/32 documentation space), checked against the
 * same function the accept path calls. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "web_acl.h"
#include "wtest.h"

static int permits4(const web_acl_t *a, const char *ip) {
    struct sockaddr_in s;
    memset(&s, 0, sizeof(s));
    s.sin_family = AF_INET;
    s.sin_port   = htons(40000);
    if (inet_pton(AF_INET, ip, &s.sin_addr) != 1) return -1;
    return web_acl_permits(a, (struct sockaddr *)&s, sizeof(s));
}

static int permits6(const web_acl_t *a, const char *ip) {
    struct sockaddr_in6 s;
    memset(&s, 0, sizeof(s));
    s.sin6_family = AF_INET6;
    s.sin6_port   = htons(40000);
    if (inet_pton(AF_INET6, ip, &s.sin6_addr) != 1) return -1;
    return web_acl_permits(a, (struct sockaddr *)&s, sizeof(s));
}

static void add(web_acl_t *a, const char *cidr) {
    web_acl_entry_t e;
    char err[128];
    WT_EQ(web_acl_parse_entry(cidr, &e, err, sizeof(err)), 0);
    WT_EQ(web_acl_add(a, &e), 0);
}

static void test_default_is_loopback_only(void) {
    web_acl_t a;
    web_acl_init_loopback(&a);
    WT_EQ(permits4(&a, "127.0.0.1"), 1);
    WT_EQ(permits4(&a, "127.255.255.254"), 1);
    WT_EQ(permits6(&a, "::1"), 1);
    WT_EQ(permits6(&a, "::ffff:127.0.0.1"), 1);   /* dual-stack form */

    /* Absence: everything else is refused. Seen red with the family
     * check in web_acl_permits() dropped and with the default list
     * widened to 0.0.0.0/0. */
    WT_EQ(permits4(&a, "192.168.1.5"), 0);
    WT_EQ(permits4(&a, "10.0.0.1"), 0);
    WT_EQ(permits4(&a, "128.0.0.1"), 0);
    WT_EQ(permits4(&a, "0.0.0.0"), 0);
    WT_EQ(permits6(&a, "2001:db8::1"), 0);
    WT_EQ(permits6(&a, "::2"), 0);
    WT_EQ(permits6(&a, "::"), 0);
    WT_EQ(permits6(&a, "fe80::1"), 0);
    WT_EQ(permits6(&a, "::ffff:192.168.1.5"), 0);
    /* ::127.0.0.1 is the deprecated IPv4-compatible form, not mapped:
     * it is not loopback and must not be folded into 127/8. */
    WT_EQ(permits6(&a, "::127.0.0.1"), 0);
}

static void test_other_families_refused(void) {
    web_acl_t a;
    web_acl_init_loopback(&a);
    struct sockaddr s;
    memset(&s, 0, sizeof(s));
    s.sa_family = AF_UNIX;
    WT_EQ(web_acl_permits(&a, &s, sizeof(s)), 0);
    WT_EQ(web_acl_permits(&a, NULL, 0), 0);

    /* A truncated sockaddr is refused rather than read past. */
    struct sockaddr_in s4;
    memset(&s4, 0, sizeof(s4));
    s4.sin_family = AF_INET;
    s4.sin_addr.s_addr = htonl(0x7f000001);
    WT_EQ(web_acl_permits(&a, (struct sockaddr *)&s4, 4), 0);
}

static void test_extension_v4(void) {
    web_acl_t a;
    web_acl_init_loopback(&a);
    add(&a, "192.168.1.0/24");
    add(&a, "10.16.0.0/12");
    WT_EQ(permits4(&a, "192.168.1.5"), 1);
    WT_EQ(permits4(&a, "192.168.1.255"), 1);
    WT_EQ(permits4(&a, "192.168.2.5"), 0);
    /* /12: a prefix that does not end on a byte boundary. */
    WT_EQ(permits4(&a, "10.16.0.1"), 1);
    WT_EQ(permits4(&a, "10.31.255.255"), 1);
    WT_EQ(permits4(&a, "10.32.0.0"), 0);
    WT_EQ(permits4(&a, "10.15.255.255"), 0);
    /* Loopback is still admitted: --web-allow extends, never replaces. */
    WT_EQ(permits4(&a, "127.0.0.1"), 1);
    /* A v4 entry admits the same peer reported by a v6 socket. */
    WT_EQ(permits6(&a, "::ffff:192.168.1.5"), 1);
    WT_EQ(permits6(&a, "::ffff:192.168.2.5"), 0);
}

static void test_extension_v6_and_host(void) {
    web_acl_t a;
    web_acl_init_loopback(&a);
    add(&a, "2001:db8::/32");
    add(&a, "fd00::7");
    add(&a, "198.51.100.7");
    WT_EQ(permits6(&a, "2001:db8:ffff::1"), 1);
    WT_EQ(permits6(&a, "2001:db9::1"), 0);
    WT_EQ(permits6(&a, "fd00::7"), 1);
    WT_EQ(permits6(&a, "fd00::8"), 0);
    WT_EQ(permits4(&a, "198.51.100.7"), 1);
    WT_EQ(permits4(&a, "198.51.100.8"), 0);
}

static void test_mapped_entry_folds_to_v4(void) {
    web_acl_entry_t e;
    char err[128];
    WT_EQ(web_acl_parse_entry("::ffff:192.0.2.0/120", &e, err, sizeof(err)), 0);
    WT_EQ(e.family, AF_INET);
    WT_EQ(e.prefix, 24);
    web_acl_t a;
    web_acl_init_loopback(&a);
    WT_EQ(web_acl_add(&a, &e), 0);
    WT_EQ(permits4(&a, "192.0.2.9"), 1);
    WT_EQ(permits6(&a, "::ffff:192.0.2.9"), 1);
}

static void test_parse_rejects(void) {
    static const char *bad[] = {
        "", "/", "/8", "10.0.0.0/", "10.0.0.0/33", "::/129", "10.0.0.0/8x",
        "10.0.0.0/-1", "10.0.0.0/+8", "10.0.0.0/0008", "10.0.0.1/8",
        "2001:db8::1/32", "localhost", "example.org", "10.0.0", "1.2.3.4.5",
        "[::1]", "10.0.0.0/8/8", " 10.0.0.1", "10.0.0.256",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        web_acl_entry_t e;
        char err[128] = "";
        int rc = web_acl_parse_entry(bad[i], &e, err, sizeof(err));
        if (rc != -1) fprintf(stderr, "    accepted bad entry \"%s\"\n", bad[i]);
        WT_EQ(rc, -1);
        WT_ASSERT(err[0] != '\0');
    }
    web_acl_entry_t e;
    char err[128];
    WT_EQ(web_acl_parse_entry("0.0.0.0/0", &e, err, sizeof(err)), 0);
    WT_EQ(e.prefix, 0);
    WT_EQ(web_acl_parse_entry("::/0", &e, err, sizeof(err)), 0);
}

static void test_list_full(void) {
    web_acl_t a;
    web_acl_init_loopback(&a);
    web_acl_entry_t e;
    char err[64];
    WT_EQ(web_acl_parse_entry("198.51.100.0/24", &e, err, sizeof(err)), 0);
    while (a.n < WEB_ACL_MAX) WT_EQ(web_acl_add(&a, &e), 0);
    WT_EQ(web_acl_add(&a, &e), -1);
    WT_EQ(a.n, WEB_ACL_MAX);
}

static void test_entry_loopback_classification(void) {
    static const struct { const char *cidr; int lo; } cases[] = {
        { "127.0.0.0/8", 1 }, { "127.0.0.1", 1 }, { "127.10.0.0/16", 1 },
        { "::1", 1 }, { "::ffff:127.0.0.1", 1 },
        { "0.0.0.0/0", 0 }, { "64.0.0.0/2", 0 }, { "126.0.0.0/7", 0 },
        { "::/0", 0 }, { "::/127", 0 }, { "10.0.0.0/8", 0 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        web_acl_entry_t e;
        char err[64];
        WT_EQ(web_acl_parse_entry(cases[i].cidr, &e, err, sizeof(err)), 0);
        int lo = web_acl_entry_is_loopback(&e);
        if (lo != cases[i].lo) fprintf(stderr, "    %s\n", cases[i].cidr);
        WT_EQ(lo, cases[i].lo);
    }
    char buf[64];
    web_acl_entry_t e;
    char err[64];
    WT_EQ(web_acl_parse_entry("2001:db8::/32", &e, err, sizeof(err)), 0);
    web_acl_entry_format(&e, buf, sizeof(buf));
    WT_HAS(buf, "2001:db8::/32");
}

void run_acl_tests(void) {
    WT_RUN(test_default_is_loopback_only);
    WT_RUN(test_other_families_refused);
    WT_RUN(test_extension_v4);
    WT_RUN(test_extension_v6_and_host);
    WT_RUN(test_mapped_entry_folds_to_v4);
    WT_RUN(test_parse_rejects);
    WT_RUN(test_list_full);
    WT_RUN(test_entry_loopback_classification);
}
