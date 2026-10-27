#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"
#include "captive_portal.h"
#include "http_log.h"
#include "alerts.h"
#include "ownership.h"
#include "sloth_clock.h"
#include "jsonl.h"
#include <unistd.h>
#include "tmp_dir.h"

/*
 * Captive-portal interception — issue #69.
 *
 * The sentinels are published, fixed values, so unlike the tool
 * fingerprints in #68 this table ships full. What these tests pin is
 * the thing that is easy to get wrong: **when the detector is allowed
 * to speak.** A body sloth did not see whole cannot be compared, and a
 * comparison made anyway turns every large page into a reported hijack.
 */

static void mk_resp(http_log_entry_t *e, const char *host, const char *path,
                    uint16_t status, const char *body, int complete) {
    memset(e, 0, sizeof(*e));
    e->is_response = 1;
    e->status = status;
    snprintf(e->host, sizeof(e->host), "%s", host);
    snprintf(e->path, sizeof(e->path), "%s", path);
    if (body) {
        int n = (int)strlen(body);
        if (n > HTTP_RESP_BODY_MAX) n = HTTP_RESP_BODY_MAX;
        memcpy(e->resp_body, body, (size_t)n);
        e->resp_body_len = n;
        e->content_length = n;
    }
    e->body_complete = complete;
}

/* The page as captive.apple.com served it on 2026-10-26: 69 bytes,
 * ending in one LF (research/tools/connectivity-check-sentinels.md). */
static const char *APPLE_OK =
    "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>\n";

/* ── the body check ── */

/* The genuine answer is quiet. An absence claim: seen red with the
 * table row's trailing "\n" removed, which is the shape that read every
 * real Apple answer as a hijack. */
static void test_correct_apple_sentinel_is_quiet(void) {
    http_log_entry_t e;
    ASSERT_EQ((int)strlen(APPLE_OK), 69);
    mk_resp(&e, "captive.apple.com", "/hotspot-detect.html", 200,
            APPLE_OK, 1);
    ASSERT_EQ(e.content_length, 69);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_wrong_apple_body_is_a_hijack(void) {
    http_log_entry_t e;
    mk_resp(&e, "captive.apple.com", "/hotspot-detect.html", 200,
            "<html>Sign in to continue</html>", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
}

static void test_redirect_on_the_sentinel_is_a_hijack(void) {
    /* The classic portal: a 302 to the login page. */
    http_log_entry_t e;
    mk_resp(&e, "captive.apple.com", "/hotspot-detect.html", 302, "", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
}

static void test_incomplete_body_never_fires(void) {
    /* **The assertion this detector rests on.** sloth does not
     * reassemble TCP, so a prefix that differs from the sentinel is
     * evidence of a segment boundary, not of interception. Comparing
     * anyway would report every large page on port 80 as a hijack. */
    http_log_entry_t e;
    mk_resp(&e, "captive.apple.com", "/hotspot-detect.html", 200,
            "<html>Sign in to continue</html>", 0 /* incomplete */);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_google_204_with_a_body_is_a_hijack(void) {
    /* A 204 that arrives with content is not a 204. */
    http_log_entry_t e;
    mk_resp(&e, "connectivitycheck.gstatic.com", "/generate_204", 204,
            "redirecting", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);

    mk_resp(&e, "connectivitycheck.gstatic.com", "/generate_204", 204,
            NULL, 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_google_wrong_status_is_a_hijack(void) {
    http_log_entry_t e;
    mk_resp(&e, "connectivitycheck.gstatic.com", "/generate_204", 200,
            NULL, 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
}

static void test_microsoft_and_firefox_sentinels(void) {
    http_log_entry_t e;
    mk_resp(&e, "www.msftconnecttest.com", "/connecttest.txt", 200,
            "Microsoft Connect Test", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
    mk_resp(&e, "www.msftconnecttest.com", "/connecttest.txt", 200,
            "Microsoft Connect Test\n", 1);      /* one byte different */
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);

    mk_resp(&e, "detectportal.firefox.com", "/success.txt", 200,
            "success\n", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_non_sentinel_host_is_ignored(void) {
    /* Ordinary web traffic must not be compared against anything. */
    http_log_entry_t e;
    mk_resp(&e, "example.com", "/index.html", 200, "anything at all", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_sentinel_host_wrong_path_is_ignored(void) {
    http_log_entry_t e;
    mk_resp(&e, "captive.apple.com", "/library/test/success.html", 200,
            "something else", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

static void test_host_match_is_case_insensitive(void) {
    http_log_entry_t e;
    mk_resp(&e, "CAPTIVE.APPLE.COM", "/hotspot-detect.html", 200,
            "wrong", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
}

static void test_path_prefix_tolerates_a_cache_buster(void) {
    http_log_entry_t e;
    mk_resp(&e, "detectportal.firefox.com", "/success.txt?ipv4", 200,
            "success\n", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
}

/* ── the DNS check ── */

static void test_sentinel_resolving_into_private_space(void) {
    ASSERT_EQ(cp_check_dns("captive.apple.com", "192.168.1.1"),
              CP_KIND_DNS_SPOOF);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "10.0.0.1"),
              CP_KIND_DNS_SPOOF);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "172.16.5.9"),
              CP_KIND_DNS_SPOOF);
    /* CGNAT — a carrier or a portal appliance, and either way not Apple. */
    ASSERT_EQ(cp_check_dns("captive.apple.com", "100.64.3.2"),
              CP_KIND_DNS_SPOOF);
}

static void test_172_range_boundaries(void) {
    /* 172.16-31 is private; 172.15 and 172.32 are not. Getting this
     * wrong either misses a portal or accuses a public host. */
    ASSERT_EQ(cp_check_dns("captive.apple.com", "172.15.0.1"),
              CP_KIND_DNS_UNEXPECTED);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "172.32.0.1"),
              CP_KIND_DNS_UNEXPECTED);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "172.31.255.254"),
              CP_KIND_DNS_SPOOF);
}

static void test_apple_public_range_is_clean(void) {
    ASSERT_EQ(cp_check_dns("captive.apple.com", "17.253.144.10"), 0);
}

static void test_apple_outside_its_range_is_unexpected_not_spoof(void) {
    /* Being wrong about a CDN range must not produce a CRIT. */
    ASSERT_EQ(cp_check_dns("captive.apple.com", "93.184.216.34"),
              CP_KIND_DNS_UNEXPECTED);
}

static void test_non_sentinel_dns_ignored(void) {
    ASSERT_EQ(cp_check_dns("example.com", "192.168.1.1"), 0);
}

static void test_nxdomain_is_not_an_address(void) {
    ASSERT_EQ(cp_check_dns("captive.apple.com", "NXDOMAIN"), 0);
    ASSERT_EQ(cp_check_dns("captive.apple.com", ""), 0);
}

static void test_ipv6_private_ranges(void) {
    ASSERT_EQ(cp_check_dns("captive.apple.com", "fd00::1"),
              CP_KIND_DNS_SPOOF);
    ASSERT_EQ(cp_check_dns("captive.apple.com", "fe80::1"),
              CP_KIND_DNS_SPOOF);
    /* A public v6 address gets no opinion — the range lists are v4. */
    ASSERT_EQ(cp_check_dns("captive.apple.com", "2001:db8::1"), 0);
}

/* ── the TLS check ── */

static void test_sentinel_tls_to_a_private_address(void) {
    ASSERT_EQ(cp_check_tls("captive.apple.com", "192.168.1.1"),
              CP_KIND_TLS_MITM);
}

static void test_sentinel_tls_to_a_public_address_is_clean(void) {
    ASSERT_EQ(cp_check_tls("captive.apple.com", "17.253.144.10"), 0);
}

static void test_non_sentinel_tls_ignored(void) {
    /* Plenty of legitimate services live on private addresses. */
    ASSERT_EQ(cp_check_tls("intranet.example", "192.168.1.1"), 0);
}

/* ── the event ring ── */

static void test_events_recorded_newest_first(void) {
    cp_clear();
    cp_record(CP_KIND_HIJACK,    "captive.apple.com", "10.0.0.5", "a", 100);
    cp_record(CP_KIND_DNS_SPOOF, "www.gstatic.com",   "10.0.0.6", "b", 200);
    ASSERT_EQ(cp_event_count(), 2);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cp_snapshot(&s);
    ASSERT_EQ(s.cp_event_count, 2);
    ASSERT_STR(s.cp_events[0].host, "www.gstatic.com");
    ASSERT_STR(s.cp_events[1].host, "captive.apple.com");
    cp_clear();
}

static void test_zero_kind_is_not_recorded(void) {
    cp_clear();
    cp_record(0, "captive.apple.com", "10.0.0.5", NULL, 100);
    ASSERT_EQ(cp_event_count(), 0);
    cp_clear();
}

static void test_every_kind_has_a_label(void) {
    ASSERT(cp_kind_label(CP_KIND_HIJACK)[0]         != '\0');
    ASSERT(cp_kind_label(CP_KIND_DNS_SPOOF)[0]      != '\0');
    ASSERT(cp_kind_label(CP_KIND_DNS_UNEXPECTED)[0] != '\0');
    ASSERT(cp_kind_label(CP_KIND_TLS_MITM)[0]       != '\0');
    ASSERT_STR(cp_kind_label(0), "");
}

static void test_sentinel_host_recognition(void) {
    ASSERT_EQ(cp_is_sentinel_host("captive.apple.com"), 1);
    ASSERT_EQ(cp_is_sentinel_host("detectportal.firefox.com"), 1);
    ASSERT_EQ(cp_is_sentinel_host("example.com"), 0);
    ASSERT_EQ(cp_is_sentinel_host(""), 0);
    ASSERT_EQ(cp_is_sentinel_host(NULL), 0);
}


/* ── #169: the two sentinels #69 lacked ── */

/* The two quiet cases are absence claims, and the table row is what
 * makes them quiet: seen red with the NCSI row's body given a trailing
 * newline, and separately with the clients3 row's status set to 200. */
static void test_ncsi_and_clients3_sentinels(void) {
    http_log_entry_t e;
    mk_resp(&e, "www.msftncsi.com", "/ncsi.txt", 200, "Microsoft NCSI", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
    mk_resp(&e, "www.msftncsi.com", "/ncsi.txt", 200, "Microsoft NCSI\n", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
    mk_resp(&e, "clients3.google.com", "/generate_204", 204, NULL, 1);
    ASSERT_EQ(cp_check_response(&e), 0);
    mk_resp(&e, "clients3.google.com", "/generate_204", 302, NULL, 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
    ASSERT_EQ(cp_is_sentinel_host("www.msftncsi.com"), 1);
    ASSERT_EQ(cp_is_sentinel_host("clients3.google.com"), 1);
}

/* NCSI's IPv6 probe hosts. The quiet cases are absence claims: seen red
 * with each row's body given a trailing newline in turn. Before these
 * rows the host was not a sentinel at all, so a hijacked v6 probe was
 * missed by all three checks; the DNS and TLS asserts pin that. */
static void test_ncsi_ipv6_sentinels(void) {
    http_log_entry_t e;
    mk_resp(&e, "ipv6.msftconnecttest.com", "/connecttest.txt", 200,
            "Microsoft Connect Test", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
    mk_resp(&e, "ipv6.msftconnecttest.com", "/connecttest.txt", 302, "", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
    mk_resp(&e, "ipv6.msftncsi.com", "/ncsi.txt", 200, "Microsoft NCSI", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
    mk_resp(&e, "ipv6.msftncsi.com", "/ncsi.txt", 200,
            "<html>Please sign in</html>", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
    ASSERT_EQ(cp_check_dns("ipv6.msftconnecttest.com", "fd00::1"),
              CP_KIND_DNS_SPOOF);
    ASSERT_EQ(cp_check_tls("ipv6.msftncsi.com", "fe80::1"),
              CP_KIND_TLS_MITM);
    /* Deliberately not a sentinel: its expected answer is a ULA. */
    ASSERT_EQ(cp_is_sentinel_host("dns.msftncsi.com"), 0);
}

/* Firefox's captive-portal service, both generations: canonical.html on
 * detectportal (ESR 115 to 140) and the empty 204 on
 * firefox-portal-detection.com (release). The quiet cases are absence
 * claims, seen red with the canonical row's body given a trailing
 * newline and, separately, the new host's 204 row set to 200. */
static const char FIREFOX_CANONICAL[] =
    "<meta http-equiv=\"refresh\" "
    "content=\"0;url=https://support.mozilla.org/kb/captive-portal\"/>";

static void test_firefox_canonical_sentinels(void) {
    http_log_entry_t e;
    ASSERT_EQ((int)strlen(FIREFOX_CANONICAL), 90);
    mk_resp(&e, "detectportal.firefox.com", "/canonical.html", 200,
            FIREFOX_CANONICAL, 1);
    ASSERT_EQ(cp_check_response(&e), 0);
    mk_resp(&e, "detectportal.firefox.com", "/canonical.html", 200,
            "<html>Sign in to continue</html>", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
    /* success.txt's body on the canonical URL is still the wrong body. */
    mk_resp(&e, "detectportal.firefox.com", "/canonical.html", 200,
            "success\n", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);

    mk_resp(&e, "firefox-portal-detection.com", "/generate_204", 204,
            NULL, 1);
    ASSERT_EQ(cp_check_response(&e), 0);
    mk_resp(&e, "firefox-portal-detection.com", "/generate_204", 302,
            NULL, 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
    mk_resp(&e, "firefox-portal-detection.com", "/success.txt?ipv6", 200,
            "success\n", 1);
    ASSERT_EQ(cp_check_response(&e), 0);
    mk_resp(&e, "firefox-portal-detection.com", "/success.txt?ipv6", 200,
            "<html>portal</html>", 1);
    ASSERT_EQ(cp_check_response(&e), CP_KIND_HIJACK);
}

/* ── #169: request and response off the wire, per vendor ──
 *
 * The bytes a client sends and a server answers, in RFC 9112 message
 * syntax (§3 request-line, §4 status-line, §5 field lines, §6 body).
 * Each goes through the real request parser, the flow pairing and the
 * response parser before the check sees it: the check's host and path
 * come from the *request*, which is the half #69's tests never built. */

#define CLI "192.168.4.20"
#define SRV "17.253.144.10"

static int wire_check(const char *req, const char *resp) {
    http_log_clear();
    http_log_entry_t rq, rs;
    if (!http_log_parse((const uint8_t *)req, (int)strlen(req), CLI, &rq))
        return -1;
    snprintf(rq.dst, sizeof(rq.dst), "%s", SRV);
    rq.src_port = 50123; rq.dst_port = 80;
    http_log_record(&rq);
    if (!http_log_parse_response((const uint8_t *)resp, (int)strlen(resp),
                                 SRV, &rs))
        return -2;
    snprintf(rs.dst, sizeof(rs.dst), "%s", CLI);
    rs.src_port = 80; rs.dst_port = 50123;
    if (!http_log_pair_response(&rs)) return -3;
    int k = cp_check_response(&rs);
    http_log_clear();
    return k;
}

static const char REQ_APPLE[] =
    "GET /hotspot-detect.html HTTP/1.0\r\n"
    "Host: captive.apple.com\r\n"
    "Connection: close\r\n"
    "User-Agent: CaptiveNetworkSupport-481.0.1 wispr\r\n"
    "\r\n";
static const char RESP_APPLE_OK[] =
    "HTTP/1.0 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 69\r\n"
    "\r\n"
    "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>\n";
/* The hotel shape: the portal answers the probe with a redirect to its
 * own sign-in page and no body. */
static const char RESP_HOTEL_302[] =
    "HTTP/1.1 302 Found\r\n"
    "Location: http://portal.hotel.example/login?orig=captive.apple.com\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

static const char REQ_MSFT[] =
    "GET /connecttest.txt HTTP/1.1\r\n"
    "Connection: Close\r\n"
    "User-Agent: Microsoft NCSI\r\n"
    "Host: www.msftconnecttest.com\r\n"
    "\r\n";
static const char RESP_MSFT_OK[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 22\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "Microsoft Connect Test";
static const char RESP_MSFT_PORTAL[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 27\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<html>Please sign in</html>";

static const char REQ_NCSI[] =
    "GET /ncsi.txt HTTP/1.1\r\n"
    "Connection: Close\r\n"
    "User-Agent: Microsoft NCSI\r\n"
    "Host: www.msftncsi.com\r\n"
    "\r\n";
static const char RESP_NCSI_OK[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 14\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "Microsoft NCSI";

static const char REQ_GSTATIC[] =
    "GET /generate_204 HTTP/1.1\r\n"
    "User-Agent: Dalvik/2.1.0 (Linux; U; Android 14)\r\n"
    "Host: connectivitycheck.gstatic.com\r\n"
    "Connection: Keep-Alive\r\n"
    "\r\n";
static const char REQ_CLIENTS3[] =
    "GET /generate_204 HTTP/1.1\r\n"
    "Host: clients3.google.com\r\n"
    "Connection: Keep-Alive\r\n"
    "\r\n";
static const char RESP_204[] =
    "HTTP/1.1 204 No Content\r\n"
    "Content-Length: 0\r\n"
    "Date: Mon, 26 Oct 2026 12:00:00 GMT\r\n"
    "\r\n";
static const char RESP_200_EMPTY[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

static const char REQ_FIREFOX[] =
    "GET /success.txt?ipv4 HTTP/1.1\r\n"
    "Host: detectportal.firefox.com\r\n"
    "Cache-Control: no-cache\r\n"
    "\r\n";
static const char RESP_FIREFOX_OK[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 8\r\n"
    "\r\n"
    "success\n";

static const char REQ_FIREFOX_CANONICAL[] =
    "GET /canonical.html HTTP/1.1\r\n"
    "Host: detectportal.firefox.com\r\n"
    "Cache-Control: no-cache\r\n"
    "\r\n";
static const char RESP_FIREFOX_CANONICAL_OK[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 90\r\n"
    "\r\n"
    "<meta http-equiv=\"refresh\" "
    "content=\"0;url=https://support.mozilla.org/kb/captive-portal\"/>";

static const char REQ_MSFT_V6[] =
    "GET /connecttest.txt HTTP/1.1\r\n"
    "Connection: Close\r\n"
    "User-Agent: Microsoft NCSI\r\n"
    "Host: ipv6.msftconnecttest.com\r\n"
    "\r\n";

static void test_wire_apple(void) {
    ASSERT_EQ(wire_check(REQ_APPLE, RESP_APPLE_OK), 0);
    ASSERT_EQ(wire_check(REQ_APPLE, RESP_HOTEL_302), CP_KIND_HIJACK);
}

static void test_wire_microsoft(void) {
    ASSERT_EQ(wire_check(REQ_MSFT, RESP_MSFT_OK), 0);
    ASSERT_EQ(wire_check(REQ_MSFT, RESP_MSFT_PORTAL), CP_KIND_HIJACK);
    ASSERT_EQ(wire_check(REQ_NCSI, RESP_NCSI_OK), 0);
    /* connecttest's body on the NCSI URL is still the wrong body. */
    ASSERT_EQ(wire_check(REQ_NCSI, RESP_MSFT_OK), CP_KIND_HIJACK);
    ASSERT_EQ(wire_check(REQ_MSFT_V6, RESP_MSFT_OK), 0);
    ASSERT_EQ(wire_check(REQ_MSFT_V6, RESP_MSFT_PORTAL), CP_KIND_HIJACK);
}

static void test_wire_google(void) {
    ASSERT_EQ(wire_check(REQ_GSTATIC, RESP_204), 0);
    ASSERT_EQ(wire_check(REQ_GSTATIC, RESP_HOTEL_302), CP_KIND_HIJACK);
    ASSERT_EQ(wire_check(REQ_CLIENTS3, RESP_204), 0);
    /* A 200 with no body: a walled garden that answers but not with 204. */
    ASSERT_EQ(wire_check(REQ_CLIENTS3, RESP_200_EMPTY), CP_KIND_HIJACK);
}

static void test_wire_firefox(void) {
    ASSERT_EQ(wire_check(REQ_FIREFOX, RESP_FIREFOX_OK), 0);
    ASSERT_EQ(wire_check(REQ_FIREFOX, RESP_HOTEL_302), CP_KIND_HIJACK);
    ASSERT_EQ(wire_check(REQ_FIREFOX_CANONICAL, RESP_FIREFOX_CANONICAL_OK), 0);
    ASSERT_EQ(wire_check(REQ_FIREFOX_CANONICAL, RESP_HOTEL_302),
              CP_KIND_HIJACK);
}

static void test_wire_truncated_body_never_judged(void) {
    /* Content-Length promises 69, the segment carries 20: a segment
     * boundary, not an interception. The cut is real bytes off
     * RESP_APPLE_OK, not a hand-picked prefix. */
    char cut[sizeof(RESP_APPLE_OK)];
    int hdr = (int)(strstr(RESP_APPLE_OK, "\r\n\r\n") - RESP_APPLE_OK) + 4;
    snprintf(cut, sizeof(cut), "%.*s", hdr + 20, RESP_APPLE_OK);
    ASSERT_EQ(wire_check(REQ_APPLE, cut), 0);
    /* Headers with no terminator carry no body to judge. Both seen red
     * with cp_check_response()'s body_complete gate removed. */
    snprintf(cut, sizeof(cut), "%.*s", hdr - 4, RESP_APPLE_OK);
    ASSERT_EQ(wire_check(REQ_APPLE, cut), 0);
}

/* ── #169: kit fingerprints ──
 *
 * Each response is the kit's first segment as its source writes it: the
 * banner its web stack sets and the opening of the page it serves,
 * copied from the file research/tools/captive-portal-kits.md names.
 * Headers other than the fingerprinted one are ordinary filler, so a
 * match is shown not to depend on header order or neighbours. */

static int kit(const char *seg, const char **label) {
    return cp_match_kit((const uint8_t *)seg, (int)strlen(seg), label);
}

static const char WP_FIRMWARE[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: TornadoServer/6.4\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Date: Mon, 26 Oct 2026 12:00:00 GMT\r\n"
    "Content-Length: 4096\r\n"
    "\r\n"
    "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
    "  <title>Router Configuration Page</title>\n"
    "  <meta charset=\"utf-8\">\n";
static const char WP_OAUTH[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Server: TornadoServer/5.1.1\r\n"
    "\r\n"
    "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">\n<!--\n"
    "Copyright (c) 2016 by Andy Tran (http://codepen.io/andytran/pen/PwoQgO)\n";
static const char WP_PLUGIN[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: TornadoServer/6.4\r\n"
    "\r\n"
    "<!DOCTYPE html>\n<html>\n   \n   <head>\n"
    "      <link rel=\"icon\" href=\"static/images/favicon.ico\">  \n"
    "      <title>Plugin Manager</title>\n";
static const char WP_WIFI_CONNECT[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: TornadoServer/6.4\r\n"
    "\r\n"
    "<!DOCTYPE html>\n<html>\n<head>\n        <script>\n"
    "            /**\n         * JavaScript Client Detection\n"
    "         * (C) viazenetti GmbH (Christian Ludwig)\n         */\n";
static const char EVIL_PORTAL[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "\r\n"
    "\n<HTML>\n    <HEAD>\n        <title>Evil Portal</title>\n"
    "    </HEAD>\n    <BODY>\n        <div style=\"text-align: center;\">\n"
    "            <h1>Evil Portal</h1>\n"
    "            <p>This is the default Evil Portal page.</p>\n";
static const char PORTALAUTH[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx\r\n"
    "\r\n"
    "<html><head><title>Guest WiFi</title>\n"
    "<script type=\"text/javascript\" src=\"jquery-3.4.1.min.js\"></script>\n"
    "<script>$.ajax({ type: \"POST\", url: \"/captiveportal/index.php\" });</script>\n"
    "<style>\n#pa_overlay-back {\n\tposition: fixed;\n}\n</style>\n";
static const char AIRGEDDON[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Server: lighttpd/1.4.76\r\n"
    "\r\n"
    "<!DOCTYPE html>\n<html>\n\t<head>\n"
    "\t\t<meta name=\"viewport\" content=\"width=device-width\"/>\n"
    "\t\t<title>Internet Portal</title>\n"
    "\t\t<link rel=\"stylesheet\" type=\"text/css\" href=\"portal.css\"/>\n"
    "\t\t<script type=\"text/javascript\" src=\"portal.js\"></script>\n"
    "\t</head>\n\t<body>\n\t\t<img src=\"pixel.png\" style=\"display: none;\"/>\n"
    "\t\t<div class=\"content\">\n"
    "\t\t\t<form method=\"post\" id=\"loginform\" name=\"loginform\" action=\"check.htm\">\n";
static const char FLUXION_307[] =
    "HTTP/1.1 307 Temporary Redirect\r\n"
    "Location: http://captive.gateway.lan/\r\n"
    "Content-Length: 0\r\n"
    "Server: lighttpd/1.4.76\r\n"
    "\r\n";
static const char FLUXION_APPLE[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 187\r\n"
    "\r\n"
    "<html><script type=\"text/javascript\">window[\"_gaUserPrefs\"] = "
    "{ ioo : function() { return true; } }</script><head><title>Success"
    "</title><style></style></head><body>Success\n</body></html>\n";
static const char FLUXION_LOGIN[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<!DOCTYPE html>\n<html>\n    <head>\n        <meta charset=\"UTF-8\">\n"
    "        <title>Wireless Protected Access: Login</title>\n"
    "        <link rel=\"stylesheet\" type=\"text/css\" href=\"css/jquery.mobile-1.4.5.min.css\"/>\n";

static void test_each_kit_row_matches_its_page(void) {
    const char *l = NULL;
    ASSERT_EQ(kit(WP_FIRMWARE, &l), CP_KIT_WIFIPHISHER);
    ASSERT_STR(l, "wifiphisher firmware-upgrade");
    ASSERT_EQ(kit(WP_OAUTH, &l), CP_KIT_WIFIPHISHER);
    ASSERT_STR(l, "wifiphisher oauth-login");
    ASSERT_EQ(kit(WP_PLUGIN, &l), CP_KIT_WIFIPHISHER);
    ASSERT_STR(l, "wifiphisher plugin_update");
    ASSERT_EQ(kit(WP_WIFI_CONNECT, &l), CP_KIT_WIFIPHISHER);
    ASSERT_STR(l, "wifiphisher wifi_connect");
    ASSERT_EQ(kit(EVIL_PORTAL, &l), CP_KIT_EVILPORTAL);
    ASSERT_EQ(kit(PORTALAUTH, &l), CP_KIT_PORTALAUTH);
    ASSERT_EQ(kit(AIRGEDDON, &l), CP_KIT_AIRGEDDON);
    ASSERT_EQ(kit(FLUXION_307, &l), CP_KIT_FLUXION);
    ASSERT_STR(l, "fluxion redirect");
    ASSERT_EQ(kit(FLUXION_APPLE, &l), CP_KIT_FLUXION);
    ASSERT_STR(l, "fluxion emulated apple check");
    ASSERT_EQ(kit(FLUXION_LOGIN, &l), CP_KIT_FLUXION);
    ASSERT_STR(l, "fluxion login page");
}

/* One feature of a two-feature row is never enough. Each case is a
 * matching page with exactly one needle kept, so a row that quietly
 * stopped requiring all of its needles goes red here.
 *
 * First needle kept, second broken: seen red with cp_match_kit()'s
 * needle loop stopped after its first needle. */
static void test_first_feature_alone_is_not_a_kit(void) {
    char b[1024];
    const char *l = "x";
    /* Tornado banner, ordinary page. */
    ASSERT_EQ(kit("HTTP/1.1 200 OK\r\nServer: TornadoServer/6.4\r\n\r\n"
                  "<html><title>Jupyter Server</title></html>", &l), 0);
    ASSERT_STR(l, "");
    /* A 307 to anywhere else. */
    ASSERT_EQ(kit("HTTP/1.1 307 Temporary Redirect\r\n"
                  "Location: http://login.hotel.example/\r\n\r\n", NULL), 0);
    /* airgeddon's stylesheet without its form. */
    snprintf(b, sizeof(b), "%s", AIRGEDDON);
    *strstr(b, "action=\"check.htm\"") = 'X';
    ASSERT_EQ(kit(b, NULL), 0);
}

/* Second needle kept, first broken: seen red with cp_match_kit()'s
 * needle loop skipping its first needle. */
static void test_second_feature_alone_is_not_a_kit(void) {
    char b[1024];
    /* wifiphisher's title from something that is not Tornado. */
    snprintf(b, sizeof(b), "%s", WP_PLUGIN);
    memcpy(strstr(b, "TornadoServer"), "TornadoServex", 13);
    ASSERT_EQ(kit(b, NULL), 0);
    /* fluxion's Location on a 302 is not fluxion's config. */
    snprintf(b, sizeof(b), "%s", FLUXION_307);
    memcpy(b + 9, "302", 3);
    ASSERT_EQ(kit(b, NULL), 0);
    /* A "Success" page without fluxion's injected script. */
    ASSERT_EQ(kit("HTTP/1.1 200 OK\r\nContent-Length: 66\r\n\r\n"
                  "<html><head><title>Success</title></head>"
                  "<body>Success</body></html>", NULL), 0);
}

static void test_kit_header_scope_and_case(void) {
    /* The header name is case-insensitive (RFC 9110 §5.1)... */
    ASSERT_EQ(kit("HTTP/1.1 307 Temporary Redirect\r\n"
                  "LOCATION:http://captive.gateway.lan/\r\n\r\n", NULL),
              CP_KIT_FLUXION);
    /* ...bare-LF line endings are what a kit may well send... */
    ASSERT_EQ(kit("HTTP/1.0 307 Temporary Redirect\n"
                  "Location: http://captive.gateway.lan/\n\n", NULL),
              CP_KIT_FLUXION);
    /* ...and a header-shaped line in the BODY is not a header. Seen red
     * with hdr_has() given the segment length instead of the header
     * block's. */
    ASSERT_EQ(kit("HTTP/1.1 307 Temporary Redirect\r\n"
                  "Content-Length: 39\r\n\r\n"
                  "\nLocation: http://captive.gateway.lan/", NULL), 0);
}

static void test_kit_body_needle_must_be_in_the_body(void) {
    /* A title in a header value is not the page's title. Seen red with
     * the body search started at the segment's start instead of past
     * the headers. */
    ASSERT_EQ(kit("HTTP/1.1 200 OK\r\n"
                  "X-Note: <title>Evil Portal</title> This is the default "
                  "Evil Portal page.\r\n\r\n<html></html>", NULL), 0);
}

static void test_kit_truncated_and_malformed(void) {
    /* Every prefix of a matching page short of its last needle is no
     * match, and none reads past the length it is given: each prefix is
     * copied into a buffer of exactly that size, so ASan fails an
     * over-read. Seen red with has_bytes() accepting a needle cut short
     * by the end of the buffer. */
    int full = (int)strlen(AIRGEDDON);
    int need = (int)(strstr(AIRGEDDON, "check.htm\">") - AIRGEDDON)
               + (int)strlen("check.htm\">");
    int bad = 0;
    for (int n = 1; n <= full; n++) {
        uint8_t *cut = (uint8_t *)malloc((size_t)n);
        if (!cut) break;
        memcpy(cut, AIRGEDDON, (size_t)n);
        int k = cp_match_kit(cut, n, NULL);
        free(cut);
        if (k != (n >= need ? CP_KIT_AIRGEDDON : 0)) bad++;
    }
    ASSERT_EQ(bad, 0);
    ASSERT_EQ(cp_match_kit(NULL, 100, NULL), 0);
    ASSERT_EQ(kit("HTTP/1.1 30", NULL), 0);                 /* < 12 bytes */
    /* Not HTTP/1.x. Seen red with the "HTTP/1." prefix test shortened
     * to "HTTP/". */
    ASSERT_EQ(kit("HTTP/2.0 307 x\r\n"
                  "Location: http://captive.gateway.lan/\r\n\r\n", NULL), 0);
    /* A status code that is not three digits, on a body-only row's page.
     * Seen red with the status-digit loop removed. */
    {
        char b[1024];
        snprintf(b, sizeof(b), "%s", AIRGEDDON);
        b[10] = 'O';
        ASSERT_EQ(kit(b, NULL), 0);
    }
    /* A request carrying a kit's bytes is not a response. Not isolable
     * to one guard: the "HTTP/1." prefix, the version digit and the SP
     * after it each reject it. */
    ASSERT_EQ(kit("GET / HTTP/1.1\r\n"
                  "Location: http://captive.gateway.lan/\r\n\r\n", NULL), 0);
    /* Headers that never end: the header needle is still read, but a
     * body needle has no body to search. Seen red with the no-blank-line
     * default of the body offset set to 0. */
    ASSERT_EQ(kit("HTTP/1.1 307 Temporary Redirect\r\n"
                  "Location: http://captive.gateway.lan/\r\n", NULL),
              CP_KIT_FLUXION);
    ASSERT_EQ(kit("HTTP/1.1 200 OK\r\nServer: TornadoServer/6.4\r\n"
                  "X: <title>Plugin Manager</title>", NULL), 0);
}

static void test_kit_names(void) {
    ASSERT_STR(cp_kit_name(CP_KIT_WIFIPHISHER), "wifiphisher");
    ASSERT_STR(cp_kit_name(CP_KIT_FLUXION), "fluxion");
    ASSERT_STR(cp_kit_name(CP_KIT_AIRGEDDON), "airgeddon");
    ASSERT(cp_kit_name(CP_KIT_EVILPORTAL)[0] != '\0');
    ASSERT(cp_kit_name(CP_KIT_PORTALAUTH)[0] != '\0');
    ASSERT_STR(cp_kit_name(0), "");
    ASSERT_STR(cp_kit_name(99), "");
    ASSERT(cp_kind_label(CP_KIND_KIT)[0] != '\0');
}

/* ── #169: graded severity ── */

static sloth_state_t g_cps;

static void cps_reset(void) {
    alerts_clear();
    ownership_clear();
    cp_clear();
    memset(&g_cps, 0, sizeof(g_cps));
}

static void cps_event(uint8_t kind, uint8_t kitid, const char *host,
                      const char *client, const char *server,
                      const char *ev) {
    int n = g_cps.cp_event_count++;
    cp_event_t *e = &g_cps.cp_events[n];
    memset(e, 0, sizeof(*e));
    e->kind = kind;
    e->kit  = kitid;
    snprintf(e->host, sizeof(e->host), "%s", host);
    snprintf(e->src, sizeof(e->src), "%s", client);
    snprintf(e->server, sizeof(e->server), "%s", server);
    e->server_port = 80;
    snprintf(e->evidence, sizeof(e->evidence), "%s", ev);
    e->ts = sloth_wall();
}

static const uint8_t BSS_A[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t STA_A[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };

static const uint8_t STA_B[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02 };

static void cps_assoc(const char *ssid) {
    assoc_t *a = &g_cps.assocs[g_cps.assoc_count++];
    memcpy(a->bssid, BSS_A, 6);
    memcpy(a->sta_mac, STA_A, 6);
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
}

/* A row in the sensor's neighbour table: what ties an event's client IP
 * to a MAC the monitor table can have heard associating. */
static void cps_neigh(const char *ip, const uint8_t mac[6],
                      const char *iface) {
    arp_entry_t *n = &g_cps.arp_entries[g_cps.arp_count++];
    snprintf(n->ip, sizeof(n->ip), "%s", ip);
    memcpy(n->mac, mac, 6);
    snprintf(n->iface, sizeof(n->iface), "%s", iface);
}

static void cps_iface(const char *name, iface_mode_t mode) {
    iface_stat_t *f = &g_cps.ifaces[g_cps.iface_count++];
    snprintf(f->name, sizeof(f->name), "%s", name);
    f->mode = mode;
}

/* The sensor's own station link, on `bssid`. */
static void cps_link(const char *bssid, int status) {
    wifi_ap_t *ap = &g_cps.aps[g_cps.ap_count++];
    snprintf(ap->ssid, sizeof(ap->ssid), "Whatever");
    snprintf(ap->bssid, sizeof(ap->bssid), "%s", bssid);
    ap->status = status;
}

static void cps_twin_a(void) {
    g_cps.twin_episode_count = 1;
    memcpy(g_cps.twin_episodes[0].twin_bssid, BSS_A, 6);
    g_cps.twin_episodes[0].attributed = 1;
}

/* A CAPTIVE_PORTAL alert by key prefix: "portal:" is a probe finding,
 * "portalkit:" a kit page. The two share the type and never a key. */
static int cps_find_key(const char *prefix) {
    size_t n = strlen(prefix);
    for (int i = 0; i < g_cps.alert_count; i++)
        if (g_cps.alerts[i].type == ALERT_TYPE_CAPTIVE_PORTAL &&
            strncmp(g_cps.alerts[i].key, prefix, n) == 0) return i;
    return -1;
}

static int cps_portal_sev(void) {
    int i = cps_find_key("portal:");
    return i >= 0 ? (int)g_cps.alerts[i].sev : -1;
}

static void test_hotel_redirect_is_graded_low(void) {
    /* The legitimate captive portal: a 302 on the probe, nothing else
     * known about the network. The detail says portals do this. Seen
     * red with the LOW arm of the grade set to CRIT. */
    cps_reset();
    cps_assoc("Hotel Guest");
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.10.0.1",
              "HTTP 302, 0 body bytes");
    alerts_update(&g_cps);
    int i = cps_find_key("portal:");
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_cps.alerts[i].sev, ALERT_SEV_LOW);
        ASSERT(strstr(g_cps.alerts[i].detail,
                      "legitimate captive portals do this too") != NULL);
        ASSERT_STR(g_cps.alerts[i].match_ip, "10.10.0.1");
        ASSERT_EQ(g_cps.alerts[i].match_port, 80);
    }
    cps_reset();
}

static void test_hijack_on_own_network_is_crit(void) {
    cps_reset();
    ASSERT_EQ(ownership_add_ssid("HomeNet"), 1);
    cps_assoc("HomeNet");
    cps_neigh(CLI, STA_A, "eth0");     /* the client is that station */
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "192.168.1.1",
              "HTTP 302, 0 body bytes");
    alerts_update(&g_cps);
    int i = cps_find_key("portal:");
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_cps.alerts[i].sev, ALERT_SEV_CRIT);
        ASSERT(strstr(g_cps.alerts[i].detail, "own network") != NULL);
    }
    cps_reset();

    /* --my-bssid, through the sensor's own station link rather than the
     * monitor table: the sensor is on the operator's AP and the client
     * is a neighbour on that Wi-Fi link. */
    ASSERT_EQ(ownership_add_bssid("02:11:22:33:44:55"), 1);
    cps_link("02:11:22:33:44:55", WIFI_STATUS_ASSOC);
    cps_iface("wlan0", IFACE_MODE_WIFI);
    cps_neigh(CLI, STA_B, "wlan0");
    cps_event(CP_KIND_DNS_SPOOF, 0, "captive.apple.com", CLI, "",
              "192.168.1.1");
    alerts_update(&g_cps);
    ASSERT_EQ(cps_portal_sev(), ALERT_SEV_CRIT);
    cps_reset();

    /* The same link reached through the responder instead: the portal
     * that answered is a neighbour on the sensor's Wi-Fi link. */
    ASSERT_EQ(ownership_add_bssid("02:11:22:33:44:55"), 1);
    cps_link("02:11:22:33:44:55", WIFI_STATUS_ASSOC);
    cps_iface("wlan0", IFACE_MODE_WIFI);
    cps_neigh("192.168.1.1", BSS_A, "wlan0");
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "192.168.1.1",
              "HTTP 302, 0 body bytes");
    alerts_update(&g_cps);
    ASSERT_EQ(cps_portal_sev(), ALERT_SEV_CRIT);
    cps_reset();
}

/* The station link says nothing about an event that did not happen on
 * it: a wired client answered by a wired portal, while the sensor's
 * Wi-Fi happens to be on the operator's AP. Seen red with the
 * cp_on_wifi_link() gate in cp_context() removed. */
static void test_station_link_needs_the_event_on_that_link(void) {
    cps_reset();
    ASSERT_EQ(ownership_add_bssid("02:11:22:33:44:55"), 1);
    cps_link("02:11:22:33:44:55", WIFI_STATUS_ASSOC);
    cps_iface("wlan0", IFACE_MODE_WIFI);
    cps_iface("eth0", IFACE_MODE_ETHER);
    cps_neigh(CLI, STA_B, "eth0");
    cps_neigh("10.0.0.1", BSS_A, "eth0");
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.0.0.1", "");
    alerts_update(&g_cps);
    ASSERT_EQ(cps_portal_sev(), ALERT_SEV_LOW);
    cps_reset();
}

static void test_link_not_associated_is_not_own_network(void) {
    /* The operator's AP in the scan list, but not the one the sensor is
     * on: no escalation. Seen red with the WIFI_STATUS_ASSOC test in
     * cp_context() removed. */
    cps_reset();
    ASSERT_EQ(ownership_add_bssid("02:11:22:33:44:55"), 1);
    cps_link("02:11:22:33:44:55", WIFI_STATUS_NONE);
    cps_iface("wlan0", IFACE_MODE_WIFI);
    cps_neigh(CLI, STA_B, "wlan0");
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.0.0.1", "");
    alerts_update(&g_cps);
    int i = cps_find_key("portal:");
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ(g_cps.alerts[i].sev, ALERT_SEV_LOW);
    cps_reset();
}

static void test_hijack_from_evil_twin_is_crit(void) {
    cps_reset();
    cps_assoc("CoffeeShop");
    cps_neigh(CLI, STA_A, "eth0");
    cps_twin_a();
    cps_event(CP_KIND_TLS_MITM, 0, "captive.apple.com", CLI, "10.0.0.1",
              "10.0.0.1");
    alerts_update(&g_cps);
    int i = cps_find_key("portal:");
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_cps.alerts[i].sev, ALERT_SEV_CRIT);
        ASSERT(strstr(g_cps.alerts[i].detail, "evil twin") != NULL);
    }
    cps_reset();
}

/* A station heard associating with an evil twin is not the event's
 * client unless something says it is. #169 first escalated every event
 * from the one heard station's BSS, whoever the client was.
 *   no neighbour row for the client      -- the old pinned shape; seen
 *                                           red against that cp_context()
 *   the client is a different MAC        -- red against it too, and with
 *                                           the sta_mac memcmp() in this
 *                                           cp_context() removed
 *   two stations, neither the client     -- LOW before and after; kept
 *                                           so the join cannot regress it */
static void test_unlinked_station_does_not_escalate(void) {
    cps_reset();
    cps_assoc("CoffeeShop");
    cps_twin_a();
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.0.0.1", "");
    alerts_update(&g_cps);
    ASSERT_EQ(cps_portal_sev(), ALERT_SEV_LOW);
    cps_reset();

    cps_assoc("CoffeeShop");
    cps_twin_a();
    cps_neigh(CLI, STA_B, "eth0");
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.0.0.1", "");
    alerts_update(&g_cps);
    ASSERT_EQ(cps_portal_sev(), ALERT_SEV_LOW);
    cps_reset();

    cps_assoc("CoffeeShop");
    cps_assoc("CoffeeShop");
    g_cps.assocs[1].sta_mac[5] = 0x03;
    cps_twin_a();
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.0.0.1", "");
    alerts_update(&g_cps);
    ASSERT_EQ(cps_portal_sev(), ALERT_SEV_LOW);
    cps_reset();
}

/* A station that roamed is on the BSS it joined last: an old
 * association with the twin does not grade a probe made from the
 * network it moved to. Seen red with the last_seen comparison in
 * cp_context() inverted. */
static void test_newest_association_wins(void) {
    cps_reset();
    cps_assoc("CoffeeShop");                 /* twin BSS_A, older */
    g_cps.assocs[0].last_seen = 100;
    cps_assoc("CoffeeShop");
    g_cps.assocs[1].bssid[5] = 0x66;         /* another BSS, newer */
    g_cps.assocs[1].last_seen = 200;
    cps_twin_a();
    cps_neigh(CLI, STA_A, "eth0");
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.0.0.1", "");
    alerts_update(&g_cps);
    ASSERT_EQ(cps_portal_sev(), ALERT_SEV_LOW);
    cps_reset();

    cps_assoc("CoffeeShop");
    g_cps.assocs[0].last_seen = 200;
    cps_assoc("CoffeeShop");
    g_cps.assocs[1].bssid[5] = 0x66;
    g_cps.assocs[1].last_seen = 100;
    cps_twin_a();
    cps_neigh(CLI, STA_A, "eth0");
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.0.0.1", "");
    alerts_update(&g_cps);
    ASSERT_EQ(cps_portal_sev(), ALERT_SEV_CRIT);
    cps_reset();
}

static void test_kit_page_escalates_the_same_client_only(void) {
    cps_reset();
    cps_event(CP_KIND_KIT, CP_KIT_FLUXION, "captive.apple.com", CLI,
              "10.254.254.1", "fluxion emulated apple check");
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.254.254.1",
              "HTTP 200, 187 body bytes");
    alerts_update(&g_cps);
    int i = cps_find_key("portal:");
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_cps.alerts[i].sev, ALERT_SEV_CRIT);
        ASSERT(strstr(g_cps.alerts[i].detail, "fluxion") != NULL);
    }
    int k = cps_find_key("portalkit:");
    ASSERT(k >= 0);
    if (k >= 0) {
        ASSERT_EQ(g_cps.alerts[k].sev, ALERT_SEV_CRIT);
        ASSERT_STR(g_cps.alerts[k].match_ip, "10.254.254.1");
        ASSERT_EQ(g_cps.alerts[k].match_port, 80);
        ASSERT(strstr(g_cps.alerts[k].detail,
                      "fluxion emulated apple check") != NULL);
        ASSERT(strncmp(g_cps.alerts[k].key, "portalkit:5:", 12) == 0);
    }
    cps_reset();

    /* A different client's kit page does not escalate this probe. Seen
     * red with the strcmp() in cp_kit_for() removed. */
    cps_event(CP_KIND_KIT, CP_KIT_FLUXION, "", "192.168.4.99",
              "10.254.254.1", "fluxion redirect");
    cps_event(CP_KIND_HIJACK, 0, "captive.apple.com", CLI, "10.254.254.1",
              "");
    alerts_update(&g_cps);
    i = cps_find_key("portal:");
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ(g_cps.alerts[i].sev, ALERT_SEV_LOW);
    cps_reset();
}

static void test_kit_event_is_not_also_a_probe_finding(void) {
    /* A kit page is its own finding, keyed by server; it must not also
     * raise a portal:<host> finding for whatever host the page answered.
     * Seen red with the `continue` after cp_fire_kit() in
     * rule_captive_portal() removed. */
    cps_reset();
    cps_event(CP_KIND_KIT, CP_KIT_WIFIPHISHER, "neverssl.example", CLI,
              "10.0.0.1", "wifiphisher firmware-upgrade");
    alerts_update(&g_cps);
    ASSERT(cps_find_key("portalkit:") >= 0);
    ASSERT_EQ(cps_find_key("portal:"), -1);
    cps_reset();
}

static void test_one_kit_on_one_server_is_one_finding(void) {
    cps_reset();
    cps_event(CP_KIND_KIT, CP_KIT_AIRGEDDON, "a.example", CLI,
              "192.168.1.1", "airgeddon captive portal");
    cps_event(CP_KIND_KIT, CP_KIT_AIRGEDDON, "b.example", "192.168.4.21",
              "192.168.1.1", "airgeddon captive portal");
    cps_event(CP_KIND_KIT, CP_KIT_AIRGEDDON, "c.example", CLI,
              "192.168.1.2", "airgeddon captive portal");
    alerts_update(&g_cps);
    int n = 0;
    for (int i = 0; i < g_cps.alert_count; i++)
        if (strncmp(g_cps.alerts[i].key, "portalkit:", 10) == 0) n++;
    ASSERT_EQ(n, 2);
    cps_reset();
}

static void test_dns_unexpected_stays_soft(void) {
    cps_reset();
    cps_event(CP_KIND_DNS_UNEXPECTED, 0, "captive.apple.com", CLI, "",
              "93.184.216.34");
    alerts_update(&g_cps);
    int i = cps_find_key("portal:");
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ(g_cps.alerts[i].sev, ALERT_SEV_LOW);
    cps_reset();

    /* On the operator's own network it rises one step, never to CRIT:
     * being wrong about a CDN range must not produce a CRIT. Seen red
     * with the DNS_UNEXPECTED branch removed (falls to the CRIT arm). */
    ASSERT_EQ(ownership_add_ssid("HomeNet"), 1);
    cps_assoc("HomeNet");
    cps_neigh(CLI, STA_A, "eth0");
    cps_event(CP_KIND_DNS_UNEXPECTED, 0, "captive.apple.com", CLI, "",
              "93.184.216.34");
    alerts_update(&g_cps);
    i = cps_find_key("portal:");
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ(g_cps.alerts[i].sev, ALERT_SEV_WARN);
    cps_reset();
}

static void test_record_ex_keeps_the_responder(void) {
    cp_clear();
    cp_record_ex(CP_KIND_KIT, CP_KIT_FLUXION, "x.example", CLI,
                 "10.254.254.1", 80, "fluxion redirect", 100);
    cp_record(CP_KIND_DNS_SPOOF, "captive.apple.com", CLI, "10.0.0.1", 101);
    sloth_state_t *s = &g_cps;
    memset(s, 0, sizeof(*s));
    cp_snapshot(s);
    ASSERT_EQ(s->cp_event_count, 2);
    ASSERT_STR(s->cp_events[0].server, "");
    ASSERT_EQ(s->cp_events[0].kit, 0);
    ASSERT_STR(s->cp_events[1].server, "10.254.254.1");
    ASSERT_EQ(s->cp_events[1].server_port, 80);
    ASSERT_EQ(s->cp_events[1].kit, CP_KIT_FLUXION);
    cp_clear();
}

/* A kit that answers every URL refreshes its one ring slot rather
 * than filling the ring, so the probe event it escalates survives.
 * Seen red with the CP_KIND_KIT refresh in cp_record_ex() removed. */
static void test_repeated_kit_page_does_not_flood_the_ring(void) {
    cp_clear();
    cp_record_ex(CP_KIND_HIJACK, 0, "captive.apple.com", CLI,
                 "10.254.254.1", 80, "HTTP 307, 0 body bytes", 100);
    for (int i = 0; i < CP_MAX_EVENTS * 2; i++)
        cp_record_ex(CP_KIND_KIT, CP_KIT_FLUXION, "x.example", CLI,
                     "10.254.254.1", 80, "fluxion redirect", 101 + i);
    ASSERT_EQ(cp_event_count(), 2);
    sloth_state_t *s = &g_cps;
    memset(s, 0, sizeof(*s));
    cp_snapshot(s);
    int hij = 0, kitn = 0;
    for (int i = 0; i < s->cp_event_count; i++) {
        if (s->cp_events[i].kind == CP_KIND_HIJACK) hij++;
        if (s->cp_events[i].kind == CP_KIND_KIT) {
            kitn++;
            ASSERT_EQ(s->cp_events[i].ts, 101 + CP_MAX_EVENTS * 2 - 1);
        }
    }
    ASSERT_EQ(hij, 1);
    ASSERT_EQ(kitn, 1);
    /* A second client is its own event: the escalation is per client. */
    cp_record_ex(CP_KIND_KIT, CP_KIT_FLUXION, "x.example", "192.168.4.99",
                 "10.254.254.1", 80, "fluxion redirect", 500);
    ASSERT_EQ(cp_event_count(), 3);
    cp_clear();
    memset(s, 0, sizeof(*s));
}

/* The JSONL record carries the responder and the kit (#169); a
 * DNS-sourced event says it has neither rather than leaving the fields
 * out, so a consumer sees one record shape. */
static void test_jsonl_carries_responder_and_kit(void) {
    static char tmp[TEST_TMP_MAX];
    int fd = mkstemp(test_tmp_tpl(tmp, sizeof(tmp), "sloth_cp_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(tmp);
    ASSERT(jsonl_open(tmp));
    sloth_state_t *s = &g_cps;
    memset(s, 0, sizeof(*s));
    s->cp_event_count = 2;
    s->cp_events[0].kind = CP_KIND_KIT;
    s->cp_events[0].kit  = CP_KIT_AIRGEDDON;
    snprintf(s->cp_events[0].server, sizeof(s->cp_events[0].server),
             "192.168.1.1");
    s->cp_events[0].server_port = 80;
    s->cp_events[1].kind = CP_KIND_DNS_SPOOF;
    jsonl_emit_cp_events(s);
    jsonl_close();
    static char buf[8192];
    buf[0] = '\0';
    FILE *fp = fopen(tmp, "r");
    if (fp) {
        size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[n] = '\0';
        fclose(fp);
    }
    unlink(tmp);
    ASSERT(strstr(buf, "\"server\":\"192.168.1.1\",\"server_port\":80,"
                       "\"kit\":\"airgeddon\"") != NULL);
    ASSERT(strstr(buf, "\"server\":\"\",\"server_port\":0,"
                       "\"kit\":\"\"") != NULL);
    memset(s, 0, sizeof(*s));
}

void run_captive_portal_tests(void) {
    TEST_SUITE("captive-portal sentinel body check (#69)");
    RUN_TEST(test_correct_apple_sentinel_is_quiet);
    RUN_TEST(test_wrong_apple_body_is_a_hijack);
    RUN_TEST(test_redirect_on_the_sentinel_is_a_hijack);
    RUN_TEST(test_incomplete_body_never_fires);
    RUN_TEST(test_google_204_with_a_body_is_a_hijack);
    RUN_TEST(test_google_wrong_status_is_a_hijack);
    RUN_TEST(test_microsoft_and_firefox_sentinels);
    RUN_TEST(test_non_sentinel_host_is_ignored);
    RUN_TEST(test_sentinel_host_wrong_path_is_ignored);
    RUN_TEST(test_host_match_is_case_insensitive);
    RUN_TEST(test_path_prefix_tolerates_a_cache_buster);

    TEST_SUITE("captive-portal DNS check (#69)");
    RUN_TEST(test_sentinel_resolving_into_private_space);
    RUN_TEST(test_172_range_boundaries);
    RUN_TEST(test_apple_public_range_is_clean);
    RUN_TEST(test_apple_outside_its_range_is_unexpected_not_spoof);
    RUN_TEST(test_non_sentinel_dns_ignored);
    RUN_TEST(test_nxdomain_is_not_an_address);
    RUN_TEST(test_ipv6_private_ranges);

    TEST_SUITE("captive-portal TLS check (#69)");
    RUN_TEST(test_sentinel_tls_to_a_private_address);
    RUN_TEST(test_sentinel_tls_to_a_public_address_is_clean);
    RUN_TEST(test_non_sentinel_tls_ignored);

    TEST_SUITE("captive-portal event ring (#69)");
    RUN_TEST(test_events_recorded_newest_first);
    RUN_TEST(test_zero_kind_is_not_recorded);
    RUN_TEST(test_every_kind_has_a_label);
    RUN_TEST(test_sentinel_host_recognition);

    TEST_SUITE("captive-portal sentinels and wire bytes (#169)");
    RUN_TEST(test_ncsi_and_clients3_sentinels);
    RUN_TEST(test_ncsi_ipv6_sentinels);
    RUN_TEST(test_firefox_canonical_sentinels);
    RUN_TEST(test_wire_apple);
    RUN_TEST(test_wire_microsoft);
    RUN_TEST(test_wire_google);
    RUN_TEST(test_wire_firefox);
    RUN_TEST(test_wire_truncated_body_never_judged);

    TEST_SUITE("captive-portal kit fingerprints (#169)");
    RUN_TEST(test_each_kit_row_matches_its_page);
    RUN_TEST(test_first_feature_alone_is_not_a_kit);
    RUN_TEST(test_second_feature_alone_is_not_a_kit);
    RUN_TEST(test_kit_header_scope_and_case);
    RUN_TEST(test_kit_body_needle_must_be_in_the_body);
    RUN_TEST(test_kit_truncated_and_malformed);
    RUN_TEST(test_kit_names);
    RUN_TEST(test_record_ex_keeps_the_responder);
    RUN_TEST(test_jsonl_carries_responder_and_kit);
    RUN_TEST(test_repeated_kit_page_does_not_flood_the_ring);

    TEST_SUITE("captive-portal graded severity (#169)");
    RUN_TEST(test_hotel_redirect_is_graded_low);
    RUN_TEST(test_hijack_on_own_network_is_crit);
    RUN_TEST(test_link_not_associated_is_not_own_network);
    RUN_TEST(test_hijack_from_evil_twin_is_crit);
    RUN_TEST(test_station_link_needs_the_event_on_that_link);
    RUN_TEST(test_unlinked_station_does_not_escalate);
    RUN_TEST(test_newest_association_wins);
    RUN_TEST(test_kit_page_escalates_the_same_client_only);
    RUN_TEST(test_kit_event_is_not_also_a_probe_finding);
    RUN_TEST(test_one_kit_on_one_server_is_one_finding);
    RUN_TEST(test_dns_unexpected_stays_soft);
}
