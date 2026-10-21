#include <string.h>
#include <stdio.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "rtsp_snoop.h"
#include "sensor_health.h"
#include "sloth_clock.h"
#ifdef WITH_PCAP
#include <pcap.h>            /* DLT_EN10MB */
#include "capture/capture.h"
#include "frame_build.h"
#endif

/* RTSP messages hand-built from RFC 2326 (RTSP/1.0) and RFC 7826
 * (RTSP/2.0). No captures, per agents/AGENTS.md: every byte below is
 * written from the request-line (2326 §6.1, 7826 §7.1), status-line
 * (2326 §7.1, 7826 §8.1), DESCRIBE (2326 §10.2, 7826 §13.2), CSeq
 * (2326 §12.17, 7826 §18.20) and 401 / WWW-Authenticate (7826 §17.4.2,
 * §18.58) clauses. Addresses are RFC 5737 / private documentation
 * ranges. The credential "admin:12345" (base64 YWRtaW46MTIzNDU=) is the
 * one the issue's own Case G names; it appears here only so the tests
 * can prove sloth never keeps it. */

static const uint8_t *u8(const char *s) { return (const uint8_t *)s; }
static int slen(const char *s) { return (int)strlen(s); }

/* RFC 2326 §10.2 shape, RTSP/1.0, default port. */
static const char DESCRIBE_2[] =
    "DESCRIBE rtsp://192.0.2.5:554/Streaming/Channels/101 RTSP/1.0\r\n"
    "CSeq: 2\r\n"
    "Accept: application/sdp\r\n"
    "User-Agent: test-client/1.0\r\n"
    "\r\n";

/* 200 carrying an SDP body (RFC 4566 §5 minimum lines). */
static const char OK_SDP_2[] =
    "RTSP/1.0 200 OK\r\n"
    "CSeq: 2\r\n"
    "Content-Base: rtsp://192.0.2.5:554/Streaming/Channels/101/\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 89\r\n"
    "\r\n"
    "v=0\r\n"
    "o=- 0 0 IN IP4 192.0.2.5\r\n"
    "s=Session\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "t=0 0\r\n"
    "m=video 0 RTP/AVP 96\r\n";

/* 401 with a Digest challenge (RFC 7826 §17.4.2 requires the
 * WWW-Authenticate header on a 401). */
static const char UNAUTH_2[] =
    "RTSP/1.0 401 Unauthorized\r\n"
    "CSeq: 2\r\n"
    "WWW-Authenticate: Digest realm=\"IP Camera\", nonce=\"8d4e1c\"\r\n"
    "\r\n";

/* The retry after a 401, with a Basic credential. */
static const char DESCRIBE_3_AUTH[] =
    "DESCRIBE rtsp://192.0.2.5:554/Streaming/Channels/101 RTSP/1.0\r\n"
    "CSeq: 3\r\n"
    "Authorization: Basic YWRtaW46MTIzNDU=\r\n"
    "\r\n";

static const char DESCRIBE_3_NOAUTH[] =
    "DESCRIBE rtsp://192.0.2.5:554/Streaming/Channels/101 RTSP/1.0\r\n"
    "CSeq: 3\r\n"
    "\r\n";

static const char OK_3[] =
    "RTSP/1.0 200 OK\r\n"
    "CSeq: 3\r\n"
    "Content-Type: application/sdp\r\n"
    "\r\n";

/* RFC 7826 §13.2's own example request, verbatim bar the line ends. */
static const char DESCRIBE_V2[] =
    "DESCRIBE rtsp://server.example.com/fizzle/foo RTSP/2.0\r\n"
    "CSeq: 312\r\n"
    "User-Agent: PhonyClient/1.2\r\n"
    "Accept: application/sdp, application/example\r\n"
    "\r\n";

#define CLI  "192.168.1.10"
#define SRV  "192.0.2.5"

/* Does `hay` contain `needle` anywhere in its n bytes? memmem is a GNU
 * extension; C99 has to do it by hand. */
static int bytes_contain(const void *hay, size_t n, const char *needle) {
    size_t m = strlen(needle);
    const unsigned char *h = hay;
    if (m == 0 || m > n) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(h + i, needle, m) == 0) return 1;
    return 0;
}

static int observe(const char *src, uint16_t sp, const char *dst, uint16_t dp,
                   const char *msg) {
    return rtsp_snoop_observe(src, sp, dst, dp, u8(msg), slen(msg), NULL, 0);
}

/* Client request then server answer on one connection. */
static void exchange(uint16_t cport, uint16_t sport,
                     const char *req, const char *resp) {
    observe(CLI, cport, SRV, sport, req);
    observe(SRV, sport, CLI, cport, resp);
}

TEST_STATE(g_s);

static void snap(void) {
    memset(&g_s, 0, sizeof(g_s));
    rtsp_snoop_snapshot(&g_s);
}

/* ── Pure parse: requests ─────────────────────────────────── */

static void test_parse_describe_request(void) {
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(DESCRIBE_2), slen(DESCRIBE_2), &m), 1);
    ASSERT_EQ((int)m.kind, (int)RTSP_MSG_REQUEST);
    ASSERT_EQ(m.version, 1);
    ASSERT_STR(m.method, "DESCRIBE");
    ASSERT_STR(m.path, "/Streaming/Channels/101");
    ASSERT_EQ(m.has_cseq, 1);
    ASSERT_EQ((long long)m.cseq, 2);
    ASSERT_EQ(m.has_auth, 0);
    ASSERT_EQ(m.url_creds, 0);
}

static void test_parse_rtsp2_example(void) {
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(DESCRIBE_V2), slen(DESCRIBE_V2), &m), 1);
    ASSERT_EQ(m.version, 2);
    ASSERT_STR(m.path, "/fizzle/foo");
    ASSERT_EQ((long long)m.cseq, 312);
}

static void test_parse_query_and_fragment_are_not_stored(void) {
    const char *r =
        "DESCRIBE rtsp://192.0.2.5/cam/realmonitor?channel=1&subtype=0 RTSP/1.0\r\n"
        "CSeq: 1\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_STR(m.path, "/cam/realmonitor");
    ASSERT_EQ(m.url_creds, 0);

    const char *f = "DESCRIBE rtsp://192.0.2.5/live#t=10 RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    ASSERT_EQ(rtsp_parse(u8(f), slen(f), &m), 1);
    ASSERT_STR(m.path, "/live");
}

static void test_parse_empty_path_is_root(void) {
    const char *r = "DESCRIBE rtsp://192.0.2.5:8554 RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_STR(m.path, "/");
}

static void test_parse_relative_uri(void) {
    const char *r = "DESCRIBE /live/main RTSP/2.0\r\nCSeq: 7\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_STR(m.path, "/live/main");
}

static void test_parse_authorization_is_presence_only(void) {
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(DESCRIBE_3_AUTH), slen(DESCRIBE_3_AUTH), &m), 1);
    ASSERT_EQ(m.has_auth, 1);
    /* The guardrail: neither the encoded nor any part of the decoded
     * credential is anywhere in the parsed message. Seen to fail by
     * copying the Authorization value into m.path in read_header(). */
    ASSERT(!bytes_contain(&m, sizeof(m), "YWRtaW46MTIzNDU="));
    ASSERT(!bytes_contain(&m, sizeof(m), "12345"));
    ASSERT(!bytes_contain(&m, sizeof(m), "admin"));

    const char *p = "DESCRIBE rtsp://192.0.2.5/x RTSP/1.0\r\nCSeq: 4\r\n"
                    "Proxy-Authorization: Basic YWRtaW46MTIzNDU=\r\n\r\n";
    ASSERT_EQ(rtsp_parse(u8(p), slen(p), &m), 1);
    ASSERT_EQ(m.has_auth, 1);
}

static void test_parse_userinfo_is_flagged_and_dropped(void) {
    const char *r = "DESCRIBE rtsp://admin:12345@192.0.2.5:554/live RTSP/1.0\r\n"
                    "CSeq: 2\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_EQ(m.url_creds, 1);
    ASSERT_STR(m.path, "");
    ASSERT(!bytes_contain(&m, sizeof(m), "12345"));
}

static void test_parse_credential_query_is_flagged(void) {
    const char *r = "DESCRIBE rtsp://192.0.2.5/live?user=admin&password=12345 RTSP/1.0\r\n"
                    "CSeq: 2\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_EQ(m.url_creds, 1);
    ASSERT_STR(m.path, "");
}

static void test_parse_firmware_credential_names_are_flagged(void) {
    /* Names other than user=/password= that camera firmwares take a
     * credential in: Foscam's loginuse/loginpas, account=, token=,
     * auth=. Each is an authenticated request, so none may be tracked
     * as anonymous. Seen to fail with the old exact-name list (user,
     * username, usr, password, passwd, pass, pwd): loginuse parses with
     * url_creds 0 and path "/videoMain". */
    static const char *const r[] = {
        "DESCRIBE rtsp://192.0.2.5/videoMain?loginuse=admin&loginpas=12345 RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        "DESCRIBE rtsp://192.0.2.5/live?account=admin&channel=1 RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        "DESCRIBE rtsp://192.0.2.5/live?token=8d4e1c RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        "DESCRIBE rtsp://192.0.2.5/live;auth=8d4e1c RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        "DESCRIBE rtsp://192.0.2.5/live?channel=1&LoginPas=12345 RTSP/1.0\r\nCSeq: 2\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof r / sizeof r[0]; i++) {
        rtsp_msg_t m;
        ASSERT_EQ(rtsp_parse(u8(r[i]), slen(r[i]), &m), 1);
        ASSERT_EQ(m.url_creds, 1);
        ASSERT_STR(m.path, "");
    }
}

static void test_firmware_credential_url_is_not_counted_anonymous(void) {
    /* The observer end of the same case: a loginuse/loginpas DESCRIBE
     * answered 200 leaves no row. */
    const char *r = "DESCRIBE rtsp://192.0.2.5/videoMain?loginuse=admin&loginpas=12345 RTSP/1.0\r\n"
                    "CSeq: 2\r\n\r\n";
    observe(CLI, 51000, SRV, 554, r);
    observe(SRV, 554, CLI, 51000, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
    ASSERT(!bytes_contain(g_s.rtsp_streams, sizeof g_s.rtsp_streams, "12345"));
}

static void test_parse_credential_in_path_segment_is_flagged(void) {
    /* The path-parameter form some firmwares accept: the credential is
     * in abs_path itself, before any '?'. Seen to fail by letting
     * uri_scan() fall through to the copy when url_creds is set: the
     * path then holds "password=12345". */
    const char *r = "DESCRIBE rtsp://192.0.2.5:554/user=admin&password=12345&channel=1&stream=0.sdp RTSP/1.0\r\n"
                    "CSeq: 2\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_EQ(m.url_creds, 1);
    ASSERT(!bytes_contain(&m, sizeof(m), "12345"));
}

static void test_parse_cred_name_needs_a_boundary(void) {
    /* "pass" inside "/compass" is not a parameter name, and "users"
     * without '=' is not one either: neither is a credential. */
    const char *r = "DESCRIBE rtsp://192.0.2.5/compass/users/stream1 RTSP/1.0\r\n"
                    "CSeq: 2\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_EQ(m.url_creds, 0);
    ASSERT_STR(m.path, "/compass/users/stream1");
    /* "compass=" ends in "pass=" but starts mid-name. Seen to fail by
     * dropping the boundary test in uri_scan(). */
    const char *q = "DESCRIBE rtsp://192.0.2.5/live?compass=north RTSP/1.0\r\n"
                    "CSeq: 2\r\n\r\n";
    ASSERT_EQ(rtsp_parse(u8(q), slen(q), &m), 1);
    ASSERT_EQ(m.url_creds, 0);
    ASSERT_STR(m.path, "/live");
}

static void test_parse_path_control_bytes_are_neutralised(void) {
    const char r[] = "DESCRIBE rtsp://192.0.2.5/a\x1b[2Jb RTSP/1.0\r\nCSeq: 2\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT(strchr(m.path, 0x1b) == NULL);
    ASSERT_STR(m.path, "/a?[2Jb");
}

/* ── Pure parse: responses ────────────────────────────────── */

static void test_parse_200_with_sdp(void) {
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(OK_SDP_2), slen(OK_SDP_2), &m), 1);
    ASSERT_EQ((int)m.kind, (int)RTSP_MSG_RESPONSE);
    ASSERT_EQ(m.status, 200);
    ASSERT_EQ(m.has_sdp, 1);
    ASSERT_EQ((long long)m.cseq, 2);
}

static void test_parse_content_type_must_be_sdp(void) {
    const char *r = "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdpx\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_EQ(m.has_sdp, 0);
    const char *p = "RTSP/1.0 200 OK\r\nCSeq: 2\r\ncontent-type: Application/SDP; charset=utf-8\r\n\r\n";
    ASSERT_EQ(rtsp_parse(u8(p), slen(p), &m), 1);
    ASSERT_EQ(m.has_sdp, 1);
}

static void test_parse_401_with_challenge(void) {
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(UNAUTH_2), slen(UNAUTH_2), &m), 1);
    ASSERT_EQ(m.status, 401);
    ASSERT_STR(m.auth_scheme, "Digest");
    /* The realm is the server's text, not a credential, but it is not
     * kept either: only the scheme token is. */
    ASSERT(!bytes_contain(&m, sizeof(m), "IP Camera"));
}

static void test_parse_status_without_reason(void) {
    const char *r = "RTSP/2.0 200\r\nCSeq: 9\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_EQ(m.status, 200);
    ASSERT_EQ(m.version, 2);
}

static void test_parse_bare_lf_is_tolerated(void) {
    /* RFC 2326 §4: receivers should be prepared for a lone LF. */
    const char *r = "RTSP/1.0 200 OK\nCSeq: 5\n\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_EQ(m.has_cseq, 1);
    ASSERT_EQ((long long)m.cseq, 5);
}

/* ── Pure parse: truncated and malformed ──────────────────── */

static void test_truncated_start_line_is_not_a_message(void) {
    /* No CRLF yet: the URI or version may continue in the next segment. */
    const char *r = "DESCRIBE rtsp://192.0.2.5/live RTSP/1.0";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 0);
    /* Control: the same bytes terminated parse. */
    const char *c = "DESCRIBE rtsp://192.0.2.5/live RTSP/1.0\r\n";
    ASSERT_EQ(rtsp_parse(u8(c), slen(c), &m), 1);
}

static void test_truncated_cseq_line_is_not_read(void) {
    /* "CSeq: 3" cut before its CRLF could be the front of "CSeq: 31".
     * Seen to fail by letting next_line() return an unterminated tail:
     * has_cseq becomes 1 with cseq 3. */
    const char *r = "RTSP/1.0 200 OK\r\nCSeq: 3";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_EQ(m.has_cseq, 0);
    const char *c = "RTSP/1.0 200 OK\r\nCSeq: 3\r\n";
    ASSERT_EQ(rtsp_parse(u8(c), slen(c), &m), 1);
    ASSERT_EQ(m.has_cseq, 1);
}

static void test_every_prefix_parses_safely(void) {
    /* Every cut of a full exchange: ASan holds the reads in bounds, and
     * a CSeq is only ever reported once its whole line has arrived. */
    const char *msgs[] = { DESCRIBE_2, OK_SDP_2, UNAUTH_2, DESCRIBE_3_AUTH };
    for (size_t k = 0; k < sizeof msgs / sizeof msgs[0]; k++) {
        int n = slen(msgs[k]);
        const char *eol = strstr(strstr(msgs[k], "CSeq:"), "\r\n");
        int cseq_end = (int)(eol - msgs[k]) + 2;
        int bad = 0;
        for (int cut = 0; cut <= n; cut++) {
            uint8_t buf[512];
            memcpy(buf, msgs[k], (size_t)cut);
            rtsp_msg_t m;
            int r = rtsp_parse(buf, cut, &m);
            if (r && m.has_cseq && cut < cseq_end) bad++;
            if (cut >= cseq_end && (!r || !m.has_cseq)) bad++;
        }
        ASSERT_EQ(bad, 0);
    }
}

static void test_malformed_start_lines(void) {
    static const char *const bad[] = {
        "DESCRIBE rtsp://192.0.2.5/x HTTP/1.1\r\nCSeq: 1\r\n\r\n",  /* HTTP, not RTSP */
        "HTTP/1.1 200 OK\r\nCSeq: 1\r\n\r\n",
        "RTSP/3.0 200 OK\r\nCSeq: 1\r\n\r\n",                        /* no such version */
        "RTSP/1.1 200 OK\r\nCSeq: 1\r\n\r\n",
        "RTSP/1.0 2OO OK\r\nCSeq: 1\r\n\r\n",                        /* letter O */
        "RTSP/1.0 200OK\r\nCSeq: 1\r\n\r\n",                         /* no SP after code */
        "RTSP/1.0 600 Nope\r\nCSeq: 1\r\n\r\n",                      /* no 6xx class */
        "DESCRIBE  RTSP/1.0\r\nCSeq: 1\r\n\r\n",                     /* empty URI */
        "DESCRIBE rtsp://192.0.2.5/x\r\nCSeq: 1\r\n\r\n",            /* no version */
        "DESC RIBE rtsp://192.0.2.5/x RTSP/1.0\r\n\r\n",             /* space in method */
        "describe\x01 rtsp://192.0.2.5/x RTSP/1.0\r\n\r\n",          /* control in method */
        "AVERYLONGMETHODNAME rtsp://h/x RTSP/1.0\r\n\r\n",           /* > 15 chars */
        "$\x00\x00\x10RTSP/1.0 200 OK\r\n\r\n",                     /* interleaved data */
    };
    int parsed = 0;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        rtsp_msg_t m;
        /* Length from the literal's own text; the '$' frame's NUL is
         * inside it, so use a fixed 20 bytes for that one. */
        int n = (bad[i][0] == '$') ? 20 : slen(bad[i]);
        if (rtsp_parse(u8(bad[i]), n, &m)) {
            printf("    rtsp: parsed malformed #%zu\n", i);
            parsed++;
        }
    }
    ASSERT_EQ(parsed, 0);
}

static void test_malformed_header_lines_are_skipped(void) {
    /* A line with no colon is not a header; the CSeq after it still is. */
    const char *r = "RTSP/1.0 200 OK\r\nthis is not a header\r\nCSeq: 6\r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(r), slen(r), &m), 1);
    ASSERT_EQ(m.has_cseq, 1);
    ASSERT_EQ((long long)m.cseq, 6);
}

static void test_bad_cseq_values(void) {
    static const char *const v[] = {
        "RTSP/1.0 200 OK\r\nCSeq: abc\r\n\r\n",
        "RTSP/1.0 200 OK\r\nCSeq:\r\n\r\n",
        "RTSP/1.0 200 OK\r\nCSeq: 12x\r\n\r\n",
        "RTSP/1.0 200 OK\r\nCSeq: 4294967296\r\n\r\n",               /* 2^32 */
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        rtsp_msg_t m;
        ASSERT_EQ(rtsp_parse(u8(v[i]), slen(v[i]), &m), 1);
        ASSERT_EQ(m.has_cseq, 0);
    }
    const char *max = "RTSP/1.0 200 OK\r\nCSeq:  4294967295 \r\n\r\n";
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(max), slen(max), &m), 1);
    ASSERT_EQ(m.has_cseq, 1);
    ASSERT_EQ((long long)m.cseq, 4294967295LL);
}

static void test_parse_null_and_short(void) {
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(NULL, 0, &m), 0);
    ASSERT_EQ(rtsp_parse(u8("RTSP/1.0 2\r\n"), 12, &m), 0);
    ASSERT_EQ(rtsp_parse(u8(OK_3), slen(OK_3), NULL), 0);
}

/* ── Observer: pairing and the anonymous decision ─────────── */

static void test_anonymous_describe_is_recorded(void) {
    exchange(51000, 554, DESCRIBE_2, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 1);
    const rtsp_stream_t *r = &g_s.rtsp_streams[0];
    ASSERT_STR(r->server, SRV);
    ASSERT_EQ(r->port, 554);
    ASSERT_STR(r->path, "/Streaming/Channels/101");
    ASSERT_STR(r->client, CLI);
    ASSERT_EQ((int)r->anon_ok, 1);
    ASSERT_EQ((int)r->auth_ok, 0);
    ASSERT_EQ((int)r->challenged, 0);
    ASSERT_EQ(r->sdp, 1);
}

static void test_challenge_then_authenticated_retry(void) {
    exchange(51000, 554, DESCRIBE_2, UNAUTH_2);
    exchange(51000, 554, DESCRIBE_3_AUTH, OK_3);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 1);
    const rtsp_stream_t *r = &g_s.rtsp_streams[0];
    ASSERT_EQ((int)r->anon_ok, 0);
    ASSERT_EQ((int)r->auth_ok, 1);
    ASSERT_EQ((int)r->challenged, 1);
    ASSERT_STR(r->auth_scheme, "Digest");
    /* The credential the client sent never reached the table. */
    ASSERT(!bytes_contain(g_s.rtsp_streams, sizeof g_s.rtsp_streams, "YWRtaW46MTIzNDU="));
}

static void test_prior_401_disqualifies_a_later_unauthenticated_200(void) {
    /* "no prior 401 challenge for that exchange": a 200 that follows a
     * challenge on the same connection is not counted anonymous even
     * when the retry carries no Authorization (a server that let the
     * second try through is not the anonymous case this reports).
     * Seen to fail by dropping `&& !e->challenged` in settle(). */
    exchange(51000, 554, DESCRIBE_2, UNAUTH_2);
    exchange(51000, 554, DESCRIBE_3_NOAUTH, OK_3);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 1);
    ASSERT_EQ((int)g_s.rtsp_streams[0].anon_ok, 0);
    ASSERT_EQ((int)g_s.rtsp_streams[0].auth_ok, 1);

    /* Control: the same unauthenticated request on a fresh connection,
     * with no 401 there, is the anonymous case. */
    exchange(51001, 554, DESCRIBE_3_NOAUTH, OK_3);
    snap();
    ASSERT_EQ((int)g_s.rtsp_streams[0].anon_ok, 1);
}

static void test_authorization_header_means_not_anonymous(void) {
    /* A client that sends credentials pre-emptively is authenticated
     * even without a 401 first. Seen to fail by ignoring p->has_auth
     * in settle(). */
    exchange(51000, 554, DESCRIBE_3_AUTH, OK_3);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 1);
    ASSERT_EQ((int)g_s.rtsp_streams[0].anon_ok, 0);
    ASSERT_EQ((int)g_s.rtsp_streams[0].auth_ok, 1);
}

static void test_unpaired_response_records_nothing(void) {
    /* A 200 with no DESCRIBE before it (capture started mid-session)
     * says nothing about which path or whether it was authenticated. */
    observe(SRV, 554, CLI, 51000, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
    /* Control: after the request, the same response is recorded. */
    observe(CLI, 51000, SRV, 554, DESCRIBE_2);
    observe(SRV, 554, CLI, 51000, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 1);
}

static void test_cseq_mismatch_does_not_pair(void) {
    /* Seen to fail by dropping the CSeq comparison in settle(). */
    observe(CLI, 51000, SRV, 554, DESCRIBE_2);
    observe(SRV, 554, CLI, 51000, OK_3);         /* CSeq 3, not 2 */
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
}

static void test_other_connection_does_not_pair(void) {
    /* CSeq series are per connection (RFC 7826 §18.20): an answer on a
     * different client port is not an answer to this request. Seen to
     * fail by dropping the cport comparison in ex_key_eq(). */
    observe(CLI, 51000, SRV, 554, DESCRIBE_2);
    observe(SRV, 554, CLI, 51999, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
    observe(SRV, 554, CLI, 51000, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 1);
}

static void test_responses_out_of_order_pair_by_cseq(void) {
    const char *da = "DESCRIBE rtsp://192.0.2.5/a RTSP/1.0\r\nCSeq: 10\r\n\r\n";
    const char *db = "DESCRIBE rtsp://192.0.2.5/b RTSP/1.0\r\nCSeq: 11\r\n\r\n";
    const char *ra = "RTSP/1.0 200 OK\r\nCSeq: 10\r\n\r\n";
    const char *rb = "RTSP/1.0 404 Not Found\r\nCSeq: 11\r\n\r\n";
    /* ra comes first while db (CSeq 11) holds the last-used slot, so a
     * settle() that took the newest pending request instead of the one
     * whose CSeq matches would credit /a's 200 to /b. Seen to fail by
     * dropping the CSeq comparison in settle(): the row is /b. */
    observe(CLI, 51000, SRV, 554, da);
    observe(CLI, 51000, SRV, 554, db);
    observe(SRV, 554, CLI, 51000, ra);
    observe(SRV, 554, CLI, 51000, rb);
    snap();
    /* /b got a 404: nothing about authentication, no row. /a: 200. */
    ASSERT_EQ(g_s.rtsp_stream_count, 1);
    ASSERT_STR(g_s.rtsp_streams[0].path, "/a");
    ASSERT_EQ((int)g_s.rtsp_streams[0].anon_ok, 1);
}

static void test_non_describe_is_not_tracked(void) {
    const char *setup = "SETUP rtsp://192.0.2.5/a/trackID=1 RTSP/1.0\r\nCSeq: 4\r\n"
                        "Transport: RTP/AVP/TCP;interleaved=0-1\r\n\r\n";
    const char *ok = "RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 12345678\r\n\r\n";
    observe(CLI, 51000, SRV, 554, setup);
    observe(SRV, 554, CLI, 51000, ok);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
}

static void test_url_credentials_are_never_tracked(void) {
    /* Neither anonymous nor storable: the row would carry the secret.
     * Two guards hold this — the observer's `!m.url_creds` and the
     * empty path uri_scan() leaves for such a URI — so either alone is
     * enough. Seen to fail by removing both from the observer's
     * DESCRIBE condition. */
    const char *r = "DESCRIBE rtsp://192.0.2.5:554/user=admin&password=12345&channel=1 RTSP/1.0\r\n"
                    "CSeq: 2\r\n\r\n";
    observe(CLI, 51000, SRV, 554, r);
    observe(SRV, 554, CLI, 51000, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
    ASSERT(!bytes_contain(g_s.rtsp_streams, sizeof g_s.rtsp_streams, "12345"));
}

static void test_parse_reports_header_block_completeness(void) {
    rtsp_msg_t m;
    ASSERT_EQ(rtsp_parse(u8(DESCRIBE_2), slen(DESCRIBE_2), &m), 1);
    ASSERT_EQ(m.complete, 1);
    const char *open_ = "DESCRIBE rtsp://192.0.2.5/x RTSP/1.0\r\nCSeq: 5\r\n";
    ASSERT_EQ(rtsp_parse(u8(open_), slen(open_), &m), 1);
    ASSERT_EQ(m.complete, 0);
    ASSERT_EQ(m.has_cseq, 1);
}

static void test_split_header_block_is_not_counted_anonymous(void) {
    /* A client that writes its headers in two send()s: the request line
     * and CSeq in one TCP segment, Authorization and the empty line in
     * the next. The first segment alone shows no Authorization, but
     * the header block is not finished, so has_auth is unknown and the
     * request must not be counted anonymous when the 200 comes back.
     * Seen to fail by dropping `m.complete` from the observer's
     * DESCRIBE condition: anon_ok becomes 1. */
    const char *seg1 = "DESCRIBE rtsp://192.0.2.5:554/p1 RTSP/1.0\r\n"
                       "CSeq: 5\r\n"
                       "User-Agent: test-client/1.0\r\n";
    const char *seg2 = "Authorization: Digest username=\"admin\", realm=\"IP Camera\", "
                       "nonce=\"8d4e1c\", uri=\"rtsp://192.0.2.5:554/p1\", "
                       "response=\"00000000000000000000000000000000\"\r\n\r\n";
    const char *ok = "RTSP/1.0 200 OK\r\nCSeq: 5\r\n"
                     "Content-Type: application/sdp\r\n\r\n";
    observe(CLI, 51000, SRV, 554, seg1);
    observe(CLI, 51000, SRV, 554, seg2);
    observe(SRV, 554, CLI, 51000, ok);
    snap();
    int anon = 0;
    for (int i = 0; i < g_s.rtsp_stream_count; i++)
        anon += (int)g_s.rtsp_streams[i].anon_ok;
    ASSERT_EQ(anon, 0);
    ASSERT_EQ(g_s.rtsp_stream_count, 0);

    /* Control: the same request in one segment is tracked (and, with
     * its Authorization, counted authenticated). */
    char whole[512];
    snprintf(whole, sizeof whole, "%s%s", seg1, seg2);
    observe(CLI, 51001, SRV, 554, whole);
    observe(SRV, 554, CLI, 51001, ok);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 1);
    ASSERT_EQ((int)g_s.rtsp_streams[0].auth_ok, 1);
    ASSERT_EQ((int)g_s.rtsp_streams[0].anon_ok, 0);
}

static void test_info_labels(void) {
    char info[64] = "";
    ASSERT_EQ(rtsp_snoop_observe(CLI, 51000, SRV, 554, u8(DESCRIBE_2),
                                 slen(DESCRIBE_2), info, sizeof info), 1);
    ASSERT_STR(info, "RTSP DESCRIBE");
    ASSERT_EQ(rtsp_snoop_observe(SRV, 554, CLI, 51000, u8(UNAUTH_2),
                                 slen(UNAUTH_2), info, sizeof info), 1);
    ASSERT_STR(info, "RTSP 401");
    info[0] = '\0';
    ASSERT_EQ(rtsp_snoop_observe(SRV, 554, CLI, 51000, u8("GET / HTTP/1.1\r\n\r\n"),
                                 18, info, sizeof info), 0);
    ASSERT_STR(info, "");
}

static void test_clear_empties_the_table(void) {
    exchange(51000, 554, DESCRIBE_2, OK_SDP_2);
    rtsp_snoop_clear();
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
    /* And the in-flight request went with it. */
    observe(SRV, 554, CLI, 51000, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
}

static time_t g_wall;
static time_t fixed_wall(void) { return g_wall; }

static void test_stream_table_eviction_is_tallied(void) {
    sloth_clock_test_set(NULL, fixed_wall);
    g_wall = 1700000000;
    char req[128], resp[64];
    for (int i = 0; i < MAX_RTSP_STREAMS; i++) {
        g_wall++;
        snprintf(req, sizeof req,
                 "DESCRIBE rtsp://192.0.2.5/p%d RTSP/1.0\r\nCSeq: %d\r\n\r\n", i, i + 1);
        snprintf(resp, sizeof resp, "RTSP/1.0 200 OK\r\nCSeq: %d\r\n\r\n", i + 1);
        exchange(51000, 554, req, resp);
    }
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_RTSP_STREAM), 0);
    g_wall++;
    snprintf(req, sizeof req, "DESCRIBE rtsp://192.0.2.5/new RTSP/1.0\r\nCSeq: 999\r\n\r\n");
    exchange(51000, 554, req, "RTSP/1.0 200 OK\r\nCSeq: 999\r\n\r\n");
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_RTSP_STREAM), 1);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, MAX_RTSP_STREAMS);
    int has_p0 = 0, has_new = 0;
    for (int i = 0; i < g_s.rtsp_stream_count; i++) {
        if (strcmp(g_s.rtsp_streams[i].path, "/p0") == 0)  has_p0 = 1;
        if (strcmp(g_s.rtsp_streams[i].path, "/new") == 0) has_new = 1;
    }
    ASSERT_EQ(has_p0, 0);                        /* the oldest went */
    ASSERT_EQ(has_new, 1);
    sloth_clock_test_set(NULL, NULL);
}

static void test_exchange_table_eviction_is_tallied(void) {
    sloth_clock_test_set(NULL, fixed_wall);
    g_wall = 1700000000;
    for (int i = 0; i < 32; i++) {
        g_wall++;
        observe(CLI, (uint16_t)(40000 + i), SRV, 554, DESCRIBE_2);
    }
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_RTSP_EXCHANGE), 0);
    g_wall++;
    observe(CLI, 49999, SRV, 554, DESCRIBE_2);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_RTSP_EXCHANGE), 1);
    /* The oldest connection lost its pending DESCRIBE; the newest kept it. */
    observe(SRV, 554, CLI, 40000, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
    observe(SRV, 554, CLI, 49999, OK_SDP_2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 1);
    sloth_clock_test_set(NULL, NULL);
}

/* ── Rule: CAM_RTSP_UNAUTH ────────────────────────────────── */

static int find_rtsp_alert(const sloth_state_t *s) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == ALERT_TYPE_CAM_RTSP_UNAUTH) return i;
    return -1;
}

static int count_rtsp_alerts(const sloth_state_t *s) {
    int n = 0;
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == ALERT_TYPE_CAM_RTSP_UNAUTH) n++;
    return n;
}

static rtsp_stream_t *seed(sloth_state_t *s, const char *server, uint16_t port,
                           const char *path, uint32_t anon, uint32_t auth) {
    rtsp_stream_t *r = &s->rtsp_streams[s->rtsp_stream_count++];
    memset(r, 0, sizeof(*r));
    snprintf(r->server, sizeof r->server, "%s", server);
    snprintf(r->path,   sizeof r->path,   "%s", path);
    r->port    = port;
    r->anon_ok = anon;
    r->auth_ok = auth;
    r->first_seen = r->last_seen = sloth_wall();
    return r;
}

static void test_rule_fires_warn_per_server(void) {
    alerts_clear();
    memset(&g_s, 0, sizeof g_s);
    seed(&g_s, SRV, 554, "/Streaming/Channels/101", 1, 0);
    alerts_update(&g_s);
    int i = find_rtsp_alert(&g_s);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
    ASSERT_STR(g_s.alerts[i].key, "cam-rtsp:192.0.2.5");
    ASSERT_STR(g_s.alerts[i].match_ip, SRV);
    ASSERT_EQ(g_s.alerts[i].match_port, 554);
    ASSERT_EQ((int)g_s.alerts[i].technique[0], 0);
    ASSERT(strstr(g_s.alerts[i].detail, "RTSP server 192.0.2.5 ") != NULL);
    ASSERT(strstr(g_s.alerts[i].detail, "e.g. /Streaming/Channels/101") != NULL);
    ASSERT(strstr(g_s.alerts[i].detail, "1 path ") != NULL);
    ASSERT(strstr(g_s.alerts[i].detail, "not confirmed") != NULL);
    /* Corroborate, never confirm: the detail names an RTSP server, and
     * does not claim the device is a camera. */
    ASSERT(strstr(g_s.alerts[i].detail, "camera") == NULL);
}

static void test_rule_quiet_when_only_authenticated(void) {
    /* Seen to fail by removing the `if (!r->anon_ok) continue;` gate. */
    alerts_clear();
    memset(&g_s, 0, sizeof g_s);
    rtsp_stream_t *r = seed(&g_s, SRV, 554, "/live", 0, 3);
    r->challenged = 2;
    alerts_update(&g_s);
    ASSERT_EQ(find_rtsp_alert(&g_s), -1);
    /* Control: the same row with one anonymous answer fires. */
    r->anon_ok = 1;
    alerts_update(&g_s);
    ASSERT(find_rtsp_alert(&g_s) >= 0);
}

static void test_rule_one_alert_per_server_with_rising_count(void) {
    alerts_clear();
    memset(&g_s, 0, sizeof g_s);
    seed(&g_s, SRV, 554, "/a", 1, 0);
    alerts_update(&g_s);
    int i = find_rtsp_alert(&g_s);
    ASSERT(i >= 0);
    if (i < 0) return;
    uint32_t obs0 = g_s.alerts[i].observations;

    /* A repeat poll of unchanged evidence: same incident, no new
     * observation. */
    alerts_update(&g_s);
    i = find_rtsp_alert(&g_s);
    ASSERT_EQ((long long)g_s.alerts[i].observations, (long long)obs0);

    /* A second anonymous path, and the 8554 listener on the same host:
     * still one incident, and the count in the detail moves. */
    seed(&g_s, SRV, 554, "/b", 1, 0);
    seed(&g_s, SRV, 8554, "/c", 2, 0);
    alerts_update(&g_s);
    ASSERT_EQ(count_rtsp_alerts(&g_s), 1);
    i = find_rtsp_alert(&g_s);
    ASSERT(strstr(g_s.alerts[i].detail, "3 paths") != NULL);
    ASSERT_EQ((long long)g_s.alerts[i].observations, (long long)obs0 + 1);
}

static void test_rule_detail_ignores_slot_order(void) {
    /* The snapshot's slot order is the stream table's, which eviction
     * and reuse reshuffle. The detail's example path is the smallest
     * one, so the same set of rows in another order is the same
     * evidence and adds no observation. Seen to fail by taking the
     * first row's path (and port) as the example: the swap moves the
     * detail from "e.g. /a" to "e.g. /b" and observations rise. */
    alerts_clear();
    memset(&g_s, 0, sizeof g_s);
    seed(&g_s, SRV, 8554, "/b", 1, 0);
    seed(&g_s, SRV, 554, "/a", 1, 0);
    alerts_update(&g_s);
    int i = find_rtsp_alert(&g_s);
    ASSERT(i >= 0);
    if (i < 0) return;
    ASSERT(strstr(g_s.alerts[i].detail, "e.g. /a") != NULL);
    ASSERT_EQ(g_s.alerts[i].match_port, 554);
    uint32_t obs0 = g_s.alerts[i].observations;

    rtsp_stream_t tmp = g_s.rtsp_streams[0];
    g_s.rtsp_streams[0] = g_s.rtsp_streams[1];
    g_s.rtsp_streams[1] = tmp;
    alerts_update(&g_s);
    i = find_rtsp_alert(&g_s);
    ASSERT(strstr(g_s.alerts[i].detail, "e.g. /a") != NULL);
    ASSERT_EQ((long long)g_s.alerts[i].observations, (long long)obs0);
}

static void test_rule_two_servers_two_alerts(void) {
    alerts_clear();
    memset(&g_s, 0, sizeof g_s);
    seed(&g_s, SRV, 554, "/a", 1, 0);
    seed(&g_s, "192.0.2.6", 8554, "/a", 1, 0);
    seed(&g_s, "192.0.2.7", 554, "/a", 0, 1);    /* authenticated: quiet */
    alerts_update(&g_s);
    ASSERT_EQ(count_rtsp_alerts(&g_s), 2);
}

static void test_rule_from_hand_built_bytes(void) {
    /* Parser to rule with nothing seeded: the issue's Case F. */
    alerts_clear();
    exchange(51000, 554, DESCRIBE_2, OK_SDP_2);
    snap();
    alerts_update(&g_s);
    ASSERT(find_rtsp_alert(&g_s) >= 0);

    /* Case F's inverse: the challenged-then-authenticated exchange
     * on another server raises nothing for it. */
    alerts_clear();
    rtsp_snoop_clear();
    exchange(51000, 554, DESCRIBE_2, UNAUTH_2);
    exchange(51000, 554, DESCRIBE_3_AUTH, OK_3);
    snap();
    alerts_update(&g_s);
    ASSERT_EQ(find_rtsp_alert(&g_s), -1);
}

/* ── Capture dispatch: both registered ports ──────────────── */

#ifdef WITH_PCAP
static const uint8_t MAC_C[6] = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x10 };
static const uint8_t MAC_S[6] = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x05 };

/* Ethernet II + IPv4 (RFC 791 §3.1, IHL 5) + TCP (RFC 9293 §3.1, data
 * offset 5, PSH|ACK) carrying `pay`. 192.168.1.10 is the client,
 * 192.168.1.5 the server. */
static int tcp_frame(uint8_t *f, int cap, int to_server,
                     uint16_t cport, uint16_t sport, const char *pay) {
    const int n = slen(pay);
    fb_t b; fb_init(&b, f, cap);
    fb_eth(&b, to_server ? MAC_S : MAC_C, to_server ? MAC_C : MAC_S, 0x0800);
    fb_u8(&b, 0x45); fb_u8(&b, 0);
    fb_be16(&b, (uint16_t)(20 + 20 + n));
    fb_be16(&b, 0x0001); fb_be16(&b, 0x4000);    /* ID, DF */
    fb_u8(&b, 64); fb_u8(&b, 6);
    fb_be16(&b, 0);
    const char *cip = "\xc0\xa8\x01\x0a", *sip = "\xc0\xa8\x01\x05";
    fb_bytes(&b, to_server ? cip : sip, 4);
    fb_bytes(&b, to_server ? sip : cip, 4);
    fb_be16(&b, to_server ? cport : sport);
    fb_be16(&b, to_server ? sport : cport);
    fb_be16(&b, 0); fb_be16(&b, 1);
    fb_be16(&b, 0); fb_be16(&b, 1);
    fb_u8(&b, 0x50); fb_u8(&b, 0x18);
    fb_be16(&b, 65535); fb_be16(&b, 0); fb_be16(&b, 0);
    fb_bytes(&b, pay, n);
    return fb_ok(&b) ? b.len : -1;
}

TEST_STATE(g_cap);

static int dispatch_exchange(uint16_t sport) {
    uint8_t req[512], resp[512];
    int rn = tcp_frame(req,  sizeof req,  1, 51000, sport, DESCRIBE_2);
    int sn = tcp_frame(resp, sizeof resp, 0, 51000, sport, OK_SDP_2);
    if (rn < 0 || sn < 0) return -1;
    const uint8_t *fs[2] = { req, resp };
    int ls[2] = { rn, sn };
    memset(&g_cap, 0, sizeof g_cap);
    return capture_test_dispatch(&g_cap, DLT_EN10MB, fs, ls, NULL, 2);
}

static void test_capture_dispatch_reaches_rtsp_on_both_ports(void) {
    static const uint16_t ports[] = { 554, 8554 };
    for (size_t k = 0; k < 2; k++) {
        rtsp_snoop_clear();
        ASSERT_EQ(dispatch_exchange(ports[k]), 2);
        snap();
        ASSERT_EQ(g_s.rtsp_stream_count, 1);
        if (g_s.rtsp_stream_count != 1) continue;
        ASSERT_STR(g_s.rtsp_streams[0].server, "192.168.1.5");
        ASSERT_STR(g_s.rtsp_streams[0].client, "192.168.1.10");
        ASSERT_EQ(g_s.rtsp_streams[0].port, ports[k]);
        ASSERT_EQ((int)g_s.rtsp_streams[0].anon_ok, 1);
        ASSERT_STR(g_cap.packets[0].info, "RTSP DESCRIBE");
        ASSERT_STR(g_cap.packets[1].info, "RTSP 200");
    }
}

static void test_capture_dispatch_ignores_other_ports(void) {
    /* The same bytes on 5540 are not RTSP to sloth. Seen to fail by
     * adding port_is(pkt, 5540) to the dispatch line in decode_tcp(). */
    rtsp_snoop_clear();
    ASSERT_EQ(dispatch_exchange(5540), 2);
    snap();
    ASSERT_EQ(g_s.rtsp_stream_count, 0);
}
#endif

void run_rtsp_snoop_tests(void) {
    TEST_SUITE("rtsp: request parse (RFC 2326 / RFC 7826)");
    RUN_TEST(test_parse_describe_request);
    RUN_TEST(test_parse_rtsp2_example);
    RUN_TEST(test_parse_query_and_fragment_are_not_stored);
    RUN_TEST(test_parse_empty_path_is_root);
    RUN_TEST(test_parse_relative_uri);
    RUN_TEST(test_parse_authorization_is_presence_only);
    RUN_TEST(test_parse_userinfo_is_flagged_and_dropped);
    RUN_TEST(test_parse_credential_query_is_flagged);
    RUN_TEST(test_parse_firmware_credential_names_are_flagged);
    RUN_TEST(test_parse_credential_in_path_segment_is_flagged);
    RUN_TEST(test_parse_cred_name_needs_a_boundary);
    RUN_TEST(test_parse_path_control_bytes_are_neutralised);

    TEST_SUITE("rtsp: response parse");
    RUN_TEST(test_parse_200_with_sdp);
    RUN_TEST(test_parse_content_type_must_be_sdp);
    RUN_TEST(test_parse_401_with_challenge);
    RUN_TEST(test_parse_status_without_reason);
    RUN_TEST(test_parse_bare_lf_is_tolerated);

    TEST_SUITE("rtsp: truncated and malformed");
    RUN_TEST(test_truncated_start_line_is_not_a_message);
    RUN_TEST(test_truncated_cseq_line_is_not_read);
    RUN_TEST(test_every_prefix_parses_safely);
    RUN_TEST(test_malformed_start_lines);
    RUN_TEST(test_malformed_header_lines_are_skipped);
    RUN_TEST(test_bad_cseq_values);
    RUN_TEST(test_parse_null_and_short);

    TEST_SUITE("rtsp: DESCRIBE pairing and the anonymous decision");
    RUN_TEST(test_anonymous_describe_is_recorded);
    RUN_TEST(test_challenge_then_authenticated_retry);
    RUN_TEST(test_prior_401_disqualifies_a_later_unauthenticated_200);
    RUN_TEST(test_authorization_header_means_not_anonymous);
    RUN_TEST(test_unpaired_response_records_nothing);
    RUN_TEST(test_cseq_mismatch_does_not_pair);
    RUN_TEST(test_other_connection_does_not_pair);
    RUN_TEST(test_responses_out_of_order_pair_by_cseq);
    RUN_TEST(test_non_describe_is_not_tracked);
    RUN_TEST(test_url_credentials_are_never_tracked);
    RUN_TEST(test_firmware_credential_url_is_not_counted_anonymous);
    RUN_TEST(test_parse_reports_header_block_completeness);
    RUN_TEST(test_split_header_block_is_not_counted_anonymous);
    RUN_TEST(test_info_labels);
    RUN_TEST(test_clear_empties_the_table);
    RUN_TEST(test_stream_table_eviction_is_tallied);
    RUN_TEST(test_exchange_table_eviction_is_tallied);

    TEST_SUITE("rtsp: CAM_RTSP_UNAUTH rule");
    RUN_TEST(test_rule_fires_warn_per_server);
    RUN_TEST(test_rule_quiet_when_only_authenticated);
    RUN_TEST(test_rule_one_alert_per_server_with_rising_count);
    RUN_TEST(test_rule_detail_ignores_slot_order);
    RUN_TEST(test_rule_two_servers_two_alerts);
    RUN_TEST(test_rule_from_hand_built_bytes);

#ifdef WITH_PCAP
    TEST_SUITE("rtsp: capture dispatch on 554 and 8554");
    RUN_TEST(test_capture_dispatch_reaches_rtsp_on_both_ports);
    RUN_TEST(test_capture_dispatch_ignores_other_ports);
#endif
}
