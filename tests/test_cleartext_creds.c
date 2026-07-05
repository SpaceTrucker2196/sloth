#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "cleartext_creds.h"
#include "http_snoop.h"
#include "ftp_snoop.h"
#include "alerts.h"

/* Roadmap #16 phase 3 — cleartext credential exposure detection.
 * Verifies both the detection paths (HTTP Basic + FTP USER/PASS) and
 * the guardrail invariants (never a password field, sanitized input,
 * ring coalescing). */

static int find_cred(const sloth_state_t *s,
                     const char *user, const char *protocol) {
    for (int i = 0; i < s->cleartext_cred_count; i++) {
        if (strcmp(s->cleartext_creds[i].username, user) == 0
            && strcmp(s->cleartext_creds[i].protocol, protocol) == 0)
            return i;
    }
    return -1;
}

/* ── HTTP Basic ─────────────────────────────────────────── */

static void test_http_basic_records_username(void) {
    /* "alice:hunter2" → "YWxpY2U6aHVudGVyMg==" */
    const char *req =
        "GET /admin HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n"
        "User-Agent: curl/8\r\n\r\n";
    cleartext_creds_reset();
    http_snoop_scan_creds((const uint8_t *)req, (int)strlen(req),
                          "10.0.0.5", "192.0.2.10", 80);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "HTTP-Basic");
    ASSERT(idx >= 0);
    ASSERT_STR(s.cleartext_creds[idx].src, "10.0.0.5");
    ASSERT_STR(s.cleartext_creds[idx].dst, "192.0.2.10");
    ASSERT_EQ((int)s.cleartext_creds[idx].dst_port, 80);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 1);
}

static void test_http_basic_ignores_bearer(void) {
    /* Authorization: Bearer <token> is NOT cleartext creds — it's an
     * opaque token. Must not fire. */
    const char *req =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Authorization: Bearer abcdef123456\r\n\r\n";
    cleartext_creds_reset();
    http_snoop_scan_creds((const uint8_t *)req, (int)strlen(req),
                          "10.0.0.5", "192.0.2.10", 80);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT_EQ(s.cleartext_cred_count, 0);
}

static void test_http_basic_case_insensitive_scheme(void) {
    /* Header name is case-insensitive per RFC 7230 §3.2; scheme name
     * per RFC 7235 §2.1. */
    const char *req =
        "POST /x HTTP/1.1\r\n"
        "Host: h\r\n"
        "AUTHORIZATION: BASIC Ym9iOnBhc3M=\r\n\r\n";  /* bob:pass */
    cleartext_creds_reset();
    http_snoop_scan_creds((const uint8_t *)req, (int)strlen(req),
                          "10.0.0.9", "192.0.2.11", 8080);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT(find_cred(&s, "bob", "HTTP-Basic") >= 0);
}

static void test_http_basic_coalesces_duplicate(void) {
    /* Two identical Authorization headers → one row, not two. */
    const char *req =
        "GET /a HTTP/1.1\r\n"
        "Host: h\r\n"
        "Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n";
    cleartext_creds_reset();
    http_snoop_scan_creds((const uint8_t *)req, (int)strlen(req),
                          "10.0.0.5", "192.0.2.10", 80);
    http_snoop_scan_creds((const uint8_t *)req, (int)strlen(req),
                          "10.0.0.5", "192.0.2.10", 80);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT_EQ(s.cleartext_cred_count, 1);
}

/* ── FTP USER/PASS ────────────────────────────────────── */

static void test_ftp_user_records_username(void) {
    const char *user_cmd = "USER alice\r\n";
    cleartext_creds_reset();
    ASSERT(ftp_snoop((const uint8_t *)user_cmd, (int)strlen(user_cmd),
                     "10.0.0.5", "192.0.2.20", 21));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "FTP");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 0);
}

static void test_ftp_pass_marks_password(void) {
    const char *user_cmd = "USER alice\r\n";
    const char *pass_cmd = "PASS hunter2\r\n";
    cleartext_creds_reset();
    ftp_snoop((const uint8_t *)user_cmd, (int)strlen(user_cmd),
              "10.0.0.5", "192.0.2.20", 21);
    ftp_snoop((const uint8_t *)pass_cmd, (int)strlen(pass_cmd),
              "10.0.0.5", "192.0.2.20", 21);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "FTP");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 1);
}

static void test_ftp_other_commands_dont_record(void) {
    const char *pwd = "PWD\r\n";
    cleartext_creds_reset();
    ASSERT(ftp_snoop((const uint8_t *)pwd, (int)strlen(pwd),
                     "10.0.0.5", "192.0.2.20", 21));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT_EQ(s.cleartext_cred_count, 0);
}

static void test_ftp_rejects_non_ftp_traffic(void) {
    const char *http = "GET / HTTP/1.1\r\n";
    cleartext_creds_reset();
    ASSERT_EQ(ftp_snoop((const uint8_t *)http, (int)strlen(http),
                        "10.0.0.5", "192.0.2.20", 21), 0);
}

/* ── Guardrail: sanitization ────────────────────────── */

static void test_username_sanitizes_control_chars(void) {
    /* USER contains \x01 (start of heading). The recorder should
     * strip that so JSONL/TUI can't be injected. */
    const char *cmd = "USER al\x01ice\r\n";
    cleartext_creds_reset();
    ftp_snoop((const uint8_t *)cmd, (int)strlen(cmd),
              "10.0.0.5", "192.0.2.20", 21);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    /* The control char was dropped, so "alice" remains. */
    int idx = find_cred(&s, "alice", "FTP");
    ASSERT(idx >= 0);
}

/* ── Alert wiring ───────────────────────────────────── */

static void test_alert_fires_on_cleartext_cred(void) {
    /* End-to-end: record a cred, run alerts_update, assert the alert
     * appears with technique T1040 (Network Sniffing). */
    cleartext_creds_reset();
    cleartext_creds_record_user("10.0.0.5", "192.0.2.30", 80,
                                "HTTP-Basic", "admin");
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);

    alerts_clear();
    alerts_update(&s);

    int idx = -1;
    for (int i = 0; i < s.alert_count; i++)
        if (s.alerts[i].type == ALERT_TYPE_CLEARTEXT_CRED) { idx = i; break; }
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
    ASSERT_STR(s.alerts[idx].title,     "CLEARTEXT_CRED");
    ASSERT_STR(s.alerts[idx].technique, "T1040");
}

void run_cleartext_creds_tests(void) {
    TEST_SUITE("cleartext creds — HTTP Basic");
    RUN_TEST(test_http_basic_records_username);
    RUN_TEST(test_http_basic_ignores_bearer);
    RUN_TEST(test_http_basic_case_insensitive_scheme);
    RUN_TEST(test_http_basic_coalesces_duplicate);

    TEST_SUITE("cleartext creds — FTP");
    RUN_TEST(test_ftp_user_records_username);
    RUN_TEST(test_ftp_pass_marks_password);
    RUN_TEST(test_ftp_other_commands_dont_record);
    RUN_TEST(test_ftp_rejects_non_ftp_traffic);

    TEST_SUITE("cleartext creds — guardrails");
    RUN_TEST(test_username_sanitizes_control_chars);

    TEST_SUITE("cleartext creds — alert wiring");
    RUN_TEST(test_alert_fires_on_cleartext_cred);
}
