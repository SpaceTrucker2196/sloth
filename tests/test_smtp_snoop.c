#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "cleartext_creds.h"
#include "smtp_snoop.h"

static int find_cred(const sloth_state_t *s,
                     const char *user, const char *protocol) {
    for (int i = 0; i < s->cleartext_cred_count; i++) {
        if (strcmp(s->cleartext_creds[i].username, user) == 0
            && strcmp(s->cleartext_creds[i].protocol, protocol) == 0)
            return i;
    }
    return -1;
}

static void test_smtp_auth_plain_extracts_user(void) {
    /* AUTH PLAIN payload: "\0alice\0hunter2" → base64 "AGFsaWNlAGh1bnRlcjI=" */
    const char *cmd = "AUTH PLAIN AGFsaWNlAGh1bnRlcjI=\r\n";
    cleartext_creds_reset();
    ASSERT(smtp_snoop((const uint8_t *)cmd, (int)strlen(cmd),
                      "10.0.0.5", "192.0.2.50", 587));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "SMTP");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 1);
}

static void test_smtp_auth_plain_with_authzid(void) {
    /* Payload: "admin\0alice\0hunter2" → base64 "YWRtaW4AYWxpY2UAaHVudGVyMg==" */
    const char *cmd = "AUTH PLAIN YWRtaW4AYWxpY2UAaHVudGVyMg==\r\n";
    cleartext_creds_reset();
    ASSERT(smtp_snoop((const uint8_t *)cmd, (int)strlen(cmd),
                      "10.0.0.5", "192.0.2.50", 587));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    /* Username is the authcid (second field), NOT the authzid. */
    ASSERT(find_cred(&s, "alice", "SMTP") >= 0);
    ASSERT_EQ(find_cred(&s, "admin", "SMTP"), -1);
}

static void test_smtp_auth_plain_case_insensitive(void) {
    const char *cmd = "auth plain AGFsaWNlAGh1bnRlcjI=\r\n";
    cleartext_creds_reset();
    ASSERT(smtp_snoop((const uint8_t *)cmd, (int)strlen(cmd),
                      "10.0.0.5", "192.0.2.50", 25));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT(find_cred(&s, "alice", "SMTP") >= 0);
}

static void test_smtp_other_verbs_recognised_no_record(void) {
    cleartext_creds_reset();
    ASSERT(smtp_snoop((const uint8_t *)"EHLO client.example\r\n", 21,
                      "10.0.0.5", "192.0.2.50", 25));
    ASSERT(smtp_snoop((const uint8_t *)"250 Hello\r\n", 11,
                      "192.0.2.50", "10.0.0.5", 25));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT_EQ(s.cleartext_cred_count, 0);
}

static void test_smtp_rejects_non_smtp(void) {
    cleartext_creds_reset();
    ASSERT_EQ(smtp_snoop((const uint8_t *)"GET / HTTP/1.1\r\n", 16,
                         "10.0.0.5", "192.0.2.50", 25), 0);
}

/* ── AUTH LOGIN (stateful three-line exchange) ─────────
 * SMTP AUTH LOGIN sends the username and password on separate
 * lines, each base64-encoded. State machine:
 *   AUTH LOGIN          →  AWAIT_USER
 *   <b64 user>          →  AWAIT_PASS, record username
 *   <b64 pass>          →  NONE, mark password observed */

static void test_smtp_auth_login_records_user_then_pass(void) {
    cleartext_creds_reset();
    smtp_snoop_reset();
    ASSERT(smtp_snoop((const uint8_t *)"AUTH LOGIN\r\n", 12,
                      "10.0.0.5", "192.0.2.60", 587));
    /* "alice" base64 = "YWxpY2U=" */
    ASSERT(smtp_snoop((const uint8_t *)"YWxpY2U=\r\n", 10,
                      "10.0.0.5", "192.0.2.60", 587));
    /* "hunter2" base64 = "aHVudGVyMg==" */
    ASSERT(smtp_snoop((const uint8_t *)"aHVudGVyMg==\r\n", 14,
                      "10.0.0.5", "192.0.2.60", 587));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "SMTP");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 1);
}

static void test_smtp_auth_login_pipelined_user(void) {
    /* Some clients (e.g. postscreen probes) put the b64 user on the
     * same line as AUTH LOGIN. */
    cleartext_creds_reset();
    smtp_snoop_reset();
    ASSERT(smtp_snoop((const uint8_t *)"AUTH LOGIN YWxpY2U=\r\n", 21,
                      "10.0.0.5", "192.0.2.60", 587));
    ASSERT(smtp_snoop((const uint8_t *)"aHVudGVyMg==\r\n", 14,
                      "10.0.0.5", "192.0.2.60", 587));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "SMTP");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 1);
}

static void test_smtp_auth_login_server_prompts_ignored(void) {
    /* Server 334 prompts must not clobber state. Sequence:
     *   C: AUTH LOGIN
     *   S: 334 VXNlcm5hbWU6   (server; src_port would be 25/587)
     *   C: <b64 user>
     *   S: 334 UGFzc3dvcmQ6
     *   C: <b64 pass>
     * We simulate the server payloads by calling smtp_snoop with the
     * client & server IPs swapped and dst_port = ephemeral. */
    cleartext_creds_reset();
    smtp_snoop_reset();
    ASSERT(smtp_snoop((const uint8_t *)"AUTH LOGIN\r\n", 12,
                      "10.0.0.5", "192.0.2.60", 587));
    /* Server prompt — direction swapped, dst_port is not SMTP. */
    ASSERT(smtp_snoop((const uint8_t *)"334 VXNlcm5hbWU6\r\n", 18,
                      "192.0.2.60", "10.0.0.5", 45678));
    ASSERT(smtp_snoop((const uint8_t *)"YWxpY2U=\r\n", 10,
                      "10.0.0.5", "192.0.2.60", 587));
    ASSERT(smtp_snoop((const uint8_t *)"334 UGFzc3dvcmQ6\r\n", 18,
                      "192.0.2.60", "10.0.0.5", 45678));
    ASSERT(smtp_snoop((const uint8_t *)"aHVudGVyMg==\r\n", 14,
                      "10.0.0.5", "192.0.2.60", 587));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "SMTP");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 1);
}

static void test_smtp_auth_login_separate_flows_independent(void) {
    /* Two overlapping AUTH LOGIN sessions on the same server from
     * different clients must not cross-contaminate. */
    cleartext_creds_reset();
    smtp_snoop_reset();
    smtp_snoop((const uint8_t *)"AUTH LOGIN\r\n", 12,
               "10.0.0.5", "192.0.2.60", 587);
    smtp_snoop((const uint8_t *)"AUTH LOGIN\r\n", 12,
               "10.0.0.9", "192.0.2.60", 587);
    /* alice from .5 */
    smtp_snoop((const uint8_t *)"YWxpY2U=\r\n", 10,
               "10.0.0.5", "192.0.2.60", 587);
    /* bob from .9 */
    smtp_snoop((const uint8_t *)"Ym9i\r\n", 6,
               "10.0.0.9", "192.0.2.60", 587);
    /* passwords, both marked */
    smtp_snoop((const uint8_t *)"aHVudGVyMg==\r\n", 14,
               "10.0.0.5", "192.0.2.60", 587);
    smtp_snoop((const uint8_t *)"c2VjcmV0\r\n", 10,
               "10.0.0.9", "192.0.2.60", 587);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT(find_cred(&s, "alice", "SMTP") >= 0);
    ASSERT(find_cred(&s, "bob",   "SMTP") >= 0);
    /* Both flows should have password_observed set. */
    int a = find_cred(&s, "alice", "SMTP");
    int b = find_cred(&s, "bob",   "SMTP");
    ASSERT_EQ(s.cleartext_creds[a].password_observed, 1);
    ASSERT_EQ(s.cleartext_creds[b].password_observed, 1);
}

void run_smtp_snoop_tests(void) {
    TEST_SUITE("smtp cleartext creds — AUTH PLAIN");
    RUN_TEST(test_smtp_auth_plain_extracts_user);
    RUN_TEST(test_smtp_auth_plain_with_authzid);
    RUN_TEST(test_smtp_auth_plain_case_insensitive);
    RUN_TEST(test_smtp_other_verbs_recognised_no_record);
    RUN_TEST(test_smtp_rejects_non_smtp);

    TEST_SUITE("smtp cleartext creds — AUTH LOGIN");
    RUN_TEST(test_smtp_auth_login_records_user_then_pass);
    RUN_TEST(test_smtp_auth_login_pipelined_user);
    RUN_TEST(test_smtp_auth_login_server_prompts_ignored);
    RUN_TEST(test_smtp_auth_login_separate_flows_independent);
}
