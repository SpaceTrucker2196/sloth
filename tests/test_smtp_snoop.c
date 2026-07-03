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

void run_smtp_snoop_tests(void) {
    TEST_SUITE("smtp cleartext creds");
    RUN_TEST(test_smtp_auth_plain_extracts_user);
    RUN_TEST(test_smtp_auth_plain_with_authzid);
    RUN_TEST(test_smtp_auth_plain_case_insensitive);
    RUN_TEST(test_smtp_other_verbs_recognised_no_record);
    RUN_TEST(test_smtp_rejects_non_smtp);
}
