#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "cleartext_creds.h"
#include "pop3_snoop.h"

/* POP3 USER/PASS: mirror of the FTP module. Same guardrails apply —
 * the recorder is exercised from a real byte-level input, and the
 * `password_observed` flag flips without any password value ever
 * being retained. */

static int find_cred(const sloth_state_t *s,
                     const char *user, const char *protocol) {
    for (int i = 0; i < s->cleartext_cred_count; i++) {
        if (strcmp(s->cleartext_creds[i].username, user) == 0
            && strcmp(s->cleartext_creds[i].protocol, protocol) == 0)
            return i;
    }
    return -1;
}

static void test_pop3_user_records_username(void) {
    const char *cmd = "USER alice\r\n";
    cleartext_creds_reset();
    ASSERT(pop3_snoop((const uint8_t *)cmd, (int)strlen(cmd),
                      "10.0.0.5", "192.0.2.30", 110));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "POP3");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 0);
}

static void test_pop3_pass_marks_password(void) {
    cleartext_creds_reset();
    pop3_snoop((const uint8_t *)"USER alice\r\n", 12,
               "10.0.0.5", "192.0.2.30", 110);
    ASSERT(pop3_snoop((const uint8_t *)"PASS hunter2\r\n", 14,
                      "10.0.0.5", "192.0.2.30", 110));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "POP3");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 1);
}

static void test_pop3_recognises_other_verbs(void) {
    /* Non-USER/PASS verbs should return 1 (recognised) but record nothing. */
    cleartext_creds_reset();
    ASSERT(pop3_snoop((const uint8_t *)"STAT\r\n", 6,
                      "10.0.0.5", "192.0.2.30", 110));
    ASSERT(pop3_snoop((const uint8_t *)"+OK 12 mails\r\n", 14,
                      "192.0.2.30", "10.0.0.5", 110));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT_EQ(s.cleartext_cred_count, 0);
}

static void test_pop3_rejects_non_pop3(void) {
    cleartext_creds_reset();
    ASSERT_EQ(pop3_snoop((const uint8_t *)"GET / HTTP/1.1\r\n", 16,
                         "10.0.0.5", "192.0.2.30", 110), 0);
}

void run_pop3_snoop_tests(void) {
    TEST_SUITE("pop3 cleartext creds");
    RUN_TEST(test_pop3_user_records_username);
    RUN_TEST(test_pop3_pass_marks_password);
    RUN_TEST(test_pop3_recognises_other_verbs);
    RUN_TEST(test_pop3_rejects_non_pop3);
}
