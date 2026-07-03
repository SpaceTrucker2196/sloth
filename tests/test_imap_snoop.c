#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "cleartext_creds.h"
#include "imap_snoop.h"

static int find_cred(const sloth_state_t *s,
                     const char *user, const char *protocol) {
    for (int i = 0; i < s->cleartext_cred_count; i++) {
        if (strcmp(s->cleartext_creds[i].username, user) == 0
            && strcmp(s->cleartext_creds[i].protocol, protocol) == 0)
            return i;
    }
    return -1;
}

static void test_imap_bare_login(void) {
    const char *cmd = "a001 LOGIN alice hunter2\r\n";
    cleartext_creds_reset();
    ASSERT(imap_snoop((const uint8_t *)cmd, (int)strlen(cmd),
                      "10.0.0.5", "192.0.2.40", 143));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    int idx = find_cred(&s, "alice", "IMAP");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.cleartext_creds[idx].password_observed, 1);
}

static void test_imap_quoted_login(void) {
    /* IMAP allows either side of LOGIN to be quoted. */
    const char *cmd = "a002 LOGIN \"bob\" \"pw\"\r\n";
    cleartext_creds_reset();
    ASSERT(imap_snoop((const uint8_t *)cmd, (int)strlen(cmd),
                      "10.0.0.5", "192.0.2.40", 143));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT(find_cred(&s, "bob", "IMAP") >= 0);
}

static void test_imap_case_insensitive_verb(void) {
    const char *cmd = "A003 login carol pw\r\n";
    cleartext_creds_reset();
    ASSERT(imap_snoop((const uint8_t *)cmd, (int)strlen(cmd),
                      "10.0.0.5", "192.0.2.40", 143));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT(find_cred(&s, "carol", "IMAP") >= 0);
}

static void test_imap_other_verbs_recognised_no_record(void) {
    cleartext_creds_reset();
    ASSERT(imap_snoop((const uint8_t *)"a004 CAPABILITY\r\n", 17,
                      "10.0.0.5", "192.0.2.40", 143));
    ASSERT(imap_snoop((const uint8_t *)"* OK IMAP4rev1 ready\r\n", 22,
                      "192.0.2.40", "10.0.0.5", 143));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_creds_snapshot(&s);
    ASSERT_EQ(s.cleartext_cred_count, 0);
}

static void test_imap_rejects_non_imap(void) {
    cleartext_creds_reset();
    ASSERT_EQ(imap_snoop((const uint8_t *)"GET / HTTP/1.1\r\n", 16,
                         "10.0.0.5", "192.0.2.40", 143), 0);
}

void run_imap_snoop_tests(void) {
    TEST_SUITE("imap cleartext creds");
    RUN_TEST(test_imap_bare_login);
    RUN_TEST(test_imap_quoted_login);
    RUN_TEST(test_imap_case_insensitive_verb);
    RUN_TEST(test_imap_other_verbs_recognised_no_record);
    RUN_TEST(test_imap_rejects_non_imap);
}
