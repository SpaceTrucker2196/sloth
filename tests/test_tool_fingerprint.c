#include <string.h>
#include "runner.h"
#include "tool_fingerprint.h"

/*
 * Attacker-tool fingerprinting — issue #68.
 *
 * The signature table ships **empty on purpose**, so these tests
 * exercise the matcher rather than any particular tool. That split is
 * the design: a contributor with a lab rig adds a row without needing
 * to understand the matching logic, and the matching logic is proven
 * before any row exists to be wrong about.
 *
 * The synthetic rows below live in the tests, never in the table.
 */


static void test_table_is_empty_on_purpose(void) {
    /* Not an accident, and worth asserting: a future contributor
     * deleting a row by mistake should see this fail rather than
     * silently ship a detector that matches nothing. When the first
     * real signature lands this test changes to `> 0` in the same
     * commit as the capture that justifies it. */
    ASSERT_EQ(tool_signature_count(), 0);
}

static void test_empty_table_matches_nothing(void) {
    /* And it must say "unknown" rather than guessing. A detector with
     * no data has to be silent, not creative. */
    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.vendor_ie_hash     = 0xdeadbeef;
    obs.beacon_interval_ms = 100;
    obs.karma_echo         = 1;
    obs.pmkid_seen         = 1;

    sloth_tool_conf_t conf = TOOL_CONF_HIGH;
    const char *label = "wrong";
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, &label),
              (int)SLOTH_TOOL_UNKNOWN);
    ASSERT_EQ((int)conf, (int)TOOL_CONF_NONE);
    ASSERT_STR(label, "");
}

static void test_null_observation_is_safe(void) {
    sloth_tool_conf_t conf = TOOL_CONF_HIGH;
    const char *label = "wrong";
    ASSERT_EQ((int)tool_fingerprint_match(NULL, &conf, &label),
              (int)SLOTH_TOOL_UNKNOWN);
    ASSERT_EQ((int)conf, (int)TOOL_CONF_NONE);
    ASSERT_STR(label, "");
    /* NULL outputs must not crash either — the alert path passes them. */
    ASSERT_EQ((int)tool_fingerprint_match(NULL, NULL, NULL),
              (int)SLOTH_TOOL_UNKNOWN);
}

static void test_every_tool_id_has_a_name(void) {
    /* A row added for a tool with no name renders as an empty string in
     * the alert detail, which reads as a bug rather than a finding. */
    for (int id = SLOTH_TOOL_UNKNOWN + 1; id < SLOTH_TOOL_COUNT; id++) {
        const char *n = tool_name((sloth_tool_id_t)id);
        ASSERT(n != NULL);
        ASSERT(n[0] != '\0');
    }
    /* UNKNOWN is deliberately nameless — it is the absence of a
     * finding, not a tool called "unknown". */
    ASSERT_STR(tool_name(SLOTH_TOOL_UNKNOWN), "");
}

static void test_confidence_names(void) {
    ASSERT_STR(tool_confidence_name(TOOL_CONF_LOW),  "low");
    ASSERT_STR(tool_confidence_name(TOOL_CONF_MED),  "med");
    ASSERT_STR(tool_confidence_name(TOOL_CONF_HIGH), "high");
    ASSERT_STR(tool_confidence_name(TOOL_CONF_NONE), "");
}

/* ── The matching rules, exercised through the real matcher ──
 *
 * These drive tool_fingerprint_match_table() with synthetic rows rather
 * than re-implementing its logic alongside it. That matters: the
 * built-in table is empty, so a test going through the normal entry
 * point cannot reach any of the matcher's guards, and a mutation to one
 * survives. Mutation testing showed exactly that before this split.
 *
 * They are also a specification of what a signature row *means*,
 * because the next person to touch this file will be adding one. */

static int match_one(const sloth_tool_sig_t *sig,
                     const sloth_tool_obs_t *obs,
                     sloth_tool_conf_t *conf) {
    return tool_fingerprint_match_table(sig, 1, obs, conf, NULL)
           != SLOTH_TOOL_UNKNOWN;
}

static void test_zero_fields_are_wildcards(void) {
    sloth_tool_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    sig.tool = SLOTH_TOOL_EAPHAMMER;
    sig.beacon_interval_ms = 100;      /* the only pinned field */

    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.beacon_interval_ms = 100;
    obs.vendor_ie_hash     = 0x11111111;   /* wildcarded, so irrelevant */
    sloth_tool_conf_t conf = TOOL_CONF_NONE;
    ASSERT_EQ(match_one(&sig, &obs, &conf), 1);
    ASSERT_EQ((int)conf, (int)TOOL_CONF_LOW);   /* one field pinned */

    obs.beacon_interval_ms = 102;
    ASSERT_EQ(match_one(&sig, &obs, NULL), 0);
}

static void test_all_wildcard_row_matches_nothing(void) {
    /* The failure mode a signature table falls into: someone adds a row
     * they were not sure about, leaves every field zero, and it matches
     * every AP in range with maximum confidence. Refused rather than
     * scored, so a malformed addition is inert instead of catastrophic. */
    sloth_tool_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    sig.tool = SLOTH_TOOL_PINEAPPLE_MK7;

    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.vendor_ie_hash = 0xabcdef01;
    ASSERT_EQ(match_one(&sig, &obs, NULL), 0);
}

static void test_preconditions_gate_without_scoring(void) {
    /* requires_karma_echo is a precondition, not a characteristic: "a
     * KARMA event happened" is already why we are looking, so it must
     * not inflate the confidence of a row that otherwise pins one
     * field. */
    sloth_tool_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    sig.tool = SLOTH_TOOL_HOSTAPD_MANA;
    sig.beacon_interval_ms  = 100;
    sig.requires_karma_echo = 1;

    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.beacon_interval_ms = 100;

    ASSERT_EQ(match_one(&sig, &obs, NULL), 0);     /* no KARMA event */
    obs.karma_echo = 1;
    sloth_tool_conf_t conf = TOOL_CONF_NONE;
    ASSERT_EQ(match_one(&sig, &obs, &conf), 1);
    /* LOW, not MED: the precondition gated the row without scoring. */
    ASSERT_EQ((int)conf, (int)TOOL_CONF_LOW);
}

static void test_more_pinned_fields_beats_fewer(void) {
    /* "Best match wins, measured by fields agreed" — a row pinning
     * three characteristics is a claim, one pinning a beacon interval
     * is a coincidence waiting to happen. */
    sloth_tool_sig_t narrow, broad;
    memset(&narrow, 0, sizeof(narrow));
    memset(&broad,  0, sizeof(broad));
    narrow.tool = SLOTH_TOOL_ESP32_MARAUDER;
    narrow.beacon_interval_ms = 100;
    broad.tool  = SLOTH_TOOL_WIFI_DUCK;
    broad.beacon_interval_ms  = 100;
    broad.vendor_ie_hash      = 0x22222222;
    broad.supported_rates     = 0x0f;

    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.beacon_interval_ms = 100;
    obs.vendor_ie_hash     = 0x22222222;
    obs.supported_rates    = 0x0f;

    /* Both in one table: the matcher must pick the broader row. */
    sloth_tool_sig_t table[2] = { narrow, broad };
    sloth_tool_conf_t conf = TOOL_CONF_NONE;
    const char *label = "";
    ASSERT_EQ((int)tool_fingerprint_match_table(table, 2, &obs, &conf, &label),
              (int)SLOTH_TOOL_WIFI_DUCK);
    ASSERT_EQ((int)conf, (int)TOOL_CONF_HIGH);    /* three fields agreed */
    ASSERT_STR(label, "Wi-Fi Duck");

    /* Order must not decide it. */
    sloth_tool_sig_t rev[2] = { broad, narrow };
    ASSERT_EQ((int)tool_fingerprint_match_table(rev, 2, &obs, NULL, NULL),
              (int)SLOTH_TOOL_WIFI_DUCK);
}

void run_tool_fingerprint_tests(void) {
    TEST_SUITE("tool fingerprint table (#68)");
    RUN_TEST(test_table_is_empty_on_purpose);
    RUN_TEST(test_empty_table_matches_nothing);
    RUN_TEST(test_null_observation_is_safe);
    RUN_TEST(test_every_tool_id_has_a_name);
    RUN_TEST(test_confidence_names);

    TEST_SUITE("tool fingerprint matching rules (#68)");
    RUN_TEST(test_zero_fields_are_wildcards);
    RUN_TEST(test_all_wildcard_row_matches_nothing);
    RUN_TEST(test_preconditions_gate_without_scoring);
    RUN_TEST(test_more_pinned_fields_beats_fewer);
}
