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


static void test_table_has_its_signatures(void) {
    /* Was ==0 while the table shipped empty. The first row landed in
     * #74; a contributor deleting one by mistake should still see this
     * fail rather than silently ship a detector that matches nothing. */
    ASSERT_EQ(tool_signature_count(), 2);
}

static void test_every_shipped_row_declares_its_provenance(void) {
    /* The rule in tool_fingerprint.c is that a row arrives with the
     * capture that corroborates it. The ESP32 Marauder row does not —
     * it came from #74's research, and landing it is only defensible
     * because the flag is *in the evidence string*, where an operator
     * reading the alert sees it.
     *
     * So: no row ships without evidence, and no row ships without a
     * discriminating field. Both are enforced here rather than in
     * review, because both are the shape a hurried addition takes. */
    ASSERT(tool_signature_count() > 0);
    for (int i = 0; i < tool_signature_count(); i++) {
        const sloth_tool_sig_t *sig = tool_signature_at(i);
        ASSERT(sig != NULL);
        if (!sig) continue;
        ASSERT(sig->evidence != NULL && sig->evidence[0] != '\0');
        /* The flag drives behaviour, the string is what an operator
         * reads. A row where they disagree reports a confidence its
         * own provenance note contradicts. */
        ASSERT_EQ(sig->unverified ? 1 : 0,
                  strncmp(sig->evidence, "UNVERIFIED", 10) == 0 ? 1 : 0);
        ASSERT(sig->human_label != NULL && sig->human_label[0] != '\0');
        ASSERT(sig->tool != SLOTH_TOOL_UNKNOWN);
        /* An all-wildcard row matches every AP and means nothing. */
        ASSERT(sig->vendor_ie_hash || sig->beacon_interval_ms ||
               sig->supported_rates || sig->require_flags ||
               sig->forbid_flags);
    }
    ASSERT(tool_signature_at(-1) == NULL);
    ASSERT(tool_signature_at(tool_signature_count()) == NULL);
}

static void test_unverified_rows_cannot_report_high(void) {
    /* The whole safety property of landing rows without captures. A
     * synthetic *verified* row pinning the same three things reports
     * HIGH; the shipped unverified one cannot. */
    static const sloth_tool_sig_t verified[] = {
        { SLOTH_TOOL_HOSTAPD_MANA, 0xabcd1234, 102, 0,
          AP_FP_FLAG_ESPRESSIF_OUI, 0, 0, 0, 0,
          "verified-three", "synthetic capture, test only" },
    };
    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.vendor_ie_hash     = 0xabcd1234;
    obs.beacon_interval_ms = 102;
    obs.fp_flags           = AP_FP_FLAG_ESPRESSIF_OUI;
    sloth_tool_conf_t conf = TOOL_CONF_NONE;
    ASSERT_EQ((int)tool_fingerprint_match_table(verified, 1, &obs, &conf, NULL),
              (int)SLOTH_TOOL_HOSTAPD_MANA);
    ASSERT_EQ((int)conf, (int)TOOL_CONF_HIGH);

    /* Same three fields, marked unverified. */
    static const sloth_tool_sig_t unverified[] = {
        { SLOTH_TOOL_HOSTAPD_MANA, 0xabcd1234, 102, 0,
          AP_FP_FLAG_ESPRESSIF_OUI, 0, 0, 0, 1,
          "unverified-three", "UNVERIFIED - synthetic, test only" },
    };
    ASSERT_EQ((int)tool_fingerprint_match_table(unverified, 1, &obs, &conf,
                                                NULL),
              (int)SLOTH_TOOL_HOSTAPD_MANA);
    ASSERT_EQ((int)conf, (int)TOOL_CONF_MED);

    /* The cap is a ceiling, not an assignment: a one-field unverified
     * row still reports LOW, not MED. */
    memset(&obs, 0, sizeof(obs));
    obs.fp_flags   = AP_FP_FLAG_HAK5_OUI;
    obs.karma_echo = 1;
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, NULL),
              (int)SLOTH_TOOL_PINEAPPLE_MK7);
    ASSERT_EQ((int)conf, (int)TOOL_CONF_LOW);
}

static void test_no_row_depends_on_an_unpopulated_flag(void) {
    /* AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS is defined and nothing in the
     * tree ever sets it. A row requiring it can never match; a row
     * forbidding it always passes and scores a hit for a comparison
     * that did not happen — inflating confidence for nothing. Either
     * way the row lies about how much it checked, and neither failure
     * is visible by reading the row. */
    for (int i = 0; i < tool_signature_count(); i++) {
        const sloth_tool_sig_t *sig = tool_signature_at(i);
        if (!sig) continue;
        ASSERT_EQ(sig->require_flags & AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS, 0);
        ASSERT_EQ(sig->forbid_flags  & AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS, 0);
    }
}

static void test_pineapple_row_is_the_hak5_oui(void) {
    /* One field, so LOW confidence — and that is the honest level.
     * Unlike Espressif, a Hak5 vanity OUI does not turn up in an air
     * conditioner, so one field is still worth saying. */
    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.fp_flags   = AP_FP_FLAG_HAK5_OUI;
    obs.karma_echo = 1;
    sloth_tool_conf_t conf = TOOL_CONF_NONE;
    const char *label = "";
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, &label),
              (int)SLOTH_TOOL_PINEAPPLE_MK7);
    ASSERT_STR(label, "Pineapple MK7");
    ASSERT_EQ((int)conf, (int)TOOL_CONF_LOW);

    /* Never without the KARMA echo: an enrichment on a finding, not a
     * finding. A Hak5 OUI alone is somebody carrying a Pineapple, which
     * is not the same as running one. */
    obs.karma_echo = 0;
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, &label),
              (int)SLOTH_TOOL_UNKNOWN);
}

static void test_the_two_rows_do_not_collide(void) {
    /* Distinct OUI families, so no observation can satisfy both — and
     * the Marauder row, pinning more, must outrank if one ever could.
     * Asserted because "add a row" is the operation most likely to
     * quietly break another row. */
    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.karma_echo         = 1;
    obs.beacon_interval_ms = 102;
    obs.fp_flags           = AP_FP_FLAG_HAK5_OUI;
    sloth_tool_conf_t conf = TOOL_CONF_NONE;
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, NULL),
              (int)SLOTH_TOOL_PINEAPPLE_MK7);

    obs.fp_flags = AP_FP_FLAG_ESPRESSIF_OUI;
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, NULL),
              (int)SLOTH_TOOL_ESP32_MARAUDER);
    /* Three fields agree on the Marauder row, which the field-count
     * model calls HIGH — but the row has no capture behind it, so the
     * unverified cap holds it at MED. Thoroughness and provenance are
     * different axes and the reported confidence must respect both. */
    ASSERT_EQ((int)conf, (int)TOOL_CONF_MED);
}

static void test_require_flags_needs_every_bit(void) {
    /* The shipped row requires one flag, so all-bits and any-bit
     * behave identically against it — a future two-flag row is where
     * the difference bites, and "any of these" is a much weaker claim
     * than the row's author meant to make. Driven through the table
     * entry point, which exists for exactly this. */
    static const sloth_tool_sig_t sigs[] = {
        { SLOTH_TOOL_WIFI_DUCK, 0, 0, 0,
          AP_FP_FLAG_ESPRESSIF_OUI | AP_FP_FLAG_WPS_UUID_ZERO, 0, 0, 0, 0,
          "two-flag", "synthetic, test only" },
    };
    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    sloth_tool_conf_t conf = TOOL_CONF_NONE;

    obs.fp_flags = AP_FP_FLAG_ESPRESSIF_OUI;          /* one of two */
    ASSERT_EQ((int)tool_fingerprint_match_table(sigs, 1, &obs, &conf, NULL),
              (int)SLOTH_TOOL_UNKNOWN);
    obs.fp_flags = AP_FP_FLAG_WPS_UUID_ZERO;          /* the other  */
    ASSERT_EQ((int)tool_fingerprint_match_table(sigs, 1, &obs, &conf, NULL),
              (int)SLOTH_TOOL_UNKNOWN);
    obs.fp_flags = AP_FP_FLAG_ESPRESSIF_OUI | AP_FP_FLAG_WPS_UUID_ZERO;
    ASSERT_EQ((int)tool_fingerprint_match_table(sigs, 1, &obs, &conf, NULL),
              (int)SLOTH_TOOL_WIFI_DUCK);
    /* Extra unrelated flags must not block it — require is a subset
     * test, not equality. */
    obs.fp_flags |= AP_FP_FLAG_HE_PRESENT;
    ASSERT_EQ((int)tool_fingerprint_match_table(sigs, 1, &obs, &conf, NULL),
              (int)SLOTH_TOOL_WIFI_DUCK);
}

static void test_marauder_row_needs_all_three_signals(void) {
    /* 100 TU is the 802.11 default and an Espressif OUI ships in real
     * IoT, so neither means anything alone. The row's claim is the
     * combination — Espressif, no HT, default interval — and every one
     * of the three has to be load-bearing or the row fires on a smart
     * plug. */
    sloth_tool_obs_t obs;
    memset(&obs, 0, sizeof(obs));
    obs.beacon_interval_ms = 102;
    obs.fp_flags           = AP_FP_FLAG_ESPRESSIF_OUI;
    obs.karma_echo         = 1;
    sloth_tool_conf_t conf = TOOL_CONF_NONE;
    const char *label = "";
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, &label),
              (int)SLOTH_TOOL_ESP32_MARAUDER);
    ASSERT_STR(label, "ESP32 Marauder");

    /* An Espressif AP that *does* negotiate HT is an IoT device, not a
     * rogue: a 2026 access point with no HT is the discriminating part. */
    obs.fp_flags = AP_FP_FLAG_ESPRESSIF_OUI | AP_FP_FLAG_HT_PRESENT;
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, &label),
              (int)SLOTH_TOOL_UNKNOWN);

    /* Not Espressif at all. */
    obs.fp_flags = 0;
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, &label),
              (int)SLOTH_TOOL_UNKNOWN);

    /* A non-default beacon interval. */
    obs.fp_flags           = AP_FP_FLAG_ESPRESSIF_OUI;
    obs.beacon_interval_ms = 300;
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, &label),
              (int)SLOTH_TOOL_UNKNOWN);

    /* And without a KARMA echo it stays silent. The row is an
     * enrichment on an existing finding, never a standalone claim —
     * that gate is what makes an unverified row safe to ship. */
    obs.beacon_interval_ms = 102;
    obs.karma_echo         = 0;
    ASSERT_EQ((int)tool_fingerprint_match(&obs, &conf, &label),
              (int)SLOTH_TOOL_UNKNOWN);
}

static void test_unmatched_observation_is_unknown(void) {
    /* A detector with no matching data has to be silent, not creative. */
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
    RUN_TEST(test_table_has_its_signatures);
    RUN_TEST(test_every_shipped_row_declares_its_provenance);
    RUN_TEST(test_unverified_rows_cannot_report_high);
    RUN_TEST(test_no_row_depends_on_an_unpopulated_flag);
    RUN_TEST(test_pineapple_row_is_the_hak5_oui);
    RUN_TEST(test_the_two_rows_do_not_collide);
    RUN_TEST(test_require_flags_needs_every_bit);
    RUN_TEST(test_marauder_row_needs_all_three_signals);
    RUN_TEST(test_unmatched_observation_is_unknown);
    RUN_TEST(test_null_observation_is_safe);
    RUN_TEST(test_every_tool_id_has_a_name);
    RUN_TEST(test_confidence_names);

    TEST_SUITE("tool fingerprint matching rules (#68)");
    RUN_TEST(test_zero_fields_are_wildcards);
    RUN_TEST(test_all_wildcard_row_matches_nothing);
    RUN_TEST(test_preconditions_gate_without_scoring);
    RUN_TEST(test_more_pinned_fields_beats_fewer);
}
