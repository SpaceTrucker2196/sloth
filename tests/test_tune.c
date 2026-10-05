#include <string.h>
#include <stdio.h>
#include "runner.h"
#include "tune.h"
#include "karma_detect.h"   /* KARMA_SSID_THRESH, the macro the knob feeds */

/* ── Operator-tunable thresholds — issue #82 ──────────────────
 *
 * The owner accepted the WPS rate thresholds "each behind a config
 * knob" (2026-09-30) when no such mechanism existed: every detector
 * threshold in src/alerts.c was a #define. These cover the registry
 * that replaced them.
 *
 * The cases that matter most are the rejections. A knob an operator
 * believes they set but did not is worse than no knob, because the
 * run looks tuned and behaves stock — so a bad --tune has to be a
 * startup error, never a default silently kept. */

static void test_defaults_are_the_shipped_values(void) {
    tune_reset();
    /* Spot-check against the values these were as #defines, so a
       mistyped registry row is caught rather than ratified. */
    ASSERT_EQ((long long)tune_val(TUNE_KARMA_SSID_THRESH), 3);
    ASSERT_EQ((long long)tune_val(TUNE_DNS_TUNNEL_LABEL_THRESH), 30);
    ASSERT_EQ((long long)tune_val(TUNE_DNS_TUNNEL_LONG_HITS), 8);
    ASSERT_EQ((long long)tune_val(TUNE_DNS_TUNNEL_TOTAL_THRESH), 15);
    ASSERT_EQ((long long)tune_val(TUNE_ICMP_TUNNEL_MIN_PAYLOAD), 64);
    ASSERT_EQ((long long)tune_val(TUNE_ICMP_TUNNEL_THRESHOLD), 8);
    ASSERT_EQ((long long)tune_val(TUNE_ICMP_TUNNEL_WINDOW_S), 60);
    ASSERT_EQ((long long)tune_val(TUNE_SSID_CONFUSION_THRESH), 3);
    ASSERT_EQ((long long)tune_val(TUNE_MGMT_FUZZ_WARN), 3);
    ASSERT_EQ((long long)tune_val(TUNE_MGMT_FUZZ_CRIT), 5);
    ASSERT_EQ((long long)tune_val(TUNE_EVIL_TWIN_PROXIMITY_DBM), 15);
    ASSERT_EQ((long long)tune_val(TUNE_DEAUTH_TWIN_WIN_SECS), 5);
    ASSERT_EQ((long long)tune_val(TUNE_TWIN_STEER_WINDOW_S), 300);
    ASSERT_EQ((long long)tune_val(TUNE_RECON_SUSTAIN_S), 600);
    ASSERT_EQ((long long)tune_val(TUNE_RECON_SUSTAIN_PROBES), 20);
    ASSERT_EQ((long long)tune_val(TUNE_KERB_PREAUTH_BURST), 5);
    ASSERT_EQ((long long)tune_val(TUNE_LDAP_SEARCH_FLOOD), 50);
    ASSERT_EQ((long long)tune_val(TUNE_BGP_NOTIFICATION_BURST), 3);
    ASSERT_EQ((long long)tune_val(TUNE_SSH_BRUTE_FORCE), 10);
    ASSERT_EQ((long long)tune_val(TUNE_RDP_BRUTE_FORCE), 10);
    ASSERT_EQ((long long)tune_val(TUNE_SNMP_COMMUNITY_BRUTE), 5);
    ASSERT_EQ((long long)tune_val(TUNE_MQTT_BRUTE_CONNECTS), 10);
    ASSERT_EQ((long long)tune_val(TUNE_MQTT_BRUTE_FAILS), 5);
    ASSERT_EQ(tune_non_default(), 0);
}

static void test_specs_match_enum_order(void) {
    /* The spec array is indexed by the enum, so a reordering of either
       would silently remap one rule's threshold onto another rule's
       value — a detector reading the wrong number with every test
       still green. Pinned by name. */
    tune_reset();
    ASSERT_STR(tune_spec(TUNE_KARMA_SSID_THRESH)->name, "karma.ssid_thresh");
    ASSERT_STR(tune_spec(TUNE_SSH_BRUTE_FORCE)->name, "ssh.brute_force");
    ASSERT_STR(tune_spec(TUNE_MQTT_BRUTE_FAILS)->name, "mqtt.brute_fails");
    ASSERT_STR(tune_spec(TUNE_TWIN_STEER_WINDOW_S)->name, "twin.steer_window_s");
    ASSERT_STR(tune_spec(TUNE_RECON_SUSTAIN_PROBES)->name, "recon.sustain_probes");
    /* Every row has a name, a unit, and a default inside its own
       bounds — a row whose default is out of range could never be
       restored by the operator. */
    for (int i = 0; i < TUNE_COUNT; i++) {
        const tune_spec_t *sp = tune_spec((tune_id_t)i);
        ASSERT(sp != NULL);
        ASSERT(sp->name && sp->name[0]);
        ASSERT(sp->unit && sp->unit[0]);
        ASSERT(sp->lo <= sp->def);
        ASSERT(sp->def <= sp->hi);
    }
}

static void test_out_of_range_ids_are_safe(void) {
    tune_reset();
    ASSERT_EQ((long long)tune_val((tune_id_t)-1), 0);
    ASSERT_EQ((long long)tune_val((tune_id_t)TUNE_COUNT), 0);
    ASSERT(tune_spec((tune_id_t)-1) == NULL);
    ASSERT(tune_spec((tune_id_t)TUNE_COUNT) == NULL);
}

static void test_set_moves_one_knob(void) {
    tune_reset();
    char err[160] = "untouched";
    ASSERT_EQ(tune_set("ssh.brute_force=25", err, sizeof(err)), 0);
    ASSERT_EQ((long long)tune_val(TUNE_SSH_BRUTE_FORCE), 25);
    /* and only that one */
    ASSERT_EQ((long long)tune_val(TUNE_RDP_BRUTE_FORCE), 10);
    ASSERT_EQ(tune_non_default(), 1);
}

static void test_set_accepts_the_range_endpoints(void) {
    tune_reset();
    char err[160];
    const tune_spec_t *sp = tune_spec(TUNE_SSH_BRUTE_FORCE);
    char spec[64];
    snprintf(spec, sizeof(spec), "ssh.brute_force=%ld", sp->lo);
    ASSERT_EQ(tune_set(spec, err, sizeof(err)), 0);
    ASSERT_EQ((long long)tune_val(TUNE_SSH_BRUTE_FORCE), (long long)sp->lo);
    snprintf(spec, sizeof(spec), "ssh.brute_force=%ld", sp->hi);
    ASSERT_EQ(tune_set(spec, err, sizeof(err)), 0);
    ASSERT_EQ((long long)tune_val(TUNE_SSH_BRUTE_FORCE), (long long)sp->hi);
}

static void test_unknown_name_is_refused(void) {
    tune_reset();
    char err[160] = "";
    ASSERT_EQ(tune_set("nope.not_a_knob=5", err, sizeof(err)), -1);
    ASSERT(strstr(err, "unknown knob") != NULL);
    ASSERT(strstr(err, "--tune-list") != NULL);
    ASSERT_EQ(tune_non_default(), 0);
}

static void test_a_prefix_of_a_real_name_is_not_a_match(void) {
    /* "ssh.brute" must not match "ssh.brute_force": the lookup compares
       lengths, not prefixes, or a truncated knob would move a threshold
       the operator did not name. */
    tune_reset();
    char err[160] = "";
    ASSERT_EQ(tune_set("ssh.brute=25", err, sizeof(err)), -1);
    ASSERT(strstr(err, "unknown knob") != NULL);
    ASSERT_EQ((long long)tune_val(TUNE_SSH_BRUTE_FORCE), 10);
}

static void test_out_of_range_values_are_refused(void) {
    tune_reset();
    char err[160] = "";
    ASSERT_EQ(tune_set("ssh.brute_force=1", err, sizeof(err)), -1);
    ASSERT(strstr(err, "out of range") != NULL);
    ASSERT_EQ(tune_set("ssh.brute_force=100000", err, sizeof(err)), -1);
    ASSERT(strstr(err, "out of range") != NULL);
    ASSERT_EQ(tune_set("ssh.brute_force=-5", err, sizeof(err)), -1);
    /* Nothing moved on any rejection. */
    ASSERT_EQ((long long)tune_val(TUNE_SSH_BRUTE_FORCE), 10);
    ASSERT_EQ(tune_non_default(), 0);
}

static void test_malformed_specs_are_refused(void) {
    tune_reset();
    char err[160] = "";
    /* Each of these would be a plausible typo, and each must exit
       rather than leave the default in place pretending to be set. */
    ASSERT_EQ(tune_set("ssh.brute_force", err, sizeof(err)), -1);
    ASSERT(strstr(err, "expected name=value") != NULL);
    ASSERT_EQ(tune_set("ssh.brute_force=", err, sizeof(err)), -1);
    ASSERT(strstr(err, "missing value") != NULL);
    ASSERT_EQ(tune_set("ssh.brute_force=20x", err, sizeof(err)), -1);
    ASSERT(strstr(err, "not an integer") != NULL);
    ASSERT_EQ(tune_set("ssh.brute_force=abc", err, sizeof(err)), -1);
    ASSERT(strstr(err, "not an integer") != NULL);
    ASSERT_EQ(tune_set("=20", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set("", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set(NULL, err, sizeof(err)), -1);
    ASSERT_EQ(tune_non_default(), 0);
}

static void test_a_value_equal_to_the_default_is_not_tuned(void) {
    /* Setting a knob to what it already was must not light the
       tuned indicator — the export would otherwise claim the sensor
       was retuned when its behaviour is stock. */
    tune_reset();
    char err[160];
    ASSERT_EQ(tune_set("ssh.brute_force=10", err, sizeof(err)), 0);
    ASSERT_EQ(tune_non_default(), 0);
    char buf[256] = "x";
    tune_format_non_default(buf, sizeof(buf));
    ASSERT_STR(buf, "");
}

static void test_non_default_list_names_the_knobs(void) {
    tune_reset();
    char err[160];
    ASSERT_EQ(tune_set("karma.ssid_thresh=5", err, sizeof(err)), 0);
    ASSERT_EQ(tune_set("ssh.brute_force=25", err, sizeof(err)), 0);
    ASSERT_EQ(tune_non_default(), 2);
    char buf[256];
    tune_format_non_default(buf, sizeof(buf));
    /* Registry order, comma-joined: the count alone would not tell a
       consumer which rule went quiet. */
    ASSERT_STR(buf, "karma.ssid_thresh=5,ssh.brute_force=25");
}

static void test_non_default_list_truncates_cleanly(void) {
    tune_reset();
    char err[160];
    ASSERT_EQ(tune_set("karma.ssid_thresh=5", err, sizeof(err)), 0);
    ASSERT_EQ(tune_set("ssh.brute_force=25", err, sizeof(err)), 0);
    char tiny[8];
    memset(tiny, 'A', sizeof(tiny));
    tune_format_non_default(tiny, sizeof(tiny));
    /* No overrun and no half-written pair: a buffer too small yields a
       shorter valid string, never a mangled one. */
    ASSERT(strlen(tiny) < sizeof(tiny));
    ASSERT(strchr(tiny, 'A') == NULL);
    char one[1] = { 'B' };
    tune_format_non_default(one, sizeof(one));
    ASSERT_EQ((long long)one[0], 0);
}

static void test_reset_restores_every_default(void) {
    tune_reset();
    char err[160];
    ASSERT_EQ(tune_set("karma.ssid_thresh=9", err, sizeof(err)), 0);
    ASSERT_EQ(tune_set("mqtt.brute_fails=99", err, sizeof(err)), 0);
    ASSERT_EQ(tune_non_default(), 2);
    tune_reset();
    ASSERT_EQ(tune_non_default(), 0);
    ASSERT_EQ((long long)tune_val(TUNE_KARMA_SSID_THRESH), 3);
    ASSERT_EQ((long long)tune_val(TUNE_MQTT_BRUTE_FAILS), 5);
}

static void test_print_list_covers_every_knob(void) {
    tune_reset();
    char path[] = "/tmp/sloth_tune_list_test.txt";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL);
    tune_print_list(f);
    fclose(f);
    f = fopen(path, "r");
    ASSERT(f != NULL);
    char all[8192];
    size_t n = fread(all, 1, sizeof(all) - 1, f);
    all[n] = '\0';
    fclose(f);
    remove(path);
    /* Every registry row reaches the operator, or a knob exists that
       --tune-list never mentions. */
    for (int i = 0; i < TUNE_COUNT; i++)
        ASSERT(strstr(all, tune_spec((tune_id_t)i)->name) != NULL);
    ASSERT(strstr(all, "default") != NULL);
    ASSERT(strstr(all, "current") != NULL);
    /* A NULL stream is a no-op, not a crash. */
    tune_print_list(NULL);
}

static void test_a_tuned_threshold_reaches_the_detector_macro(void) {
    /* The point of the whole slice: the macro src/alerts.c compiles
       against must follow the knob. KARMA_SSID_THRESH is the one a
       header exposes, so it can be read from a test. */
    tune_reset();
    ASSERT_EQ(KARMA_SSID_THRESH, 3);
    char err[160];
    ASSERT_EQ(tune_set("karma.ssid_thresh=7", err, sizeof(err)), 0);
    ASSERT_EQ(KARMA_SSID_THRESH, 7);
    tune_reset();
    ASSERT_EQ(KARMA_SSID_THRESH, 3);
}

void run_tune_tests(void) {
    TEST_SUITE("tune: operator-tunable detector thresholds (#82)");
    RUN_TEST(test_defaults_are_the_shipped_values);
    RUN_TEST(test_specs_match_enum_order);
    RUN_TEST(test_out_of_range_ids_are_safe);
    RUN_TEST(test_set_moves_one_knob);
    RUN_TEST(test_set_accepts_the_range_endpoints);
    RUN_TEST(test_unknown_name_is_refused);
    RUN_TEST(test_a_prefix_of_a_real_name_is_not_a_match);
    RUN_TEST(test_out_of_range_values_are_refused);
    RUN_TEST(test_malformed_specs_are_refused);
    RUN_TEST(test_a_value_equal_to_the_default_is_not_tuned);
    RUN_TEST(test_non_default_list_names_the_knobs);
    RUN_TEST(test_non_default_list_truncates_cleanly);
    RUN_TEST(test_reset_restores_every_default);
    RUN_TEST(test_print_list_covers_every_knob);
    RUN_TEST(test_a_tuned_threshold_reaches_the_detector_macro);
}
