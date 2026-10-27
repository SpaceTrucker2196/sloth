#include <string.h>
#include <stdio.h>
#include "runner.h"
#include "tune.h"
#include "karma_detect.h"
#include "alerts.h"        /* the --wps-* aliases folded onto the registry */   /* KARMA_SSID_THRESH, the macro the knob feeds */
/* The owners of the #defines the #120 rows default to. */
#include "sloth.h"
#include "action_snoop.h"
#include "beacon_detect.h"
#include "ctrl_frames.h"
#include "db.h"
#include "eapol_log.h"
#include "presence.h"
#include "queue_evict.h"
#include "seqnum_track.h"
#include "transit.h"
#include "tmp_dir.h"

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
    /* #135: 4 slots per peer of 16; idle = 3 × JSONL_HEARTBEAT_SECS. */
    ASSERT_EQ((long long)tune_val(TUNE_SOCKET_MAX_PER_PEER), 4);
    ASSERT_EQ((long long)tune_val(TUNE_SOCKET_IDLE_SECS), 900);
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
    ASSERT_STR(tune_spec(TUNE_SOCKET_MAX_PER_PEER)->name, "socket.max_per_peer");
    ASSERT_STR(tune_spec(TUNE_SOCKET_IDLE_SECS)->name, "socket.idle_secs");
    /* #120 appended these; the first and last of each group pin the
       run between them. */
    ASSERT_STR(tune_spec(TUNE_CORRELATE_RETAIN_SECS)->name, "correlate.retain_secs");
    ASSERT_STR(tune_spec(TUNE_HANDSHAKE_RETENTION_DAYS)->name, "handshake.retention_days");
    ASSERT_STR(tune_spec(TUNE_DB_INTERVAL_SECS)->name, "db.interval_secs");
    ASSERT_STR(tune_spec(TUNE_DB_RETAIN_DAYS)->name, "db.retain_days");
    ASSERT_STR(tune_spec(TUNE_DB_MAX_MB)->name, "db.max_mb");
    ASSERT_STR(tune_spec(TUNE_SCAN_PORT_THRESH)->name, "scan.port_thresh");
    ASSERT_STR(tune_spec(TUNE_DEAUTH_FLOOD_WINDOW_S)->name, "deauth.flood_window_s");
    ASSERT_STR(tune_spec(TUNE_PROBE_FLOOD_FRAMES)->name, "probe.flood_frames");
    ASSERT_STR(tune_spec(TUNE_RTS_FLOOD_SUSTAIN_S)->name, "rts.flood_sustain_s");
    ASSERT_STR(tune_spec(TUNE_BD_MIN_CONCENTRATION_PCT)->name, "bd.min_concentration_pct");
    ASSERT_STR(tune_spec(TUNE_QUEUE_EVICT_REPORT_SECS)->name, "queue_evict.report_secs");
    ASSERT_STR(tune_spec(TUNE_PRESENCE_MIN_SAMPLES)->name, "presence.min_samples");
    ASSERT_STR(tune_spec(TUNE_SEQNUM_CORR_DT_MAX_S)->name, "seqnum.corr_dt_max_s");
    /* Every name is unique — two rows answering to one name would make
       --tune set whichever the lookup met first. */
    int dupes = 0;
    for (int i = 0; i < TUNE_COUNT; i++)
        for (int j = i + 1; j < TUNE_COUNT; j++)
            if (strcmp(tune_spec((tune_id_t)i)->name,
                       tune_spec((tune_id_t)j)->name) == 0) dupes++;
    ASSERT_EQ(dupes, 0);
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
    char path[TEST_TMP_MAX];
    test_tmp_path(path, sizeof(path), "sloth_tune_list_test.txt");
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL);
    tune_print_list(f);
    fclose(f);
    f = fopen(path, "r");
    ASSERT(f != NULL);
    char all[32768];
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
    /* The point of the whole slice: the macro src/alerts/ compiles
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

/* ── #82's own three, reconciled 2026-10-05 ───────────────────
 *
 * d652502 shipped --wps-pin-brute-cycles / --wps-lockout-cycles /
 * --wps-pbc-concurrent with module statics behind them, answering the
 * same owner decision this registry answers. Both now read one value.
 * These pin that, and pin the bug it closed: a threshold moved by flag
 * used to reach no export at all. */

static void test_wps_defaults_match_the_shipped_macros(void) {
    tune_reset();
    ASSERT_EQ((long long)tune_val(TUNE_WPS_PIN_BRUTE_CYCLES), WPS_PIN_BRUTE_CYCLES);
    ASSERT_EQ((long long)tune_val(TUNE_WPS_LOCKOUT_CYCLES),   WPS_LOCKOUT_CYCLES);
    ASSERT_EQ((long long)tune_val(TUNE_WPS_PBC_CONCURRENT),   WPS_PBC_CONCURRENT);
    /* and the accessors the rules actually call agree */
    ASSERT_EQ(alerts_wps_pin_brute_cycles(), WPS_PIN_BRUTE_CYCLES);
    ASSERT_EQ(alerts_wps_lockout_cycles(),   WPS_LOCKOUT_CYCLES);
    ASSERT_EQ(alerts_wps_pbc_concurrent(),   WPS_PBC_CONCURRENT);
    ASSERT_EQ(tune_non_default(), 0);
}

static void test_wps_both_spellings_reach_one_value(void) {
    /* --tune in, accessor out. */
    tune_reset();
    char err[160];
    ASSERT_EQ(tune_set("wps.pin_brute_cycles=9", err, sizeof(err)), 0);
    ASSERT_EQ(alerts_wps_pin_brute_cycles(), 9);
    /* --wps-* in, registry out. */
    ASSERT_EQ(alerts_set_wps_lockout_cycles(7), 1);
    ASSERT_EQ((long long)tune_val(TUNE_WPS_LOCKOUT_CYCLES), 7);
    /* Last writer wins on the same knob, whichever spelling it used —
       there is one value, not two that can disagree. */
    ASSERT_EQ(alerts_set_wps_pin_brute_cycles(4), 1);
    ASSERT_EQ(alerts_wps_pin_brute_cycles(), 4);
    ASSERT_EQ((long long)tune_val(TUNE_WPS_PIN_BRUTE_CYCLES), 4);
    ASSERT_EQ(tune_set("wps.pin_brute_cycles=6", err, sizeof(err)), 0);
    ASSERT_EQ(alerts_wps_pin_brute_cycles(), 6);
    tune_reset();
}

static void test_wps_flag_path_reaches_the_tamper_record(void) {
    /* The defect this reconciliation closed. Before it, the statics were
       invisible to the export: --wps-pin-brute-cycles 900 silenced
       WPS_PIN_BRUTE while sensor_health still said tuned_count 0 and the
       health strip showed nothing — a detuned sensor reading exactly
       like a quiet one. */
    tune_reset();
    ASSERT_EQ(tune_non_default(), 0);
    ASSERT_EQ(alerts_set_wps_pin_brute_cycles(900), 1);
    ASSERT_EQ(tune_non_default(), 1);
    char buf[256];
    tune_format_non_default(buf, sizeof(buf));
    ASSERT(strstr(buf, "wps.pin_brute_cycles=900") != NULL);
    tune_reset();
}

static void test_wps_setters_keep_their_published_contract(void) {
    /* alerts.h documents 1 on accept, 0 on reject with the previous
       value standing, and rejects "zero or less" rather than reading it
       as an off switch. Folding these onto the registry must not have
       widened or narrowed that. */
    tune_reset();
    ASSERT_EQ(alerts_set_wps_pin_brute_cycles(0), 0);
    ASSERT_EQ(alerts_set_wps_pin_brute_cycles(-1), 0);
    ASSERT_EQ(alerts_wps_pin_brute_cycles(), WPS_PIN_BRUTE_CYCLES);
    ASSERT_EQ(tune_non_default(), 0);          /* a rejection moves nothing */
    /* 1 is accepted — the boundary their contract names explicitly. */
    ASSERT_EQ(alerts_set_wps_lockout_cycles(1), 1);
    ASSERT_EQ(alerts_wps_lockout_cycles(), 1);
    ASSERT_EQ(alerts_set_wps_pbc_concurrent(0), 0);
    ASSERT_EQ(alerts_wps_pbc_concurrent(), WPS_PBC_CONCURRENT);
    tune_reset();
}

static void test_tune_set_id_rejects_out_of_range_and_bad_ids(void) {
    tune_reset();
    ASSERT_EQ(tune_set_id(TUNE_WPS_PIN_BRUTE_CYCLES, 0), 0);
    ASSERT_EQ(tune_set_id(TUNE_WPS_PIN_BRUTE_CYCLES, 100000), 0);
    ASSERT_EQ(tune_set_id((tune_id_t)-1, 5), 0);
    ASSERT_EQ(tune_set_id((tune_id_t)TUNE_COUNT, 5), 0);
    ASSERT_EQ(tune_non_default(), 0);
    ASSERT_EQ(tune_set_id(TUNE_WPS_PIN_BRUTE_CYCLES, 3), 1);
    ASSERT_EQ((long long)tune_val(TUNE_WPS_PIN_BRUTE_CYCLES), 3);
    tune_reset();
}


/* ── #120: the remaining thresholds and the five atoi() flags ──── */

/* Each row defaults to the #define it replaced at the use site, by
 * construction (tune.c reads the macro). Pinned anyway, because the
 * alternative failure — a row typed in by hand that drifted — is
 * invisible: every detector would still run, on the wrong number. */
static void test_issue120_rows_default_to_their_macros(void) {
    tune_reset();
    ASSERT_EQ((long long)tune_val(TUNE_CORRELATE_RETAIN_SECS), SEQNUM_CORR_RETAIN_S);
    ASSERT_EQ((long long)tune_val(TUNE_HANDSHAKE_RETENTION_DAYS), EAPOL_DEFAULT_RETENTION_DAYS);
    ASSERT_EQ((long long)tune_val(TUNE_DB_INTERVAL_SECS), DB_DEFAULT_INTERVAL_S);
    ASSERT_EQ((long long)tune_val(TUNE_DB_RETAIN_DAYS), DB_DEFAULT_RETAIN_DAYS);
    ASSERT_EQ((long long)tune_val(TUNE_DB_MAX_MB), DB_DEFAULT_MAX_MB);
    ASSERT_EQ((long long)tune_val(TUNE_SCAN_PORT_THRESH), SCAN_PORT_THRESH);
    ASSERT_EQ((long long)tune_val(TUNE_DEAUTH_FLOOD_THRESH), DEAUTH_FLOOD_THRESH);
    ASSERT_EQ((long long)tune_val(TUNE_DEAUTH_FLOOD_WINDOW_S), DEAUTH_FLOOD_WIN_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_BEACON_FLOOD_THRESH), BEACON_FLOOD_THRESH);
    ASSERT_EQ((long long)tune_val(TUNE_BEACON_FLOOD_WINDOW_S), BEACON_FLOOD_WIN_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_AUTH_FLOOD_THRESH), AUTH_FLOOD_THRESH);
    ASSERT_EQ((long long)tune_val(TUNE_AUTH_FLOOD_WINDOW_S), AUTH_FLOOD_WIN_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_ASSOC_FLOOD_THRESH), ASSOC_FLOOD_THRESH);
    ASSERT_EQ((long long)tune_val(TUNE_ASSOC_FLOOD_WINDOW_S), ASSOC_FLOOD_WIN_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_PROBE_FLOOD_FRAMES), PROBE_FLOOD_FRAMES);
    ASSERT_EQ((long long)tune_val(TUNE_PROBE_FLOOD_WINDOW_S), PROBE_FLOOD_WIN_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_BTM_ABUSE_THRESH), BTM_ABUSE_THRESH);
    ASSERT_EQ((long long)tune_val(TUNE_BTM_ABUSE_WINDOW_S), BTM_ABUSE_WIN_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_SAQ_FLOOD_THRESH), SAQ_FLOOD_THRESH);
    ASSERT_EQ((long long)tune_val(TUNE_SAQ_FLOOD_WINDOW_S), SAQ_FLOOD_WIN_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_RTS_FLOOD_RATE), RTS_FLOOD_RATE);
    ASSERT_EQ((long long)tune_val(TUNE_RTS_FLOOD_SUSTAIN_S), RTS_FLOOD_SUSTAIN_S);
    ASSERT_EQ((long long)tune_val(TUNE_BD_MIN_SAMPLES), BD_MIN_SAMPLES);
    ASSERT_EQ((long long)tune_val(TUNE_BD_MIN_INTERVAL_S), BD_MIN_INTERVAL_S);
    ASSERT_EQ((long long)tune_val(TUNE_BD_MAX_JITTER_PCT), BD_MAX_JITTER_PCT);
    ASSERT_EQ((long long)tune_val(TUNE_BD_MIN_SAMPLES_V2), BD_MIN_SAMPLES_V2);
    ASSERT_EQ((long long)tune_val(TUNE_BD_MIN_CONCENTRATION_PCT), BD_MIN_CONCENTRATION_PCT);
    ASSERT_EQ((long long)tune_val(TUNE_QUEUE_EVICT_WINDOW_MS), QUEUE_EVICT_WINDOW_MS);
    ASSERT_EQ((long long)tune_val(TUNE_QUEUE_EVICT_MIN_FRAMES), QUEUE_EVICT_MIN_FRAMES);
    ASSERT_EQ((long long)tune_val(TUNE_QUEUE_EVICT_REPORT_SECS), QUEUE_EVICT_REPORT_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_TRANSIT_GAP_SECS), TRANSIT_GAP_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_TRANSIT_WINDOW_SECS), TRANSIT_WINDOW_SECS);
    ASSERT_EQ((long long)tune_val(TUNE_TRANSIT_RECUR_THRESH), TRANSIT_RECUR_THRESH);
    ASSERT_EQ((long long)tune_val(TUNE_PRESENCE_SWING_DBM), PRESENCE_SWING_DBM);
    ASSERT_EQ((long long)tune_val(TUNE_PRESENCE_TRANSIENT_MAX_S), PRESENCE_TRANSIENT_MAX_S);
    ASSERT_EQ((long long)tune_val(TUNE_PRESENCE_VISITOR_MIN_S), PRESENCE_VISITOR_MIN_S);
    ASSERT_EQ((long long)tune_val(TUNE_PRESENCE_RESIDENT_MIN_S), PRESENCE_RESIDENT_MIN_S);
    ASSERT_EQ((long long)tune_val(TUNE_PRESENCE_MIN_SAMPLES), PRESENCE_MIN_SAMPLES);
    ASSERT_EQ((long long)tune_val(TUNE_SEQNUM_CORR_SEQ_WINDOW), SEQNUM_CORR_SEQ_WINDOW);
    ASSERT_EQ((long long)tune_val(TUNE_SEQNUM_CORR_DT_MAX_S), SEQNUM_CORR_DT_MAX_S);
    /* The percent forms are the same doubles the ratios were. */
    ASSERT(BD_MAX_JITTER_RATIO == 0.25);
    ASSERT(BD_MIN_CONCENTRATION == 0.60);
    ASSERT_EQ(tune_non_default(), 0);
}

/* A count held in a fixed ring caps at the ring: a threshold above what
 * the detector can store would never fire, which disables a rule
 * rather than tuning it. */
static void test_issue120_ring_bounded_caps(void) {
    tune_reset();
    ASSERT_EQ((long long)tune_spec(TUNE_DEAUTH_FLOOD_THRESH)->hi, FLOOD_WIN_CAP);
    ASSERT_EQ((long long)tune_spec(TUNE_PROBE_FLOOD_FRAMES)->hi, FLOOD_WIN_CAP);
    ASSERT_EQ((long long)tune_spec(TUNE_SCAN_PORT_THRESH)->hi, MAX_SCAN_PORTS);
    ASSERT_EQ((long long)tune_spec(TUNE_SAQ_FLOOD_THRESH)->hi, SAQ_FLOOD_THRESH * 4);
    ASSERT_EQ((long long)tune_spec(TUNE_BD_MIN_SAMPLES)->hi, BD_MAX_SAMPLES);
    ASSERT_EQ((long long)tune_spec(TUNE_BD_MIN_SAMPLES_V2)->hi, BD_MAX_SAMPLES);
    ASSERT_EQ((long long)tune_spec(TUNE_TRANSIT_RECUR_THRESH)->hi, MAX_TRANSIT_PASSES);
    ASSERT_EQ((long long)tune_spec(TUNE_PRESENCE_MIN_SAMPLES)->hi, RSSI_WIN_SAMPLES);
    char err[160] = "";
    ASSERT_EQ(tune_set("deauth.flood_thresh=33", err, sizeof(err)), -1);
    ASSERT(strstr(err, "out of range") != NULL);
}

/* tune_set_value() is what the five flags parse through now. Every
 * input atoi() would have read as some other number is refused, the
 * error names the knob, and nothing moves. */
static void test_set_value_refuses_what_atoi_accepted(void) {
    tune_reset();
    char err[160];
    static const char *bad[] = { "5x", "", "abc", " ", "1e3", "0x10",
                                 "99999999999999999999" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        err[0] = '\0';
        ASSERT_EQ(tune_set_value(TUNE_DB_MAX_MB, bad[i], err, sizeof(err)), -1);
        ASSERT(strstr(err, "db.max_mb") != NULL);
    }
    ASSERT_EQ(tune_set_value(TUNE_DB_MAX_MB, NULL, err, sizeof(err)), -1);
    ASSERT(strstr(err, "missing value") != NULL);
    ASSERT_EQ(tune_set_value((tune_id_t)TUNE_COUNT, "5", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set_value((tune_id_t)-1, "5", NULL, 0), -1);
    ASSERT_EQ(tune_non_default(), 0);
    ASSERT_EQ((long long)tune_val(TUNE_DB_MAX_MB), DB_DEFAULT_MAX_MB);
}

static void test_set_value_enforces_each_flags_bounds(void) {
    tune_reset();
    char err[160] = "";
    /* --db-retain-days 0 used to mean "default" via atoi; it is now out
       of range, said so, rather than quietly read as 30. */
    ASSERT_EQ(tune_set_value(TUNE_DB_RETAIN_DAYS, "0", err, sizeof(err)), -1);
    ASSERT(strstr(err, "out of range") != NULL);
    ASSERT_EQ(tune_set_value(TUNE_DB_INTERVAL_SECS, "0", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set_value(TUNE_CORRELATE_RETAIN_SECS, "0", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set_value(TUNE_CORRELATE_RETAIN_SECS, "-5", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set_value(TUNE_HANDSHAKE_RETENTION_DAYS, "-1", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set_value(TUNE_HANDSHAKE_RETENTION_DAYS, "36501", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set_value(TUNE_WPS_PIN_BRUTE_CYCLES, "0", err, sizeof(err)), -1);
    ASSERT_EQ(tune_non_default(), 0);
    /* The meaningful zeroes the shipped flags published still work. */
    ASSERT_EQ(tune_set_value(TUNE_DB_MAX_MB, "0", err, sizeof(err)), 0);           /* unlimited */
    ASSERT_EQ(tune_set_value(TUNE_HANDSHAKE_RETENTION_DAYS, "0", err, sizeof(err)), 0); /* forever */
    ASSERT_EQ(tune_set_value(TUNE_HANDSHAKE_RETENTION_DAYS, "36500", err, sizeof(err)), 0);
    ASSERT_EQ(tune_set_value(TUNE_WPS_PIN_BRUTE_CYCLES, "1", err, sizeof(err)), 0);
    tune_reset();
}

/* The defect class #82's WPS reconciliation closed, closed for the five:
 * a value moved by flag must reach `tuned`, or a sensor retaining a
 * tenth of the default looks stock in its own export. */
static void test_flag_rows_reach_the_tuned_record(void) {
    tune_reset();
    char err[160];
    ASSERT_EQ(tune_set_value(TUNE_DB_MAX_MB, "64", err, sizeof(err)), 0);
    ASSERT_EQ(eapol_set_retention_days(2), 0);
    seqnum_corr_set_retain_secs(30);
    char buf[512];
    tune_format_non_default(buf, sizeof(buf));
    ASSERT(strstr(buf, "db.max_mb=64") != NULL);
    ASSERT(strstr(buf, "handshake.retention_days=2") != NULL);
    ASSERT(strstr(buf, "correlate.retain_secs=30") != NULL);
    ASSERT_EQ(tune_non_default(), 3);
    tune_reset();
}

/* --handshake-retention and --tune handshake.retention_days are one
 * value, and the module's own validation is unchanged. */
static void test_handshake_retention_is_the_registry_row(void) {
    tune_reset();
    char err[160];
    ASSERT_EQ(tune_set("handshake.retention_days=14", err, sizeof(err)), 0);
    ASSERT_EQ(eapol_retention_days(), 14);
    ASSERT_EQ(eapol_set_retention_days(3), 0);
    ASSERT_EQ((long long)tune_val(TUNE_HANDSHAKE_RETENTION_DAYS), 3);
    ASSERT_EQ(eapol_set_retention_days(-1), -1);
    ASSERT_EQ(eapol_retention_days(), 3);              /* previous stands */
    tune_reset();
    ASSERT_EQ(eapol_retention_days(), EAPOL_DEFAULT_RETENTION_DAYS);
}

#ifdef WITH_SQLITE
static void test_db_flags_are_the_registry_rows(void) {
    tune_reset();
    char err[160];
    ASSERT_EQ(tune_set("db.retain_days=7", err, sizeof(err)), 0);
    ASSERT_EQ(tune_set("db.max_mb=64", err, sizeof(err)), 0);
    ASSERT_EQ(tune_set("db.interval_secs=10", err, sizeof(err)), 0);
    ASSERT_EQ(db_retain_days(), 7);
    ASSERT_EQ(db_max_mb(), 64);
    ASSERT_EQ(db_interval(), 10);
    /* The setters keep their published shape: 0 / negative restore the
       default (retain, interval), 0 is unlimited (max_mb). */
    db_set_retain_days(0);
    ASSERT_EQ((long long)tune_val(TUNE_DB_RETAIN_DAYS), DB_DEFAULT_RETAIN_DAYS);
    db_set_max_mb(0);
    ASSERT_EQ((long long)tune_val(TUNE_DB_MAX_MB), 0);
    db_set_interval(-3);
    ASSERT_EQ((long long)tune_val(TUNE_DB_INTERVAL_SECS), DB_DEFAULT_INTERVAL_S);
    tune_reset();
}
#endif

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
    RUN_TEST(test_wps_defaults_match_the_shipped_macros);
    RUN_TEST(test_wps_both_spellings_reach_one_value);
    RUN_TEST(test_wps_flag_path_reaches_the_tamper_record);
    RUN_TEST(test_wps_setters_keep_their_published_contract);
    RUN_TEST(test_tune_set_id_rejects_out_of_range_and_bad_ids);
    TEST_SUITE("tune: remaining thresholds and the atoi() flags (#120)");
    RUN_TEST(test_issue120_rows_default_to_their_macros);
    RUN_TEST(test_issue120_ring_bounded_caps);
    RUN_TEST(test_set_value_refuses_what_atoi_accepted);
    RUN_TEST(test_set_value_enforces_each_flags_bounds);
    RUN_TEST(test_flag_rows_reach_the_tuned_record);
    RUN_TEST(test_handshake_retention_is_the_registry_row);
#ifdef WITH_SQLITE
    RUN_TEST(test_db_flags_are_the_registry_rows);
#endif
}
