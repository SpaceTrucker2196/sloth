#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "sloth_clock.h"
#include "fake_platform.h"
#include "sys_status.h"
#include "capture_side.h"
#include "alerts/rules.h"
#include "rf_side.h"
#include "alerts/engine_internal.h"

/*
 * The rule table is data the application selects (#213): `sloth` the
 * whole table, sloth-rf the RF one (src/alerts/rules_table_rf.c). These
 * hold the RF table to what ADR 0010 gives sloth-rf - the four GNSS
 * rules, ADSB_EMERGENCY and SENSOR_SOURCE_DOWN - and to the 2026-11-15
 * ruling that SENSOR_UNDERVOLT is the capture daemon's alone.
 *
 * The under-voltage alarm is the fake platform's /sys file, as in
 * tests/test_sensor_rules.c. main_test.c re-installs `sloth`'s table
 * before every test, so a test here that selects another one cannot
 * leave it selected.
 *
 * Every absence assertion names the mutation it was seen red under.
 */

TEST_STATE(g_s);

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }

static void begin(void) {
    g_mono = 5000000;
    g_wall = (time_t)1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    fake_net_reset();
    sys_status_reset();
    alerts_clear();
    memset(&g_s, 0, sizeof(g_s));
}

static void end(void) {
    capture_side_install();
    alerts_clear();
    fake_net_reset();
    sys_status_reset();
    sloth_clock_test_set(NULL, NULL);
}

static void tick(void) {
    g_mono += 1000;
    g_wall += 1;
    sys_status_poll(&g_s, g_wall, g_mono);
    alerts_update(&g_s);
}

static void ticks(int n) { for (int i = 0; i < n; i++) tick(); }

static int open_count(alert_type_t ty) {
    int n = 0;
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == ty && !g_s.alerts[i].resolved) n++;
    return n;
}

static int row_of(const alert_rule_table_t *t, const char *name) {
    for (int i = 0; i < t->count; i++)
        if (strcmp(t->rules[i].name, name) == 0) return i;
    return -1;
}

static void put_pi_alarm(const char *v) {
    fake_sys_put("/sys/class/hwmon/hwmon1/name", "rpi_volt\n");
    fake_sys_put("/sys/class/hwmon/hwmon1/in0_lcrit_alarm", v);
}

/* The RF table is exactly these six, in this order. Spelled out, not
 * derived: the list IS the table, and a diff to it is a change someone
 * has to mean. */
static void test_rf_table_rows_and_order(void) {
    static const char *const want[] = {
        "rule_gnss_jamming", "rule_gnss_time_jump", "rule_gnss_position_jump",
        "rule_gnss_spoof_suspect", "rule_adsb_emergency",
        "rule_sensor_source_down",
    };
    int n = (int)(sizeof(want) / sizeof(want[0]));
    ASSERT_EQ(g_alert_table_rf.count, n);
    for (int i = 0; i < n && i < g_alert_table_rf.count; i++) {
        ASSERT_STR(g_alert_table_rf.rules[i].name, want[i]);
        ASSERT(g_alert_table_rf.rules[i].fn != NULL);
    }
    /* By function too: a row named for one rule and calling another. */
    ASSERT(g_alert_table_rf.rules[0].fn == rule_gnss_jamming);
    ASSERT(g_alert_table_rf.rules[4].fn == rule_adsb_emergency);
    ASSERT(g_alert_table_rf.rules[5].fn == rule_sensor_source_down);
}

/* The two tables against each other since the cutover (#216). Until
 * then sloth-rf's was a subsequence of the one binary's; now the GNSS
 * rules and ADSB_EMERGENCY are in sloth-rf's only - not a row of
 * sloth-wifi's by name or by function - and the single row both run is
 * rule_sensor_source_down, with one body, which judges whichever source
 * rows its daemon reports.
 *
 * Seen red (2026-11-15) with R(rule_gnss_jamming) and then
 * R(rule_adsb_emergency) put back in src/alerts/rules_table.c: the
 * by-name and the by-function assertion each fail, and the Makefile's
 * check_wifi_no_rf refuses the link. */
static void test_gnss_and_adsb_rules_are_the_rf_tables_alone(void) {
    static const char *const rf_only[] = {
        "rule_gnss_jamming", "rule_gnss_time_jump", "rule_gnss_position_jump",
        "rule_gnss_spoof_suspect", "rule_adsb_emergency",
    };
    for (int i = 0; i < 5; i++) {
        ASSERT_GE(row_of(&g_alert_table_rf, rf_only[i]), 0);
        if (row_of(&g_alert_table_wifi, rf_only[i]) >= 0)
            fprintf(stderr, "    %s is a row of sloth-wifi's table\n", rf_only[i]);
        ASSERT_EQ(row_of(&g_alert_table_wifi, rf_only[i]), -1);
    }
    for (int i = 0; i < g_alert_table_wifi.count; i++) {
        alert_rule_fn fn = g_alert_table_wifi.rules[i].fn;
        ASSERT(fn != rule_gnss_jamming && fn != rule_gnss_time_jump &&
               fn != rule_gnss_position_jump && fn != rule_gnss_spoof_suspect &&
               fn != rule_adsb_emergency);
    }
    int shared = 0;
    for (int i = 0; i < g_alert_table_rf.count; i++) {
        int at = row_of(&g_alert_table_wifi, g_alert_table_rf.rules[i].name);
        if (at < 0) continue;
        shared++;
        ASSERT_STR(g_alert_table_rf.rules[i].name, "rule_sensor_source_down");
        ASSERT(g_alert_table_wifi.rules[at].fn == g_alert_table_rf.rules[i].fn);
    }
    ASSERT_EQ(shared, 1);
    /* 93 rows before the cutover, less these five. */
    ASSERT_EQ(g_alert_table_wifi.count, 88);
    /* Neither table drops the other's history. */
    for (int i = 0; i < g_alert_table_wifi.forget_count; i++)
        ASSERT(g_alert_table_wifi.forget[i] != rules_gnss_forget &&
               g_alert_table_wifi.forget[i] != rules_adsb_forget);
}

/* SENSOR_UNDERVOLT is not sloth-rf's (owner ruling 2026-11-15): not a
 * row, by name or by function, and with the host's alarm reading 1 the
 * RF table opens no such incident however long it is held - while the
 * Wi-Fi table, over the same snapshot, opens it on the next tick. The
 * second half is what makes the first one mean something: the alarm is
 * there to be seen. (Seen red, both the row check and the incident
 * count, with R(rule_sensor_undervolt) added to rules_table_rf.c.) */
static void test_undervolt_is_not_in_the_rf_table(void) {
    ASSERT_EQ(row_of(&g_alert_table_rf, "rule_sensor_undervolt"), -1);
    for (int i = 0; i < g_alert_table_rf.count; i++)
        ASSERT(g_alert_table_rf.rules[i].fn != rule_sensor_undervolt);
    ASSERT_GE(row_of(&g_alert_table_wifi, "rule_sensor_undervolt"), 0);

    begin();
    put_pi_alarm("1\n");
    alerts_set_table(&g_alert_table_rf);
    ticks(30);
    ASSERT_EQ(sys_status_get()->has_undervolt, 1);
    ASSERT_EQ(sys_status_get()->undervolt, 1);
    ASSERT_EQ(open_count(ALERT_TYPE_SENSOR_UNDERVOLT), 0);
    ASSERT_EQ(g_s.alert_count, 0);

    alerts_set_table(&g_alert_table_wifi);
    tick();
    ASSERT_EQ(open_count(ALERT_TYPE_SENSOR_UNDERVOLT), 1);
    end();
}

/* The RF table does fire what is its own. A configured ADS-B decoder
 * that is down opens SENSOR_SOURCE_DOWN under it, keyed for that
 * source. */
static void test_rf_table_fires_source_down_for_its_sources(void) {
    begin();
    rf_side_install();   /* its table and its four source rows */
    g_s.adsb.configured = 1;
    g_s.adsb.state = ADSB_ERROR;
    snprintf(g_s.adsb.src, sizeof(g_s.adsb.src), "file:/run/test/aircraft.json");
    snprintf(g_s.adsb.err, sizeof(g_s.adsb.err), "open: No such file or directory");
    ticks(60);
    ASSERT_EQ(open_count(ALERT_TYPE_SENSOR_SOURCE_DOWN), 1);
    int found = 0;
    for (int i = 0; i < g_s.alert_count; i++)
        if (!strcmp(g_s.alerts[i].key, "srcdown:adsb")) found = 1;
    ASSERT(found);
    end();
}

/* A daemon with no capture side has no capture rows to judge. The
 * state names a monitor radio whose worker is not running, which under
 * `sloth` is a CRIT srcdown:monitor; with the capture side
 * unregistered (what sloth-rf is: it never links src/capture_side.c)
 * the row is unnamed and nothing opens. (Seen red with the
 * sys_status_set_capture_side(NULL) line removed: srcdown:monitor
 * opened.) */
static void test_no_capture_side_judges_no_capture_row(void) {
    begin();
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "wlan9mon");
    g_s.mon_health.open = 1;
    g_s.mon_health.running = 0;
    alerts_set_table(&g_alert_table_rf);
    sys_status_set_capture_side(NULL);
    ticks(60);
    ASSERT_EQ(open_count(ALERT_TYPE_SENSOR_SOURCE_DOWN), 0);
    ASSERT(sys_status_get()->src[SYS_SRC_MONITOR].name == NULL);
    ASSERT(sys_status_get()->src[SYS_SRC_CAPTURE].name == NULL);
    ASSERT(sys_status_get()->src[SYS_SRC_GNSS].name != NULL);

    /* The same state with the capture side back: the row is judged. */
    capture_side_install();
    alerts_set_table(&g_alert_table_rf);
    ticks(60);
    ASSERT_EQ(open_count(ALERT_TYPE_SENSOR_SOURCE_DOWN), 1);
    end();
}

/* What a table brings beside its rows: the RF one names no exporter
 * (it captures nothing to export) and only its own rules' history; the
 * Wi-Fi one names both exporters. */
static void test_rf_table_names_no_exporter(void) {
    ASSERT(g_alert_table_rf.exporter == NULL);
    ASSERT(g_alert_table_wifi.exporter != NULL);
    ASSERT_EQ(g_alert_table_rf.forget_count, 3);
    /* Three each since #216: wired, twin and sensor there; GNSS, ADS-B
     * and sensor here. */
    ASSERT_EQ(g_alert_table_wifi.forget_count, 3);
    for (int i = 0; i < g_alert_table_rf.forget_count; i++)
        ASSERT(g_alert_table_rf.forget[i] != NULL);
}

/* The selection is what alerts_update() runs: the selected table's
 * rows are the engine's, and with none selected there are none and a
 * tick is a no-op, not a crash. */
static void test_selection_is_what_the_engine_runs(void) {
    begin();
    alerts_set_table(&g_alert_table_rf);
    ASSERT(alerts_table() == &g_alert_table_rf);
    ASSERT(g_alert_rules == g_alert_table_rf.rules);
    ASSERT_EQ(g_alert_rule_count, g_alert_table_rf.count);

    alerts_set_table(NULL);
    ASSERT(alerts_table() == NULL);
    ASSERT_EQ(g_alert_rule_count, 0);
    put_pi_alarm("1\n");
    ticks(3);
    ASSERT_EQ(g_s.alert_count, 0);
    alerts_clear();

    capture_side_install();
    ASSERT(alerts_table() == &g_alert_table_wifi);
    ASSERT_EQ(g_alert_rule_count, g_alert_table_wifi.count);
    end();
}

void run_rf_rules_tests(void) {
    TEST_SUITE("sloth-rf: the rule table it selects (#213)");
    RUN_TEST(test_rf_table_rows_and_order);
    RUN_TEST(test_gnss_and_adsb_rules_are_the_rf_tables_alone);
    RUN_TEST(test_undervolt_is_not_in_the_rf_table);
    RUN_TEST(test_rf_table_fires_source_down_for_its_sources);
    RUN_TEST(test_no_capture_side_judges_no_capture_row);
    RUN_TEST(test_rf_table_names_no_exporter);
    RUN_TEST(test_selection_is_what_the_engine_runs);
}
