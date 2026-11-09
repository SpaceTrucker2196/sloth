#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "adsb.h"
#include "alerts.h"
#include "sloth_clock.h"
#include "tune.h"

/*
 * ADSB_EMERGENCY (src/alerts/rules_adsb.c, #186).
 *
 * Every input is an aircraft.json document written here by hand from
 * readsb's README-json.md ("squawk: Mode A code (Squawk), encoded as 4
 * octal digits"; "emergency: ADS-B emergency/priority status, a
 * superset of the 7x00 squawks ... (none, general, lifeguard, minfuel,
 * nordo, unlawful, downed, reserved)"), fed through the module's own
 * parser, table and poll - adsb_doc_parse(), adsb_feed_doc(),
 * adsb_health_poll() - so the rule reads the table src/adsb.c builds.
 * The addresses and callsigns are invented. No decoder, no capture.
 *
 * Both clocks are pinned. The hold runs on the monotonic clock the rows
 * carry; the wall clock only stamps the engine.
 *
 * Every absence assertion names the mutation it was seen red under
 * (agents/AGENTS.md).
 */

TEST_STATE(g_s);
static adsb_doc_t g_doc;       /* ~50 KB: off the stack */

static uint64_t g_mono;
static time_t   g_wall;
static double   g_now;         /* the decoder's "now" */
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }

#define T0_WALL 1800000000

static void begin(void) {
    g_mono = 7000000;
    g_wall = (time_t)T0_WALL;
    g_now = T0_WALL;
    sloth_clock_test_set(pin_mono, pin_wall);
    tune_reset();
    adsb_reset();
    alerts_clear();
    memset(&g_s, 0, sizeof(g_s));
    adsb_set_source("file:/run/readsb/aircraft.json");
}

static void end(void) {
    alerts_clear();
    adsb_reset();
    tune_reset();
    sloth_clock_test_set(NULL, NULL);
}

/* One second on: the decoder writes `aircraft` (the inside of the
 * array) with its clock advanced, sloth reads it, polls and evaluates. */
static void tick(const char *aircraft) {
    g_mono += 1000;
    g_wall += 1;
    g_now += 1;
    char doc[2048];
    snprintf(doc, sizeof(doc), "{\"now\":%.1f,\"messages\":100,\"aircraft\":[%s]}",
             g_now, aircraft);
    ASSERT_EQ(adsb_doc_parse(doc, strlen(doc), &g_doc), 0);
    adsb_feed_doc(&g_doc, 0, g_wall, g_mono);
    adsb_health_poll(&g_s, g_wall, g_mono);
    alerts_update(&g_s);
}

/* One second on with no new document: the decoder has stopped. */
static void tick_silent(void) {
    g_mono += 1000;
    g_wall += 1;
    adsb_health_poll(&g_s, g_wall, g_mono);
    alerts_update(&g_s);
}

static int n_type(void) {
    int n = 0;
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == ALERT_TYPE_ADSB_EMERGENCY) n++;
    return n;
}

static const alert_t *by_key(const char *key) {
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == ALERT_TYPE_ADSB_EMERGENCY &&
            strcmp(g_s.alerts[i].key, key) == 0)
            return &g_s.alerts[i];
    return NULL;
}

/* ── fires ─────────────────────────────────────────────────────── */

/* Each ICAO emergency code, alone (no status key), fires once on its
 * address, LOW on first sight, keyed on the code, and the detail names
 * the address, the callsign, the squawk and the absent status. */
static void test_each_code_fires(void) {
    static const char *const codes[] = { "7500", "7600", "7700" };
    for (int i = 0; i < 3; i++) {
        begin();
        char ac[160];
        snprintf(ac, sizeof(ac),
                 "{\"hex\":\"a1b2c3\",\"flight\":\"SYN%d   \",\"squawk\":\"%s\",\"seen\":0}",
                 i, codes[i]);
        tick(ac);
        char key[64];
        snprintf(key, sizeof(key), "adsbemerg:a1b2c3:icao:%s", codes[i]);
        const alert_t *a = by_key(key);
        ASSERT(a != NULL);
        ASSERT_EQ(n_type(), 1);
        if (a) {
            ASSERT_EQ(a->sev, ALERT_SEV_LOW);
            char want[64];
            snprintf(want, sizeof(want), "ICAO a1b2c3 callsign SYN%d squawk %s emergency -", i, codes[i]);
            ASSERT(strstr(a->detail, want) != NULL);
            ASSERT(strstr(a->detail, "flag only") != NULL);
            ASSERT_STR(a->match_ip, "");
        }
        end();
    }
}

/* Each emergency/priority status other than none fires with an
 * ordinary squawk, keyed on the status word. */
static void test_each_status_fires(void) {
    static const char *const words[] = {
        "general", "lifeguard", "minfuel", "nordo", "unlawful", "downed", "reserved"
    };
    for (int i = 0; i < 7; i++) {
        begin();
        char ac[160];
        snprintf(ac, sizeof(ac),
                 "{\"hex\":\"0abcde\",\"squawk\":\"1200\",\"emergency\":\"%s\"}", words[i]);
        tick(ac);
        char key[64];
        snprintf(key, sizeof(key), "adsbemerg:0abcde:icao:%s", words[i]);
        const alert_t *a = by_key(key);
        ASSERT(a != NULL);
        ASSERT_EQ(n_type(), 1);
        if (a) {
            char want[96];
            snprintf(want, sizeof(want), "ICAO 0abcde callsign - squawk 1200 emergency %s", words[i]);
            ASSERT(strstr(a->detail, want) != NULL);
        }
        end();
    }
}

/* A non-ICAO address ('~', TIS-B) is its own key space: the same 24
 * bits with and without '~' are two findings. */
static void test_non_icao_is_its_own_key(void) {
    begin();
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\"},{\"hex\":\"~a1b2c3\",\"squawk\":\"7700\"}");
    ASSERT_EQ(n_type(), 2);
    ASSERT(by_key("adsbemerg:a1b2c3:icao:7700") != NULL);
    const alert_t *t = by_key("adsbemerg:a1b2c3:nonicao:7700");
    ASSERT(t != NULL);
    if (t) ASSERT(strstr(t->detail, "non-ICAO ~a1b2c3") != NULL);
    end();
}

/* ── does not fire ─────────────────────────────────────────────── */

/* Status none, status absent, ordinary squawks (including 7000, 7777
 * and 0000, which are not emergency codes), a squawk absent: nothing.
 * Seen red under condition() taking ADSB_EMERG_NONE as a condition
 * (`>= ADSB_EMERG_NONE`), and under emerg_code() matching any squawk
 * whose first digit is 7. */
static void test_none_and_absent_do_not_fire(void) {
    begin();
    for (int i = 0; i < 5; i++)
        tick("{\"hex\":\"100001\",\"squawk\":\"1200\",\"emergency\":\"none\"},"
             "{\"hex\":\"100002\",\"squawk\":\"7000\"},"
             "{\"hex\":\"100003\",\"squawk\":\"7777\",\"emergency\":\"none\"},"
             "{\"hex\":\"100004\",\"squawk\":\"0000\"},"
             "{\"hex\":\"100005\",\"emergency\":\"none\"},"
             "{\"hex\":\"100006\",\"flight\":\"SYN9\"},"
             "{\"hex\":\"100007\",\"squawk\":\"7701\"}");
    ASSERT_EQ(g_s.adsb_count, 7);      /* the rows are there to judge */
    ASSERT_EQ(n_type(), 0);
    end();
}

/* An aircraft that leaves the table is no longer evaluated, and its
 * incident resolves on the engine's quiet period. Seen red with the
 * rule re-firing, from its own hold memory, every address it held last
 * pass that the table no longer lists. (A rule that also walked
 * s->adsb_gone would not turn this red: that list holds a retired row
 * for one poll only, which is before `ev` is read.) */
static void test_gone_aircraft_not_evaluated(void) {
    begin();
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\",\"seen\":0}");
    const alert_t *a = by_key("adsbemerg:a1b2c3:icao:7700");
    ASSERT(a != NULL);
    /* The decoder stops listing it; the clock still moves. */
    for (int i = 0; i < ADSB_EXPIRE_S + 1; i++) tick("");
    ASSERT_EQ(g_s.adsb_count, 0);
    a = by_key("adsbemerg:a1b2c3:icao:7700");
    ASSERT(a != NULL);
    uint32_t ev = a ? a->evaluations : 0;
    for (int i = 0; i < 30; i++) tick("");
    a = by_key("adsbemerg:a1b2c3:icao:7700");
    ASSERT(a != NULL);
    if (a) ASSERT_EQ(a->evaluations, ev);
    for (int i = 0; i < ALERT_RESOLVE_AFTER_S; i++) tick("");
    a = by_key("adsbemerg:a1b2c3:icao:7700");
    if (a) ASSERT_EQ(a->resolved, 1);
    end();
}

/* A decoder that stops writing goes STALE, and its last rows are not
 * evidence about now: no evaluation while stale. Seen red with the
 * `s->adsb.state == ADSB_LIVE` test removed. */
static void test_stale_source_not_evaluated(void) {
    begin();
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7600\",\"seen\":0}");
    for (int i = 0; i < ADSB_STALE_S + 1; i++) tick_silent();
    ASSERT_EQ(g_s.adsb.state, ADSB_STALE);
    ASSERT(g_s.adsb_count >= 1);       /* the row is still listed */
    const alert_t *a = by_key("adsbemerg:a1b2c3:icao:7600");
    ASSERT(a != NULL);
    uint32_t ev = a ? a->evaluations : 0;
    for (int i = 0; i < 12; i++) tick_silent();
    a = by_key("adsbemerg:a1b2c3:icao:7600");
    if (a) ASSERT_EQ(a->evaluations, ev);
    end();
}

/* ── one incident, re-fire on change ───────────────────────────── */

/* 7700 to 7500 is a new condition and a new incident; back to 1200 the
 * 7500 one stops being evaluated. Seen red with the condition left out
 * of the key, and with the rule re-firing its remembered holds. */
static void test_code_change_refires(void) {
    begin();
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\"}");
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7500\"}");
    ASSERT_EQ(n_type(), 2);
    ASSERT(by_key("adsbemerg:a1b2c3:icao:7700") != NULL);
    const alert_t *b = by_key("adsbemerg:a1b2c3:icao:7500");
    ASSERT(b != NULL);
    if (b) ASSERT_EQ(b->sev, ALERT_SEV_LOW);    /* the hold starts over */
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"1200\"}");
    b = by_key("adsbemerg:a1b2c3:icao:7500");
    uint32_t ev = b ? b->evaluations : 0;
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"1200\"}");
    b = by_key("adsbemerg:a1b2c3:icao:7500");
    if (b) ASSERT_EQ(b->evaluations, ev);
    ASSERT_EQ(n_type(), 2);
    end();
}

/* A steady 7700 read every second is one incident, and once its
 * detail has settled (the status following the code from none to
 * general, then first sight to held) standing passes add no
 * observation (#173). The status change is the same condition, not a
 * second incident. Seen red under three mutations: the held seconds
 * appended to the detail; the key built with the status word as well
 * as the code; and the key built with the poll's wall second. */
static void test_steady_state_is_one_incident(void) {
    begin();
    tick("{\"hex\":\"a1b2c3\",\"flight\":\"SYN7\",\"squawk\":\"7700\",\"emergency\":\"none\",\"seen\":0}");
    for (int i = 0; i < 69; i++)
        tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\",\"emergency\":\"general\",\"seen\":0}");
    const alert_t *a = by_key("adsbemerg:a1b2c3:icao:7700");
    ASSERT(a != NULL);
    uint32_t obs = a ? a->observations : 0;
    for (int i = 0; i < 50; i++)
        tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\",\"emergency\":\"general\",\"seen\":0}");
    ASSERT_EQ(n_type(), 1);
    a = by_key("adsbemerg:a1b2c3:icao:7700");
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->evaluations, 120u);
        ASSERT_EQ(a->observations, obs);
        ASSERT_EQ(a->sev, ALERT_SEV_WARN);
        ASSERT(strstr(a->detail, "callsign SYN7 squawk 7700 emergency general") != NULL);
    }
    end();
}

/* ── severity ──────────────────────────────────────────────────── */

/* LOW until the condition has held adsb.emerg_hold_s (10 s) of the
 * aircraft's own messages, WARN from then, never CRIT. */
static void test_held_condition_escalates_to_warn(void) {
    begin();
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\",\"seen\":0}");
    for (int i = 0; i < 9; i++) tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\",\"seen\":0}");
    const alert_t *a = by_key("adsbemerg:a1b2c3:icao:7700");
    ASSERT(a != NULL);
    if (a) ASSERT_EQ(a->sev, ALERT_SEV_LOW);           /* 9 s held */
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\",\"seen\":0}");
    a = by_key("adsbemerg:a1b2c3:icao:7700");
    if (a) {
        ASSERT_EQ(a->sev, ALERT_SEV_WARN);             /* 10 s held */
        ASSERT(strstr(a->detail, "held past adsb.emerg_hold_s") != NULL);
    }
    for (int i = 0; i < 40; i++) tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\",\"seen\":0}");
    a = by_key("adsbemerg:a1b2c3:icao:7700");
    if (a) ASSERT_EQ(a->sev, ALERT_SEV_WARN);          /* never CRIT */
    end();
}

/* One 7700 heard once and then relisted by the decoder without a new
 * message (`seen` growing) stays LOW: the hold is the aircraft's
 * message time, not sloth's poll time. Seen red with the hold measured
 * on sloth_mono_ms() at the poll instead of the row's last_mono_ms. */
static void test_relisted_without_messages_stays_low(void) {
    begin();
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7700\",\"seen\":0}");
    for (int i = 1; i <= 20; i++) {
        char ac[96];
        snprintf(ac, sizeof(ac), "{\"hex\":\"a1b2c3\",\"squawk\":\"7700\",\"seen\":%d}", i);
        tick(ac);
    }
    const alert_t *a = by_key("adsbemerg:a1b2c3:icao:7700");
    ASSERT(a != NULL);
    if (a) ASSERT_EQ(a->sev, ALERT_SEV_LOW);
    end();
}

/* The knob is the hold: at 30 s, 20 s held is still LOW. */
static void test_hold_is_the_knob(void) {
    begin();
    ASSERT_EQ(tune_set_id(TUNE_ADSB_EMERG_HOLD_S, 30), 1);
    for (int i = 0; i < 21; i++) tick("{\"hex\":\"a1b2c3\",\"emergency\":\"unlawful\",\"seen\":0}");
    const alert_t *a = by_key("adsbemerg:a1b2c3:icao:unlawful");
    ASSERT(a != NULL);
    if (a) ASSERT_EQ(a->sev, ALERT_SEV_LOW);
    for (int i = 0; i < 10; i++) tick("{\"hex\":\"a1b2c3\",\"emergency\":\"unlawful\",\"seen\":0}");
    a = by_key("adsbemerg:a1b2c3:icao:unlawful");
    if (a) ASSERT_EQ(a->sev, ALERT_SEV_WARN);
    end();
}

/* 'c' (alerts_clear) drops the holds: a standing emergency comes back
 * LOW and holds again. Seen red with rules_adsb_forget() not called
 * from alerts_clear(). */
static void test_clear_restarts_the_hold(void) {
    begin();
    for (int i = 0; i < 15; i++) tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7600\",\"seen\":0}");
    const alert_t *a = by_key("adsbemerg:a1b2c3:icao:7600");
    if (a) ASSERT_EQ(a->sev, ALERT_SEV_WARN);
    alerts_clear();
    tick("{\"hex\":\"a1b2c3\",\"squawk\":\"7600\",\"seen\":0}");
    a = by_key("adsbemerg:a1b2c3:icao:7600");
    ASSERT(a != NULL);
    if (a) ASSERT_EQ(a->sev, ALERT_SEV_LOW);
    end();
}

void run_adsb_rules_tests(void) {
    RUN_TEST(test_each_code_fires);
    RUN_TEST(test_each_status_fires);
    RUN_TEST(test_non_icao_is_its_own_key);
    RUN_TEST(test_none_and_absent_do_not_fire);
    RUN_TEST(test_gone_aircraft_not_evaluated);
    RUN_TEST(test_stale_source_not_evaluated);
    RUN_TEST(test_code_change_refires);
    RUN_TEST(test_steady_state_is_one_incident);
    RUN_TEST(test_held_condition_escalates_to_warn);
    RUN_TEST(test_relisted_without_messages_stays_low);
    RUN_TEST(test_hold_is_the_knob);
    RUN_TEST(test_clear_restarts_the_hold);
}
