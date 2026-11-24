#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rf_scenario.h"

/*
 * The loop, end to end, twice: the same canned ADS-B, APRS, rtl_433 and
 * gpsd input (tests/rf_scenario.h) through the readers into JSONL, once
 * under sloth-wifi's poll table with its capture side and once under
 * sloth-rf's with its own side.
 *
 * Until the cutover (#216) the first run was the one binary's, which
 * read the decoders too, and this file held sloth-rf's RF records to
 * being its, line for line (#213). That comparison was made while both
 * existed and cannot be made now: sloth-wifi writes none of them. What
 * is held instead is the split itself - every RF kind, the 7700
 * incident and the decoder source rows are in sloth-rf's stream and in
 * no line of sloth-wifi's, from one input, with each run the other's
 * control - and the counts and words the comparison used to ride on.
 *
 * Two members are masked where lines are picked. An incident's id is a
 * hash over a process-wide counter the engine never resets
 * (src/alerts/engine.c incident_id_make()), so the second run of the
 * scenario in one process gets other ids for the same incidents.
 */

static char g_jl_a[TEST_TMP_MAX], g_jl_b[TEST_TMP_MAX];

static void tmp_jsonl(char *buf, size_t sz) {
    buf[0] = '\0';
    int fd = mkstemp(test_tmp_tpl(buf, sz, "sloth_rfl_XXXXXX"));
    if (fd >= 0) close(fd);
}

/* The record kinds sloth-rf owns (ADR 0010), and since JSONL 2.0.0
 * writes alone. */
static const char *const RF_KINDS[] = {
    "gnss_fix", "gnss_sky", "gnss_sat", "adsb_aircraft",
    "aprs_packet", "aprs_station", "rtl433_device", "victron_device",
};
#define RF_KIND_N ((int)(sizeof(RF_KINDS) / sizeof(RF_KINDS[0])))

/* The type of the record on the line at `p`, into out. */
static void line_type(const char *p, char *out, size_t sz) {
    out[0] = '\0';
    static const char pfx[] = "{\"type\":\"";
    if (strncmp(p, pfx, sizeof(pfx) - 1) != 0) return;
    p += sizeof(pfx) - 1;
    size_t n = 0;
    while (p[n] && p[n] != '"' && p[n] != '\n' && n + 1 < sz) { out[n] = p[n]; n++; }
    out[n] = '\0';
}

static int in_list(const char *t, const char *const *list, int n) {
    for (int i = 0; i < n; i++) if (strcmp(t, list[i]) == 0) return 1;
    return 0;
}

static void mask_ids(char *line) {
    static const char *const keys[] = { "\"incident_id\":\"", "\"event_id\":\"" };
    for (int k = 0; k < 2; k++) {
        char *p = strstr(line, keys[k]);
        if (!p) continue;
        p += strlen(keys[k]);
        for (int i = 0; i < 16 && p[i] && p[i] != '"'; i++) p[i] = 'x';
    }
}

/* The lines of `text` whose type is in `list` (or, with `alerts`, an
 * alert record of the given title), ids masked, in order. Caller frees. */
static char *pick(const char *text, const char *const *list, int n,
                  const char *alert_title) {
    size_t cap = strlen(text) + 2, off = 0;
    char *out = malloc(cap);
    if (!out) return NULL;
    out[0] = '\0';
    for (const char *p = text; *p; ) {
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) + 1 : strlen(p);
        char ty[40];
        line_type(p, ty, sizeof(ty));
        int take = list && in_list(ty, list, n);
        if (!take && alert_title &&
            (!strcmp(ty, "alert") || !strncmp(ty, "alert.", 6))) {
            char want[96];
            snprintf(want, sizeof(want), "\"title\":\"%s\"", alert_title);
            char *line = malloc(len + 1);
            if (line) {
                memcpy(line, p, len); line[len] = '\0';
                take = strstr(line, want) != NULL;
                free(line);
            }
        }
        if (take) {
            memcpy(out + off, p, len);
            out[off + len] = '\0';
            mask_ids(out + off);
            off += len;
        }
        p += len;
    }
    return out;
}

static int count_lines(const char *text) {
    int n = 0;
    for (const char *p = text; *p; p++) if (*p == '\n') n++;
    return n;
}

static int count_type(const char *text, const char *type) {
    char want[64];
    snprintf(want, sizeof(want), "{\"type\":\"%s\",", type);
    int n = 0;
    for (const char *p = text; (p = strstr(p, want)) != NULL; p += strlen(want))
        if (p == text || p[-1] == '\n') n++;
    return n;
}

/* The RF records are sloth-rf's, every kind, more than once where the
 * input had more than one - and sloth-wifi, given the same decoder
 * files and the same receiver, writes not one of them.
 *
 * Seen red (2026-11-15), the sloth-wifi half: with the five
 * jsonl_emit_{gnss,adsb,aprs,rtl433,victron} calls put back in
 * jsonl_emit_state_snapshots() the gnss_* counts are 1, 1 and 3 (the
 * decoders' stay 0 there for want of a health_rf stage); with health_rf
 * put back in wifi_stages[] as well, every count below is non-zero. */
static void test_rf_records_are_sloth_rfs_alone(void) {
    tmp_jsonl(g_jl_a, sizeof(g_jl_a));
    tmp_jsonl(g_jl_b, sizeof(g_jl_b));
    rfs_run(&g_poll_wifi, 0, g_jl_a, NULL);
    rfs_run(&g_poll_rf,   1, g_jl_b, NULL);
    char *a = rfs_slurp(g_jl_a), *b = rfs_slurp(g_jl_b);
    ASSERT(a != NULL && b != NULL);
    if (!a || !b) { free(a); free(b); return; }

    char *pa = pick(a, RF_KINDS, RF_KIND_N, NULL);
    char *pb = pick(b, RF_KINDS, RF_KIND_N, NULL);
    ASSERT(pa != NULL && pb != NULL);
    if (pa && pb) {
        ASSERT_GE(count_lines(pb), 10);
        ASSERT_GE(count_type(pb, "gnss_fix"), 1);
        ASSERT_GE(count_type(pb, "gnss_sky"), 1);
        ASSERT_EQ(count_type(pb, "gnss_sat"), 3);
        ASSERT_GE(count_type(pb, "adsb_aircraft"), 2);
        ASSERT_EQ(count_type(pb, "aprs_packet"), 2);
        ASSERT_GE(count_type(pb, "aprs_station"), 2);
        ASSERT_GE(count_type(pb, "rtl433_device"), 2);
        ASSERT_GE(count_type(pb, "victron_device"), 1);
        /* The input's own words made it through: nothing here is a
         * statement about an empty stream. */
        ASSERT(strstr(pb, "\"N0TEST-9\"") != NULL);
        ASSERT(strstr(pb, "\"Testco-WX9\"") != NULL);
        ASSERT(strstr(pb, "a1b2c3") != NULL);
        ASSERT(strstr(pb, "TESTBMV0001") != NULL);
        /* What the decoders wrote before the daemon started is not a
         * record: both logs are tailed from their end. */
        ASSERT(strstr(pb, "N0OLD-1") == NULL);
        ASSERT(strstr(pb, "Testco-OLD") == NULL);
        ASSERT(strstr(pb, "TESTOLD0001") == NULL);

        /* sloth-wifi: none, by kind and by the input's words. */
        ASSERT_EQ(count_lines(pa), 0);
        for (int i = 0; i < RF_KIND_N; i++) {
            if (count_type(a, RF_KINDS[i]) != 0)
                fprintf(stderr, "    sloth-wifi wrote a \"%s\" record\n", RF_KINDS[i]);
            ASSERT_EQ(count_type(a, RF_KINDS[i]), 0);
        }
        /* Victron's is in RF_KINDS, so the loop above holds it; the
         * scenario feeds sloth-va's file since #216's review, and the
         * sloth-rf half above is its control. */
        ASSERT(strstr(a, "TESTBMV0001") == NULL);
        ASSERT(strstr(a, "N0TEST-9") == NULL);
        ASSERT(strstr(a, "Testco-WX9") == NULL);
        ASSERT(strstr(a, "a1b2c3") == NULL);
        /* And it did run: its own records are there. */
        ASSERT_GE(count_type(a, "iface"), 1);
        ASSERT_GE(count_type(a, "sensor_health"), 1);
    }
    free(pa); free(pb); free(a); free(b);
    unlink(g_jl_a); unlink(g_jl_b);
}

/* The 7700 squawk is sloth-rf's incident - the legacy record and its
 * lifecycle, in order - and sloth-wifi, with the same aircraft.json on
 * disk, opens none. */
static void test_adsb_emergency_is_sloth_rfs_alone(void) {
    tmp_jsonl(g_jl_a, sizeof(g_jl_a));
    tmp_jsonl(g_jl_b, sizeof(g_jl_b));
    rfs_run(&g_poll_wifi, 0, g_jl_a, NULL);
    rfs_run(&g_poll_rf,   1, g_jl_b, NULL);
    char *a = rfs_slurp(g_jl_a), *b = rfs_slurp(g_jl_b);
    ASSERT(a != NULL && b != NULL);
    if (!a || !b) { free(a); free(b); return; }
    char *pa = pick(a, NULL, 0, "ADSB_EMERGENCY");
    char *pb = pick(b, NULL, 0, "ADSB_EMERGENCY");
    ASSERT(pa != NULL && pb != NULL);
    if (pa && pb) {
        ASSERT_GE(count_type(pb, "alert"), 1);
        ASSERT_GE(count_type(pb, "alert.create"), 1);
        ASSERT(strstr(pb, "squawk 7700") != NULL);
        ASSERT_EQ(count_lines(pa), 0);
        ASSERT(strstr(a, "ADSB_EMERGENCY") == NULL);
    }
    free(pa); free(pb); free(a); free(b);
    unlink(g_jl_a); unlink(g_jl_b);
}

/* What sloth-rf's stream is made of: its own kinds, the sensor
 * registry, the host status and its own source rows, alerts, and its
 * sensor_health - and nothing of the capture's, on a host that has an
 * interface, an associated Wi-Fi station and a supply alarm for a
 * capture daemon to report. Three absences, each with its control:
 *
 *   no record of any other type  (sloth-wifi, same run: "iface" is there)
 *   no SENSOR_UNDERVOLT          (sloth-wifi, same run: it fires)
 *   no capture source row        (sloth-wifi, same run: "capture" is there)
 *
 * Seen red, all three, with the one binary's table and services passed
 * to the second run in place of sloth-rf's (#213). */
static void test_rf_stream_is_only_its_own(void) {
    static const char *const ALLOWED[] = {
        "gnss_fix", "gnss_sky", "gnss_sat", "adsb_aircraft", "aprs_packet",
        "aprs_station", "rtl433_device", "victron_device", "sensor", "sensor_health",
        "sys_status", "sys_sensor", "source_status", "receiver_hw",
        "rule_status", "coverage",
        "alert", "alert.create", "alert.update", "alert.escalate",
        "alert.resolve",
    };
    const int allowed_n = (int)(sizeof(ALLOWED) / sizeof(ALLOWED[0]));
    tmp_jsonl(g_jl_a, sizeof(g_jl_a));
    tmp_jsonl(g_jl_b, sizeof(g_jl_b));
    rfs_run(&g_poll_wifi, 0, g_jl_a, NULL);
    rfs_run(&g_poll_rf,    1, g_jl_b, NULL);
    char *a = rfs_slurp(g_jl_a), *b = rfs_slurp(g_jl_b);
    ASSERT(a != NULL && b != NULL);
    if (!a || !b) { free(a); free(b); return; }

    int other = 0, lines = 0;
    for (const char *p = b; *p; ) {
        const char *e = strchr(p, '\n');
        char ty[40];
        line_type(p, ty, sizeof(ty));
        lines++;
        if (!in_list(ty, ALLOWED, allowed_n)) {
            if (!other) fprintf(stderr, "    sloth-rf wrote a \"%s\" record\n", ty);
            other++;
        }
        if (!e) break;
        p = e + 1;
    }
    ASSERT_GE(lines, 15);
    ASSERT_EQ(other, 0);
    ASSERT_GE(count_type(a, "iface"), 1);                 /* the control */

    ASSERT(strstr(b, "SENSOR_UNDERVOLT") == NULL);
    ASSERT(strstr(a, "\"title\":\"SENSOR_UNDERVOLT\"") != NULL);
    /* The alarm itself is in both: sys_status reports the host. */
    ASSERT(strstr(b, "\"undervolt\":1") != NULL);

    ASSERT(strstr(b, "\"type\":\"source_status\"") != NULL);
    ASSERT(strstr(b, "\"name\":\"capture\"") == NULL);
    ASSERT(strstr(b, "\"name\":\"monitor\"") == NULL);
    ASSERT(strstr(b, "\"name\":\"btmon\"") == NULL);
    ASSERT(strstr(b, "\"name\":\"btcap\"") == NULL);
    ASSERT(strstr(a, "\"name\":\"capture\"") != NULL);
    ASSERT(strstr(a, "\"name\":\"monitor\"") != NULL);
    static const char *const own[] = { "gnss", "adsb", "aprs", "rtl433", "victron" };
    for (int i = 0; i < 5; i++) {
        char want[48];
        snprintf(want, sizeof(want), "\"name\":\"%s\",", own[i]);
        ASSERT(strstr(b, want) != NULL);
    }
    /* A row the daemon does not have is not written under an empty
     * name either. (Seen red with the `name` guards taken out of
     * src/sys_status.c's emit path: four nameless rows a batch.) */
    ASSERT(strstr(b, "\"name\":\"\"") == NULL);
    /* sys_status counts the rows the daemon has, all five configured
     * in this scenario. */
    ASSERT(strstr(b, "\"sources\":5,\"sources_configured\":5,") != NULL);
    /* sloth-wifi's rows are the capture's four and the receiver's
     * (#216): nine until the cutover, when it named the decoders'. */
    ASSERT(strstr(a, "\"sources\":5,") != NULL);

    /* sys_status's beacon-recall block is the beacon table's, which
     * this daemon does not have: absent, not zero
     * (docs/wiki/jsonl-schema.md says so). sloth-wifi, same run, writes
     * it. (Seen red with has_recall forced to 1 in
     * src/sys_status.c's sample.) */
    ASSERT(strstr(b, "\"type\":\"sys_status\"") != NULL);
    ASSERT(strstr(b, "beacon_recall_") == NULL);
    ASSERT(strstr(a, "\"beacon_recall_slots\":") != NULL);
    ASSERT(strstr(a, "\"beacon_recall_quiet\":") != NULL);

    /* The daemon says which it is, once per record. */
    ASSERT(strstr(b, "\"daemon\":\"rf\"") != NULL);
    ASSERT(strstr(b, "\"daemon\":\"wifi\"") == NULL);
    ASSERT(strstr(a, "\"daemon\":\"wifi\"") != NULL);
    ASSERT(strstr(a, "\"daemon\":\"rf\"") == NULL);

    /* The five sensors, from slot 0, and no radio. */
    ASSERT_EQ(count_type(b, "sensor") % 5, 0);
    ASSERT(strstr(b, "\"name\":\"Victron (sloth-va)\"") != NULL);
    ASSERT(strstr(b, "\"name\":\"GNSS receiver\"") != NULL);
    ASSERT(strstr(b, "\"name\":\"rtl_433 decoder\"") != NULL);
    free(a); free(b);
    unlink(g_jl_a); unlink(g_jl_b);
}

/* sloth-wifi keeps the receiver without owning its records (#216,
 * owner ruling 2026-11-15). From the scenario's gpsd stream - a fix, a
 * sky of three satellites, and the sensor moving - its stream has the
 * receiver's health (gps_*, gnss_*) and the position (loc_*) in
 * sensor_health, its `gnss` source row, its sensor row and the loc_*
 * stamp on the incident it opens; and it has no gnss_fix / gnss_sky /
 * gnss_sat record, no GNSS_* alert, and no decoder's source row,
 * sensor row or sensor_health member. sloth-rf, same input, is the
 * control for each absence.
 *
 * Seen red (2026-11-15): the record absences with jsonl_emit_gnss()
 * put back in jsonl_emit_state_snapshots(); the source rows with
 * sys_status_set_rf_side(sys_status_rf_fill) left registered in
 * capture_side_install(); the sensor rows and members with health_rf
 * and sensors_rf put back in wifi_stages[] and the jsonl_sh_* calls in
 * jsonl_emit_sensor_health(). The GNSS_* absence: with
 * R(rule_gnss_position_jump) put back in src/alerts/rules_table.c and
 * the scenario's third fix moved 2 degrees, sloth-wifi opens
 * GNSS_POSITION_JUMP; tests/test_rf_rules.c holds the row's absence. */
static void test_wifi_stream_keeps_gnss_health_and_no_gnss_record(void) {
    tmp_jsonl(g_jl_a, sizeof(g_jl_a));
    tmp_jsonl(g_jl_b, sizeof(g_jl_b));
    rfs_run(&g_poll_wifi, 0, g_jl_a, NULL);
    rfs_run(&g_poll_rf,   1, g_jl_b, NULL);
    char *a = rfs_slurp(g_jl_a), *b = rfs_slurp(g_jl_b);
    ASSERT(a != NULL && b != NULL);
    if (!a || !b) { free(a); free(b); return; }

    /* Kept: the receiver's health, the position, its rows. */
    ASSERT(strstr(a, "\"gps_state\":\"fix\"") != NULL);
    ASSERT(strstr(a, "\"gps_src\":\"gpsd:127.0.0.1:2947\"") != NULL);
    ASSERT(strstr(a, "\"gnss_sats_in_view\":3,") != NULL);
    ASSERT(strstr(a, "\"loc_lat\":") != NULL);
    ASSERT(strstr(a, "\"loc_src\":\"gps\"") != NULL);
    ASSERT(strstr(a, "\"name\":\"gnss\",") != NULL);
    ASSERT(strstr(a, "\"name\":\"GNSS receiver\"") != NULL);
    /* The stamp on its own incident. */
    const char *uv = strstr(a, "\"title\":\"SENSOR_UNDERVOLT\"");
    ASSERT(uv != NULL);
    if (uv) {
        const char *ls = uv;
        while (ls > a && ls[-1] != '\n') ls--;
        const char *le = strchr(uv, '\n');
        const char *loc = strstr(ls, "\"loc\":{");
        ASSERT(loc != NULL && le != NULL && loc < le);
    }

    /* Gone: the records and the alerts. */
    ASSERT_EQ(count_type(a, "gnss_fix"), 0);
    ASSERT_EQ(count_type(a, "gnss_sky"), 0);
    ASSERT_EQ(count_type(a, "gnss_sat"), 0);
    ASSERT(strstr(a, "GNSS_JAMMING") == NULL);
    ASSERT(strstr(a, "GNSS_SPOOF_SUSPECT") == NULL);
    ASSERT(strstr(a, "GNSS_TIME_JUMP") == NULL);
    ASSERT(strstr(a, "GNSS_POSITION_JUMP") == NULL);
    ASSERT_GE(count_type(b, "gnss_fix"), 1);              /* the control */
    ASSERT_EQ(count_type(b, "gnss_sat"), 3);

    /* Gone: every decoder's source row, sensor row and health member. */
    static const char *const rf_rows[] = { "adsb", "aprs", "rtl433", "victron" };
    for (int i = 0; i < 4; i++) {
        char want[48];
        snprintf(want, sizeof(want), "\"name\":\"%s\",", rf_rows[i]);
        if (strstr(a, want)) fprintf(stderr, "    sloth-wifi wrote a %s source row\n", rf_rows[i]);
        ASSERT(strstr(a, want) == NULL);
        ASSERT(strstr(b, want) != NULL);                  /* the control */
    }
    ASSERT(strstr(a, "\"name\":\"ADS-B decoder\"") == NULL);
    ASSERT(strstr(a, "\"name\":\"APRS decoder\"") == NULL);
    ASSERT(strstr(a, "\"name\":\"rtl_433 decoder\"") == NULL);
    ASSERT(strstr(a, "\"name\":\"Victron (sloth-va)\"") == NULL);
    ASSERT(strstr(b, "\"name\":\"ADS-B decoder\"") != NULL);
    ASSERT(strstr(b, "\"name\":\"Victron (sloth-va)\"") != NULL);
    ASSERT(strstr(a, "\"adsb_") == NULL);
    ASSERT(strstr(a, "\"aprs_") == NULL);
    ASSERT(strstr(a, "\"rtl433_") == NULL);
    ASSERT(strstr(a, "\"victron_") == NULL);
    ASSERT(strstr(b, "\"adsb_state\":") != NULL);
    ASSERT(strstr(b, "\"victron_state\":") != NULL);     /* the control */
    /* Both say 2.x, and which they are. */
    char ver[64];
    snprintf(ver, sizeof(ver), "\"jsonl_version\":\"%s\"", SLOTH_JSONL_VERSION);
    ASSERT(strstr(a, ver) != NULL);
    ASSERT(strstr(b, ver) != NULL);
    ASSERT_EQ(strncmp(SLOTH_JSONL_VERSION, "2.", 2), 0);
    free(a); free(b);
    unlink(g_jl_a); unlink(g_jl_b);
}

void run_rf_loop_tests(void) {
    TEST_SUITE("sloth-rf: canned inputs to JSONL, against sloth-wifi's (#213, #216)");
    RUN_TEST(test_rf_records_are_sloth_rfs_alone);
    RUN_TEST(test_adsb_emergency_is_sloth_rfs_alone);
    RUN_TEST(test_rf_stream_is_only_its_own);
    RUN_TEST(test_wifi_stream_keeps_gnss_health_and_no_gnss_record);
}
