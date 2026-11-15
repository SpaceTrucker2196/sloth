#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rf_scenario.h"

/*
 * The loop, end to end, twice (#213): the same canned ADS-B, APRS,
 * rtl_433 and gpsd input (tests/rf_scenario.h) through the readers into
 * JSONL, once under `sloth`'s poll table with its capture side and once
 * under sloth-rf's with its own rule table and nothing registered. The
 * records of the RF kinds must come out the same from both - the same
 * lines, in the same order - because sloth-rf's whole claim is that it
 * is `sloth`'s RF half, moved, and not a second implementation of it.
 *
 * Two members are not compared as written. An incident's id is a hash
 * over a process-wide counter the engine never resets
 * (src/alerts/engine.c incident_id_make()), so the second run of the
 * scenario in one process gets other ids for the same incidents; the 16
 * hex digits of incident_id, and of the event_id built on it, are
 * masked. Nothing else is: the timestamps are the pinned clock's.
 */

static char g_jl_a[TEST_TMP_MAX], g_jl_b[TEST_TMP_MAX];

static void tmp_jsonl(char *buf, size_t sz) {
    buf[0] = '\0';
    int fd = mkstemp(test_tmp_tpl(buf, sz, "sloth_rfl_XXXXXX"));
    if (fd >= 0) close(fd);
}

/* The record kinds sloth-rf owns (ADR 0010), which both daemons write
 * from the same inputs until cutover. */
static const char *const RF_KINDS[] = {
    "gnss_fix", "gnss_sky", "gnss_sat", "adsb_aircraft",
    "aprs_packet", "aprs_station", "rtl433_device",
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

/* Where two picks first differ, for the failure message. */
static void show_first_difference(const char *a, const char *b) {
    int line = 1;
    while (*a && *b) {
        const char *ea = strchr(a, '\n'), *eb = strchr(b, '\n');
        size_t la = ea ? (size_t)(ea - a) : strlen(a);
        size_t lb = eb ? (size_t)(eb - b) : strlen(b);
        if (la != lb || memcmp(a, b, la) != 0) {
            fprintf(stderr, "    line %d differs:\n      sloth:    %.*s\n"
                            "      sloth-rf: %.*s\n", line,
                    (int)(la > 300 ? 300 : la), a, (int)(lb > 300 ? 300 : lb), b);
            return;
        }
        a += la + (ea ? 1 : 0);
        b += lb + (eb ? 1 : 0);
        line++;
    }
    fprintf(stderr, "    one stream ends at line %d and the other goes on\n", line);
}

/* The RF records are the same from both daemons, line for line. And
 * the comparison is over something: every kind is in it, more than
 * once where the input had more than one. */
static void test_rf_records_match_sloths(void) {
    tmp_jsonl(g_jl_a, sizeof(g_jl_a));
    tmp_jsonl(g_jl_b, sizeof(g_jl_b));
    rfs_run(&g_poll_sloth, 0, g_jl_a, NULL);
    rfs_run(&g_poll_rf,    1, g_jl_b, NULL);
    char *a = rfs_slurp(g_jl_a), *b = rfs_slurp(g_jl_b);
    ASSERT(a != NULL && b != NULL);
    if (!a || !b) { free(a); free(b); return; }

    char *pa = pick(a, RF_KINDS, RF_KIND_N, NULL);
    char *pb = pick(b, RF_KINDS, RF_KIND_N, NULL);
    ASSERT(pa != NULL && pb != NULL);
    if (pa && pb) {
        int same = strcmp(pa, pb) == 0;
        if (!same) show_first_difference(pa, pb);
        ASSERT(same);
        ASSERT_GE(count_lines(pb), 10);
        ASSERT_GE(count_type(pb, "gnss_fix"), 1);
        ASSERT_GE(count_type(pb, "gnss_sky"), 1);
        ASSERT_EQ(count_type(pb, "gnss_sat"), 3);
        ASSERT_GE(count_type(pb, "adsb_aircraft"), 2);
        ASSERT_EQ(count_type(pb, "aprs_packet"), 2);
        ASSERT_GE(count_type(pb, "aprs_station"), 2);
        ASSERT_GE(count_type(pb, "rtl433_device"), 2);
        /* The input's own words made it through both: nothing here is
         * a comparison of two empty streams. */
        ASSERT(strstr(pb, "\"N0TEST-9\"") != NULL);
        ASSERT(strstr(pb, "\"Testco-WX9\"") != NULL);
        ASSERT(strstr(pb, "a1b2c3") != NULL);
        /* What the decoders wrote before the daemon started is not a
         * record: both logs are tailed from their end. */
        ASSERT(strstr(pb, "N0OLD-1") == NULL);
        ASSERT(strstr(pb, "Testco-OLD") == NULL);
    }
    free(pa); free(pb); free(a); free(b);
    unlink(g_jl_a); unlink(g_jl_b);
}

/* The alert both daemons own - the 7700 squawk - is the same incident
 * from both: the legacy record and its lifecycle, in order. */
static void test_adsb_emergency_matches_sloths(void) {
    tmp_jsonl(g_jl_a, sizeof(g_jl_a));
    tmp_jsonl(g_jl_b, sizeof(g_jl_b));
    rfs_run(&g_poll_sloth, 0, g_jl_a, NULL);
    rfs_run(&g_poll_rf,    1, g_jl_b, NULL);
    char *a = rfs_slurp(g_jl_a), *b = rfs_slurp(g_jl_b);
    ASSERT(a != NULL && b != NULL);
    if (!a || !b) { free(a); free(b); return; }
    char *pa = pick(a, NULL, 0, "ADSB_EMERGENCY");
    char *pb = pick(b, NULL, 0, "ADSB_EMERGENCY");
    ASSERT(pa != NULL && pb != NULL);
    if (pa && pb) {
        int same = strcmp(pa, pb) == 0;
        if (!same) show_first_difference(pa, pb);
        ASSERT(same);
        ASSERT_GE(count_type(pb, "alert"), 1);
        ASSERT_GE(count_type(pb, "alert.create"), 1);
        ASSERT(strstr(pb, "squawk 7700") != NULL);
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
 *   no record of any other type  (`sloth`, same run: "iface" is there)
 *   no SENSOR_UNDERVOLT          (`sloth`, same run: it fires)
 *   no capture source row        (`sloth`, same run: "capture" is there)
 *
 * Seen red, all three, with g_poll_sloth and `sloth`'s services passed
 * to the second run in place of sloth-rf's. */
static void test_rf_stream_is_only_its_own(void) {
    static const char *const ALLOWED[] = {
        "gnss_fix", "gnss_sky", "gnss_sat", "adsb_aircraft", "aprs_packet",
        "aprs_station", "rtl433_device", "sensor", "sensor_health",
        "sys_status", "sys_sensor", "source_status", "receiver_hw",
        "alert", "alert.create", "alert.update", "alert.escalate",
        "alert.resolve",
    };
    const int allowed_n = (int)(sizeof(ALLOWED) / sizeof(ALLOWED[0]));
    tmp_jsonl(g_jl_a, sizeof(g_jl_a));
    tmp_jsonl(g_jl_b, sizeof(g_jl_b));
    rfs_run(&g_poll_sloth, 0, g_jl_a, NULL);
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
    static const char *const own[] = { "gnss", "adsb", "aprs", "rtl433" };
    for (int i = 0; i < 4; i++) {
        char want[48];
        snprintf(want, sizeof(want), "\"name\":\"%s\",", own[i]);
        ASSERT(strstr(b, want) != NULL);
    }
    /* A row the daemon does not have is not written under an empty
     * name either. (Seen red with the `name` guards taken out of
     * src/sys_status.c's emit path: four nameless rows a batch.) */
    ASSERT(strstr(b, "\"name\":\"\"") == NULL);
    /* sys_status counts the rows the daemon has. */
    ASSERT(strstr(b, "\"sources\":4,\"sources_configured\":4,") != NULL);
    ASSERT(strstr(a, "\"sources\":8,") != NULL);

    /* sys_status's beacon-recall block is the beacon table's, which
     * this daemon does not have: absent, not zero
     * (docs/wiki/jsonl-schema.md says so). `sloth`, same run, writes
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

    /* The four sensors, from slot 0, and no radio. */
    ASSERT_EQ(count_type(b, "sensor") % 4, 0);
    ASSERT(strstr(b, "\"name\":\"GNSS receiver\"") != NULL);
    ASSERT(strstr(b, "\"name\":\"rtl_433 decoder\"") != NULL);
    free(a); free(b);
    unlink(g_jl_a); unlink(g_jl_b);
}

void run_rf_loop_tests(void) {
    TEST_SUITE("sloth-rf: canned inputs to JSONL, against sloth's (#213)");
    RUN_TEST(test_rf_records_match_sloths);
    RUN_TEST(test_adsb_emergency_matches_sloths);
    RUN_TEST(test_rf_stream_is_only_its_own);
}
