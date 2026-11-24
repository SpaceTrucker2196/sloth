#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"
#include "alerts/rules.h"

/* The ordered rule table (#118).
 *
 * alerts_update() runs g_alert_rules[] in order, and the order is
 * load-bearing (src/alerts/rules_table.c says why). These tests hold
 * the table to two things a hand-written call sequence held only by
 * being read: that every rule defined under src/alerts/ is run exactly
 * once, and that the pairs whose order matters are still in that
 * order. Same shape as the source scrapers in test_clock_seam.c and
 * test_docs_consistency.c: read the source, count, assert. */

static int ar_index(const char *name) {
    for (int i = 0; i < g_alert_rule_count; i++)
        if (g_alert_rules[i].name && strcmp(g_alert_rules[i].name, name) == 0)
            return i;
    return -1;
}

/* A rule definition starts a line with `void rule_<name>(`, optionally
 * `static`. Calls are indented, and rules_wired_forget() is `rules_`,
 * not `rule_`, so neither reads as a definition. */
static int ar_parse_def(const char *line, char *name, size_t n) {
    const char *p = line;
    if (strncmp(p, "static ", 7) == 0) p += 7;
    if (strncmp(p, "void rule_", 10) != 0) return 0;
    p += 5;
    const char *e = strchr(p, '(');
    if (!e || (size_t)(e - p) >= n) return 0;
    memcpy(name, p, (size_t)(e - p));
    name[e - p] = '\0';
    return 1;
}

#define AR_MAX_DEFS 256
#define AR_NAME_LEN 64

typedef struct {
    char names[AR_MAX_DEFS][AR_NAME_LEN];
    int  n;
    int  files;
} ar_defs_t;

/* Every .c under src/alerts/ except the table itself. The engine is
 * scanned too: a rule left behind there (or put back) is still a rule
 * the table has to run. */
static void ar_scrape(ar_defs_t *d) {
    memset(d, 0, sizeof(*d));
    DIR *dir = opendir("src/alerts");
    if (!dir) return;
    struct dirent *e;
    while ((e = readdir(dir)) != NULL) {
        size_t nl = strlen(e->d_name);
        if (nl < 3 || strcmp(e->d_name + nl - 2, ".c") != 0) continue;
        if (strcmp(e->d_name, "rules_table.c") == 0) continue;
        char path[512];
        snprintf(path, sizeof(path), "src/alerts/%.200s", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        d->files++;
        char line[512];
        char name[AR_NAME_LEN];
        while (fgets(line, sizeof(line), f)) {
            if (!ar_parse_def(line, name, sizeof(name))) continue;
            int dup = 0;
            for (int i = 0; i < d->n; i++)
                if (strcmp(d->names[i], name) == 0) dup = 1;
            if (!dup && d->n < AR_MAX_DEFS)
                snprintf(d->names[d->n++], AR_NAME_LEN, "%s", name);
        }
        fclose(f);
    }
    closedir(dir);
}

/* The parser must see definitions before its count means anything. */
static void test_rule_scraper_sees_definitions(void) {
    char name[AR_NAME_LEN];
    ASSERT(ar_parse_def("void rule_port_scan(const sloth_state_t *s, time_t now) {\n",
                        name, sizeof(name)));
    ASSERT_STR(name, "rule_port_scan");
    ASSERT(ar_parse_def("static void rule_x(const sloth_state_t *s,\n",
                        name, sizeof(name)));
    ASSERT_STR(name, "rule_x");
    ASSERT(!ar_parse_def("    rule_port_scan(s, now);\n", name, sizeof(name)));
    ASSERT(!ar_parse_def("void rules_wired_forget(void) {\n", name, sizeof(name)));
    ASSERT(!ar_parse_def("    R(rule_port_scan),\n", name, sizeof(name)));
}

/* Every rule defined is run, exactly once, by the daemon that owns it,
 * and the tables run nothing that is not a rule. Mutation-proved:
 * deleting the R(rule_beaconing) row from rules_table.c turns this red
 * naming rule_beaconing (68 definitions, 67 rows), and doubling the
 * R(rule_port_scan) row turns it red on the count and on "in the table
 * 2 times".
 *
 * Two tables since the cutover (#216): sloth-wifi's (the one this
 * binary has selected, g_alert_rules) and sloth-rf's. A definition is
 * in sloth-wifi's once and not in sloth-rf's - except the five that are
 * sloth-rf's alone (once there, never here) and
 * rule_sensor_source_down, which both run. So a rule dropped from one
 * table without landing in the other is still a red suite. */
static int ar_rf_only(const char *name) {
    return strncmp(name, "rule_gnss_", 10) == 0 ||
           strcmp(name, "rule_adsb_emergency") == 0;
}

static void test_rule_table_is_complete(void) {
    ar_defs_t d;
    ar_scrape(&d);
    /* The scan found the files: a wrong relative path would otherwise
     * compare an empty scrape against an empty expectation. */
    ASSERT_GE(d.files, 1);
    ASSERT_GE(d.n, 1);
    ASSERT(alerts_table() == &g_alert_table_wifi);
    int rf_only = 0;
    for (int i = 0; i < d.n; i++) rf_only += ar_rf_only(d.names[i]);
    ASSERT_EQ(rf_only, 5);
    if (d.n != g_alert_rule_count + rf_only)
        fprintf(stderr, "    %d rule definitions, %d sloth-wifi rows and %d "
                        "sloth-rf-only\n", d.n, g_alert_rule_count, rf_only);
    ASSERT_EQ(d.n, g_alert_rule_count + rf_only);
    ASSERT_EQ(g_alert_table_rf.count, rf_only + 1);

    for (int i = 0; i < d.n; i++) {
        int hits = 0, rf_hits = 0;
        for (int r = 0; r < g_alert_rule_count; r++)
            if (strcmp(g_alert_rules[r].name, d.names[i]) == 0) hits++;
        for (int r = 0; r < g_alert_table_rf.count; r++)
            if (strcmp(g_alert_table_rf.rules[r].name, d.names[i]) == 0) rf_hits++;
        int want = ar_rf_only(d.names[i]) ? 0 : 1;
        int want_rf = ar_rf_only(d.names[i]) ||
                      strcmp(d.names[i], "rule_sensor_source_down") == 0;
        if (hits != want || rf_hits != want_rf)
            fprintf(stderr, "    %s is in sloth-wifi's table %d times (want %d) "
                            "and sloth-rf's %d (want %d)\n",
                    d.names[i], hits, want, rf_hits, want_rf);
        ASSERT_EQ(hits, want);
        ASSERT_EQ(rf_hits, want_rf);
    }
    for (int r = 0; r < g_alert_rule_count; r++) {
        ASSERT(g_alert_rules[r].fn != NULL);
        ASSERT(strncmp(g_alert_rules[r].name, "rule_", 5) == 0);
    }
}

static char *ar_slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/* The three dependencies rules_table.c names, pinned by name.
 *
 * Mutation-proved, one per claim, each reddening its own assertion
 * alone: swapping the rule_deauth_flood and rule_karma_ap rows (the
 * flood lands after the chain) the first; swapping the rule_evil_twin
 * and rule_evil_twin_attack_chain rows the second; moving
 * wifi_downgrade_update(s) below the loop the third. Swapping deauth
 * with the chain row directly is NOT a clean mutation for the first —
 * it also puts the chain ahead of rule_evil_twin and reddens both.
 *
 * Only the third is also caught by behaviour (the wpa_downgrade tests
 * in test_alerts.c go red with it). Neither row swap reddened anything
 * outside this test: no existing scenario observes same-tick JSONL
 * order or a same-tick taint read, so these name pins are the whole of
 * the coverage for the first two. */
static void test_rule_order_dependencies(void) {
    int deauth = ar_index("rule_deauth_flood");
    int twin   = ar_index("rule_evil_twin");
    int chain  = ar_index("rule_evil_twin_attack_chain");
    int wpa    = ar_index("rule_wpa_downgrade");
    ASSERT(deauth >= 0);
    ASSERT(twin >= 0);
    ASSERT(chain >= 0);
    ASSERT(wpa >= 0);

    /* The chain's finding cites a deauth flood; the flood reaches the
     * stream first. */
    ASSERT_LT(deauth, chain);
    /* The chain taints the rogue half; rule_evil_twin reads the taint
     * through twin_choose_sides() on the next tick, not this one. */
    ASSERT_LT(twin, chain);

    /* The cutover (#216) took five rows out of this table and moved
     * nothing: rule_gnss_jamming, rule_gnss_time_jump,
     * rule_gnss_position_jump, rule_gnss_spoof_suspect and
     * rule_adsb_emergency stood, in that order, between
     * rule_cam_rtsp_unauth and the sensor's own pair, depended on no
     * other rule and had none depend on them (the table's own comment
     * said so). So the three dependencies above are untouched; what is
     * pinned here is that the five are gone and that the rows that
     * were either side of them are now adjacent, in the same order, at
     * the end. sloth-rf's table keeps the five in their order
     * (tests/test_rf_rules.c). */
    ASSERT_EQ(ar_index("rule_gnss_jamming"), -1);
    ASSERT_EQ(ar_index("rule_gnss_time_jump"), -1);
    ASSERT_EQ(ar_index("rule_gnss_position_jump"), -1);
    ASSERT_EQ(ar_index("rule_gnss_spoof_suspect"), -1);
    ASSERT_EQ(ar_index("rule_adsb_emergency"), -1);
    int rtsp = ar_index("rule_cam_rtsp_unauth");
    int uv   = ar_index("rule_sensor_undervolt");
    int down = ar_index("rule_sensor_source_down");
    ASSERT(rtsp >= 0);
    ASSERT_EQ(uv, rtsp + 1);
    ASSERT_EQ(down, uv + 1);
    /* SENSOR_SUPPRESSED (#242 item 4) after the pair, last: it reads
     * no other rule's output. */
    ASSERT_EQ(ar_index("rule_sensor_suppressed"), down + 1);
    ASSERT_EQ(down, g_alert_rule_count - 2);

    /* The posture rule_wpa_downgrade reads is derived before any rule
     * runs. Not a table row, so this reads alerts_update() itself. */
    char *src = ar_slurp("src/alerts/engine.c");
    ASSERT(src != NULL);
    if (!src) return;
    const char *fn   = strstr(src, "void alerts_update(sloth_state_t *s) {");
    ASSERT(fn != NULL);
    if (fn) {
        const char *end  = strstr(fn, "\n}\n");
        const char *post = strstr(fn, "wifi_downgrade_update(s);");
        const char *loop = strstr(fn, "g_alert_rules[i].fn(s, now);");
        ASSERT(end != NULL);
        ASSERT(post != NULL && post < end);
        ASSERT(loop != NULL && loop < end);
        ASSERT(post && loop && post < loop);
    }
    free(src);
}

void run_alert_rules_tests(void) {
    TEST_SUITE("alert rules: the ordered rule table (#118)");
    RUN_TEST(test_rule_scraper_sees_definitions);
    RUN_TEST(test_rule_table_is_complete);
    RUN_TEST(test_rule_order_dependencies);
}
