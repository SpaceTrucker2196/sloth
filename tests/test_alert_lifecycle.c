/* The finding lifecycle (#245): preliminary, confirmed, withdrawn,
 * lapsed, and the per-kind table behind it.
 *
 * Driven through a JSONL file sink and read back, as the #98 lifecycle
 * tests in test_alerts.c are: what the issue changes is what a remote
 * consumer sees. Both clocks are the sloth_clock seam, so windows are
 * crossed exactly and nothing sleeps. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "runner.h"
#include "tmp_dir.h"
#include "sloth.h"
#include "alerts.h"
#include "alert_lifecycle.h"
#include "jsonl.h"
#include "sloth_clock.h"

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t al_mono(void) { return g_mono; }
static time_t   al_wall(void) { return g_wall; }

static char al_path[TEST_TMP_MAX];

static void al_begin(void) {
    jsonl_close();
    alerts_clear();
    alert_lifecycle_reset();
    alert_lc_counts_clear();
    int fd = mkstemp(test_tmp_tpl(al_path, sizeof(al_path), "sloth_lc245_XXXXXX"));
    if (fd >= 0) close(fd);
    unlink(al_path);
    ASSERT(jsonl_open(al_path));
    g_mono = 1000000;
    g_wall = 1700000000;
    sloth_clock_test_set(al_mono, al_wall);
}

static void al_end(void) {
    jsonl_close();
    alerts_clear();
    alert_lifecycle_reset();
    alert_lc_counts_clear();
    unlink(al_path);
    al_path[strlen(al_path) - 6] = '\0';
    strcat(al_path, "XXXXXX");
    sloth_clock_test_set(NULL, NULL);
}

static void al_advance(long secs) {
    g_mono += (uint64_t)secs * 1000u;
    g_wall += (time_t)secs;
}

static const char *al_stream(void) {
    static char buf[131072];
    buf[0] = '\0';
    FILE *fp = fopen(al_path, "r");
    if (!fp) return buf;
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static int al_count(const char *needle) {
    const char *p = al_stream();
    int n = 0;
    for (const char *q = strstr(p, needle); q; q = strstr(q + 1, needle)) n++;
    return n;
}

/* The line of the `nth` (0-based) record of `type`, "" when there is
 * none. */
static const char *al_line(const char *type, int nth) {
    static char out[8192];
    char t[64];
    snprintf(t, sizeof t, "{\"type\":\"%s\",", type);
    out[0] = '\0';
    const char *p = al_stream();
    for (const char *q = strstr(p, t); q; q = strstr(q + 1, t)) {
        if (nth-- > 0) continue;
        const char *e = strchr(q, '\n');
        size_t n = e ? (size_t)(e - q) : strlen(q);
        if (n >= sizeof out) n = sizeof out - 1;
        memcpy(out, q, n);
        out[n] = '\0';
        break;
    }
    return out;
}

static void str_field(const char *line, const char *field, char *out, size_t sz) {
    char f[64];
    snprintf(f, sizeof f, "\"%s\":\"", field);
    out[0] = '\0';
    const char *p = strstr(line, f);
    if (!p) return;
    p += strlen(f);
    size_t i = 0;
    while (p[i] && p[i] != '"' && i + 1 < sz) { out[i] = p[i]; i++; }
    out[i] = '\0';
}

/* Run the engine's end-of-tick passes with no rule table: what a tick
 * does to incidents nothing re-asserted. */
static void al_tick(void) {
    static sloth_state_t s;
    memset(&s, 0, sizeof s);
    alerts_update(&s);
}

#define K  ALERT_TYPE_PMKID_HARVEST
#define KEY "pmkidharvest:02:cc:00:00:00:01"

/* ── The table ─────────────────────────────────────────────── */

static const char *const k_alert_ids[] = {
#define X(id, technique) #id,
#include "sloth_alerts.def"
#undef X
};
static const char *const k_value_ids[] = {
#define X(id, value_s, prelim_s, basis) #id,
#include "sloth_alert_value.def"
#undef X
};

static void test_def_matches_alert_list(void) {
    int na = (int)(sizeof(k_alert_ids) / sizeof(*k_alert_ids));
    int nv = (int)(sizeof(k_value_ids) / sizeof(*k_value_ids));
    ASSERT_EQ(na, (int)ALERT_TYPE_COUNT);
    ASSERT_EQ(nv, na);
    for (int i = 0; i < na && i < nv; i++)
        ASSERT_STR(k_value_ids[i], k_alert_ids[i]);
}

/* Every row off the defaults names an existing research/ document that
 * names the kind; every row at them names none. 300 s is the owner's
 * default for every kind (2026-11-25). */
static void test_every_non_default_row_cites_research(void) {
    for (int t = 0; t < (int)ALERT_TYPE_COUNT; t++) {
        alert_type_t at = (alert_type_t)t;
        const char *basis = alert_lifecycle_basis(at);
        int off = alert_value_period_default_s(at) != 300 ||
                  alert_prelim_window_s(at) != 0;
        if (!off) {
            ASSERT_STR(basis, "");
            continue;
        }
        ASSERT(strncmp(basis, "research/", 9) == 0);
        char path[256];
        snprintf(path, sizeof path, "%s", basis);
        FILE *fp = fopen(path, "r");
        ASSERT(fp != NULL);
        if (!fp) { fprintf(stderr, "  missing basis %s\n", path); continue; }
        static char doc[65536];
        size_t n = fread(doc, 1, sizeof doc - 1, fp);
        doc[n] = '\0';
        fclose(fp);
        ASSERT(strstr(doc, alert_type_name(at)) != NULL);
        ASSERT(strstr(doc, "#245") != NULL);
    }
}

static void test_value_period_flag(void) {
    char err[160];
    alert_lifecycle_reset();
    ASSERT_EQ(alert_value_period_s(K), 300u);
    ASSERT_EQ(alert_value_period_set("PMKID_HARVEST=600", err, sizeof err), 0);
    ASSERT_EQ(alert_value_period_s(K), 600u);
    ASSERT_EQ(alert_value_period_default_s(K), 300u);
    ASSERT_EQ(alert_value_period_set("ALERT_TYPE_EVIL_TWIN=2592000", err, sizeof err), 0);
    ASSERT_EQ(alert_value_period_s(ALERT_TYPE_EVIL_TWIN), 2592000u);
    ASSERT_EQ(alert_value_period_set("EVIL_TWIN=2592001", err, sizeof err), -1);
    ASSERT(strstr(err, "2592000") != NULL);
    ASSERT_EQ(alert_value_period_set("EVIL_TWIN=0", err, sizeof err), -1);
    ASSERT_EQ(alert_value_period_set("EVIL_TWIN=-5", err, sizeof err), -1);
    ASSERT_EQ(alert_value_period_set("EVIL_TWIN=5x", err, sizeof err), -1);
    ASSERT_EQ(alert_value_period_set("EVIL_TWIN=", err, sizeof err), -1);
    ASSERT_EQ(alert_value_period_set("NOT_A_KIND=60", err, sizeof err), -1);
    ASSERT(strstr(err, "unknown alert kind") != NULL);
    ASSERT_EQ(alert_value_period_set("ALERT_TYPE_=60", err, sizeof err), -1);
    ASSERT_EQ(alert_value_period_set("=60", err, sizeof err), -1);
    ASSERT_EQ(alert_value_period_set("EVIL_TWIN", err, sizeof err), -1);
    /* A refused value leaves the one before it. */
    ASSERT_EQ(alert_value_period_s(ALERT_TYPE_EVIL_TWIN), 2592000u);
    alert_lifecycle_reset();
    ASSERT_EQ(alert_value_period_s(ALERT_TYPE_EVIL_TWIN), 300u);
}

/* ── Preliminary, then confirmed ───────────────────────────── */

static void test_preliminary_then_confirmed(void) {
    al_begin();
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one PMKID");
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.preliminary\","), 1);
    ASSERT_EQ(al_count("{\"type\":\"alert.create\","), 0);
    ASSERT_EQ(al_count("{\"type\":\"alert\","), 0);
    const char *p = al_line("alert.preliminary", 0);
    ASSERT(strstr(p, "\"detail\":\"not evaluated: first evidence only - one PMKID\"") != NULL);
    ASSERT(strstr(p, "\"state\":\"preliminary\"") != NULL);
    ASSERT(strstr(p, "\"value_period_s\":300") != NULL);
    ASSERT(strstr(p, "\"prelim_at\":1700000000") != NULL);
    char iid[32];
    str_field(p, "incident_id", iid, sizeof iid);
    ASSERT(iid[0] != '\0');

    /* Re-evaluated as first evidence: nothing more goes out. */
    al_advance(5);
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one PMKID, again");
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.preliminary\","), 1);
    ASSERT_EQ(al_count("{\"type\":\"alert.update\","), 0);

    /* Past the 60 s update floor with moved evidence: still nothing.
     * Seen red with fire_inv()'s preliminary early return removed. */
    al_advance(65);
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "two PMKIDs");
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.update\","), 0);
    ASSERT_EQ(al_count("{\"type\":\"alert.preliminary\","), 1);

    al_advance(30);
    alerts_fire_for_test(K, ALERT_SEV_WARN, KEY, "three", NULL, 0);
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.create\","), 1);
    ASSERT_EQ(al_count("{\"type\":\"alert\","), 1);
    ASSERT_EQ(al_count("{\"type\":\"alert.escalate\","), 0);
    const char *c = al_line("alert.create", 0);
    char ciid[32];
    str_field(c, "incident_id", ciid, sizeof ciid);
    ASSERT_STR(ciid, iid);
    ASSERT(strstr(c, "\"state\":\"confirmed\"") != NULL);
    ASSERT(strstr(c, "\"sev\":1") != NULL);
    ASSERT(strstr(c, "\"detail\":\"three\"") != NULL);
    ASSERT(strstr(c, "\"prelim_at\":1700000000") != NULL);
    ASSERT(strstr(c, "\"confirmed_at\":1700000100") != NULL);
    ASSERT(strstr(al_line("alert", 0), "\"state\":\"confirmed\"") != NULL);

    alert_lc_counts_t n;
    alert_lc_counts(K, &n);
    ASSERT_EQ(n.preliminary, 1u);
    ASSERT_EQ(n.confirmed, 1u);
    ASSERT_EQ(n.withdrawn, 0u);
    ASSERT_EQ(n.median_ms, 100000u);
    const char *lc = al_line("alert_lifecycle", 1);
    ASSERT(strstr(lc, "\"kind\":\"PMKID_HARVEST\"") != NULL);
    ASSERT(strstr(lc, "\"preliminary\":1,\"confirmed\":1,\"withdrawn\":0") != NULL);
    ASSERT(strstr(lc, "\"median_confirm_ms\":100000") != NULL);
    ASSERT(strstr(lc, "\"prelim_window_s\":900") != NULL);
    /* No median before a confirmation. */
    ASSERT(strstr(al_line("alert_lifecycle", 0), "median_confirm_ms") == NULL);
    al_end();
}

/* A confirmed finding is not reopened, nor touched, by first evidence:
 * nothing is emitted, and its detail is the confirming one. */
static void test_preliminary_on_a_confirmed_key_does_nothing(void) {
    al_begin();
    alerts_fire_for_test(K, ALERT_SEV_WARN, KEY, "three", NULL, 0);
    al_tick();
    al_advance(5);
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    static sloth_state_t s;
    memset(&s, 0, sizeof s);
    alerts_update(&s);
    ASSERT_EQ(al_count("{\"type\":\"alert.preliminary\","), 0);
    ASSERT_EQ(al_count("{\"type\":\"alert.update\","), 0);
    ASSERT_EQ(s.alert_count, 1);
    ASSERT_STR(s.alerts[0].detail, "three");
    ASSERT_EQ((int)s.alerts[0].sev, (int)ALERT_SEV_WARN);
    al_end();
}

/* A kind with no window is not on the list: first evidence for it is
 * dropped. */
static void test_unlisted_kind_has_no_preliminary(void) {
    al_begin();
    ASSERT_EQ(alert_prelim_window_s(ALERT_TYPE_PORT_SCAN), 0u);
    alerts_fire_prelim_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW, "ps:x", "x");
    al_tick();
    ASSERT_EQ(al_count("\"type\":\"alert"), 0);
    al_end();
}

/* ── Withdrawn ─────────────────────────────────────────────── */

/* The window's edge, both sides: re-asserted each 100 s so the 300 s
 * resolve never runs, the preliminary stands at 899 s and is withdrawn
 * at 900 s, once, with why. */
static void test_preliminary_withdrawn_at_the_window_edge(void) {
    al_begin();
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    al_tick();
    for (int t = 100; t < 900; t += 100) {
        al_advance(100);
        alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
        al_tick();
    }
    al_advance(99);                       /* 899 s */
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.resolve\","), 0);
    al_advance(1);                        /* 900 s */
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.resolve\","), 1);
    const char *r = al_line("alert.resolve", 0);
    ASSERT(strstr(r, "\"reason\":\"withdrawn\"") != NULL);
    ASSERT(strstr(r, "\"state\":\"withdrawn\"") != NULL);
    ASSERT(strstr(r, "\"withdraw_why\":\"unconfirmed\"") != NULL);
    ASSERT_EQ(al_count("{\"type\":\"alert.create\","), 0);

    /* The same first evidence a tick later does not reopen it... */
    al_advance(1);
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.preliminary\","), 1);
    /* ...until one more window has passed. */
    al_advance(899);
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.preliminary\","), 2);

    alert_lc_counts_t n;
    alert_lc_counts(K, &n);
    ASSERT_EQ(n.preliminary, 2u);
    ASSERT_EQ(n.withdrawn, 1u);
    ASSERT_EQ(n.confirmed, 0u);
    al_end();
}

/* A withdrawn key is not held off a confirmation: the threshold met
 * the tick after is a finding at once, opened confirmed. */
static void test_confirmation_after_withdrawal_opens_confirmed(void) {
    al_begin();
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    for (int t = 0; t < 9; t++) {
        al_advance(100);
        al_tick();
        alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    }
    al_tick();
    ASSERT_EQ(al_count("\"reason\":\"withdrawn\""), 1);
    al_advance(1);
    alerts_fire_for_test(K, ALERT_SEV_WARN, KEY, "three", NULL, 0);
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.create\","), 1);
    const char *c = al_line("alert.create", 0);
    ASSERT(strstr(c, "\"state\":\"confirmed\"") != NULL);
    ASSERT(strstr(c, "prelim_at") == NULL);
    al_end();
}

/* The rule stops reporting the first evidence before the window ends:
 * withdrawn at the 300 s resolve, "evidence_aged", never "expired". */
static void test_preliminary_whose_evidence_ages_out(void) {
    al_begin();
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    al_tick();
    al_advance(ALERT_RESOLVE_AFTER_S - 1);
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.resolve\","), 0);
    al_advance(1);
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.resolve\","), 1);
    ASSERT(strstr(al_line("alert.resolve", 0),
                  "\"withdraw_why\":\"evidence_aged\"") != NULL);
    ASSERT_EQ(al_count("\"reason\":\"expired\""), 0);
    al_end();
}

/* ── Lapsed ────────────────────────────────────────────────── */

/* A standing finding re-asserted unchanged: at its value period it
 * lapses with one record and stays open; nothing more is emitted while
 * nothing new is observed; a new observation confirms it again with one
 * record; the 300 s resolve still closes it as "expired". */
static void test_lapse_and_renewal(void) {
    al_begin();
    alerts_fire_for_test(ALERT_TYPE_MGMT_FUZZ, ALERT_SEV_WARN, "mf:1", "same", NULL, 0);
    al_tick();
    for (int t = 0; t < 2; t++) {
        al_advance(100);
        alerts_fire_for_test(ALERT_TYPE_MGMT_FUZZ, ALERT_SEV_WARN, "mf:1", "same", NULL, 0);
        al_tick();
    }
    al_advance(99);                       /* 299 s since the observation */
    alerts_fire_for_test(ALERT_TYPE_MGMT_FUZZ, ALERT_SEV_WARN, "mf:1", "same", NULL, 0);
    al_tick();
    ASSERT_EQ(al_count("\"reason\":\"lapsed\""), 0);
    al_advance(1);                        /* 300 s */
    alerts_fire_for_test(ALERT_TYPE_MGMT_FUZZ, ALERT_SEV_WARN, "mf:1", "same", NULL, 0);
    al_tick();
    ASSERT_EQ(al_count("\"reason\":\"lapsed\""), 1);
    const char *u = al_line("alert.update", 0);
    ASSERT(strstr(u, "\"state\":\"lapsed\"") != NULL);
    ASSERT_EQ(al_count("{\"type\":\"alert.resolve\","), 0);

    for (int t = 0; t < 5; t++) {
        al_advance(50);
        alerts_fire_for_test(ALERT_TYPE_MGMT_FUZZ, ALERT_SEV_WARN, "mf:1", "same", NULL, 0);
        al_tick();
    }
    ASSERT_EQ(al_count("{\"type\":\"alert.update\","), 1);

    alerts_fire_for_test(ALERT_TYPE_MGMT_FUZZ, ALERT_SEV_WARN, "mf:1", "moved", NULL, 0);
    al_tick();
    ASSERT_EQ(al_count("{\"type\":\"alert.update\","), 2);
    ASSERT(strstr(al_line("alert.update", 1), "\"state\":\"confirmed\"") != NULL);

    al_advance(ALERT_RESOLVE_AFTER_S);
    al_tick();
    ASSERT_EQ(al_count("\"reason\":\"expired\""), 1);
    ASSERT_EQ(al_count("\"reason\":\"lapsed\""), 1);
    al_end();
}

/* --value-period moves the lapse for that kind only. */
static void test_value_period_override_moves_the_lapse(void) {
    al_begin();
    char err[160];
    ASSERT_EQ(alert_value_period_set("MGMT_FUZZ=60", err, sizeof err), 0);
    alerts_fire_for_test(ALERT_TYPE_MGMT_FUZZ, ALERT_SEV_WARN, "mf:1", "same", NULL, 0);
    alerts_fire_for_test(ALERT_TYPE_BEACON_FLOOD, ALERT_SEV_WARN, "bf:1", "same", NULL, 0);
    al_tick();
    ASSERT(strstr(al_line("alert.create", 0), "\"value_period_s\":60") != NULL);
    al_advance(60);
    alerts_fire_for_test(ALERT_TYPE_MGMT_FUZZ, ALERT_SEV_WARN, "mf:1", "same", NULL, 0);
    alerts_fire_for_test(ALERT_TYPE_BEACON_FLOOD, ALERT_SEV_WARN, "bf:1", "same", NULL, 0);
    al_tick();
    ASSERT_EQ(al_count("\"reason\":\"lapsed\""), 1);
    ASSERT(strstr(al_line("alert.update", 0), "\"key\":\"mf:1\"") != NULL);
    al_end();
}

/* ── Off ───────────────────────────────────────────────────── */

/* --no-preliminary: no preliminary, no lapse, and none of the fields;
 * the records are the pre-#245 records. */
static void test_off_emits_nothing_new(void) {
    al_begin();
    alert_lifecycle_set_enabled(0);
    alerts_fire_prelim_for_test(K, ALERT_SEV_LOW, KEY, "one");
    al_tick();
    ASSERT_EQ(al_count("\"type\":\"alert"), 0);
    alerts_fire_for_test(K, ALERT_SEV_WARN, KEY, "three", NULL, 0);
    al_tick();
    for (int t = 0; t < 4; t++) {
        al_advance(100);
        alerts_fire_for_test(K, ALERT_SEV_WARN, KEY, "three", NULL, 0);
        al_tick();
    }
    ASSERT_EQ(al_count("{\"type\":\"alert.create\","), 1);
    ASSERT_EQ(al_count("{\"type\":\"alert.update\","), 0);
    ASSERT_EQ(al_count("\"state\":"), 0);
    ASSERT_EQ(al_count("value_period_s"), 0);
    ASSERT_EQ(al_count("alert_lifecycle"), 0);
    al_end();
}

void run_alert_lifecycle_tests(void) {
    TEST_SUITE("finding lifecycle (#245)");
    RUN_TEST(test_def_matches_alert_list);
    RUN_TEST(test_every_non_default_row_cites_research);
    RUN_TEST(test_value_period_flag);
    RUN_TEST(test_preliminary_then_confirmed);
    RUN_TEST(test_preliminary_on_a_confirmed_key_does_nothing);
    RUN_TEST(test_unlisted_kind_has_no_preliminary);
    RUN_TEST(test_preliminary_withdrawn_at_the_window_edge);
    RUN_TEST(test_confirmation_after_withdrawal_opens_confirmed);
    RUN_TEST(test_preliminary_whose_evidence_ages_out);
    RUN_TEST(test_lapse_and_renewal);
    RUN_TEST(test_value_period_override_moves_the_lapse);
    RUN_TEST(test_off_emits_nothing_new);
}
