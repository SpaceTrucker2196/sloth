#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tmp_dir.h"
#include "runner.h"
#include "sloth.h"
#include "questions.h"
#include "exposure.h"
#include "rule_coverage_live.h"
#include "alert_lifecycle.h"

/*
 * Site questions (#244): the seven defaults
 * (include/sloth_questions.def), the kind-to-question map
 * (include/sloth_question_map.def) against sloth_alerts.def, against
 * the exposure groups and against docs/wiki/site-questions.md § 2.
 * Expectations are written out from the issue's seven questions, not
 * read back from the table.
 */

static const char *const k_alert_ids[] = {
#define X(id, technique) #id,
#include "sloth_alerts.def"
#undef X
};
static const char *const k_map_ids[] = {
#define X(id, qmask, reason) #id,
#include "sloth_question_map.def"
#undef X
};

static int contains(const char *hay, const char *needle) {
    return hay && needle && strstr(hay, needle) != NULL;
}

static char *slurp_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    if (b) {
        size_t got = fread(b, 1, (size_t)n, f);
        b[got] = '\0';
    }
    fclose(f);
    return b;
}

/* ── the tables ────────────────────────────────────────────────────── */

static void test_map_matches_alert_list(void) {
    int na = (int)(sizeof(k_alert_ids) / sizeof(*k_alert_ids));
    int nm = (int)(sizeof(k_map_ids) / sizeof(*k_map_ids));
    ASSERT_EQ(na, (int)ALERT_TYPE_COUNT);
    ASSERT_EQ(nm, na);
    for (int i = 0; i < na && i < nm; i++)
        ASSERT_STR(k_map_ids[i], k_alert_ids[i]);
}

/* Every kind answers a question or says why it answers none; never
 * both, never neither. */
static void test_every_kind_has_a_question_or_a_reason(void) {
    unsigned all = (1u << Q_DEFAULT_COUNT) - 1;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        unsigned m = q_default_mask((alert_type_t)t);
        const char *r = q_default_reason((alert_type_t)t);
        ASSERT(r != NULL);
        if (!r) continue;
        if (m) {
            if (r[0]) fprintf(stderr, "  %s: a question and a reason\n", k_alert_ids[t]);
            ASSERT_STR(r, "");
            ASSERT_EQ(m & ~all, 0u);
        } else {
            if (strlen(r) < 20) fprintf(stderr, "  %s: no question and no reason\n", k_alert_ids[t]);
            ASSERT(strlen(r) >= 20);
        }
    }
    ASSERT_EQ(q_default_mask((alert_type_t)-1), 0u);
    ASSERT_EQ(q_default_mask(ALERT_TYPE_COUNT), 0u);
    ASSERT_STR(q_default_reason(ALERT_TYPE_COUNT), "");
}

static void test_every_question_has_an_indicator(void) {
    for (int i = 0; i < Q_DEFAULT_COUNT; i++) {
        int n = 0;
        for (int t = 0; t < ALERT_TYPE_COUNT; t++)
            if (q_default_mask((alert_type_t)t) & (1u << i)) n++;
        if (!n) fprintf(stderr, "  %s has no indicator\n", q_default_id(i));
        ASSERT(n > 0);
    }
}

/* Q5 is the exposure report's groups, no more and no less: the two
 * tables cannot drift. */
static void test_q5_is_the_exposure_set(void) {
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        int q5  = (q_default_mask((alert_type_t)t) & QM(Q5)) != 0;
        int exp = exp_group_of((alert_type_t)t) != EXP_G_NONE;
        if (q5 != exp) fprintf(stderr, "  %s: Q5 %d, exposure %d\n", k_alert_ids[t], q5, exp);
        ASSERT_EQ(q5, exp);
    }
}

/* The issue's examples, each in its question. */
static void test_named_indicators(void) {
    static const struct { alert_type_t t; unsigned q; } k[] = {
        { ALERT_TYPE_EVIL_TWIN,          QM(Q1) },
        { ALERT_TYPE_KARMA_AP,           QM(Q1) },
        { ALERT_TYPE_ROGUE_RADIUS,       QM(Q1) },
        { ALERT_TYPE_ARP_SPOOF,          QM(Q1) },
        { ALERT_TYPE_ROGUE_DHCP,         QM(Q1) },
        { ALERT_TYPE_ROGUE_RA,           QM(Q1) },
        { ALERT_TYPE_UNKNOWN_DEVICE,     QM(Q2) },
        { ALERT_TYPE_PMKID_HARVEST,      QM(Q3) },
        { ALERT_TYPE_HANDSHAKE_HARVEST,  QM(Q3) },
        { ALERT_TYPE_CLEARTEXT_CRED,     QM(Q3) },
        { ALERT_TYPE_MY_NETWORK_RECON,   QM(Q4) },
        { ALERT_TYPE_PROBE_FLOOD,        QM(Q4) },
        { ALERT_TYPE_PORT_SCAN,          QM(Q4) },
        { ALERT_TYPE_DEAUTH_FLOOD,       QM(Q6) },
        { ALERT_TYPE_RF_DEGRADED,        QM(Q6) },
        { ALERT_TYPE_GNSS_JAMMING,       QM(Q6) },
        { ALERT_TYPE_NO_MONITOR_MODE,    QM(Q7) },
        { ALERT_TYPE_SENSOR_SOURCE_DOWN, QM(Q7) },
        { ALERT_TYPE_SENSOR_SUPPRESSED,  QM(Q7) },
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(*k); i++)
        ASSERT(q_default_mask(k[i].t) & k[i].q);
    /* Q7 is the sensor's own state and nothing else. */
    ASSERT_EQ(q_default_mask(ALERT_TYPE_EVIL_TWIN) & QM(Q7), 0u);
    ASSERT_EQ(q_default_mask(ALERT_TYPE_BT_OWN_TRANSMIT), 0u);
}

static void test_default_questions(void) {
    ASSERT_EQ((int)Q_DEFAULT_COUNT, 7);
    static const char *const ids[7] = { "Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7" };
    for (int i = 0; i < Q_DEFAULT_COUNT; i++) {
        ASSERT_STR(q_default_id(i), ids[i]);
        ASSERT(q_default_priority(i) >= 1 && q_default_priority(i) <= Q_PRIORITY_MAX);
        const char *t = q_default_text(i);
        /* One question (FM 2-0 1-34): one '?', at the end. */
        ASSERT(strlen(t) > 10 && strlen(t) < Q_TEXT_LEN);
        ASSERT(strchr(t, '?') == t + strlen(t) - 1);
        ASSERT(strlen(q_default_decision(i)) > 10 && strlen(q_default_decision(i)) < Q_TEXT_LEN);
    }
    ASSERT_STR(q_default_text(1), "Is a device that I do not know on my network?");
    ASSERT_STR(q_default_id(Q_DEFAULT_COUNT), "");

    q_set_t set;
    q_set_defaults(&set);
    ASSERT_EQ(set.n, Q_DEFAULT_COUNT);
    for (int i = 0; i < set.n; i++) {
        ASSERT_STR(set.q[i].id, ids[i]);
        int n = 0;
        for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
            ASSERT_EQ((int)set.q[i].kind[t], (q_default_mask((alert_type_t)t) >> i) & 1);
            n += set.q[i].kind[t];
        }
        ASSERT_EQ(set.q[i].nkinds, n);
    }
    ASSERT(set.q[0].kind[ALERT_TYPE_EVIL_TWIN]);
    ASSERT(!set.q[0].kind[ALERT_TYPE_DEAUTH_FLOOD]);
}

/* ── the page ──────────────────────────────────────────────────────── */

/* docs/wiki/site-questions.md § 2 has one row per kind: the kind, its
 * questions joined with ", " ("—" for none) and its reason, verbatim.
 * § 1 has each default question's row. */
static void test_page_holds_the_tables(void) {
    char *page = slurp_file("docs/wiki/site-questions.md");
    ASSERT(page != NULL);
    if (!page) return;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        unsigned m = q_default_mask((alert_type_t)t);
        char qs[64] = "";
        size_t off = 0;
        for (int i = 0; i < Q_DEFAULT_COUNT; i++) {
            if (!(m & (1u << i))) continue;
            off += (size_t)snprintf(qs + off, sizeof(qs) - off, "%s%s",
                                    off ? ", " : "", q_default_id(i));
        }
        char row[512];
        snprintf(row, sizeof(row), "\n| `%s` | %s | %s |\n", cov_kind_name((alert_type_t)t),
                 m ? qs : "\xe2\x80\x94", q_default_reason((alert_type_t)t));
        if (!contains(page, row)) fprintf(stderr, "  page lacks the row%s", row);
        ASSERT(contains(page, row));
    }
    for (int i = 0; i < Q_DEFAULT_COUNT; i++) {
        char row[512];
        snprintf(row, sizeof(row), "\n| %s | %d | %s | %s |\n", q_default_id(i),
                 q_default_priority(i), q_default_text(i), q_default_decision(i));
        if (!contains(page, row)) fprintf(stderr, "  page lacks the row%s", row);
        ASSERT(contains(page, row));
    }
    free(page);
}


/* ── status ────────────────────────────────────────────────────────── */

static alert_t g_al[16];

static alert_t *al(int i, alert_type_t t, const char *id) {
    alert_t *a = &g_al[i];
    memset(a, 0, sizeof(*a));
    a->type = t;
    a->sev = ALERT_SEV_WARN;
    snprintf(a->incident_id, sizeof(a->incident_id), "%s", id);
    return a;
}

/* The sensor as the issue's second replay has it: no monitor radio and
 * no IP capture; the status sampler runs. */
static void env_no_radio(cov_env_t *e) {
    memset(e, 0, sizeof(*e));
    e->input[COV_IN_SYS] = COV_AV_UP;
}

/* A radio, the IP capture and the host tables, every designation. */
static void env_site(cov_env_t *e, int radios, int channels) {
    memset(e, 0, sizeof(*e));
    e->input[COV_IN_SYS] = COV_AV_UP;
    e->input[COV_IN_DOT11] = COV_AV_UP;
    e->input[COV_IN_IP] = COV_AV_UP;
    e->input[COV_IN_HOST] = COV_AV_UP;
    e->bands = COV_B_ALL;
    e->radios = radios;
    e->channels = channels;
    e->hopping = 1;
    e->config = COV_N_ALL;
}

static void test_status_names(void) {
    ASSERT_STR(q_status_name(Q_ST_FINDING), "finding");
    ASSERT_STR(q_status_name(Q_ST_NO_FINDING), "no_finding");
    ASSERT_STR(q_status_name(Q_ST_NO_FINDING_PARTLY), "no_finding_partly");
    ASSERT_STR(q_status_name(Q_ST_NOT_OBSERVABLE), "not_observable");
    ASSERT_STR(q_status_name(Q_ST_NOT_ASSESSED), "not_assessed");
    ASSERT_STR(q_status_name(Q_ST_COUNT), "");
}

/* The issue's acceptance, as the owner ruled it (2026-11-25): with no
 * monitor radio Q1 is not observable, and a replayed evil twin is a
 * finding beside coverage that was never assessed. */
static void test_acceptance(void) {
    q_set_t set;
    q_set_defaults(&set);
    const q_question_t *q1 = &set.q[Q_ID_Q1];
    cov_env_t e;
    env_no_radio(&e);
    q_cov_t c;
    q_cov_from_env(&c, COV_DAEMON_WIFI, &e);
    q_result_t r;
    ASSERT(q_derive(q1, NULL, 0, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_NOT_OBSERVABLE);
    ASSERT_EQ((int)r.why, (int)COV_R_NO_SOURCE);
    ASSERT_EQ(r.blind, r.kinds);
    ASSERT_EQ(r.n_alerts, 0);

    /* A --replay run: coverage is not assessed (cov_live declines). */
    q_cov_from_env(&c, COV_DAEMON_WIFI, NULL);
    ASSERT(q_derive(q1, NULL, 0, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_NOT_ASSESSED);
    ASSERT_EQ(r.observable + r.partly + r.blind, 0);
    al(0, ALERT_TYPE_EVIL_TWIN, "00000000000000e1");
    ASSERT(q_derive(q1, g_al, 1, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_FINDING);
    ASSERT_EQ(r.n_alerts, 1);
    ASSERT_EQ(r.nids, 1);
    ASSERT_STR(r.ids[0], "00000000000000e1");
    char k[256];
    q_found_str(r.found, k, sizeof(k));
    ASSERT_STR(k, "EVIL_TWIN");
    /* The same finding with no radio: still a finding. */
    q_cov_from_env(&c, COV_DAEMON_WIFI, &e);
    ASSERT(q_derive(q1, g_al, 1, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_FINDING);
    /* Another question's kind is not Q1's finding. */
    al(0, ALERT_TYPE_DEAUTH_FLOOD, "00000000000000d1");
    ASSERT(q_derive(q1, g_al, 1, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_NOT_OBSERVABLE);
}

static void test_partly_and_observable(void) {
    q_set_t set;
    q_set_defaults(&set);
    const q_question_t *q1 = &set.q[Q_ID_Q1];
    cov_env_t e;
    q_cov_t c;
    q_result_t r;
    /* One radio hopping 3 channels: EVIL_TWIN (a beacon's content) is
     * read in one visit, EVIL_TWIN_PROXIMITY (a rate) is not. */
    env_site(&e, 1, 3);
    q_cov_from_env(&c, COV_DAEMON_WIFI, &e);
    ASSERT(q_derive(q1, NULL, 0, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_NO_FINDING_PARTLY);
    ASSERT_EQ((int)r.why, (int)COV_R_HOP);
    ASSERT_EQ(r.blind, 0);
    ASSERT(r.partly > 0 && r.observable > 0);
    ASSERT_EQ(c.st[ALERT_TYPE_EVIL_TWIN], (uint8_t)COV_OBSERVABLE);
    /* One radio per channel: nothing is left. */
    env_site(&e, 3, 3);
    q_cov_from_env(&c, COV_DAEMON_WIFI, &e);
    ASSERT(q_derive(q1, NULL, 0, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_NO_FINDING);
    ASSERT_EQ(r.observable, r.kinds);
    ASSERT_EQ((int)r.why, (int)COV_R_NONE);
    /* The IP capture gone: its kinds blind, the rest observable, and
     * the blind reason is the one named. */
    e.input[COV_IN_IP] = COV_AV_NONE;
    e.hopping = 1;
    e.radios = 1;
    q_cov_from_env(&c, COV_DAEMON_WIFI, &e);
    ASSERT(q_derive(q1, NULL, 0, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_NO_FINDING_PARTLY);
    ASSERT_EQ((int)r.why, (int)COV_R_NO_SOURCE);
    ASSERT(r.blind > 0 && r.blind < r.kinds);
}

/* A withdrawn or resolved incident is not a finding. Seen red with
 * q_alert_open() answering 1 for both. */
static void test_closed_findings_do_not_count(void) {
    q_set_t set;
    q_set_defaults(&set);
    cov_env_t e;
    env_site(&e, 3, 3);
    q_cov_t c;
    q_cov_from_env(&c, COV_DAEMON_WIFI, &e);
    q_result_t r;
    al(0, ALERT_TYPE_EVIL_TWIN, "0000000000000001")->state = ALERT_STATE_WITHDRAWN;
    al(1, ALERT_TYPE_KARMA_AP, "0000000000000002")->resolved = 1;
    ASSERT(q_derive(&set.q[Q_ID_Q1], g_al, 2, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_NO_FINDING);
    ASSERT_EQ(r.n_alerts, 0);
    al(1, ALERT_TYPE_KARMA_AP, "0000000000000002")->state = ALERT_STATE_PRELIMINARY;
    ASSERT(q_derive(&set.q[Q_ID_Q1], g_al, 2, &c, &r));
    ASSERT_EQ((int)r.st, (int)Q_ST_FINDING);
    ASSERT_STR(r.ids[0], "0000000000000002");
}

/* Every finding counts; the ids stop at Q_IDS_MAX, newest first. */
static void test_ids_are_bounded(void) {
    q_set_t set;
    q_set_defaults(&set);
    q_cov_t c;
    q_cov_from_env(&c, COV_DAEMON_WIFI, NULL);
    for (int i = 0; i < 12; i++) {
        char id[ALERT_INCIDENT_ID_LEN];
        snprintf(id, sizeof(id), "%016x", i + 1);
        al(i, i % 2 ? ALERT_TYPE_PMKID_HARVEST : ALERT_TYPE_HANDSHAKE_HARVEST, id);
    }
    q_result_t r;
    ASSERT(q_derive(&set.q[Q_ID_Q3], g_al, 12, &c, &r));
    ASSERT_EQ(r.n_alerts, 12);
    ASSERT_EQ(r.nids, Q_IDS_MAX);
    ASSERT_STR(r.ids[0], "0000000000000001");
    ASSERT_STR(r.ids[Q_IDS_MAX - 1], "0000000000000008");
    char k[256];
    q_found_str(r.found, k, sizeof(k));
    ASSERT_STR(k, "PMKID_HARVEST,HANDSHAKE_HARVEST");
}

/* Each daemon answers for the kinds it raises: sloth-rf has Q6 (the
 * GNSS kinds) and Q7 (SENSOR_SOURCE_DOWN) and no answer to Q1. A GNSS
 * finding in sloth-wifi's snapshot cannot happen; if it did it would
 * not be sloth-wifi's answer. */
static void test_per_daemon(void) {
    q_set_t set;
    q_set_defaults(&set);
    q_cov_t c;
    q_result_t r;
    q_cov_from_env(&c, COV_DAEMON_RF, NULL);
    ASSERT_EQ(q_derive(&set.q[Q_ID_Q1], NULL, 0, &c, &r), 0);
    ASSERT_EQ(r.kinds, 0);
    ASSERT(q_derive(&set.q[Q_ID_Q6], NULL, 0, &c, &r));
    ASSERT_EQ(r.kinds, 4);
    ASSERT(q_derive(&set.q[Q_ID_Q7], NULL, 0, &c, &r));
    ASSERT_EQ(r.kinds, 1);
    q_cov_from_env(&c, COV_DAEMON_WIFI, NULL);
    al(0, ALERT_TYPE_GNSS_JAMMING, "00000000000000aa");
    ASSERT(q_derive(&set.q[Q_ID_Q6], g_al, 1, &c, &r));
    ASSERT_EQ(r.n_alerts, 0);
    for (int i = 0; i < Q_DEFAULT_COUNT; i++)
        ASSERT(q_derive(&set.q[i], NULL, 0, &c, &r));
}


/* ── the operator's file ───────────────────────────────────────────── */

static const char *k_good =
    "# the operator's own questions\n"
    "\n"
    "  TWIN | 1 | Is someone copying HomeNet? | Tell the household. | EVIL_TWIN, KARMA_AP\n"
    "harvest|2|Is anyone after the key?|Rotate the key.|PMKID_HARVEST,HANDSHAKE_HARVEST,PMKID_HARVEST\r\n"
    "eyes|1|Can the sensor see?|Fix it.|NO_MONITOR_MODE";

static void test_parse_good(void) {
    q_set_t set;
    char err[256];
    ASSERT_EQ(q_set_parse(&set, k_good, err, sizeof(err)), 0);
    ASSERT_STR(err, "");
    ASSERT_EQ(set.n, 3);
    ASSERT_STR(set.q[0].id, "TWIN");
    ASSERT_EQ(set.q[0].priority, 1);
    ASSERT_STR(set.q[0].text, "Is someone copying HomeNet?");
    ASSERT_STR(set.q[0].decision, "Tell the household.");
    ASSERT_EQ(set.q[0].nkinds, 2);
    ASSERT(set.q[0].kind[ALERT_TYPE_EVIL_TWIN] && set.q[0].kind[ALERT_TYPE_KARMA_AP]);
    /* A kind named twice counts once; a CRLF line reads as LF. */
    ASSERT_EQ(set.q[1].nkinds, 2);
    ASSERT_EQ(set.q[1].priority, 2);
    ASSERT_STR(set.q[1].decision, "Rotate the key.");
    ASSERT_STR(set.q[2].id, "eyes");
    ASSERT_EQ(set.q[2].nkinds, 1);
    ASSERT_EQ(q_kind_by_name("SENSOR_SUPPRESSED"), (int)ALERT_TYPE_SENSOR_SUPPRESSED);
    ASSERT_EQ(q_kind_by_name("ALERT_TYPE_EVIL_TWIN"), -1);
    ASSERT_EQ(q_kind_by_name("evil_twin"), -1);
}

/* Each refusal names its line, and a refused file leaves the set as it
 * was (the defaults stay). */
static void test_parse_refusals(void) {
    static const struct { const char *text; const char *err; } k[] = {
        { "a|1|Q?|D.|EVIL_TWIN\nb|1|Q?|D.|EVIL_TWIN,NOT_A_KIND\n",
          "line 2: unknown alert kind \"NOT_A_KIND\"" },
        { "a|1|Q?|D.|EVIL_TWIN\n# c\na|2|R?|E.|KARMA_AP\n", "line 3: duplicate id \"a\"" },
        { "a|0|Q?|D.|EVIL_TWIN\n", "line 1: the priority \"0\" is not 1 to 9" },
        { "a|10|Q?|D.|EVIL_TWIN\n", "line 1: the priority \"10\" is not 1 to 9" },
        { "a|1x|Q?|D.|EVIL_TWIN\n", "line 1: the priority \"1x\" is not 1 to 9" },
        { "a|1|Q?|EVIL_TWIN\n", "line 1: want id|priority|question|decision|KIND,KIND" },
        { "a|1|Q?|D.|EVIL_TWIN|x\n", "line 1: more than five fields" },
        { "a|1|Q?|D.| , \n", "line 1: no alert kind" },
        { "a b|1|Q?|D.|EVIL_TWIN\n",
          "line 1: the id \"a b\" may hold only letters, digits, '_' and '-'" },
        { "0123456789abcdef|1|Q?|D.|EVIL_TWIN\n", "line 1: the id must be 1 to 15 characters" },
        { "a|1| |D.|EVIL_TWIN\n", "line 1: the question must be 1 to 159 bytes" },
        { "a|1|Q?||EVIL_TWIN\n", "line 1: the decision must be 1 to 159 bytes" },
        { "# nothing\n\n", "no questions" },
        { "", "no questions" },
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(*k); i++) {
        q_set_t set;
        q_set_defaults(&set);
        char err[256];
        ASSERT_EQ(q_set_parse(&set, k[i].text, err, sizeof(err)), -1);
        if (strcmp(err, k[i].err) != 0) fprintf(stderr, "  case %zu: \"%s\"\n", i, err);
        ASSERT_STR(err, k[i].err);
        ASSERT_EQ(set.n, Q_DEFAULT_COUNT);
        ASSERT_STR(set.q[0].id, "Q1");
    }
    /* Thirty-two questions are allowed, the thirty-third is not. */
    static char big[64 * 40];
    size_t off = 0;
    for (int i = 0; i < 33; i++)
        off += (size_t)snprintf(big + off, sizeof(big) - off, "q%d|1|Q?|D.|EVIL_TWIN\n", i);
    q_set_t set;
    char err[256];
    ASSERT_EQ(q_set_parse(&set, big, err, sizeof(err)), -1);
    ASSERT_STR(err, "line 33: more than 32 questions");
    big[strlen(big) - strlen("q32|1|Q?|D.|EVIL_TWIN\n")] = '\0';
    ASSERT_EQ(q_set_parse(&set, big, err, sizeof(err)), 0);
    ASSERT_EQ(set.n, Q_MAX);
}

static void test_load_file(void) {
    char path[512];
    int fd = mkstemp(test_tmp_tpl(path, sizeof(path), "sloth_q_XXXXXX"));
    ASSERT(fd >= 0);
    if (fd < 0) return;
    ASSERT_EQ((size_t)write(fd, k_good, strlen(k_good)), strlen(k_good));
    close(fd);
    q_set_t set;
    char err[256];
    ASSERT_EQ(q_set_load(&set, path, err, sizeof(err)), 0);
    ASSERT_EQ(set.n, 3);
    /* A file with a NUL is not text. */
    FILE *f = fopen(path, "wb");
    ASSERT(f != NULL);
    if (f) { fwrite("a|1|Q?|D.|EVIL_TWIN\n\0", 1, 21, f); fclose(f); }
    q_set_defaults(&set);
    ASSERT_EQ(q_set_load(&set, path, err, sizeof(err)), -1);
    ASSERT_STR(err, "not a text file");
    ASSERT_EQ(set.n, Q_DEFAULT_COUNT);
    unlink(path);
    ASSERT_EQ(q_set_load(&set, path, err, sizeof(err)), -1);
    ASSERT(contains(err, "cannot open: "));
}

void run_questions_tests(void) {
    TEST_SUITE("site questions (#244)");
    RUN_TEST(test_map_matches_alert_list);
    RUN_TEST(test_every_kind_has_a_question_or_a_reason);
    RUN_TEST(test_every_question_has_an_indicator);
    RUN_TEST(test_q5_is_the_exposure_set);
    RUN_TEST(test_named_indicators);
    RUN_TEST(test_default_questions);
    RUN_TEST(test_page_holds_the_tables);
    RUN_TEST(test_status_names);
    RUN_TEST(test_acceptance);
    RUN_TEST(test_partly_and_observable);
    RUN_TEST(test_closed_findings_do_not_count);
    RUN_TEST(test_ids_are_bounded);
    RUN_TEST(test_per_daemon);
    RUN_TEST(test_parse_good);
    RUN_TEST(test_parse_refusals);
    RUN_TEST(test_load_file);
}
