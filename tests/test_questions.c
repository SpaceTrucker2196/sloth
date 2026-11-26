#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "questions.h"
#include "exposure.h"
#include "rule_coverage_live.h"

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

void run_questions_tests(void) {
    TEST_SUITE("site questions (#244)");
    RUN_TEST(test_map_matches_alert_list);
    RUN_TEST(test_every_kind_has_a_question_or_a_reason);
    RUN_TEST(test_every_question_has_an_indicator);
    RUN_TEST(test_q5_is_the_exposure_set);
    RUN_TEST(test_named_indicators);
    RUN_TEST(test_default_questions);
    RUN_TEST(test_page_holds_the_tables);
}
