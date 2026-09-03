#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "posture.h"
#include "query.h"

/* Roadmap #16 phase 5 — posture report export.
 *
 * These are golden-shape tests, not byte-for-byte comparisons: the
 * timestamps in the output vary per run, so we assert *structural*
 * invariants (headings present, alert counts correct, ATT&CK table
 * present when techniques are tagged, cleartext section present when
 * a cred was observed). */

static int contains(const char *hay, const char *needle) {
    return strstr(hay, needle) != NULL;
}

static void seed_alert(sloth_state_t *s, alert_type_t type, alert_sev_t sev,
                       const char *title, const char *tech, const char *match_ip)
{
    if (s->alert_count >= MAX_ALERTS) return;
    alert_t *a = &s->alerts[s->alert_count++];
    memset(a, 0, sizeof(*a));
    a->type = type;
    a->sev  = sev;
    a->count = 1;
    snprintf(a->title,     sizeof(a->title),     "%s", title);
    snprintf(a->technique, sizeof(a->technique), "%s", tech);
    if (match_ip)
        snprintf(a->match_ip, sizeof(a->match_ip), "%s", match_ip);
    a->first_seen = a->last_seen = 1700000000;
}

static void test_md_header_and_alert_summary(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW,
               "PORT_SCAN", "T1046", "10.0.0.99");
    seed_alert(&s, ALERT_TYPE_SSH_BRUTE_FORCE, ALERT_SEV_WARN,
               "SSH_BRUTE_FORCE", "T1110.001", "203.0.113.5");

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT(fp);
    posture_render_md(fp, &s, 1700000000, NULL);
    fclose(fp);

    ASSERT(contains(buf, "# sloth posture report"));
    ASSERT(contains(buf, "## Alert summary"));
    ASSERT(contains(buf, "| CRIT | 0 |"));
    ASSERT(contains(buf, "| WARN | 1 |"));
    ASSERT(contains(buf, "| LOW  | 1 |"));
}

static void test_md_lists_techniques(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_alert(&s, ALERT_TYPE_SSH_BRUTE_FORCE, ALERT_SEV_WARN,
               "SSH_BRUTE", "T1110.001", "1.2.3.4");
    seed_alert(&s, ALERT_TYPE_RDP_BRUTE_FORCE, ALERT_SEV_WARN,
               "RDP_BRUTE", "T1110.001", "1.2.3.5");

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    posture_render_md(fp, &s, 1700000000, NULL);
    fclose(fp);

    ASSERT(contains(buf, "MITRE ATT&CK"));
    /* Two brute rules, same technique → one row, count 2. */
    ASSERT(contains(buf, "`T1110.001` | 2"));
}

static void test_md_lists_cleartext_creds(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_cred_t *c = &s.cleartext_creds[s.cleartext_cred_count++];
    snprintf(c->src, sizeof(c->src), "10.0.0.5");
    snprintf(c->dst, sizeof(c->dst), "192.0.2.10");
    c->dst_port = 80;
    snprintf(c->protocol, sizeof(c->protocol), "HTTP-Basic");
    snprintf(c->username, sizeof(c->username), "alice");
    c->password_observed = 1;

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    posture_render_md(fp, &s, 1700000000, NULL);
    fclose(fp);

    ASSERT(contains(buf, "Cleartext credential"));
    ASSERT(contains(buf, "alice"));
    /* Guardrail note visible in the report — the reader should see
     * explicitly that no password value is stored. */
    ASSERT(contains(buf, "Passwords are never stored"));
}

static void test_md_lists_high_risk_devices_only(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* Two devices: one LOW (should be omitted from High-risk section),
     * one CRIT (should appear). */
    device_t *d1 = &s.devices[s.device_count++];
    memset(d1, 0, sizeof(*d1));
    snprintf(d1->hostname, sizeof(d1->hostname), "printer.local");
    snprintf(d1->ip,       sizeof(d1->ip),       "10.0.0.20");
    d1->risk_level = DEV_RISK_LOW;

    device_t *d2 = &s.devices[s.device_count++];
    memset(d2, 0, sizeof(*d2));
    snprintf(d2->hostname, sizeof(d2->hostname), "unknown-host");
    snprintf(d2->ip,       sizeof(d2->ip),       "10.0.0.99");
    d2->risk_level = DEV_RISK_CRIT;

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    posture_render_md(fp, &s, 1700000000, NULL);
    fclose(fp);

    ASSERT(contains(buf, "High-risk devices"));
    ASSERT(contains(buf, "unknown-host"));
    ASSERT(contains(buf, "**CRIT**"));
    /* LOW device must not appear in the High-risk section. */
    ASSERT(!contains(buf, "printer.local"));
}

static void test_json_shape(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW,
               "PORT_SCAN", "T1046", "10.0.0.99");

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    posture_render_json(fp, &s, 1700000000);
    fclose(fp);

    ASSERT(contains(buf, "\"type\": \"posture_report\""));
    ASSERT(contains(buf, "\"crit\": 0"));
    ASSERT(contains(buf, "\"low\":  1"));
    ASSERT(contains(buf, "\"techniques\":"));
    ASSERT(contains(buf, "T1046"));
}


/* ── References block from the research corpus (#73) ──────── */

/* Distinct from seed_alert() above: that one takes a severity and a
 * detail, this one takes the title, because these tests are about the
 * type-to-name mapping and the title is the thing that must NOT be
 * used for it. */
static void seed_titled_alert(sloth_state_t *s, alert_type_t t,
                              const char *title) {
    alert_t *a = &s->alerts[s->alert_count++];
    memset(a, 0, sizeof(*a));
    a->type = t;
    a->sev  = ALERT_SEV_WARN;
    snprintf(a->title,  sizeof(a->title),  "%s", title);
    snprintf(a->detail, sizeof(a->detail), "seeded");
    a->first_seen = a->last_seen = 1700000000;
    a->count = 1;
}

static char *render_with(sloth_state_t *s, struct rq_handle *h, char *buf,
                         size_t cap) {
    FILE *fp = tmpfile();
    if (!fp) return NULL;
    posture_render_md(fp, s, 1700000000, h);
    fflush(fp);
    rewind(fp);
    size_t n = fread(buf, 1, cap - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static void test_no_corpus_means_no_references_block(void) {
    /* The additive contract: without --with-research the report is
     * exactly what it was before #73. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    static char buf[65536];
    ASSERT(render_with(&s, NULL, buf, sizeof(buf)) != NULL);
    ASSERT(strstr(buf, "## References") == NULL);
}

static void test_references_block_cites_the_alert(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    static char buf[65536];
    ASSERT(render_with(&s, h, buf, sizeof(buf)) != NULL);
    ASSERT(strstr(buf, "## References") != NULL);
    ASSERT(strstr(buf, "standards.ieee.org") != NULL);
    ASSERT(strstr(buf, "retrieved 2026-08-31") != NULL);
    rq_close(h);
}

static void test_lookup_uses_the_enum_name_not_the_title(void) {
    /* The bug this test exists for: alert titles are display strings
     * abbreviated to fit ALERT_TITLE_LEN, so BLOCKACK_ATK is the title
     * for ALERT_TYPE_BLOCKACK_ATTACK. Building the lookup key as
     * "ALERT_TYPE_" + title silently finds nothing for every alert
     * whose title was shortened — and a References block that is
     * quietly incomplete looks exactly like one that is complete.
     *
     * Seeded with a deliberately wrong title to prove the lookup does
     * not depend on it. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_WPA_DOWNGRADE, "NOT_THE_ENUM_NAME");
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    static char buf[65536];
    render_with(&s, h, buf, sizeof(buf));
    ASSERT(strstr(buf, "## References") != NULL);
    ASSERT(strstr(buf, "kb.cert.org") != NULL);
    rq_close(h);
}

static void test_uncited_alert_produces_no_block(void) {
    /* 11 of 47 kinds are cited at slice 1. An alert with no documents
     * must not emit an empty References heading. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_PORT_SCAN, "PORT_SCAN");
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    static char buf[65536];
    render_with(&s, h, buf, sizeof(buf));
    ASSERT(strstr(buf, "## References") == NULL);
    rq_close(h);
}

static void test_repeated_alerts_cited_once(void) {
    /* An alert firing against three BSSIDs is three rows and one set of
     * sources. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    static char buf[65536];
    render_with(&s, h, buf, sizeof(buf));
    const char *p = strstr(buf, "standards.ieee.org");
    ASSERT(p != NULL);
    ASSERT(strstr(p + 1, "standards.ieee.org") == NULL);
    rq_close(h);
}

static void test_report_is_reproducible(void) {
    /* Two renders of the same state and corpus must be identical —
     * that is why rq_for_alert orders by retrieved and path rather than
     * by BM25, which shifts as the corpus grows. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_WPA_DOWNGRADE, "WPA_DOWNGRADE");
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    static char a[65536], b[65536];
    render_with(&s, h, a, sizeof(a));
    render_with(&s, h, b, sizeof(b));
    ASSERT_EQ(strcmp(a, b), 0);
    rq_close(h);
}

static void test_every_alert_type_has_a_name(void) {
    /* alert_type_name() is hand-maintained beside the enum. A new alert
     * that forgets an entry loses its citations silently, so the guard
     * is here rather than in a comment. */
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        const char *n = alert_type_name((alert_type_t)t);
        ASSERT(n != NULL);
        ASSERT(n[0] != '\0');
        ASSERT(strncmp(n, "ALERT_TYPE_", 11) == 0);
    }
    ASSERT_STR(alert_type_name(ALERT_TYPE_COUNT), "");
}

void run_posture_tests(void) {
    TEST_SUITE("posture report — Markdown");
    RUN_TEST(test_md_header_and_alert_summary);
    RUN_TEST(test_md_lists_techniques);
    RUN_TEST(test_md_lists_cleartext_creds);
    RUN_TEST(test_md_lists_high_risk_devices_only);

    TEST_SUITE("posture report — JSON");
    RUN_TEST(test_json_shape);
    TEST_SUITE("posture: research References block (#73)");
    RUN_TEST(test_no_corpus_means_no_references_block);
    RUN_TEST(test_references_block_cites_the_alert);
    RUN_TEST(test_lookup_uses_the_enum_name_not_the_title);
    RUN_TEST(test_uncited_alert_produces_no_block);
    RUN_TEST(test_repeated_alerts_cited_once);
    RUN_TEST(test_report_is_reproducible);
    RUN_TEST(test_every_alert_type_has_a_name);
}
