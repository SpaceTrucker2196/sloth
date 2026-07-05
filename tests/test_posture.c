#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "posture.h"

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
    posture_render_md(fp, &s, 1700000000);
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
    posture_render_md(fp, &s, 1700000000);
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
    posture_render_md(fp, &s, 1700000000);
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
    posture_render_md(fp, &s, 1700000000);
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

void run_posture_tests(void) {
    TEST_SUITE("posture report — Markdown");
    RUN_TEST(test_md_header_and_alert_summary);
    RUN_TEST(test_md_lists_techniques);
    RUN_TEST(test_md_lists_cleartext_creds);
    RUN_TEST(test_md_lists_high_risk_devices_only);

    TEST_SUITE("posture report — JSON");
    RUN_TEST(test_json_shape);
}
