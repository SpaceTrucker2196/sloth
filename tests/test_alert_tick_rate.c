#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "sloth_clock.h"
#include "pm_forge.h"
#include "fragattack.h"
#include "beacon_snoop.h"
#include "rsn_ie.h"

/*
 * Rules whose count followed the tick rate (#173).
 *
 * The engine counts an observation when an evaluation's rendered detail
 * differs from the one it last emitted (src/alerts/engine.c, fire_inv),
 * and refreshes that stored copy only on an emitted event. So a detail
 * that moves without the evidence moving - a seconds counter, a source
 * that alternates between ring slots, a frame total - makes observations
 * follow evaluations, several a second, for as long as the condition
 * stands. The reference host showed it as fire counts of 1e7 to 3e9 on a
 * handful of keys (docs/wiki/alert-assessments/).
 *
 * Each test drives one rule through a standing condition, one alert pass
 * a simulated second apart on an injected clock (the 60 s update floor
 * needs time to pass, which a pinned clock never gives it), and holds it
 * to the documented observation count. Then a real change in what is
 * observed, and observations move by one.
 *
 * Each absence assertion was seen red under the mutation named at the
 * test, with the figure it produced: the rule's old detail or old
 * per-entry fire restored, or - where the old detail happened to hold
 * still in that test's setup - the newest evidence's age appended to the
 * detail, the shape of WPA_DOWNGRADE's old "(observed Ns)".
 */

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t tr_mono(void) { return g_mono; }
static time_t   tr_wall(void) { return g_wall; }

static sloth_state_t g_s;

static sloth_state_t *tr_begin(void) {
    g_mono = 9000000ull;
    g_wall = (time_t)1760000000;
    sloth_clock_test_set(tr_mono, tr_wall);
    alerts_clear();
    memset(&g_s, 0, sizeof(g_s));
    return &g_s;
}

static void tr_end(void) {
    alerts_clear();
    sloth_clock_test_set(NULL, NULL);
}

static void tr_advance(long secs) {
    g_mono += (uint64_t)secs * 1000ull;
    g_wall += (time_t)secs;
}

/* `n` alert passes, one a second. */
static void tr_ticks(sloth_state_t *s, int n) {
    for (int i = 0; i < n; i++) {
        alerts_update(s);
        tr_advance(1);
    }
}

static int tr_find(const sloth_state_t *s, alert_type_t type) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type && !s->alerts[i].resolved) return i;
    return -1;
}

static int tr_count_open(const sloth_state_t *s, alert_type_t type) {
    int n = 0;
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type && !s->alerts[i].resolved) n++;
    return n;
}

/* ── ATTACK_TOOL_UA: one fire per (src, tool), not per ring entry ── */

static void add_http(sloth_state_t *s, const char *src, const char *host,
                     const char *ua) {
    if (s->http_log_count >= MAX_HTTP_LOG) return;
    /* The ring is newest first (http_log_snapshot), so a new request
     * goes in at index 0. */
    memmove(&s->http_log[1], &s->http_log[0],
            sizeof(s->http_log[0]) * (size_t)s->http_log_count);
    http_log_entry_t *e = &s->http_log[0];
    memset(e, 0, sizeof(*e));
    snprintf(e->src,        sizeof(e->src),        "%s", src);
    snprintf(e->host,       sizeof(e->host),       "%s", host);
    snprintf(e->method,     sizeof(e->method),     "GET");
    snprintf(e->path,       sizeof(e->path),       "/");
    snprintf(e->user_agent, sizeof(e->user_agent), "%s", ua);
    e->ts = g_wall;
    s->http_log_count++;
}

static void test_attack_tool_ua_ring_does_not_multiply(void) {
    /* One scanner, 30 requests in the ring across three hosts, standing
     * for 600 passes. Seen red with the per-entry fire restored:
     * evaluations 18000 (30 a pass) and observations 12005, the detail's
     * host switching between entries inside each pass; and with the
     * newest request's age in the detail, observations 600. */
    sloth_state_t *s = tr_begin();
    static const char *hosts[3] = { "a.example", "b.example", "c.example" };
    for (int i = 0; i < 30; i++)
        add_http(s, "10.0.0.5", hosts[i % 3], "sqlmap/1.7.5#stable");
    tr_ticks(s, 600);

    ASSERT_EQ(tr_count_open(s, ALERT_TYPE_ATTACK_TOOL_UA), 1);
    int i = tr_find(s, ALERT_TYPE_ATTACK_TOOL_UA);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].evaluations, 600);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);
    ASSERT(strstr(s->alerts[i].detail, "3 hosts") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "10+ matching requests") != NULL);
    ASSERT_STR(s->alerts[i].match_ip, "10.0.0.5");

    /* A real change: the scanner reaches a fourth host. One more
     * observation, and the standing passes after it add none. */
    add_http(s, "10.0.0.5", "d.example", "sqlmap/1.7.5#stable");
    tr_ticks(s, 120);
    i = tr_find(s, ALERT_TYPE_ATTACK_TOOL_UA);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].observations, 2);
    ASSERT(strstr(s->alerts[i].detail, "4 hosts") != NULL);
    tr_end();
}

static void test_attack_tool_ua_one_host_names_it(void) {
    /* The single-target case names the target and counts exactly below
     * ten: a second request to it is a change worth one observation.
     * Seen red with the per-entry fire restored (evaluations 360), and
     * with the newest request's age in the detail (observations 120,
     * then 240). */
    sloth_state_t *s = tr_begin();
    add_http(s, "10.0.0.6", "target.example", "Nikto/2.5.0");
    tr_ticks(s, 120);
    int i = tr_find(s, ALERT_TYPE_ATTACK_TOOL_UA);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT(strstr(s->alerts[i].detail,
                  "10.0.0.6 -> target.example [nikto]: 1 matching request")
           != NULL);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);
    add_http(s, "10.0.0.6", "target.example", "Nikto/2.5.0");
    tr_ticks(s, 120);
    i = tr_find(s, ALERT_TYPE_ATTACK_TOOL_UA);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].observations, 2);
    ASSERT_EQ((long long)s->alerts[i].evaluations, 240);
    ASSERT(strstr(s->alerts[i].detail, "2 matching requests") != NULL);
    tr_end();
}

/* ── DGA_DOMAIN: the querying client speaks for the name ── */

static void add_dns(sloth_state_t *s, const char *src, const char *qname,
                    int is_resp) {
    if (s->dns_log_count >= MAX_DNS_LOG) return;
    memmove(&s->dns_log[1], &s->dns_log[0],
            sizeof(s->dns_log[0]) * (size_t)s->dns_log_count);
    dns_log_entry_t *e = &s->dns_log[0];
    memset(e, 0, sizeof(*e));
    snprintf(e->src,   sizeof(e->src),   "%s", src);
    snprintf(e->qname, sizeof(e->qname), "%s", qname);
    snprintf(e->qtype, sizeof(e->qtype), "A");
    if (is_resp) snprintf(e->answer, sizeof(e->answer), "NXDOMAIN");
    e->is_resp = is_resp;
    e->ts = g_wall;
    s->dns_log_count++;
}

static void test_dga_domain_does_not_flip_to_the_resolver(void) {
    /* A query from the client and its response from the resolver, both
     * in the ring. Seen red with the per-entry fire restored: 1200
     * evaluations in 600 passes and observations 605, the detail
     * alternating between "192.168.1.20 queried" and "192.168.1.1
     * queried" inside each pass, and the resolver as match_ip. */
    sloth_state_t *s = tr_begin();
    add_dns(s, "192.168.1.20", "xbqfkzpqvwj.com", 0);
    add_dns(s, "192.168.1.1",  "xbqfkzpqvwj.com", 1);
    tr_ticks(s, 600);

    ASSERT_EQ(tr_count_open(s, ALERT_TYPE_DGA_DOMAIN), 1);
    int i = tr_find(s, ALERT_TYPE_DGA_DOMAIN);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].evaluations, 600);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);
    ASSERT(strstr(s->alerts[i].detail, "192.168.1.20 queried") != NULL);
    ASSERT_STR(s->alerts[i].match_ip, "192.168.1.20");

    /* A second client asks for the name: that is new, and it moves. */
    add_dns(s, "192.168.1.30", "xbqfkzpqvwj.com", 0);
    tr_ticks(s, 120);
    i = tr_find(s, ALERT_TYPE_DGA_DOMAIN);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].observations, 2);
    ASSERT(strstr(s->alerts[i].detail, "192.168.1.30 queried") != NULL);
    tr_end();
}

static void test_dga_domain_response_only_names_the_resolver(void) {
    /* The query has left the ring: the response is all there is, and
     * the detail says whose answer it was rather than calling the
     * resolver the asker. */
    sloth_state_t *s = tr_begin();
    add_dns(s, "192.168.1.1", "a8x9b2zqp4kvw.net", 1);
    alerts_update(s);
    int i = tr_find(s, ALERT_TYPE_DGA_DOMAIN);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT(strstr(s->alerts[i].detail, "192.168.1.1 answered") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "queried") == NULL);
    tr_end();
}

/* ── WPA_DOWNGRADE: the posture's age as a band ── */

static beacon_ap_t *add_transition_ap(sloth_state_t *s, long observed_secs) {
    beacon_ap_t *a = &s->beacon_aps[s->beacon_count++];
    memset(a, 0, sizeof(*a));
    static const uint8_t b[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x73 };
    memcpy(a->bssid, b, 6);
    snprintf(a->ssid, sizeof(a->ssid), "corp");
    snprintf(a->enc,  sizeof(a->enc),  "WPA3");
    a->akm_bits   = RSN_AKM_PSK | RSN_AKM_SAE;
    a->mfp        = 2;
    a->channel    = 36;
    a->first_seen = g_wall - observed_secs;
    a->last_seen  = g_wall;
    return a;
}

static void test_wpa_downgrade_age_is_banded(void) {
    /* A transition-mode AP standing from 31 s to 631 s old. Seen red
     * with "(observed %lds)" restored: observations 600, one a pass,
     * and an alert.update every floor. With the band, one observation
     * until the posture is five minutes old and one more when it is. */
    sloth_state_t *s = tr_begin();
    beacon_ap_t *a = add_transition_ap(s, 31);
    tr_ticks(s, 268);                   /* last pass at age 298 s */
    int i = tr_find(s, ALERT_TYPE_WPA_DOWNGRADE);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].evaluations, 268);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);
    ASSERT(strstr(s->alerts[i].detail, "(observed 30s+)") != NULL);

    tr_ticks(s, 332);                   /* through age 630 s */
    i = tr_find(s, ALERT_TYPE_WPA_DOWNGRADE);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].observations, 2);
    ASSERT(strstr(s->alerts[i].detail, "(observed 5m+)") != NULL);

    /* What the AP beacons changes: that is observed. */
    snprintf(a->ssid, sizeof(a->ssid), "corp-guest");
    tr_ticks(s, 120);
    i = tr_find(s, ALERT_TYPE_WPA_DOWNGRADE);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].observations, 3);
    tr_end();
}

/* ── MGMT_FUZZ: a rate, not the running counters ── */

static beacon_ap_t *add_fuzz_ap(sloth_state_t *s) {
    beacon_ap_t *a = &s->beacon_aps[s->beacon_count++];
    memset(a, 0, sizeof(*a));
    static const uint8_t b[6] = { 0xba, 0xad, 0xf0, 0x0d, 0x01, 0x73 };
    memcpy(a->bssid, b, 6);
    snprintf(a->ssid, sizeof(a->ssid), "NetGear");
    snprintf(a->enc,  sizeof(a->enc),  "WPA2");
    a->channel    = 6;
    a->first_seen = g_wall;
    a->last_seen  = g_wall;
    return a;
}

static void test_mgmt_fuzz_steady_fault_is_one_observation(void) {
    /* A driver putting one overrun IE in every beacon, ten beacons a
     * second, for 600 passes: the counters climb from 50 to 6040. Seen
     * red with the raw-counter detail restored: observations 600. The
     * rate band holds ("50 or more" per 100 frames) while the fault
     * does. */
    sloth_state_t *s = tr_begin();
    beacon_ap_t *a = add_fuzz_ap(s);
    a->frame_count      = 50;
    a->fuzz_ie_overruns = 50;
    for (int t = 0; t < 600; t++) {
        alerts_update(s);
        tr_advance(1);
        a->frame_count      += 10;
        a->fuzz_ie_overruns  = (uint16_t)(a->fuzz_ie_overruns + 10);
    }
    int i = tr_find(s, ALERT_TYPE_MGMT_FUZZ);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((int)s->alerts[i].sev, (int)ALERT_SEV_CRIT);
    ASSERT_EQ((long long)s->alerts[i].evaluations, 600);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);
    ASSERT(strstr(s->alerts[i].detail, "(IE overrun)") != NULL);
    ASSERT(strstr(s->alerts[i].detail, "50 or more per 100 frames") != NULL);

    /* A second defect kind appears: a different malformation, seen. */
    a->fuzz_truncated_rsn = 1;
    tr_ticks(s, 120);
    i = tr_find(s, ALERT_TYPE_MGMT_FUZZ);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].observations, 2);
    ASSERT(strstr(s->alerts[i].detail, "IE overrun, truncated RSN") != NULL);
    tr_end();
}

static void test_mgmt_fuzz_stray_frames_read_as_stray(void) {
    /* Three malformed IEs in ten thousand frames is the other end of the
     * scale from a fault in every frame, and the detail says so. */
    sloth_state_t *s = tr_begin();
    beacon_ap_t *a = add_fuzz_ap(s);
    a->frame_count        = 10000;
    a->fuzz_oversize_ssid = 3;
    alerts_update(s);
    int i = tr_find(s, ALERT_TYPE_MGMT_FUZZ);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((int)s->alerts[i].sev, (int)ALERT_SEV_WARN);
    ASSERT(strstr(s->alerts[i].detail, "(oversize SSID): under 1 per 100")
           != NULL);
    tr_end();
}

static void test_mgmt_fuzz_saturated_counter_is_not_a_falling_rate(void) {
    /* The counters stop at 0xffff while frame_count keeps climbing, so
     * past saturation score/frames falls with every frame and a fault in
     * every beacon would drift down the bands to the stray-frame reading.
     * Here the counter has just saturated at 131,000 frames (50.02 per
     * 100) and ten more frames a pass arrive for 600 passes, taking the
     * quotient to 47. Seen red with the saturated branch removed: the
     * detail read "10-49 per 100" and observations 54 (the band change
     * landed inside the first update floor). */
    sloth_state_t *s = tr_begin();
    beacon_ap_t *a = add_fuzz_ap(s);
    a->frame_count      = 131000;
    a->fuzz_ie_overruns = 0xffff;
    for (int t = 0; t < 600; t++) {
        alerts_update(s);
        tr_advance(1);
        a->frame_count += 10;
    }
    int i = tr_find(s, ALERT_TYPE_MGMT_FUZZ);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].evaluations, 600);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);
    ASSERT(strstr(s->alerts[i].detail,
                  "(IE overrun): counters saturated, rate no longer measured")
           != NULL);
    ASSERT(strstr(s->alerts[i].detail, "per 100") == NULL);
    tr_end();
}

/* ── PM_FORGE: a recency bound ── */

static int pm_frame(uint8_t *f, int sub, int pm, const uint8_t bssid[6],
                    const uint8_t sta[6], int tid) {
    /* STA -> AP, IEEE 802.11-2020 §9.2.4.1.7 / §9.3.2.1: FC (ToDS,
     * PwrMgt), Duration, addr1 = BSSID, addr2 = STA, addr3 = BSSID,
     * Sequence Control, and QoS Control for a QoS subtype. */
    memset(f, 0, 32);
    f[0] = (uint8_t)((sub << 4) | (2 << 2));
    f[1] = (uint8_t)(0x01 | (pm ? 0x10 : 0));
    memcpy(f + 4,  bssid, 6);
    memcpy(f + 10, sta,   6);
    memcpy(f + 16, bssid, 6);
    int len = 24;
    if (sub & 0x08) { f[24] = (uint8_t)(tid & 0x0f); len = 26; }
    return len;
}

static void pm_contradiction(const uint8_t bssid[6], const uint8_t sta[6],
                             time_t at) {
    uint8_t f[32];
    int len = pm_frame(f, 0xC, 1, bssid, sta, 0);   /* QoS-Null, PM=1 */
    pm_forge_observe(f, len, at, 0);
    len = pm_frame(f, 0x8, 0, bssid, sta, 5);       /* QoS data, PM=0 */
    pm_forge_observe(f, len, at, 50000);            /* 50 ms later */
}

static void test_pm_forge_stops_reporting_a_stale_contradiction(void) {
    /* One contradiction, then 1500 s of the row sitting in the table.
     * Seen red with the recency bound removed: evaluations 1500, one a
     * pass for as long as the row stays in the 128-entry LRU, and the
     * incident never resolves; and with the contradiction's age in the
     * detail, observations 10 in the second incident's 10 passes. */
    static const uint8_t bssid[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x73 };
    static const uint8_t sta[6]   = { 0x02, 0xaa, 0x00, 0x00, 0x01, 0x73 };
    sloth_state_t *s = tr_begin();
    pm_forge_clear();
    beacon_clear();
    beacon_record(bssid, "Net", -50, 6, "WPA2", 100, NULL);
    time_t t0 = g_wall;
    pm_contradiction(bssid, sta, t0);

    tr_ticks(s, 1500);
    int i = -1;
    for (int k = 0; k < s->alert_count; k++)
        if (s->alerts[k].type == ALERT_TYPE_PM_FORGE) i = k;
    ASSERT(i >= 0);
    if (i < 0) { pm_forge_clear(); beacon_clear(); tr_end(); return; }
    /* Reported while the contradiction is under PM_FORGE_REPORT_SECS
     * (900 s) old: passes at t0 .. t0+900. */
    ASSERT_EQ((long long)s->alerts[i].evaluations, 901);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);
    ASSERT_EQ(s->alerts[i].resolved, 1);
    ASSERT_EQ(tr_find(s, ALERT_TYPE_PM_FORGE), -1);

    /* A new contradiction is a new finding. The beacon is heard again
     * first: the window is the AP's own beacon interval, read from the
     * beacon table. */
    beacon_record(bssid, "Net", -50, 6, "WPA2", 100, NULL);
    pm_contradiction(bssid, sta, g_wall);
    tr_ticks(s, 10);
    i = tr_find(s, ALERT_TYPE_PM_FORGE);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((long long)s->alerts[i].evaluations, 10);
        ASSERT(strstr(s->alerts[i].detail, "2 time(s)") != NULL);
    }
    pm_forge_clear();
    beacon_clear();
    tr_end();
}

static void test_pm_forge_new_contradiction_inside_the_bound(void) {
    /* Inside the bound a further contradiction is evidence moving: one
     * observation, after a standing stretch that added none. Seen red
     * with the contradiction's age in the detail: observations 300, then
     * 600. */
    static const uint8_t bssid[6] = { 0x00, 0x11, 0x22, 0x33, 0x45, 0x73 };
    static const uint8_t sta[6]   = { 0x02, 0xaa, 0x00, 0x00, 0x02, 0x73 };
    sloth_state_t *s = tr_begin();
    pm_forge_clear();
    beacon_clear();
    beacon_record(bssid, "Net", -50, 6, "WPA2", 100, NULL);
    pm_contradiction(bssid, sta, g_wall);
    tr_ticks(s, 300);
    int i = tr_find(s, ALERT_TYPE_PM_FORGE);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ((long long)s->alerts[i].observations, 1);
    beacon_record(bssid, "Net", -50, 6, "WPA2", 100, NULL);
    pm_contradiction(bssid, sta, g_wall);
    tr_ticks(s, 300);
    i = tr_find(s, ALERT_TYPE_PM_FORGE);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((long long)s->alerts[i].observations, 2);
        ASSERT_EQ((long long)s->alerts[i].evaluations, 600);
    }
    pm_forge_clear();
    beacon_clear();
    tr_end();
}

static void test_pm_forge_bound_runs_on_arrival_not_capture_time(void) {
    /* A --replay hands the table each frame's capture stamp, and the
     * alert pass runs on the host clock. A contradiction captured
     * two years before it is replayed is still a new finding when it
     * arrives, and ages out PM_FORGE_REPORT_SECS after *that*. Seen red
     * with the bound measured on last_contradiction_ts (the capture
     * stamp): no PM_FORGE at all, the replayed attack silent. */
    static const uint8_t bssid[6] = { 0x00, 0x11, 0x22, 0x33, 0x46, 0x73 };
    static const uint8_t sta[6]   = { 0x02, 0xaa, 0x00, 0x00, 0x03, 0x73 };
    sloth_state_t *s = tr_begin();
    pm_forge_clear();
    beacon_clear();
    beacon_record(bssid, "Net", -50, 6, "WPA2", 100, NULL);
    pm_contradiction(bssid, sta, g_wall - 2 * 365 * 86400);
    tr_ticks(s, 10);
    int i = tr_find(s, ALERT_TYPE_PM_FORGE);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ((long long)s->alerts[i].evaluations, 10);
    tr_ticks(s, 1490);
    ASSERT_EQ(tr_find(s, ALERT_TYPE_PM_FORGE), -1);
    pm_forge_clear();
    beacon_clear();
    tr_end();
}

/* ── FRAG_PLAINTEXT: no shared pair, the count by decade ── */

/* AP -> STA data frame, IEEE 802.11-2020 §9.3.2.1: FromDS, addr1 = DA,
 * addr2 = BSSID, addr3 = SA; LLC/SNAP with `ethertype` when unprotected,
 * an opaque body when Protected (FC bit 0x40). */
static int frag_frame(uint8_t *f, uint8_t fc1, const uint8_t *da,
                      const uint8_t *bssid, const uint8_t *sa,
                      int frag_num, uint16_t ethertype) {
    memset(f, 0, 64);
    f[0] = 2 << 2;
    f[1] = (uint8_t)(fc1 | 0x02);
    memcpy(f + 4, da, 6); memcpy(f + 10, bssid, 6); memcpy(f + 16, sa, 6);
    f[22] = (uint8_t)(frag_num & 0x0f);
    if (fc1 & 0x40) return 40;
    f[24] = 0xaa; f[25] = 0xaa; f[26] = 0x03;
    f[30] = (uint8_t)(ethertype >> 8);
    f[31] = (uint8_t)(ethertype & 0xff);
    return 36;
}

static const uint8_t FT_BSS[6]  = { 0x02, 0xaa, 0xbb, 0, 0x73, 1 };
static const uint8_t FT_STA[6]  = { 0x02, 0xaa, 0xbb, 0, 0x73, 0x10 };
static const uint8_t FT_AP[6]   = { 0x02, 0xaa, 0xbb, 0, 0x73, 0x20 };
static const uint8_t FT_SA2[6]  = { 0x02, 0xaa, 0xbb, 0, 0x73, 0x30 };
static const uint8_t FT_BC[6]   = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static void test_frag_plaintext_other_kind_does_not_move_it(void) {
    /* One plaintext frame after key install, then ten passes later a
     * plaintext broadcast fragment from another source on the same BSS
     * (FRAG_BCAST's finding, which rewrites the row's last pair). Seen
     * red with "last %s -> %s" restored: the second hit changed this
     * alert's detail inside the update floor, and observations rose
     * every pass until the floor passed (52 by the end). */
    sloth_state_t *s = tr_begin();
    frag_clear();
    uint8_t f[64];
    int n = frag_frame(f, 0x40, FT_STA, FT_BSS, FT_AP, 0, 0);  /* key install */
    frag_observe(f, n, g_wall);
    n = frag_frame(f, 0, FT_STA, FT_BSS, FT_AP, 0, 0x0800);
    frag_observe(f, n, g_wall);
    tr_ticks(s, 10);
    n = frag_frame(f, 0x40, FT_STA, FT_BSS, FT_SA2, 0, 0);
    frag_observe(f, n, g_wall);
    n = frag_frame(f, 0x04, FT_BC, FT_BSS, FT_SA2, 0, 0x0800); /* MoreFrag */
    frag_observe(f, n, g_wall);
    tr_ticks(s, 590);

    ASSERT(tr_find(s, ALERT_TYPE_FRAG_BCAST) >= 0);
    int i = tr_find(s, ALERT_TYPE_FRAG_PLAINTEXT);
    ASSERT(i >= 0);
    if (i < 0) { frag_clear(); tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].evaluations, 600);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);
    ASSERT(strstr(s->alerts[i].detail, "1 unprotected data frame on") != NULL);

    /* A second plaintext frame is the evidence growing: one more. */
    n = frag_frame(f, 0, FT_STA, FT_BSS, FT_AP, 0, 0x0800);
    frag_observe(f, n, g_wall);
    tr_ticks(s, 120);
    i = tr_find(s, ALERT_TYPE_FRAG_PLAINTEXT);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((long long)s->alerts[i].observations, 2);
        ASSERT(strstr(s->alerts[i].detail, "2 unprotected data frames")
               != NULL);
    }
    frag_clear();
    tr_end();
}

/* ── SMB1_USE: the packet count by decade ── */

static smb_session_t *add_smb1(sloth_state_t *s) {
    smb_session_t *e = &s->smb_sessions[s->smb_session_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->client_ip, sizeof(e->client_ip), "10.0.0.5");
    snprintf(e->server_ip, sizeof(e->server_ip), "10.0.0.10");
    e->server_port = 445;
    snprintf(e->dialect, sizeof(e->dialect), "SMB1");
    e->first_seen = g_wall;
    e->last_seen  = g_wall;
    return e;
}

static void test_smb1_use_busy_session_moves_by_decade(void) {
    /* An SMBv1 transfer, three packets a pass for 600 passes: the
     * session count runs 100 -> 1897. Seen red with "(count=%d)"
     * restored: observations 600. By decade: one when it opens at 100+
     * and one when it reaches 1000+ (pass 300), nothing between. */
    sloth_state_t *s = tr_begin();
    smb_session_t *e = add_smb1(s);
    e->count = 100;
    for (int t = 0; t < 600; t++) {
        alerts_update(s);
        tr_advance(1);
        e->count += 3;
        e->last_seen = g_wall;
    }
    int i = tr_find(s, ALERT_TYPE_SMB1_USE);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].evaluations, 600);
    ASSERT_EQ((long long)s->alerts[i].observations, 2);
    ASSERT(strstr(s->alerts[i].detail, "(1000+ SMB packets)") != NULL);
    tr_end();
}

static void test_smb1_use_single_exchange_is_exact(void) {
    /* Below ten the count is exact, so a second packet on a quiet
     * session is one observation, and the standing passes add none.
     * Seen red with the session's idle seconds in the detail:
     * observations 120, then 240. */
    sloth_state_t *s = tr_begin();
    smb_session_t *e = add_smb1(s);
    e->count = 1;
    tr_ticks(s, 120);
    int i = tr_find(s, ALERT_TYPE_SMB1_USE);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT(strstr(s->alerts[i].detail, "(1 SMB packet)") != NULL);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);
    e->count = 2;
    tr_ticks(s, 120);
    i = tr_find(s, ALERT_TYPE_SMB1_USE);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].observations, 2);
    tr_end();
}

/* ── CAM_SETUP_OUI: already change-only; pinned ── */

static void test_cam_setup_oui_standing_ap_is_one_observation(void) {
    /* A Hikvision-block BSSID beaconing for 600 passes, its signal,
     * frame count and last_seen moving every pass as a live beacon row's
     * do. The rule's detail reads none of them, so this needed no code
     * change for #173; the test pins it. Seen red with the row's
     * frame_count appended to the detail: observations 600. */
    sloth_state_t *s = tr_begin();
    beacon_ap_t *a = &s->beacon_aps[s->beacon_count++];
    memset(a, 0, sizeof(*a));
    static const uint8_t b[6] = { 0x44, 0x19, 0xB6, 0x0a, 0x0b, 0x73 };
    memcpy(a->bssid, b, 6);
    snprintf(a->ssid, sizeof(a->ssid), "Cam-Setup");
    snprintf(a->enc,  sizeof(a->enc),  "WPA2");
    a->channel = 6;
    for (int t = 0; t < 600; t++) {
        a->last_seen   = g_wall;
        a->frame_count += 10;
        a->signal_dbm  = (int8_t)(-50 - (t % 7));
        alerts_update(s);
        tr_advance(1);
    }
    int i = tr_find(s, ALERT_TYPE_CAM_SETUP_OUI);
    ASSERT(i >= 0);
    if (i < 0) { tr_end(); return; }
    ASSERT_EQ((long long)s->alerts[i].evaluations, 600);
    ASSERT_EQ((long long)s->alerts[i].observations, 1);

    /* The AP moves channel: what it advertises changed. */
    a->channel = 11;
    tr_ticks(s, 120);
    i = tr_find(s, ALERT_TYPE_CAM_SETUP_OUI);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ((long long)s->alerts[i].observations, 2);
    tr_end();
}

void run_alert_tick_rate_tests(void) {
    RUN_TEST(test_attack_tool_ua_ring_does_not_multiply);
    RUN_TEST(test_attack_tool_ua_one_host_names_it);
    RUN_TEST(test_dga_domain_does_not_flip_to_the_resolver);
    RUN_TEST(test_dga_domain_response_only_names_the_resolver);
    RUN_TEST(test_wpa_downgrade_age_is_banded);
    RUN_TEST(test_mgmt_fuzz_steady_fault_is_one_observation);
    RUN_TEST(test_mgmt_fuzz_stray_frames_read_as_stray);
    RUN_TEST(test_mgmt_fuzz_saturated_counter_is_not_a_falling_rate);
    RUN_TEST(test_pm_forge_stops_reporting_a_stale_contradiction);
    RUN_TEST(test_pm_forge_new_contradiction_inside_the_bound);
    RUN_TEST(test_pm_forge_bound_runs_on_arrival_not_capture_time);
    RUN_TEST(test_frag_plaintext_other_kind_does_not_move_it);
    RUN_TEST(test_smb1_use_busy_session_moves_by_decade);
    RUN_TEST(test_smb1_use_single_exchange_is_exact);
    RUN_TEST(test_cam_setup_oui_standing_ap_is_one_observation);
}
