#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "tmp_dir.h"
#include "fake_platform.h"
#include "sys_status.h"
#include "capture_side.h"
#include "ownership.h"
#include "rule_coverage_live.h"
#include "alert_key.h"
#include "jsonl.h"
#include "db.h"
#include "posture.h"
#include "exposure.h"
#include "alerts.h"

/*
 * What this site reveals (#243): the kind-to-group table
 * (include/sloth_exposure.def), its remedies against
 * docs/wiki/alert-remediation.md, the scope test, the report section
 * and the exposure_summary record. Expectations are written out from
 * the issue's six groups and from the rules' key builders under
 * src/alerts/, not read back from the table.
 */

static const char *const k_alert_ids[] = {
#define X(id, technique) #id,
#include "sloth_alerts.def"
#undef X
};
static const char *const k_exp_ids[] = {
#define X(id, group, scope, remedy) #id,
#include "sloth_exposure.def"
#undef X
};

static int contains(const char *hay, const char *needle) {
    return hay && needle && strstr(hay, needle) != NULL;
}

static int count_of(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* ── the table ─────────────────────────────────────────────────────── */

static void test_def_matches_alert_list(void) {
    /* Every kind classified, same order: a kind appended to
     * sloth_alerts.def with no row here is red (the build's own size
     * check catches a missing row first; this catches a misspelt or
     * reordered one). */
    int na = (int)(sizeof(k_alert_ids) / sizeof(*k_alert_ids));
    int ne = (int)(sizeof(k_exp_ids) / sizeof(*k_exp_ids));
    ASSERT_EQ(na, (int)ALERT_TYPE_COUNT);
    ASSERT_EQ(ne, na);
    for (int i = 0; i < na && i < ne; i++)
        ASSERT_STR(k_exp_ids[i], k_alert_ids[i]);
}

static void test_rows_are_well_formed(void) {
    int per_group[EXP_G_COUNT] = { 0 };
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        exp_group_t g  = exp_group_of((alert_type_t)t);
        exp_scope_t sc = exp_scope_of((alert_type_t)t);
        const char *r  = exp_remedy((alert_type_t)t);
        ASSERT((int)g >= 0 && g < EXP_G_COUNT);
        per_group[g]++;
        if (g == EXP_G_NONE) {
            ASSERT_EQ((int)sc, (int)EXP_S_NA);
            ASSERT_STR(r, "");
        } else {
            ASSERT(sc != EXP_S_NA);
            ASSERT(r && strlen(r) > 10);
        }
    }
    /* Every group has a rule behind it, or its statement could never be
     * anything but "not observable". */
    for (int g = EXP_G_NONE + 1; g < EXP_G_COUNT; g++) ASSERT(per_group[g] > 0);
    ASSERT_EQ((int)exp_group_of((alert_type_t)-1), (int)EXP_G_NONE);
    ASSERT_EQ((int)exp_group_of(ALERT_TYPE_COUNT), (int)EXP_G_NONE);
    ASSERT_STR(exp_remedy(ALERT_TYPE_COUNT), "");
}

static void test_named_groups(void) {
    /* The issue's list of exposure findings, each in the group of what
     * it discloses (docs/wiki/exposure-report.md has the reasons). */
    static const struct { alert_type_t t; exp_group_t g; exp_scope_t sc; } k[] = {
        { ALERT_TYPE_MY_NETWORK_RECON,     EXP_G_NAMES,    EXP_S_OWN },
        { ALERT_TYPE_SURV_CLOUD_SNI,       EXP_G_DEVICES,  EXP_S_LAN },
        { ALERT_TYPE_SURV_DNS,             EXP_G_DEVICES,  EXP_S_LAN },
        { ALERT_TYPE_RECURRING_TRANSIT,    EXP_G_DEVICES,  EXP_S_AIR },
        { ALERT_TYPE_TPC_ABSENT_HIGH_BAND, EXP_G_DEVICES,  EXP_S_OWN },
        { ALERT_TYPE_COUNTRY_ABSENT,       EXP_G_DEVICES,  EXP_S_AIR },
        { ALERT_TYPE_CLEARTEXT_CRED,       EXP_G_CREDS,    EXP_S_LAN },
        { ALERT_TYPE_PEAP_NO_SERVER_CERT,  EXP_G_CREDS,    EXP_S_AIR },
        { ALERT_TYPE_CAM_WS_DISCOVERY,     EXP_G_ANNOUNCE, EXP_S_LAN },
        { ALERT_TYPE_CAM_MDNS_SERVICE,     EXP_G_ANNOUNCE, EXP_S_LAN },
        { ALERT_TYPE_CAM_SSDP_DEVICE,      EXP_G_ANNOUNCE, EXP_S_LAN },
        { ALERT_TYPE_CAM_RTSP_UNAUTH,      EXP_G_ANNOUNCE, EXP_S_LAN },
        { ALERT_TYPE_WPA_DOWNGRADE,        EXP_G_LANES,    EXP_S_AIR },
        { ALERT_TYPE_SAE_PSK_SPLIT,        EXP_G_LANES,    EXP_S_AIR },
        { ALERT_TYPE_SAE_PSK_REGRESSION,   EXP_G_LANES,    EXP_S_AIR },
        { ALERT_TYPE_SSID_CONFUSION,       EXP_G_LANES,    EXP_S_AIR },
        { ALERT_TYPE_MLE_CROSS_LINK_CIPHER_DOWNGRADE, EXP_G_LANES, EXP_S_AIR },
        { ALERT_TYPE_OPEN_SETUP_AP,        EXP_G_SETUP,    EXP_S_AIR },
        { ALERT_TYPE_CAM_SETUP_SSID,       EXP_G_SETUP,    EXP_S_AIR },
        { ALERT_TYPE_CAM_SETUP_OUI,        EXP_G_SETUP,    EXP_S_AIR },
    };
    int n = (int)(sizeof(k) / sizeof(*k));
    for (int i = 0; i < n; i++) {
        ASSERT_EQ((int)exp_group_of(k[i].t), (int)k[i].g);
        ASSERT_EQ((int)exp_scope_of(k[i].t), (int)k[i].sc);
    }
    /* Exactly these: an attack, an anomaly or the sensor's own state is
     * not something the site reveals. */
    int grouped = 0;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++)
        if (exp_group_of((alert_type_t)t) != EXP_G_NONE) grouped++;
    ASSERT_EQ(grouped, n);
    ASSERT_EQ((int)exp_group_of(ALERT_TYPE_SENSOR_SUPPRESSED), (int)EXP_G_NONE);
    ASSERT_EQ((int)exp_group_of(ALERT_TYPE_DEAUTH_FLOOD), (int)EXP_G_NONE);
    ASSERT_EQ((int)exp_group_of(ALERT_TYPE_EVIL_TWIN), (int)EXP_G_NONE);
}

static void test_names(void) {
    ASSERT_STR(exp_group_name(EXP_G_NAMES), "network_names");
    ASSERT_STR(exp_group_name(EXP_G_DEVICES), "devices");
    ASSERT_STR(exp_group_name(EXP_G_CREDS), "credentials");
    ASSERT_STR(exp_group_name(EXP_G_ANNOUNCE), "self_announcing");
    ASSERT_STR(exp_group_name(EXP_G_LANES), "weak_lanes");
    ASSERT_STR(exp_group_name(EXP_G_SETUP), "setup_mode");
    ASSERT_STR(exp_group_name(EXP_G_NONE), "");
    ASSERT_STR(exp_state_name(EXP_ST_NEEDS_DESIGNATION), "needs_designation");
    ASSERT_STR(exp_state_name(EXP_ST_FOUND), "found");
    ASSERT_STR(exp_state_name(EXP_ST_NONE_OBSERVABLE), "none_observable");
    ASSERT_STR(exp_state_name(EXP_ST_NONE_PARTLY), "none_partly");
    ASSERT_STR(exp_state_name(EXP_ST_NOT_OBSERVABLE), "not_observable");
    ASSERT_STR(exp_state_name(EXP_ST_NOT_ASSESSED), "not_assessed");
    char w[64];
    exp_why_str((1u << COV_R_NO_SOURCE) | (1u << COV_R_HOP), w, sizeof(w));
    ASSERT_STR(w, "no_source,hop");
    exp_why_str(0, w, sizeof(w));
    ASSERT_STR(w, "");
}

/* ── the remedies, held to the page ────────────────────────────────── */

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

/* The first Fix step of `kind`'s section, its lines joined with one
 * space and the "1. " dropped: what include/sloth_exposure.def says its
 * REMEDY is. 0 when the section or the step is missing. */
static int page_first_fix(const char *page, const char *kind, char *out, size_t sz) {
    char head[96];
    snprintf(head, sizeof(head), "\n## `%s`\n", kind);
    const char *p = strstr(page, head);
    if (!p) return 0;
    p += strlen(head);
    const char *next = strstr(p, "\n## ");
    const char *fix = strstr(p, "\n**Fix**\n");
    if (!fix || (next && fix > next)) return 0;
    p = fix + strlen("\n**Fix**\n");
    while (*p == '\n') p++;
    if (!(isdigit((unsigned char)p[0]) && p[1] == '.' && p[2] == ' ')) return 0;
    p += 3;
    size_t o = 0;
    while (*p && o + 1 < sz) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        const char *s = p;
        while (len && (*s == ' ')) { s++; len--; }
        if (o && o + 1 < sz) out[o++] = ' ';
        for (size_t i = 0; i < len && o + 1 < sz; i++) out[o++] = s[i];
        if (!eol) break;
        p = eol + 1;
        /* The step ends at a blank line or the next numbered step. */
        if (*p == '\n' || (isdigit((unsigned char)p[0]) && p[1] == '.')) break;
    }
    out[o] = '\0';
    return 1;
}

static void test_remedy_is_the_pages_first_fix_step(void) {
    char *page = slurp_file("docs/wiki/alert-remediation.md");
    ASSERT(page != NULL);
    if (!page) return;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        if (exp_group_of((alert_type_t)t) == EXP_G_NONE) continue;
        char want[1024];
        int ok = page_first_fix(page, cov_kind_name((alert_type_t)t), want, sizeof(want));
        ASSERT(ok);
        if (!ok) continue;
        if (strcmp(exp_remedy((alert_type_t)t), want) != 0)
            fprintf(stderr, "  %s: the page's first Fix step is now\n    \"%s\"\n",
                    cov_kind_name((alert_type_t)t), want);
        ASSERT_STR(exp_remedy((alert_type_t)t), want);
    }
    free(page);
}

/* ── state ─────────────────────────────────────────────────────────── */

TEST_STATE(g_s);
static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }
static char     g_buf[1 << 17];
static char     g_path[512];

static void begin(void) {
    capture_side_install();
    g_mono = 5000000;
    g_wall = (time_t)1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    ownership_clear();
    memset(&g_s, 0, sizeof(g_s));
}

static void end(void) {
    jsonl_close();
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    ownership_clear();
    capture_side_install();
    sloth_clock_test_set(NULL, NULL);
}

static void tick(void) {
    g_mono += 1000;
    g_wall += 1;
    sys_status_poll(&g_s, g_wall, g_mono);
    cov_live_poll(&g_s);
}

/* One monitor radio on the default --hop list, no IP capture. */
static void one_hopping_radio(void) {
    static const int ch[] = { 1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161 };
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "mon0");
    g_s.mon_health.open = 1;
    g_s.mon_health.running = 1;
    g_s.mon_health.stale_secs = 0;
    g_s.scan_chan_count = (int)(sizeof(ch) / sizeof(*ch));
    for (int i = 0; i < g_s.scan_chan_count; i++) g_s.scan_chans[i] = ch[i];
}

static void ip_capture_up(void) {
    snprintf(g_s.pkt_iface, sizeof(g_s.pkt_iface), "eth0");
    g_s.pkt_linktype = 1;
    g_s.cap_health.open = 1;
    g_s.cap_health.running = 1;
    g_s.cap_health.stale_secs = 0;
}

static alert_t *seed(alert_type_t t, const char *key, int observations,
                     time_t first, time_t last) {
    alert_t *a = &g_s.alerts[g_s.alert_count++];
    memset(a, 0, sizeof(*a));
    a->type = t;
    a->sev = ALERT_SEV_WARN;
    snprintf(a->title, sizeof(a->title), "%s", cov_kind_name(t));
    snprintf(a->key, sizeof(a->key), "%s", key);
    snprintf(a->detail, sizeof(a->detail), "detail of %s", key);
    a->observations = (uint32_t)observations;
    a->count = observations;
    a->first_seen = first;
    a->last_seen = last;
    return a;
}

static const uint8_t SETUP_BSS[6]   = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t NEIGH_BSS[6]   = { 0x02, 0x66, 0x77, 0x88, 0x99, 0xaa };
static const uint8_t LAPTOP_MAC[6]  = { 0x02, 0x00, 0x5e, 0x10, 0x00, 0x01 };

/* The rules' own key shapes: opensetup:<bssid> (rules_twin.c) and
 * cred:<src>:<dst>:<port>:<proto>:<user> (rules_wired.c). */
static void key_opensetup(char *out, size_t n, const uint8_t b[6]) {
    snprintf(out, n, "opensetup:%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}
static void key_cred(char *out, size_t n, const char *src, const char *user) {
    akey_t k;
    akey_begin(&k, out, n, "cred");
    akey_ip(&k, src);
    akey_ip(&k, "198.51.100.5");
    akey_u(&k, 21);
    akey_tok(&k, "FTP");
    akey_remote(&k, user, 32);
    akey_end(&k);
}

static void roster_laptop(const char *ip) {
    device_t *d = &g_s.devices[g_s.device_count++];
    memset(d, 0, sizeof(*d));
    memcpy(d->mac, LAPTOP_MAC, 6);
    snprintf(d->ip, sizeof(d->ip), "%s", ip);
    ASSERT(ownership_add_known_mac("02:00:5e:10:00:01"));
}

static const char *md(void) {
    FILE *fp = fmemopen(g_buf, sizeof(g_buf), "w");
    if (!fp) { g_buf[0] = '\0'; return g_buf; }
    posture_render_md(fp, &g_s, 1800000000, NULL);
    fclose(fp);
    return g_buf;
}

static const char *json(void) {
    FILE *fp = fmemopen(g_buf, sizeof(g_buf), "w");
    if (!fp) { g_buf[0] = '\0'; return g_buf; }
    posture_render_json(fp, &g_s, 1800000000);
    fclose(fp);
    return g_buf;
}

/* The text of group `g`'s subsection of the Markdown in g_buf, copied
 * out so the next render does not overwrite it. */
static char g_sec[1 << 14];
static const char *section(const char *text, int g) {
    char head[16];
    snprintf(head, sizeof(head), "### %d. ", g);
    g_sec[0] = '\0';
    const char *p = strstr(text, head);
    if (!p) return g_sec;
    const char *e = strstr(p + 1, "### ");
    const char *e2 = strstr(p + 1, "\n## ");
    if (!e || (e2 && e2 < e)) e = e2;
    size_t n = e ? (size_t)(e - p) : strlen(p);
    if (n >= sizeof(g_sec)) n = sizeof(g_sec) - 1;
    memcpy(g_sec, p, n);
    g_sec[n] = '\0';
    return g_sec;
}

/* ── scope ─────────────────────────────────────────────────────────── */

static void test_scope_air(void) {
    begin();
    char key[ALERT_KEY_LEN];
    key_opensetup(key, sizeof(key), SETUP_BSS);
    alert_t *a = seed(ALERT_TYPE_OPEN_SETUP_AP, key, 1, 1, 1);
    /* Nothing designated: nothing is in scope. */
    ASSERT(!exp_in_scope(&g_s, a));
    /* A designated BSSID elsewhere does not make this one the site's.
     * Seen red with mac_is_site() answering 1. */
    ASSERT(ownership_add_bssid("02:66:77:88:99:aa"));
    ASSERT(!exp_in_scope(&g_s, a));
    /* The BSSID itself designated. */
    ASSERT(ownership_add_bssid("02:11:22:33:44:55"));
    ASSERT(exp_in_scope(&g_s, a));
    ownership_clear();

    /* A BSSID beaconing a designated SSID. */
    ASSERT(ownership_add_ssid("HomeNet"));
    ASSERT(!exp_in_scope(&g_s, a));
    beacon_ap_t *b = &g_s.beacon_aps[g_s.beacon_count++];
    memset(b, 0, sizeof(*b));
    memcpy(b->bssid, SETUP_BSS, 6);
    snprintf(b->ssid, sizeof(b->ssid), "HomeNet");
    ASSERT(exp_in_scope(&g_s, a));
    /* The same BSSID beaconing another SSID is not. */
    snprintf(b->ssid, sizeof(b->ssid), "OtherNet");
    ASSERT(!exp_in_scope(&g_s, a));
    /* Once the operator names their BSSIDs, another BSSID beaconing the
     * designated SSID (a twin) does not make its findings the site's:
     * anyone can beacon a name. Seen red with mac_is_site()'s
     * ownership_bssid_count() test removed. */
    snprintf(b->ssid, sizeof(b->ssid), "HomeNet");
    ASSERT(ownership_add_bssid("02:66:77:88:99:aa"));
    ASSERT(!exp_in_scope(&g_s, a));
    /* Nor does a key naming both the designated SSID and the twin's
     * BSSID (SAE_PSK_REGRESSION's raw form, SSID_CONFUSION's hashed
     * one): the address decides. Seen red with exp_in_scope()'s
     * mac_seen test removed. */
    alert_t *rg = seed(ALERT_TYPE_SAE_PSK_REGRESSION,
                       "saereg:HomeNet:02:11:22:33:44:55", 1, 1, 1);
    ASSERT(!exp_in_scope(&g_s, rg));
    char ck[ALERT_KEY_LEN];
    akey_t ak;
    akey_begin(&ak, ck, sizeof(ck), "ssidconf");
    akey_remote(&ak, "HomeNet", 32);
    akey_mac(&ak, SETUP_BSS);
    akey_end(&ak);
    alert_t *cf = seed(ALERT_TYPE_SSID_CONFUSION, ck, 1, 1, 1);
    ASSERT(!exp_in_scope(&g_s, cf));
    /* The designated BSSID's own finding still is. */
    ASSERT(ownership_add_bssid("02:11:22:33:44:55"));
    ASSERT(exp_in_scope(&g_s, rg));
    ASSERT(exp_in_scope(&g_s, cf));
    ownership_clear();
    g_s.alert_count = 0;
    g_s.beacon_count = 0;

    /* A rostered station: RECURRING_TRANSIT's transit:<mac>. */
    alert_t *tr = seed(ALERT_TYPE_RECURRING_TRANSIT, "transit:02:00:5e:10:00:01", 3, 1, 2);
    ASSERT(ownership_add_ssid("HomeNet"));
    ASSERT(!exp_in_scope(&g_s, tr));
    ASSERT(ownership_add_known_mac("02:00:5e:10:00:01"));
    ASSERT(exp_in_scope(&g_s, tr));
    end();
}

static void test_scope_ssid_in_key(void) {
    begin();
    /* SAE_PSK_SPLIT keys the SSID through akey_remote(): a sanitised
     * prefix and the hash of the whole string. An SSID with a ':' and
     * one longer than the kept prefix still match by the hash. */
    static const char *const ssids[] = { "Home:Net", "HomeNet",
        "A network name of 32 characters" };
    for (int i = 0; i < 3; i++) {
        ownership_clear();
        g_s.alert_count = 0;
        char key[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "saesplit");
        akey_remote(&k, ssids[i], 32);
        akey_end(&k);
        alert_t *a = seed(ALERT_TYPE_SAE_PSK_SPLIT, key, 1, 1, 1);
        ASSERT(ownership_add_ssid("Elsewhere"));
        ASSERT(!exp_in_scope(&g_s, a));
        ASSERT(ownership_add_ssid(ssids[i]));
        ASSERT(exp_in_scope(&g_s, a));
    }
    /* A raw SSID component (SAE_PSK_REGRESSION's "%.40s"). */
    ownership_clear();
    g_s.alert_count = 0;
    alert_t *r = seed(ALERT_TYPE_SAE_PSK_REGRESSION, "saereg:HomeNet:02:66:77:88:99:aa", 1, 1, 1);
    /* A prefix is not the name. Seen red with has_token()'s end check
     * removed. */
    ASSERT(ownership_add_ssid("Home"));
    ASSERT(!exp_in_scope(&g_s, r));
    ASSERT(ownership_add_ssid("HomeNet"));
    ASSERT(exp_in_scope(&g_s, r));

    /* A raw SSID that only contains the name as a component: an
     * impostor's "x:HomeNet" is not HomeNet. */
    ownership_clear();
    g_s.alert_count = 0;
    alert_t *im = seed(ALERT_TYPE_SAE_PSK_REGRESSION, "saereg:x:HomeNet:02:66:77:88:99:aa", 1, 1, 1);
    ASSERT(ownership_add_ssid("HomeNet"));
    ASSERT(!exp_in_scope(&g_s, im));

    /* A short designated SSID equal to another component of the key
     * (WPA_DOWNGRADE's kind digit, a key prefix word, a MAC octet) is
     * not the key naming it. Each seen red with key_raw_ssid_is()
     * replaced by the old has_token(key, ssid). */
    static const struct { alert_type_t t; const char *key, *ssid; } wrong[] = {
        { ALERT_TYPE_WPA_DOWNGRADE,     "wpadg:02:66:77:88:99:aa:1", "1" },
        { ALERT_TYPE_WPA_DOWNGRADE,     "wpadg:02:66:77:88:99:aa:8", "8" },
        { ALERT_TYPE_RECURRING_TRANSIT, "transit:02:66:77:88:99:aa", "transit" },
        { ALERT_TYPE_RECURRING_TRANSIT, "transit:02:66:77:88:99:aa", "02" },
        { ALERT_TYPE_COUNTRY_ABSENT,    "countryabsent:02:66:77:88:99:aa", "aa" },
        { ALERT_TYPE_SAE_PSK_REGRESSION, "saereg:Cafe:02:66:77:88:99:aa", "66" },
    };
    for (size_t i = 0; i < sizeof(wrong) / sizeof(wrong[0]); i++) {
        ownership_clear();
        g_s.alert_count = 0;
        alert_t *w = seed(wrong[i].t, wrong[i].key, 1, 1, 1);
        ASSERT(ownership_add_ssid(wrong[i].ssid));
        ASSERT(!exp_in_scope(&g_s, w));
    }
    end();
}

/* key_raw_ssid_is() reads SAE_PSK_REGRESSION's key by its shape; the
 * shape is the rule's, so a change there must come here too. */
static void test_raw_ssid_key_shape_is_the_rules(void) {
    char *src = slurp_file("src/alerts/rules_twin.c");
    ASSERT(src != NULL);
    if (!src) return;
    ASSERT(contains(src, "\"saereg:%.40s:%.17s\", r->ssid, r->bssid"));
    free(src);
}

static void test_scope_lan(void) {
    begin();
    char key[ALERT_KEY_LEN];
    key_cred(key, sizeof(key), "192.0.2.10", "alice");
    alert_t *a = seed(ALERT_TYPE_CLEARTEXT_CRED, key, 2, 1, 2);
    ASSERT(ownership_add_ssid("HomeNet"));
    ASSERT(!exp_in_scope(&g_s, a));
    /* A rostered device whose address is a prefix of the key's is not
     * this one: 192.0.2.1 against a key naming 192.0.2.10. Seen red
     * with has_token()'s end check removed. */
    roster_laptop("192.0.2.1");
    ASSERT(!exp_in_scope(&g_s, a));
    /* The rostered device's own address. */
    snprintf(g_s.devices[0].ip, sizeof(g_s.devices[0].ip), "192.0.2.10");
    ASSERT(exp_in_scope(&g_s, a));
    /* Unrostered, the same address is not the site's. */
    ownership_clear();
    ASSERT(ownership_add_ssid("HomeNet"));
    ASSERT(!exp_in_scope(&g_s, a));
    /* An IPv6 source, bracketed in the key. */
    g_s.alert_count = 0;
    key_cred(key, sizeof(key), "2001:db8::1", "alice");
    alert_t *v6 = seed(ALERT_TYPE_CLEARTEXT_CRED, key, 1, 1, 1);
    snprintf(g_s.devices[0].ip, sizeof(g_s.devices[0].ip), "2001:db8::1");
    ASSERT(!exp_in_scope(&g_s, v6));
    ASSERT(ownership_add_known_mac("02:00:5e:10:00:01"));
    ASSERT(exp_in_scope(&g_s, v6));
    ownership_clear();

    /* The managed link associated to a designated network: what the IP
     * capture sees is that network's, rostered or not. */
    g_s.alert_count = 0;
    alert_t *m = seed(ALERT_TYPE_CAM_MDNS_SERVICE, "cammdns:Front_door:0123456789abcdef", 1, 1, 1);
    ASSERT(ownership_add_ssid("HomeNet"));
    wifi_ap_t *ap = &g_s.aps[g_s.ap_count++];
    memset(ap, 0, sizeof(*ap));
    snprintf(ap->ssid, sizeof(ap->ssid), "HomeNet");
    snprintf(ap->bssid, sizeof(ap->bssid), "02:11:22:33:44:55");
    ap->status = WIFI_STATUS_NONE;
    /* Seen but not associated. Seen red with the status test removed. */
    ASSERT(!exp_in_scope(&g_s, m));
    ap->status = WIFI_STATUS_ASSOC;
    ASSERT(exp_in_scope(&g_s, m));
    /* Associated to a network that is not designated. */
    snprintf(ap->ssid, sizeof(ap->ssid), "CafeNet");
    ASSERT(!exp_in_scope(&g_s, m));
    ASSERT(ownership_add_bssid("02:11:22:33:44:55"));
    ASSERT(exp_in_scope(&g_s, m));
    ownership_clear();
    g_s.ap_count = 0;

    /* A camera keyed by its UUID (CAM_WS_DISCOVERY) or USN
     * (CAM_SSDP_DEVICE) carries its address in match_ip only: a
     * rostered camera is the site's through it. Seen red with
     * names_rostered_ip()'s match_ip test removed. */
    g_s.alert_count = 0;
    alert_t *w = seed(ALERT_TYPE_CAM_WS_DISCOVERY,
                      "cam-wsd:urn:uuid:4509a7c0-3b13-11e6-ac61-9e71128cae77", 1, 1, 1);
    snprintf(w->match_ip, sizeof(w->match_ip), "192.0.2.10");
    ASSERT(ownership_add_ssid("HomeNet"));
    ASSERT(!exp_in_scope(&g_s, w));
    ASSERT(ownership_add_known_mac("02:00:5e:10:00:01"));
    snprintf(g_s.devices[0].ip, sizeof(g_s.devices[0].ip), "192.0.2.10");
    ASSERT(exp_in_scope(&g_s, w));
    /* Another rostered address is not this camera's. */
    snprintf(g_s.devices[0].ip, sizeof(g_s.devices[0].ip), "192.0.2.1");
    ASSERT(!exp_in_scope(&g_s, w));
    end();
}

/* ── the report ────────────────────────────────────────────────────── */

static void test_undesignated_site_names_the_flags(void) {
    begin();
    one_hopping_radio();
    tick();
    char key[ALERT_KEY_LEN];
    key_opensetup(key, sizeof(key), NEIGH_BSS);
    seed(ALERT_TYPE_OPEN_SETUP_AP, key, 4, 1800000000, 1800000100);
    const char *m = md();
    ASSERT(contains(m, "## What this site reveals"));
    ASSERT(contains(m, "nothing is designated"));
    ASSERT(contains(m, "`--my-ssid`, `--my-bssid`, `--known-mac` or `--known-macs`"));
    /* The neighbourhood is not listed: no group, no kind. Seen red with
     * exp_report_md()'s designation test removed (the six groups
     * printed). */
    ASSERT(!contains(m, "### 1. "));
    ASSERT(!contains(m, "### 6. "));
    ASSERT(!contains(m, "outside the designation"));
    const char *j = json();
    ASSERT(contains(j, "\"exposure\": {\"designated\":false,\"needs\":[\"--my-ssid\","
                       "\"--my-bssid\",\"--known-mac\",\"--known-macs\"]},\n"));
    ASSERT(!contains(j, "\"groups\""));
    /* Its place: after risky_devices, before findings; coverage last. */
    const char *rd = strstr(j, "\"risky_devices\"");
    const char *ex = strstr(j, "\"exposure\"");
    const char *fi = strstr(j, "\"findings\"");
    const char *cv = strstr(j, "\"coverage\"");
    ASSERT(rd && ex && fi && cv && rd < ex && ex < fi && fi < cv);
    ASSERT(contains(j, "]}\n}\n"));
    end();
}

/* The acceptance case: an open setup AP and a clear-text credential,
 * both the site's, give one line each in the right group. */
static void test_setup_ap_and_cleartext_cred(void) {
    begin();
    one_hopping_radio();
    ip_capture_up();
    tick();
    ASSERT(ownership_add_bssid("02:11:22:33:44:55"));
    roster_laptop("192.0.2.10");

    char key[ALERT_KEY_LEN];
    key_opensetup(key, sizeof(key), SETUP_BSS);
    seed(ALERT_TYPE_OPEN_SETUP_AP, key, 4, 1800000000, 1800000300);
    key_cred(key, sizeof(key), "192.0.2.10", "alice");
    seed(ALERT_TYPE_CLEARTEXT_CRED, key, 3, 1800000010, 1800000200);
    /* Two more that are not the site's: a neighbour's setup AP and a
     * credential from an unrostered host. */
    key_opensetup(key, sizeof(key), NEIGH_BSS);
    seed(ALERT_TYPE_OPEN_SETUP_AP, key, 9, 1700000000, 1800000300);
    key_cred(key, sizeof(key), "192.0.2.99", "bob");
    seed(ALERT_TYPE_CLEARTEXT_CRED, key, 9, 1700000000, 1800000300);
    /* An attack kind is in no group at all. */
    seed(ALERT_TYPE_DEAUTH_FLOOD, "deauth:02:11:22:33:44:55", 5, 1, 2);

    exp_group_sum_t sum[EXP_G_COUNT];
    exp_summarise(&g_s, sum);
    ASSERT_EQ((int)sum[EXP_G_SETUP].state, (int)EXP_ST_FOUND);
    ASSERT_EQ(sum[EXP_G_SETUP].findings, 1);
    ASSERT_EQ(sum[EXP_G_SETUP].outside, 1);
    ASSERT_EQ((int)sum[EXP_G_SETUP].evidence, 4);
    ASSERT_EQ((long)sum[EXP_G_SETUP].first_seen, 1800000000L);
    ASSERT_EQ((long)sum[EXP_G_SETUP].last_seen, 1800000300L);
    ASSERT_EQ((int)sum[EXP_G_CREDS].state, (int)EXP_ST_FOUND);
    ASSERT_EQ(sum[EXP_G_CREDS].findings, 1);
    ASSERT_EQ(sum[EXP_G_CREDS].outside, 1);
    ASSERT_EQ((int)sum[EXP_G_CREDS].evidence, 3);
    for (int g = EXP_G_NONE + 1; g < EXP_G_COUNT; g++) {
        if (g == EXP_G_SETUP || g == EXP_G_CREDS) continue;
        ASSERT(sum[g].state != EXP_ST_FOUND);
        ASSERT_EQ(sum[g].findings, 0);
    }

    const char *m = md();
    ASSERT(contains(m, "## What this site reveals"));
    char six[1 << 14];
    snprintf(six, sizeof(six), "%s", section(m, EXP_G_SETUP));
    const char *three = section(m, EXP_G_CREDS);
    ASSERT(contains(six, "### 6. Devices in setup mode"));
    ASSERT(contains(six, "Found: 1 finding of 1 kind."));
    ASSERT(contains(six, "- `OPEN_SETUP_AP`: 1 finding, evidence 4, first "
                         "`2027-01-15T08:00:00Z`, last `2027-01-15T08:05:00Z`. Fix: "));
    ASSERT(contains(six, exp_remedy(ALERT_TYPE_OPEN_SETUP_AP)));
    ASSERT(contains(six, "_1 finding of this group outside the designation, not listed._"));
    ASSERT(!contains(six, "CLEARTEXT_CRED"));
    ASSERT(contains(three, "### 3. Credentials and user names in clear text"));
    ASSERT(contains(three, "- `CLEARTEXT_CRED`: 1 finding, evidence 3,"));
    ASSERT(contains(three, exp_remedy(ALERT_TYPE_CLEARTEXT_CRED)));
    ASSERT(!contains(three, "OPEN_SETUP_AP"));
    /* The other groups carry a statement, never a line. */
    const char *one = section(m, EXP_G_NAMES);
    ASSERT(contains(one, "### 1. "));
    ASSERT(!contains(one, "- `"));

    /* The section names kinds, never what the findings were about: no
     * address, no user name. The cleartext table elsewhere in the
     * report is the operator's local record; this section is not. */
    const char *sec = strstr(m, "## What this site reveals");
    ASSERT(sec != NULL);
    if (sec) {
        const char *after = strstr(sec + 1, "\n## ");
        char body[1 << 15];
        size_t n = after ? (size_t)(after - sec) : strlen(sec);
        if (n >= sizeof(body)) n = sizeof(body) - 1;
        memcpy(body, sec, n);
        body[n] = '\0';
        ASSERT(!contains(body, "192.0.2."));
        ASSERT(!contains(body, "alice"));
        ASSERT(!contains(body, "02:11:22"));
        ASSERT(!contains(body, "02:66:77"));
    }

    const char *j = json();
    ASSERT(contains(j, "\"exposure\": {\"designated\":true,\"ssids\":0,\"bssids\":1,"
                       "\"rostered\":1,\"groups\":["));
    ASSERT(contains(j, "{\"group\":\"setup_mode\",\"title\":\"Devices in setup mode\","
                       "\"state\":\"found\",\"findings\":1,\"evidence\":4,\"outside\":1,"
                       "\"assessed\":true,"));
    ASSERT(contains(j, "\"lines\":[{\"kind\":\"OPEN_SETUP_AP\",\"findings\":1,"
                       "\"evidence\":4,\"first_seen\":\"2027-01-15T08:00:00Z\","
                       "\"last_seen\":\"2027-01-15T08:05:00Z\",\"remedy\":"));
    ASSERT(contains(j, "{\"group\":\"credentials\","));
    ASSERT(contains(j, "\"lines\":[{\"kind\":\"CLEARTEXT_CRED\",\"findings\":1,"
                       "\"evidence\":3,"));
    ASSERT_EQ(count_of(j, "\"group\":"), EXP_G_COUNT - 1);
    end();
}

/* The same acceptance case with the rules firing: the beacon, the
 * credential and the camera announcement seeded as their parsers would
 * leave them and alerts_update() run, so the scope test is held to the
 * keys and match_ip the rules write, not to a copy of their format.
 * Seen red with rule_open_setup_ap()'s key writing the BSSID with '-'
 * separators (test_setup_ap_and_cleartext_cred stayed green), and with
 * names_rostered_ip()'s match_ip test removed (the camera group read
 * none_*). An upper-case BSSID or an extra component does not change
 * scope: each_mac() reads either. */
static void test_rules_fire_into_the_report(void) {
    begin();
    one_hopping_radio();
    ip_capture_up();
    tick();
    alerts_clear();
    ASSERT(ownership_add_bssid("02:11:22:33:44:55"));
    roster_laptop("192.0.2.10");
    device_t *cam = &g_s.devices[g_s.device_count++];
    memset(cam, 0, sizeof(*cam));
    static const uint8_t CAM_MAC[6] = { 0x02, 0x00, 0x5e, 0x10, 0x00, 0x02 };
    memcpy(cam->mac, CAM_MAC, 6);
    snprintf(cam->ip, sizeof(cam->ip), "192.0.2.20");
    ASSERT(ownership_add_known_mac("02:00:5e:10:00:02"));

    static const uint8_t *const bss[2] = { SETUP_BSS, NEIGH_BSS };
    for (int i = 0; i < 2; i++) {
        beacon_ap_t *b = &g_s.beacon_aps[g_s.beacon_count++];
        memset(b, 0, sizeof(*b));
        snprintf(b->ssid, sizeof(b->ssid), "SETUP-A1B%d", i);
        memcpy(b->bssid, bss[i], 6);
        snprintf(b->enc, sizeof(b->enc), "OPEN");
        b->channel = 6;
        b->signal_dbm = -55;
        b->last_seen = g_wall;
        memcpy(b->fp.oui, bss[i], 3);
    }
    static const char *const src[2] = { "192.0.2.10", "192.0.2.99" };
    static const char *const user[2] = { "alice", "bob" };
    for (int i = 0; i < 2; i++) {
        cleartext_cred_t *c = &g_s.cleartext_creds[g_s.cleartext_cred_count++];
        memset(c, 0, sizeof(*c));
        snprintf(c->src, sizeof(c->src), "%s", src[i]);
        snprintf(c->dst, sizeof(c->dst), "198.51.100.5");
        snprintf(c->protocol, sizeof(c->protocol), "FTP");
        snprintf(c->username, sizeof(c->username), "%s", user[i]);
        c->dst_port = 21;
    }
    /* The rostered camera announces itself with a UUID, the usual ONVIF
     * case: its key has no address. */
    onvif_device_t *o = &g_s.onvif_devices[g_s.onvif_count++];
    memset(o, 0, sizeof(*o));
    snprintf(o->ip, sizeof(o->ip), "192.0.2.20");
    snprintf(o->uuid, sizeof(o->uuid), "urn:uuid:4509a7c0-3b13-11e6-ac61-9e71128cae77");
    snprintf(o->kind, sizeof(o->kind), "Hello");
    o->is_camera = 1;
    o->last_seen = g_wall;

    alerts_update(&g_s);
    int setup = 0, cred = 0, wsd = 0;
    for (int i = 0; i < g_s.alert_count; i++) {
        setup += g_s.alerts[i].type == ALERT_TYPE_OPEN_SETUP_AP;
        cred  += g_s.alerts[i].type == ALERT_TYPE_CLEARTEXT_CRED;
        wsd   += g_s.alerts[i].type == ALERT_TYPE_CAM_WS_DISCOVERY;
    }
    ASSERT_EQ(setup, 2);
    ASSERT_EQ(cred, 2);
    ASSERT_EQ(wsd, 1);

    exp_group_sum_t sum[EXP_G_COUNT];
    exp_summarise(&g_s, sum);
    ASSERT_EQ((int)sum[EXP_G_SETUP].state, (int)EXP_ST_FOUND);
    ASSERT_EQ(sum[EXP_G_SETUP].findings, 1);
    ASSERT_EQ(sum[EXP_G_SETUP].outside, 1);
    ASSERT_EQ((int)sum[EXP_G_CREDS].state, (int)EXP_ST_FOUND);
    ASSERT_EQ(sum[EXP_G_CREDS].findings, 1);
    ASSERT_EQ(sum[EXP_G_CREDS].outside, 1);
    ASSERT_EQ((int)sum[EXP_G_ANNOUNCE].state, (int)EXP_ST_FOUND);
    ASSERT_EQ(sum[EXP_G_ANNOUNCE].findings, 1);
    ASSERT_EQ(sum[EXP_G_ANNOUNCE].outside, 0);
    const char *m = md();
    ASSERT(contains(section(m, EXP_G_SETUP), "- `OPEN_SETUP_AP`: 1 finding,"));
    ASSERT(contains(section(m, EXP_G_CREDS), "- `CLEARTEXT_CRED`: 1 finding,"));
    ASSERT(contains(section(m, EXP_G_ANNOUNCE), "- `CAM_WS_DISCOVERY`: 1 finding,"));
    alerts_clear();
    g_s.alert_count = 0;
    end();
}

/* A site with nothing found: each group says so, with its rules'
 * status, so the empty group is not read as an empty site. */
static void test_nothing_found_states_coverage(void) {
    begin();
    /* One hopping radio, no IP capture, a roster and no designated
     * network: MY_NETWORK_RECON reads blind (no_own_net), the IP rules
     * blind (no_source), the 802.11 ones partly (hop). */
    one_hopping_radio();
    roster_laptop("192.0.2.10");
    tick();
    exp_group_sum_t sum[EXP_G_COUNT];
    exp_summarise(&g_s, sum);
    for (int g = EXP_G_NONE + 1; g < EXP_G_COUNT; g++) {
        ASSERT(sum[g].assessed);
        ASSERT_EQ(sum[g].findings, 0);
        ASSERT_EQ(sum[g].observable + sum[g].partly + sum[g].blind, sum[g].rules);
    }
    ASSERT_EQ((int)sum[EXP_G_NAMES].state, (int)EXP_ST_NOT_OBSERVABLE);
    ASSERT_EQ((int)sum[EXP_G_ANNOUNCE].state, (int)EXP_ST_NOT_OBSERVABLE);
    ASSERT_EQ((int)sum[EXP_G_CREDS].state, (int)EXP_ST_NONE_PARTLY);
    /* A STATE rule reads its evidence in one visit: hop costs it
     * nothing (rule_coverage.h), so the setup group is observable. */
    ASSERT_EQ((int)sum[EXP_G_SETUP].state, (int)EXP_ST_NONE_OBSERVABLE);

    const char *m = md();
    ASSERT(contains(section(m, EXP_G_NAMES), "Not observable: no_own_net."));
    ASSERT(contains(section(m, EXP_G_NAMES), "Rules: 1; observable 0, partly 0, blind 1 (no_own_net)."));
    ASSERT(contains(section(m, EXP_G_ANNOUNCE), "Not observable: no_source."));
    ASSERT(contains(section(m, EXP_G_CREDS), "Nothing found; rules partly observable: no_source,hop."));
    ASSERT(contains(section(m, EXP_G_SETUP), "Nothing found, rules observable."));
    /* No group is silent, and none says "found". */
    for (int g = EXP_G_NONE + 1; g < EXP_G_COUNT; g++) {
        const char *sx = section(m, g);
        ASSERT(contains(sx, "Not observable: ") || contains(sx, "Nothing found"));
        ASSERT(!contains(sx, "Found:"));
    }

    /* The IP capture up and a designated network: the LAN-only group
     * reads observable; the credentials group has CLEARTEXT_CRED
     * observable and PEAP_NO_SERVER_CERT partly (hop), so it is partly
     * with no blind rule. Seen red with exp_summarise()'s partly test
     * dropped (`gs->blind || gs->partly` -> `gs->blind`): group 3 then
     * read "rules observable" with a rule the hop costs evidence. */
    ip_capture_up();
    ASSERT(ownership_add_ssid("HomeNet"));
    tick();
    exp_summarise(&g_s, sum);
    ASSERT_EQ((int)sum[EXP_G_ANNOUNCE].state, (int)EXP_ST_NONE_OBSERVABLE);
    ASSERT_EQ((int)sum[EXP_G_CREDS].state, (int)EXP_ST_NONE_PARTLY);
    ASSERT_EQ(sum[EXP_G_CREDS].blind, 0);
    m = md();
    ASSERT(contains(section(m, EXP_G_ANNOUNCE), "Nothing found, rules observable."));
    ASSERT(contains(section(m, EXP_G_CREDS), "Nothing found; rules partly observable: hop."));
    ASSERT(!contains(section(m, EXP_G_CREDS), "rules observable."));
    end();
}

static void test_not_assessed_before_a_sample(void) {
    begin();
    ASSERT(ownership_add_ssid("HomeNet"));
    const char *m = md();
    ASSERT(contains(section(m, EXP_G_SETUP),
                    "Nothing found; coverage not assessed: no status sample has been "
                    "taken yet."));
    ASSERT(contains(section(m, EXP_G_SETUP), "Rules: 3, not assessed."));
    /* No count that would read as coverage. Seen red with
     * md_coverage()'s assessed test removed ("observable 0"). */
    ASSERT(!contains(section(m, EXP_G_SETUP), "observable 0"));
    end();
}

/* ── the record ────────────────────────────────────────────────────── */

static void sink_open(void) {
    g_path[0] = '\0';
    int fd = mkstemp(test_tmp_tpl(g_path, sizeof(g_path), "sloth_exp_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    db_close();
    unlink(g_path);
    ASSERT(jsonl_open(g_path));
}

static const char *sink_read(void) {
    jsonl_close();
    g_buf[0] = '\0';
    FILE *fp = fopen(g_path, "r");
    if (fp) {
        size_t n = fread(g_buf, 1, sizeof(g_buf) - 1, fp);
        g_buf[n] = '\0';
        fclose(fp);
    }
    unlink(g_path);
    return g_buf;
}

static void test_record(void) {
    begin();
    one_hopping_radio();
    ip_capture_up();
    tick();
    ASSERT(ownership_add_bssid("02:11:22:33:44:55"));
    roster_laptop("192.0.2.10");
    char key[ALERT_KEY_LEN];
    key_opensetup(key, sizeof(key), SETUP_BSS);
    alert_t *setup = seed(ALERT_TYPE_OPEN_SETUP_AP, key, 4, 1800000000, 1800000300);
    key_cred(key, sizeof(key), "192.0.2.10", "alice");
    seed(ALERT_TYPE_CLEARTEXT_CRED, key, 3, 1800000010, 1800000200);

    sink_open();
    exp_emit(&g_s);
    const char *out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"exposure_summary\""), EXP_G_COUNT - 1);
    ASSERT(contains(out, "\"group\":\"setup_mode\",\"designated\":1,\"state\":\"found\","
                         "\"findings\":1,\"evidence\":4,\"outside\":0,"
                         "\"kinds\":\"OPEN_SETUP_AP\",\"first_seen\":1800000000,"
                         "\"last_seen\":1800000300,\"rules\":3,\"assessed\":1,"));
    ASSERT(contains(out, "\"group\":\"credentials\",\"designated\":1,\"state\":\"found\","
                         "\"findings\":1,\"evidence\":3,\"outside\":0,"
                         "\"kinds\":\"CLEARTEXT_CRED\","));
    ASSERT(contains(out, "\"group\":\"network_names\",\"designated\":1,"
                         "\"state\":\"not_observable\",\"findings\":0,"));
    /* The fleet rule: kinds, counts, words and times only. No address,
     * name or user name, wherever the finding came from. */
    ASSERT(!contains(out, "192.0.2."));
    ASSERT(!contains(out, "198.51.100."));
    ASSERT(!contains(out, "alice"));
    ASSERT(!contains(out, "02:11:22"));
    ASSERT(!contains(out, "02:00:5e"));
    ASSERT(!contains(out, "\"remedy\""));

    /* Change-only: the same picture writes nothing; more evidence and a
     * later last_seen on the same finding write nothing either (they
     * move with every observation, outside the signature). Seen red
     * with gs->evidence added to sig_v (a line per group whose evidence
     * moved). */
    /* (jsonl_open() clears the change cache, so one sink holds the
     * first emission and everything after it.) */
    sink_open();
    exp_emit(&g_s);
    exp_emit(&g_s);
    setup->observations += 5;
    setup->last_seen += 60;
    exp_emit(&g_s);
    out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"exposure_summary\""), EXP_G_COUNT - 1);

    /* A new finding is a change: its group's line, and only that one. */
    sink_open();
    exp_emit(&g_s);
    seed(ALERT_TYPE_CAM_SETUP_OUI, "camoui:02:11:22:33:44:55", 1, 1800000400, 1800000400);
    exp_emit(&g_s);
    out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"exposure_summary\""), EXP_G_COUNT);
    ASSERT_EQ(count_of(out, "\"group\":\"setup_mode\""), 2);
    ASSERT(contains(out, "\"kinds\":\"OPEN_SETUP_AP,CAM_SETUP_OUI\""));
    ASSERT(contains(out, "\"evidence\":10,"));
    end();
}

static void test_record_undesignated(void) {
    begin();
    sink_open();
    exp_emit(&g_s);
    const char *out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"exposure_summary\""), EXP_G_COUNT - 1);
    ASSERT_EQ(count_of(out, "\"designated\":0,\"state\":\"needs_designation\""),
              EXP_G_COUNT - 1);
    /* Not assessed: the coverage counts are absent, never 0. */
    ASSERT(!contains(out, "\"observable\""));
    ASSERT(!contains(out, "\"first_seen\""));
    end();
}

void run_exposure_tests(void) {
    TEST_SUITE("exposure report (#243)");
    RUN_TEST(test_def_matches_alert_list);
    RUN_TEST(test_rows_are_well_formed);
    RUN_TEST(test_named_groups);
    RUN_TEST(test_names);
    RUN_TEST(test_remedy_is_the_pages_first_fix_step);
    RUN_TEST(test_scope_air);
    RUN_TEST(test_scope_ssid_in_key);
    RUN_TEST(test_raw_ssid_key_shape_is_the_rules);
    RUN_TEST(test_scope_lan);
    RUN_TEST(test_undesignated_site_names_the_flags);
    RUN_TEST(test_setup_ap_and_cleartext_cred);
    RUN_TEST(test_rules_fire_into_the_report);
    RUN_TEST(test_nothing_found_states_coverage);
    RUN_TEST(test_not_assessed_before_a_sample);
    RUN_TEST(test_record);
    RUN_TEST(test_record_undesignated);
}
