/* What this site reveals (#243): src/exposure.h. */

#include <ctype.h>
#include <string.h>
#include "exposure.h"
#include "alert_key.h"
#include "ownership.h"
#include "rule_coverage_live.h"
#include "jsonl.h"
#include "jsonl_internal.h"
#include "sloth_clock.h"

/* ── The table ────────────────────────────────────────────────────── */

typedef struct {
    exp_group_t g;
    exp_scope_t sc;
    const char *remedy;
} exp_row_t;

static const exp_row_t k_rows[] = {
#define X(id, group, scope, remedy) { EXP_G_##group, EXP_S_##scope, remedy },
#include "sloth_exposure.def"
#undef X
};

/* A row appended to sloth_alerts.def with none here fails the build
 * before it fails the test. */
typedef char exp_rows_match_kinds[
    (sizeof(k_rows) / sizeof(k_rows[0]) == ALERT_TYPE_COUNT) ? 1 : -1];

static const exp_row_t *row(alert_type_t t) {
    if ((int)t < 0 || t >= ALERT_TYPE_COUNT) return NULL;
    return &k_rows[t];
}

exp_group_t exp_group_of(alert_type_t t) { const exp_row_t *r = row(t); return r ? r->g : EXP_G_NONE; }
exp_scope_t exp_scope_of(alert_type_t t) { const exp_row_t *r = row(t); return r ? r->sc : EXP_S_NA; }
const char *exp_remedy(alert_type_t t)   { const exp_row_t *r = row(t); return r ? r->remedy : ""; }

const char *exp_group_name(exp_group_t g) {
    switch (g) {
    case EXP_G_NAMES:    return "network_names";
    case EXP_G_DEVICES:  return "devices";
    case EXP_G_CREDS:    return "credentials";
    case EXP_G_ANNOUNCE: return "self_announcing";
    case EXP_G_LANES:    return "weak_lanes";
    case EXP_G_SETUP:    return "setup_mode";
    default:             return "";
    }
}

const char *exp_group_title(exp_group_t g) {
    switch (g) {
    case EXP_G_NAMES:    return "Network names and their history";
    case EXP_G_DEVICES:  return "Device makes, models and presence times";
    case EXP_G_CREDS:    return "Credentials and user names in clear text";
    case EXP_G_ANNOUNCE: return "Cameras and other devices that announce themselves";
    case EXP_G_LANES:    return "Weak encryption lanes a device can be moved to";
    case EXP_G_SETUP:    return "Devices in setup mode";
    default:             return "";
    }
}

const char *exp_state_name(exp_state_t st) {
    switch (st) {
    case EXP_ST_NEEDS_DESIGNATION: return "needs_designation";
    case EXP_ST_FOUND:             return "found";
    case EXP_ST_NONE_OBSERVABLE:   return "none_observable";
    case EXP_ST_NONE_PARTLY:       return "none_partly";
    case EXP_ST_NOT_OBSERVABLE:    return "not_observable";
    case EXP_ST_NOT_ASSESSED:      return "not_assessed";
    }
    return "";
}

int exp_designated(void) {
    return ownership_any() || ownership_known_count() > 0;
}

/* ── Scope ────────────────────────────────────────────────────────── */

/* A key is ':'-joined components (src/alert_key.h); an IPv6 address
 * sits in brackets. A component starts at the key's start, after ':'
 * or after '['. */
static int starts_token(const char *key, const char *p) {
    return p == key || p[-1] == ':' || p[-1] == '[';
}
static int ends_token(char c) {
    return c == '\0' || c == ':' || c == ']';
}

/* Every "aa:bb:cc:dd:ee:ff" in the key, each passed to `fn`; 1 at the
 * first for which it answers 1. */
static int each_mac(const char *key, int (*fn)(const sloth_state_t *, const uint8_t[6]),
                    const sloth_state_t *s) {
    size_t n = strlen(key);
    for (size_t i = 0; i + 17 <= n; i++) {
        const char *p = key + i;
        if (!starts_token(key, p) || !ends_token(p[17])) continue;
        int ok = 1;
        for (int k = 0; k < 17 && ok; k++)
            ok = (k % 3 == 2) ? p[k] == ':' : isxdigit((unsigned char)p[k]) != 0;
        if (!ok) continue;
        char buf[18];
        memcpy(buf, p, 17);
        buf[17] = '\0';
        uint8_t mac[6];
        if (ownership_parse_mac(buf, mac) && fn(s, mac)) return 1;
    }
    return 0;
}

/* `needle` as a whole component of `key`. */
static int has_token(const char *key, const char *needle) {
    size_t nl = strlen(needle);
    if (!nl) return 0;
    for (const char *p = strstr(key, needle); p; p = strstr(p + 1, needle))
        if (starts_token(key, p) && ends_token(p[nl])) return 1;
    return 0;
}

static int mac_is_site(const sloth_state_t *s, const uint8_t mac[6]) {
    if (ownership_is_my_bssid(mac) || ownership_is_known_device(mac)) return 1;
    /* A BSSID beaconing a designated SSID. */
    for (int i = 0; i < s->beacon_count && i < MAX_BEACON_APS; i++) {
        const beacon_ap_t *b = &s->beacon_aps[i];
        if (memcmp(b->bssid, mac, 6) == 0 && ownership_is_my_ssid(b->ssid)) return 1;
    }
    return 0;
}

/* A designated SSID in the key: raw (a key built with "%.40s") or as
 * akey_remote() writes it, whose last component is a hash of the whole
 * string, so a long or sanitised SSID still matches. */
static int key_names_my_ssid(const char *key) {
    for (int i = 0; i < ownership_ssid_count(); i++) {
        const char *ssid = ownership_ssid_at(i);
        if (!ssid || !ssid[0]) continue;
        if (!strchr(ssid, ':') && has_token(key, ssid)) return 1;
        char buf[ALERT_KEY_LEN];
        akey_t k;
        akey_begin(&k, buf, sizeof(buf), "x");
        akey_remote(&k, ssid, 32);
        const char *enc = akey_end(&k);
        size_t el = strlen(enc);
        if (el > 17 && has_token(key, enc + el - 16)) return 1;
    }
    return 0;
}

/* The managed link is associated to a designated network: what the IP
 * capture sees is then that network's. */
static int lan_is_designated(const sloth_state_t *s) {
    for (int i = 0; i < s->ap_count && i < MAX_WIFI_APS; i++) {
        const wifi_ap_t *a = &s->aps[i];
        if (a->status != WIFI_STATUS_ASSOC) continue;
        if (ownership_is_my_ssid(a->ssid)) return 1;
        uint8_t b[6];
        if (ownership_parse_mac(a->bssid, b) && ownership_is_my_bssid(b)) return 1;
    }
    return 0;
}

static int key_names_rostered_ip(const sloth_state_t *s, const char *key) {
    for (int i = 0; i < s->device_count && i < MAX_DEVICES; i++) {
        const device_t *d = &s->devices[i];
        if (!d->ip[0] || !ownership_is_known_device(d->mac)) continue;
        if (has_token(key, d->ip)) return 1;
    }
    return 0;
}

int exp_in_scope(const sloth_state_t *s, const alert_t *a) {
    if (!s || !a || !exp_designated()) return 0;
    switch (exp_scope_of(a->type)) {
    case EXP_S_OWN:
        return 1;
    case EXP_S_AIR:
        return each_mac(a->key, mac_is_site, s) || key_names_my_ssid(a->key);
    case EXP_S_LAN:
        return lan_is_designated(s) || key_names_rostered_ip(s, a->key);
    default:
        return 0;
    }
}

/* ── Summary ──────────────────────────────────────────────────────── */

int exp_why_str(unsigned why, char *out, size_t sz) {
    if (!out || !sz) return 0;
    out[0] = '\0';
    size_t off = 0;
    for (int r = COV_R_NONE + 1; r < COV_R_COUNT; r++) {
        if (!(why & (1u << r))) continue;
        int n = snprintf(out + off, sz - off, "%s%s", off ? "," : "",
                         cov_reason_name((cov_reason_t)r));
        if (n < 0 || (size_t)n >= sz - off) { out[off] = '\0'; break; }
        off += (size_t)n;
    }
    return (int)off;
}

static void sum_coverage(exp_group_sum_t *gs) {
    gs->assessed = cov_live_state() == COV_LIVE_VALID;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        if (exp_group_of((alert_type_t)t) != gs->g) continue;
        gs->rules++;
        cov_status_t st;
        cov_reason_t why;
        if (!gs->assessed || !cov_live_get((alert_type_t)t, &st, &why)) continue;
        if (st == COV_OBSERVABLE)  gs->observable++;
        else if (st == COV_PARTLY) gs->partly++;
        else                       gs->blind++;
        if (st != COV_OBSERVABLE && why != COV_R_NONE) gs->why |= 1u << why;
    }
}

static void add_finding(exp_group_sum_t *gs, const alert_t *a) {
    exp_line_t *ln = NULL;
    for (int i = 0; i < gs->nlines; i++)
        if (gs->line[i].kind == a->type) { ln = &gs->line[i]; break; }
    if (!ln) {
        if (gs->nlines >= EXP_KINDS_MAX) return;
        /* Kept in sloth_alerts.def order. */
        int at = gs->nlines;
        while (at > 0 && gs->line[at - 1].kind > a->type) {
            gs->line[at] = gs->line[at - 1];
            at--;
        }
        ln = &gs->line[at];
        memset(ln, 0, sizeof(*ln));
        ln->kind = a->type;
        gs->nlines++;
    }
    long ev = a->observations ? (long)a->observations : (a->count > 0 ? a->count : 1);
    ln->findings++;
    ln->evidence += ev;
    if (a->first_seen && (!ln->first_seen || a->first_seen < ln->first_seen))
        ln->first_seen = a->first_seen;
    if (a->last_seen > ln->last_seen) ln->last_seen = a->last_seen;
    gs->findings++;
    gs->evidence += ev;
    if (a->first_seen && (!gs->first_seen || a->first_seen < gs->first_seen))
        gs->first_seen = a->first_seen;
    if (a->last_seen > gs->last_seen) gs->last_seen = a->last_seen;
}

void exp_summarise(const sloth_state_t *s, exp_group_sum_t out[EXP_G_COUNT]) {
    if (!out) return;
    memset(out, 0, sizeof(exp_group_sum_t) * EXP_G_COUNT);
    int designated = exp_designated();
    for (int g = EXP_G_NONE + 1; g < EXP_G_COUNT; g++) {
        out[g].g = (exp_group_t)g;
        sum_coverage(&out[g]);
    }
    if (designated && s) {
        for (int i = 0; i < s->alert_count && i < MAX_ALERTS; i++) {
            const alert_t *a = &s->alerts[i];
            exp_group_t g = exp_group_of(a->type);
            if (g == EXP_G_NONE) continue;
            if (exp_in_scope(s, a)) add_finding(&out[g], a);
            else                    out[g].outside++;
        }
    }
    for (int g = EXP_G_NONE + 1; g < EXP_G_COUNT; g++) {
        exp_group_sum_t *gs = &out[g];
        if (!designated)                      gs->state = EXP_ST_NEEDS_DESIGNATION;
        else if (gs->findings > 0)            gs->state = EXP_ST_FOUND;
        else if (!gs->assessed)               gs->state = EXP_ST_NOT_ASSESSED;
        else if (gs->blind == gs->rules)      gs->state = EXP_ST_NOT_OBSERVABLE;
        else if (gs->blind || gs->partly)     gs->state = EXP_ST_NONE_PARTLY;
        else                                  gs->state = EXP_ST_NONE_OBSERVABLE;
    }
}

/* ── The report ───────────────────────────────────────────────────── */

static void iso(char out[32], time_t t) {
    struct tm tm_buf;
    struct tm *tm = t ? gmtime_r(&t, &tm_buf) : NULL;
    if (tm) strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", tm);
    else    snprintf(out, 32, "-");
}

#define EXP_FLAGS "`--my-ssid`, `--my-bssid`, `--known-mac` or `--known-macs`"

/* The group's one-sentence statement. */
static void md_statement(FILE *out, const exp_group_sum_t *gs) {
    char why[160];
    exp_why_str(gs->why, why, sizeof(why));
    switch (gs->state) {
    case EXP_ST_FOUND:
        fprintf(out, "Found: %d finding%s of %d kind%s.", gs->findings,
                gs->findings == 1 ? "" : "s", gs->nlines, gs->nlines == 1 ? "" : "s");
        break;
    case EXP_ST_NONE_OBSERVABLE:
        fprintf(out, "Nothing found, rules observable.");
        break;
    case EXP_ST_NONE_PARTLY:
        fprintf(out, "Nothing found; rules partly observable: %s.", why[0] ? why : "?");
        break;
    case EXP_ST_NOT_OBSERVABLE:
        fprintf(out, "Not observable: %s.", why[0] ? why : "?");
        break;
    case EXP_ST_NOT_ASSESSED:
        fprintf(out, "Nothing found; coverage not assessed: %s.",
                cov_live_state_why(cov_live_state()));
        break;
    case EXP_ST_NEEDS_DESIGNATION:
        break;
    }
}

static void md_coverage(FILE *out, const exp_group_sum_t *gs) {
    if (!gs->assessed) {
        fprintf(out, " Rules: %d, not assessed.", gs->rules);
        return;
    }
    char why[160];
    exp_why_str(gs->why, why, sizeof(why));
    fprintf(out, " Rules: %d; observable %d, partly %d, blind %d%s%s%s.", gs->rules,
            gs->observable, gs->partly, gs->blind,
            why[0] ? " (" : "", why, why[0] ? ")" : "");
}

void exp_report_md(FILE *out, const sloth_state_t *s) {
    if (!out) return;
    fprintf(out, "## What this site reveals\n\n");
    if (!exp_designated()) {
        fprintf(out, "Not produced: this section is about the operator's own site "
                     "and nothing is designated, so it does not list the "
                     "neighbourhood. Name the site with " EXP_FLAGS
                     " (docs/wiki/exposure-report.md).\n\n");
        return;
    }
    fprintf(out, "What an outside observer can learn about the designated networks "
                 "(%d SSID%s, %d BSSID%s) and rostered devices (%d), by what it "
                 "learns. Each group states whether its rules could see: "
                 "nothing found is not nothing there "
                 "(docs/wiki/exposure-report.md).\n\n",
            ownership_ssid_count(), ownership_ssid_count() == 1 ? "" : "s",
            ownership_bssid_count(), ownership_bssid_count() == 1 ? "" : "s",
            ownership_known_count());
    exp_group_sum_t sum[EXP_G_COUNT];
    exp_summarise(s, sum);
    for (int g = EXP_G_NONE + 1; g < EXP_G_COUNT; g++) {
        const exp_group_sum_t *gs = &sum[g];
        fprintf(out, "### %d. %s\n\n", g, exp_group_title((exp_group_t)g));
        md_statement(out, gs);
        md_coverage(out, gs);
        fprintf(out, "\n\n");
        for (int i = 0; i < gs->nlines; i++) {
            const exp_line_t *ln = &gs->line[i];
            char f[32], l[32];
            iso(f, ln->first_seen);
            iso(l, ln->last_seen);
            fprintf(out, "- `%s`: %d finding%s, evidence %ld, first `%s`, last `%s`. "
                         "Fix: %s\n",
                    cov_kind_name(ln->kind), ln->findings, ln->findings == 1 ? "" : "s",
                    ln->evidence, f, l, exp_remedy(ln->kind));
        }
        if (gs->nlines) fprintf(out, "\n");
        if (gs->outside)
            fprintf(out, "_%d finding%s of this group outside the designation, "
                         "not listed._\n\n",
                    gs->outside, gs->outside == 1 ? "" : "s");
    }
}

static void json_str(FILE *out, const char *v) {
    char buf[1024];
    int off = 0;
    jsonl_escape(v ? v : "", buf, (int)sizeof(buf), &off);
    fprintf(out, "\"%s\"", buf);
}

void exp_report_json(FILE *out, const sloth_state_t *s) {
    if (!out) return;
    fprintf(out, "  \"exposure\": {");
    if (!exp_designated()) {
        fprintf(out, "\"designated\":false,\"needs\":[\"--my-ssid\",\"--my-bssid\","
                     "\"--known-mac\",\"--known-macs\"]},\n");
        return;
    }
    fprintf(out, "\"designated\":true,\"ssids\":%d,\"bssids\":%d,\"rostered\":%d,"
                 "\"groups\":[",
            ownership_ssid_count(), ownership_bssid_count(), ownership_known_count());
    exp_group_sum_t sum[EXP_G_COUNT];
    exp_summarise(s, sum);
    for (int g = EXP_G_NONE + 1; g < EXP_G_COUNT; g++) {
        const exp_group_sum_t *gs = &sum[g];
        char why[160];
        exp_why_str(gs->why, why, sizeof(why));
        fprintf(out, "%s{\"group\":\"%s\",\"title\":", g > 1 ? "," : "",
                exp_group_name((exp_group_t)g));
        json_str(out, exp_group_title((exp_group_t)g));
        fprintf(out, ",\"state\":\"%s\",\"findings\":%d,\"evidence\":%ld,"
                     "\"outside\":%d,\"assessed\":%s,\"rules\":%d",
                exp_state_name(gs->state), gs->findings, gs->evidence, gs->outside,
                gs->assessed ? "true" : "false", gs->rules);
        if (gs->assessed)
            fprintf(out, ",\"observable\":%d,\"partly\":%d,\"blind\":%d,\"why\":\"%s\"",
                    gs->observable, gs->partly, gs->blind, why);
        fprintf(out, ",\"lines\":[");
        for (int i = 0; i < gs->nlines; i++) {
            const exp_line_t *ln = &gs->line[i];
            char f[32], l[32];
            iso(f, ln->first_seen);
            iso(l, ln->last_seen);
            fprintf(out, "%s{\"kind\":\"%s\",\"findings\":%d,\"evidence\":%ld,"
                         "\"first_seen\":\"%s\",\"last_seen\":\"%s\",\"remedy\":",
                    i ? "," : "", cov_kind_name(ln->kind), ln->findings, ln->evidence,
                    f, l);
            json_str(out, exp_remedy(ln->kind));
            fprintf(out, "}");
        }
        fprintf(out, "]}");
    }
    fprintf(out, "]},\n");
}

/* ── The stream ───────────────────────────────────────────────────── */

void exp_emit(const sloth_state_t *s) {
    if (!jsonl_any_sink()) return;
    time_t wall = sloth_wall();
    int designated = exp_designated();
    exp_group_sum_t sum[EXP_G_COUNT];
    exp_summarise(s, sum);
    for (int g = EXP_G_NONE + 1; g < EXP_G_COUNT; g++) {
        const exp_group_sum_t *gs = &sum[g];
        char kinds[512] = "", why[160];
        size_t off = 0;
        for (int i = 0; i < gs->nlines; i++) {
            int n = snprintf(kinds + off, sizeof(kinds) - off, "%s%s", off ? "," : "",
                             cov_kind_name(gs->line[i].kind));
            if (n < 0 || (size_t)n >= sizeof(kinds) - off) break;
            off += (size_t)n;
        }
        exp_why_str(gs->why, why, sizeof(why));
        /* Words and counts of findings only. The evidence total and the
         * times move with every observation, so they ride the record and
         * stay out of the signature (agents/AGENTS.md, change-only
         * emission): a new finding, a new kind, a changed state or a
         * changed coverage is what writes a line. */
        const int sig_v[9] = { designated, (int)gs->state, gs->findings, gs->outside,
                               gs->assessed, gs->observable, gs->partly, gs->blind,
                               (int)gs->why };
        uint64_t sig = jsonl_fnv1a(sig_v, sizeof(sig_v), 0);
        sig = jsonl_fnv1a(kinds, strlen(kinds), sig);
        uint8_t key = (uint8_t)g;
        if (!jsonl_changed(JD_EXPOSURE, &key, 1, sig, wall)) continue;

        jsonl_field_t f[16];
        int n = 0;
#define FS(k, v)  f[n++] = (jsonl_field_t){ (k), JSONL_F_STR, (v), 0, 0.0, 0 }
#define FI(k, v)  f[n++] = (jsonl_field_t){ (k), JSONL_F_INT, NULL, (long long)(v), 0.0, 0 }
        FS("group", exp_group_name((exp_group_t)g));
        FI("designated", designated);
        FS("state", exp_state_name(gs->state));
        FI("findings", gs->findings);
        FI("evidence", gs->evidence);
        FI("outside", gs->outside);
        FS("kinds", kinds);
        if (gs->first_seen) FI("first_seen", gs->first_seen);
        if (gs->last_seen)  FI("last_seen", gs->last_seen);
        FI("rules", gs->rules);
        FI("assessed", gs->assessed);
        if (gs->assessed) {
            FI("observable", gs->observable);
            FI("partly", gs->partly);
            FI("blind", gs->blind);
            FS("why", why);
        }
#undef FS
#undef FI
        jsonl_emit_fields("exposure_summary", wall, f, n);
    }
}
