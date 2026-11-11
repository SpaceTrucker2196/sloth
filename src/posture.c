/* Posture report export — roadmap #16 phase 5.
 *
 * Renders a summary of what sloth observed this session into either
 * Markdown (for hand-audit) or JSON (for SIEM diff / CI compare).
 * Reads only sloth_state_t and the alert/cleartext ring snapshots
 * that are already there — no new observation surface. Runs once at
 * shutdown so the file is a signed-off session record; since #190 the
 * same renderers also feed a separate live file while the session runs
 * (the last section of this file). */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include "posture.h"
#include "sloth_clock.h"
#include "query.h"
#include "beacon_snoop.h"
#include "db.h"
#include "alerts.h"
#include "wifi_assess.h"
#include "wifi_baseline.h"

/* An IP-only camera device record (#106 round 2) has an all-zero MAC;
 * it is printed as `none`, the same way the JSONL device record does,
 * rather than as an address nobody has. */
static void posture_mac(const uint8_t m[6], char *out, size_t n,
                        const char *none) {
    static const uint8_t z[6] = {0};
    if (memcmp(m, z, 6) == 0) { snprintf(out, n, "%s", none); return; }
    snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void iso_time(char out[32], time_t t) {
    struct tm tm_buf;
    struct tm *tm = gmtime_r(&t, &tm_buf);
    if (tm) strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", tm);
    else    snprintf(out, 32, "?");
}

/* Count alerts by severity so the report can lead with the headline
 * "X CRIT, Y WARN, Z LOW". */
static void alert_sev_counts(const sloth_state_t *s,
                             int *n_low, int *n_warn, int *n_crit)
{
    *n_low = *n_warn = *n_crit = 0;
    for (int i = 0; i < s->alert_count; i++) {
        switch (s->alerts[i].sev) {
        case ALERT_SEV_LOW:  (*n_low)++;  break;
        case ALERT_SEV_WARN: (*n_warn)++; break;
        case ALERT_SEV_CRIT: (*n_crit)++; break;
        }
    }
}

/* Group alerts by ATT&CK technique so the operator can see attack
 * families at a glance. Simple linear scan — alert_count is capped at
 * MAX_ALERTS (128) so this stays cheap. */
typedef struct { char technique[16]; int count; } tech_bucket_t;

static int bucketize_techniques(const sloth_state_t *s,
                                tech_bucket_t *out, int max)
{
    int n = 0;
    for (int i = 0; i < s->alert_count && n < max; i++) {
        const char *t = s->alerts[i].technique;
        if (!t[0]) continue;
        int j;
        for (j = 0; j < n; j++)
            if (strcmp(out[j].technique, t) == 0) { out[j].count++; break; }
        if (j == n) {
            snprintf(out[n].technique, sizeof(out[n].technique), "%s", t);
            out[n].count = 1;
            n++;
        }
    }
    return n;
}

/* `live` is the one difference between the signed-off report and the
 * one written mid-session (#190): a live report has no session end, and
 * says so where the end would be, so it cannot be read as a finished
 * record. */
static int render_md(FILE *out, const sloth_state_t *s,
                     time_t session_start, struct rq_handle *research,
                     int live) {
    if (!out || !s) return 0;
    time_t now = sloth_wall();
    char ts_start[32], ts_end[32];
    iso_time(ts_start, session_start);
    iso_time(ts_end,   now);

    int n_low = 0, n_warn = 0, n_crit = 0;
    alert_sev_counts(s, &n_low, &n_warn, &n_crit);

    fprintf(out, "# sloth posture report\n\n");
    fprintf(out, "- **Session start**: `%s`\n", ts_start);
    if (live) {
        fprintf(out, "- **Session end**:   (running)\n");
        fprintf(out, "- **As of**:         `%s`\n", ts_end);
    } else {
        fprintf(out, "- **Session end**:   `%s`\n", ts_end);
    }
    fprintf(out, "- **Duration**:      `%lds`\n", (long)(now - session_start));
    fprintf(out, "\n");
    fprintf(out, "## Alert summary\n\n");
    fprintf(out, "| Sev | Count |\n|-----|------:|\n");
    fprintf(out, "| CRIT | %d |\n", n_crit);
    fprintf(out, "| WARN | %d |\n", n_warn);
    fprintf(out, "| LOW  | %d |\n", n_low);
    fprintf(out, "| **Total** | **%d** |\n\n", s->alert_count);

    /* ATT&CK breakdown */
    tech_bucket_t techs[32];
    int nt = bucketize_techniques(s, techs, 32);
    if (nt > 0) {
        fprintf(out, "## MITRE ATT&CK techniques observed\n\n");
        fprintf(out, "| Technique | Hits |\n|-----------|-----:|\n");
        for (int i = 0; i < nt; i++)
            fprintf(out, "| `%s` | %d |\n", techs[i].technique, techs[i].count);
        fprintf(out, "\n");
    }

    /* Cleartext credential exposures */
    if (s->cleartext_cred_count > 0) {
        fprintf(out, "## Cleartext credential exposures\n\n");
        fprintf(out, "| src | -> | dst:port | protocol | username | password observed? |\n");
        fprintf(out, "|-----|:--:|----------|----------|----------|-------------------:|\n");
        for (int i = 0; i < s->cleartext_cred_count; i++) {
            const cleartext_cred_t *c = &s->cleartext_creds[i];
            fprintf(out, "| `%s` | -> | `%s:%u` | %s | `%s` | %s |\n",
                    c->src, c->dst, (unsigned)c->dst_port,
                    c->protocol, c->username,
                    c->password_observed ? "yes" : "no");
        }
        fprintf(out, "\n");
        fprintf(out, "*Passwords are never stored; only the fact that one was seen.*\n\n");
    }

    /* Top-risk devices (HIGH + CRIT only). */
    int risky = 0;
    for (int i = 0; i < s->device_count; i++)
        if (s->devices[i].risk_level >= DEV_RISK_HIGH) risky++;
    if (risky > 0) {
        fprintf(out, "## High-risk devices\n\n");
        fprintf(out, "| MAC | IP | Vendor | Hostname | Bucket | Signals |\n");
        fprintf(out, "|-----|----|--------|----------|--------|---------|\n");
        for (int i = 0; i < s->device_count; i++) {
            const device_t *d = &s->devices[i];
            if (d->risk_level < DEV_RISK_HIGH) continue;
            char mac[20];
            posture_mac(d->mac, mac, sizeof(mac), "-");
            fprintf(out, "| `%s` | `%s` | %s | %s | **%s** | `0x%x` |\n",
                    mac,
                    d->ip[0] ? d->ip : "-",
                    d->vendor[0]   ? d->vendor   : "?",
                    d->hostname[0] ? d->hostname : "-",
                    device_risk_label(d->risk_level),
                    (unsigned)d->risk_signals);
        }
        fprintf(out, "\n");
    }

    {
        wifi_finding_t wf[64];
        int wn = wifi_assess(s, wf, 64);
        if (wn > 0) {
            fprintf(out, "## Wireless hygiene findings\n\n");
            fprintf(out, "| Severity | Finding | Evidence |\n");
            fprintf(out, "|----------|---------|----------|\n");
            for (int i = 0; i < wn; i++)
                fprintf(out, "| %s | %s | %s |\n",
                        wf[i].severity, wf[i].title, wf[i].evidence);
            fprintf(out, "\n");
        }
    }

    /* Per-alert references from the research corpus (#73). Populated
     * only when --with-research supplied a readable corpus; absent
     * otherwise, which is the additive contract — a report without
     * citations is the report sloth produced before this existed. */
    if (research && s->alert_count > 0) {
        char seen[MAX_ALERTS][40];
        int  seen_n = 0;
        int  printed_header = 0;

        for (int i = 0; i < s->alert_count; i++) {
            const alert_t *a = &s->alerts[i];
            /* alert_t carries the technique and the title, not the enum
             * name, so the lookup key is the title — which is what the
             * corpus frontmatter would have to name anyway for a human
             * to connect the two. */
            const char *kind = alert_type_name(a->type);
            if (!kind[0]) continue;

            int dup = 0;
            for (int k = 0; k < seen_n; k++)
                if (!strcmp(seen[k], kind)) { dup = 1; break; }
            if (dup) continue;
            if (seen_n < MAX_ALERTS)
                snprintf(seen[seen_n++], sizeof(seen[0]), "%s", kind);

            rq_hit_t hits[RQ_MAX_HITS];
            int n = rq_for_alert(research, kind, hits, RQ_MAX_HITS);
            if (n <= 0) continue;

            if (!printed_header) {
                fprintf(out, "## References\n\n");
                fprintf(out, "Sources backing the alerts above, from the "
                             "research corpus.\n\n");
                printed_header = 1;
            }
            fprintf(out, "**%s**\n\n", a->title);
            for (int k = 0; k < n; k++)
                fprintf(out, "- [%s](%s) — retrieved %s\n",
                        hits[k].title[0] ? hits[k].title : hits[k].path,
                        hits[k].source_url, hits[k].retrieved);
            fprintf(out, "\n");
        }
    }

    /* Downgrade postures (#62). wifi_assess already reports encryption
     * hygiene per AP; this is the narrower question of which APs are
     * advertising a *second, weaker* lane beside their primary one —
     * the prerequisite CVE-2023-52424 and Dragonblood both need. */
    {
        int dg_aps = 0;
        for (int i = 0; i < s->beacon_count; i++)
            if (s->beacon_aps[i].downgrade_flags) dg_aps++;
        if (dg_aps > 0) {
            fprintf(out, "## Downgrade lanes advertised\n\n");
            fprintf(out, "%d AP%s offering a weaker lane beside its "
                         "primary one.\n\n",
                    dg_aps, dg_aps == 1 ? " is" : "s are");
            fprintf(out, "| BSSID | SSID | Lanes |\n");
            fprintf(out, "|-------|------|-------|\n");
            for (int i = 0; i < s->beacon_count; i++) {
                const beacon_ap_t *a = &s->beacon_aps[i];
                if (!a->downgrade_flags) continue;
                char bss[18];
                snprintf(bss, sizeof(bss), "%02x:%02x:%02x:%02x:%02x:%02x",
                         a->bssid[0], a->bssid[1], a->bssid[2],
                         a->bssid[3], a->bssid[4], a->bssid[5]);
                char lanes[96];
                size_t lo = 0;
                lanes[0] = '\0';
                for (int b = 0; b < 4; b++) {
                    uint8_t kind = (uint8_t)(1u << b);
                    if (!(a->downgrade_flags & kind)) continue;
                    int n = snprintf(lanes + lo, sizeof(lanes) - lo, "%s%s",
                                     lo ? ", " : "",
                                     wifi_downgrade_label(kind));
                    if (n < 0 || (size_t)n >= sizeof(lanes) - lo) break;
                    lo += (size_t)n;
                }
                fprintf(out, "| `%s` | %s | **%s** |\n", bss,
                        a->ssid[0] ? a->ssid : "&lt;hidden&gt;", lanes);
            }
            fprintf(out, "\n");
        }
    }

    /* Association downgrades (#60). The ask-vs-ask delta: a client that
     * requested SAE with MFP required and then re-requested for less
     * has been moved, and neither request shows it alone. This is the
     * runtime signature of CVE-2023-52424 from the client side — the
     * AP-side prerequisite is SSID_CONFUSION. */
    {
        int dg = 0;
        for (int i = 0; i < s->assoc_req_count; i++)
            if (s->assoc_reqs[i].downgrade_flags) dg++;

        if (s->assoc_req_count > 0) {
            fprintf(out, "## Association requests\n\n");
            fprintf(out, "%d client ask%s observed, **%d** carrying a "
                         "downgrade.\n\n",
                    s->assoc_req_count, s->assoc_req_count == 1 ? "" : "s",
                    dg);
        }
        if (dg > 0) {
            fprintf(out, "| STA | AP | SSID | Asked | Previously | Lost |\n");
            fprintf(out, "|-----|----|------|-------|------------|------|\n");
            for (int i = 0; i < s->assoc_req_count; i++) {
                const assoc_req_t *r = &s->assoc_reqs[i];
                if (!r->downgrade_flags) continue;
                char sta[18], ap[18], ask[12], prev[12], lost[48];
                snprintf(sta, sizeof(sta), "%02x:%02x:%02x:%02x:%02x:%02x",
                         r->sta[0], r->sta[1], r->sta[2],
                         r->sta[3], r->sta[4], r->sta[5]);
                snprintf(ap, sizeof(ap), "%02x:%02x:%02x:%02x:%02x:%02x",
                         r->bssid[0], r->bssid[1], r->bssid[2],
                         r->bssid[3], r->bssid[4], r->bssid[5]);
                rsn_akm_label(r->akm_bits,      ask,  sizeof(ask));
                rsn_akm_label(r->prev_akm_bits, prev, sizeof(prev));
                lost[0] = '\0';
                size_t lo = 0;
                if (r->downgrade_flags & ASSOC_DG_AKM)
                    lo += (size_t)snprintf(lost + lo, sizeof(lost) - lo,
                                           "%sAKM", lo ? ", " : "");
                if (r->downgrade_flags & ASSOC_DG_MFP)
                    lo += (size_t)snprintf(lost + lo, sizeof(lost) - lo,
                                           "%sMFP (%d->%d)", lo ? ", " : "",
                                           r->prev_mfp, r->requested_mfp);
                if (r->downgrade_flags & ASSOC_DG_PAIRWISE)
                    snprintf(lost + lo, sizeof(lost) - lo,
                             "%scipher", lo ? ", " : "");
                fprintf(out, "| `%s` | `%s` | %s | %s | %s | **%s** |\n",
                        sta, ap,
                        r->requested_ssid[0] ? r->requested_ssid : "-",
                        ask, prev, lost);
            }
            fprintf(out, "\n");
        }
    }

    /* 802.11v steering (#59). Sits in the report because a forced roam
     * is the one Wi-Fi attack that leaves no deauth trace — an operator
     * reading a clean deauth section needs this to know whether clients
     * were moved anyway. Ordinary steering is listed alongside the
     * forcing so the reader can see the baseline it stands out from. */
    if (s->btm_steer_count > 0) {
        int forcing = 0;
        for (int i = 0; i < s->btm_steer_count; i++)
            if (s->btm_steers[i].imminent_count > 0) forcing++;

        fprintf(out, "## 802.11v BSS-Transition steering\n\n");
        fprintf(out, "%d steered client%s observed, %d with "
                     "Disassociation Imminent set.\n\n",
                s->btm_steer_count, s->btm_steer_count == 1 ? "" : "s",
                forcing);
        fprintf(out, "| AP | STA | Requests | Forcing | Candidates |\n");
        fprintf(out, "|----|-----|----------|---------|------------|\n");
        for (int i = 0; i < s->btm_steer_count; i++) {
            const btm_steer_t *b = &s->btm_steers[i];
            char ap[18], sta[18];
            snprintf(ap,  sizeof(ap),  "%02x:%02x:%02x:%02x:%02x:%02x",
                     b->bssid[0], b->bssid[1], b->bssid[2],
                     b->bssid[3], b->bssid[4], b->bssid[5]);
            snprintf(sta, sizeof(sta), "%02x:%02x:%02x:%02x:%02x:%02x",
                     b->sta[0], b->sta[1], b->sta[2],
                     b->sta[3], b->sta[4], b->sta[5]);
            char cand[MAX_AP_NEIGHBORS * 19 + 1];
            size_t off = 0;
            cand[0] = '\0';
            for (int c = 0; c < b->candidate_count && c < MAX_AP_NEIGHBORS; c++) {
                int n = snprintf(cand + off, sizeof(cand) - off,
                                 "%s`%02x:%02x:%02x:%02x:%02x:%02x`",
                                 off ? ", " : "",
                                 b->candidates[c][0], b->candidates[c][1],
                                 b->candidates[c][2], b->candidates[c][3],
                                 b->candidates[c][4], b->candidates[c][5]);
                if (n < 0 || (size_t)n >= sizeof(cand) - off) break;
                off += (size_t)n;
            }
            fprintf(out, "| `%s` | `%s` | %d | %s | %s |\n",
                    ap, sta, b->req_count,
                    b->imminent_count ? "**yes**" : "no",
                    cand[0] ? cand : "-");
        }
        fprintf(out, "\n");
    }

    if (wifi_baseline_ready()) {
        drift_finding_t df[64];
        int dn = wifi_baseline_drift(s, df, 64);
        fprintf(out, "## RF drift since session baseline\n\n");
        if (dn == 0) {
            fprintf(out, "No AP inventory / security / channel drift.\n\n");
        } else {
            fprintf(out, "| Change | Detail |\n");
            fprintf(out, "|--------|--------|\n");
            for (int i = 0; i < dn; i++)
                fprintf(out, "| %s | %s |\n", df[i].kind, df[i].detail);
            fprintf(out, "\n");
        }
    }

    /* New since the previous visit (#56). Only meaningful with --db,
     * because it is a comparison against a persisted history; without
     * one the section is silently absent rather than claiming
     * everything is new. first_seen is MIN-ed across every upsert, so
     * an entity seen on an earlier visit keeps its original timestamp
     * and only genuinely new ones fall inside this window. */
    {
        time_t since = db_previous_session_end();
        if (db_is_open() && since > 0) {
            char ts_prev[32];
            iso_time(ts_prev, since);
            fprintf(out, "## New since last survey (%s)\n\n", ts_prev);

            static const struct {
                db_new_kind_t kind;
                const char   *heading;
            } kinds[] = {
                { DB_NEW_BEACON_AP,    "Access points" },
                { DB_NEW_DEVICE,       "Devices"       },
                { DB_NEW_PROBE_CLIENT, "Probe clients" },
            };
            int any = 0;
            for (unsigned k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
                db_new_entity_t rows[32];
                int n = db_new_since(kinds[k].kind, since, rows, 32);
                int total = db_count_new_since(kinds[k].kind, since);
                if (total == 0) continue;
                any = 1;
                fprintf(out, "**%s** — %d new\n\n", kinds[k].heading, total);
                fprintf(out, "| Identity | Name | First seen |\n");
                fprintf(out, "|----------|------|------------|\n");
                for (int i = 0; i < n; i++) {
                    char ts_first[32];
                    iso_time(ts_first, rows[i].first_seen);
                    fprintf(out, "| %s | %s | %s |\n",
                            rows[i].ident,
                            rows[i].label[0] ? rows[i].label : "-",
                            ts_first);
                }
                if (total > n)
                    fprintf(out, "\n_%d more not listed._\n", total - n);
                fprintf(out, "\n");
            }
            if (!any)
                fprintf(out, "Nothing new since the previous visit.\n\n");
        }
    }

    fprintf(out, "---\n\n");
    fprintf(out, "Generated by sloth. Passive observation only; every finding above "
                 "is derived from traffic the host already saw, without probing, "
                 "injecting, or altering kernel state.\n");
    return 1;
}

int posture_render_md(FILE *out, const sloth_state_t *s,
                      time_t session_start, struct rq_handle *research) {
    return render_md(out, s, session_start, research, 0);
}

static int render_json(FILE *out, const sloth_state_t *s,
                       time_t session_start, int live) {
    if (!out || !s) return 0;
    time_t now = sloth_wall();
    char ts_start[32], ts_end[32];
    iso_time(ts_start, session_start);
    iso_time(ts_end,   now);

    int n_low = 0, n_warn = 0, n_crit = 0;
    alert_sev_counts(s, &n_low, &n_warn, &n_crit);

    fprintf(out, "{\n");
    fprintf(out, "  \"type\": \"posture_report\",\n");
    fprintf(out, "  \"session_start\": \"%s\",\n", ts_start);
    if (live) {
        fprintf(out, "  \"session_end\":   null,\n");
        fprintf(out, "  \"running\":       true,\n");
        fprintf(out, "  \"as_of\":         \"%s\",\n", ts_end);
    } else {
        fprintf(out, "  \"session_end\":   \"%s\",\n", ts_end);
    }
    fprintf(out, "  \"duration_s\":    %ld,\n", (long)(now - session_start));
    fprintf(out, "  \"alerts\": {\n");
    fprintf(out, "    \"crit\": %d,\n", n_crit);
    fprintf(out, "    \"warn\": %d,\n", n_warn);
    fprintf(out, "    \"low\":  %d,\n", n_low);
    fprintf(out, "    \"total\": %d\n", s->alert_count);
    fprintf(out, "  },\n");

    tech_bucket_t techs[32];
    int nt = bucketize_techniques(s, techs, 32);
    fprintf(out, "  \"techniques\": [");
    for (int i = 0; i < nt; i++) {
        fprintf(out, "%s{\"id\":\"%s\",\"hits\":%d}",
                i ? "," : "", techs[i].technique, techs[i].count);
    }
    fprintf(out, "],\n");

    fprintf(out, "  \"cleartext_creds\": [");
    for (int i = 0; i < s->cleartext_cred_count; i++) {
        const cleartext_cred_t *c = &s->cleartext_creds[i];
        fprintf(out, "%s{\"src\":\"%s\",\"dst\":\"%s\",\"dst_port\":%u,"
                     "\"protocol\":\"%s\",\"username\":\"%s\",\"pw_observed\":%d}",
                i ? "," : "",
                c->src, c->dst, (unsigned)c->dst_port,
                c->protocol, c->username, c->password_observed);
    }
    fprintf(out, "],\n");

    fprintf(out, "  \"risky_devices\": [");
    int first = 1;
    for (int i = 0; i < s->device_count; i++) {
        const device_t *d = &s->devices[i];
        if (d->risk_level < DEV_RISK_HIGH) continue;
        char mac[20];
        posture_mac(d->mac, mac, sizeof(mac), "");
        fprintf(out, "%s{\"mac\":\"%s\",\"ip\":\"%s\",\"vendor\":\"%s\","
                     "\"hostname\":\"%s\",\"risk\":\"%s\",\"risk_signals\":%d}",
                first ? "" : ",",
                mac, d->ip, d->vendor, d->hostname,
                device_risk_label(d->risk_level),
                d->risk_signals);
        first = 0;
    }
    fprintf(out, "]\n");
    fprintf(out, "}\n");
    return 1;
}

int posture_render_json(FILE *out, const sloth_state_t *s, time_t session_start) {
    return render_json(out, s, session_start, 0);
}

/* ── Live report and per-session records (#190) ──────────────────────── */

/* Where the file name starts and where its extension starts. The
 * extension is the last dot of the name unless that dot leads it
 * (".report" has none). -1 for a path with no file name. */
static int path_split(const char *path, size_t *base, size_t *ext) {
    if (!path || !path[0]) return -1;
    const char *slash = strrchr(path, '/');
    const char *b = slash ? slash + 1 : path;
    if (!b[0]) return -1;
    const char *dot = strrchr(b, '.');
    *base = (size_t)(b - path);
    *ext  = (dot && dot != b) ? (size_t)(dot - path) : strlen(path);
    return 0;
}

static int fits(int n, size_t sz) { return n >= 0 && (size_t)n < sz; }

static void stamp_utc(char out[20], time_t t) {
    struct tm tm_buf;
    struct tm *tm = gmtime_r(&t, &tm_buf);
    if (!tm || strftime(out, 20, "%Y%m%dT%H%M%SZ", tm) == 0)
        snprintf(out, 20, "0");
}

int posture_live_path(const char *path, char *out, size_t n) {
    size_t base, ext;
    if (path_split(path, &base, &ext) != 0) return -1;
    return fits(snprintf(out, n, "%.*s.live%s", (int)ext, path, path + ext), n)
           ? 0 : -1;
}

/* "<stem>.<stamp><tag>" with the extension returned apart, the shape
 * sfile_fopen_unique() and the _N walk below both want. */
static int stamped_stem(const char *path, time_t t, const char *tag,
                        char *stem, size_t n, const char **ext_out) {
    size_t base, ext;
    char stamp[20];
    if (path_split(path, &base, &ext) != 0) return -1;
    stamp_utc(stamp, t);
    *ext_out = path + ext;
    return fits(snprintf(stem, n, "%.*s.%s%s", (int)ext, path, stamp, tag), n)
           ? 0 : -1;
}

int posture_session_path(const char *path, time_t session_start,
                         char *out, size_t n) {
    char stem[POSTURE_PATH_MAX];
    const char *ext;
    if (stamped_stem(path, session_start, "", stem, sizeof(stem), &ext) != 0)
        return -1;
    return fits(snprintf(out, n, "%s%s", stem, ext), n) ? 0 : -1;
}

void posture_live_init(posture_live_t *L, const char *md_path,
                       const char *json_path, unsigned interval_s,
                       time_t session_start, struct rq_handle *research) {
    memset(L, 0, sizeof(*L));
    L->md_path       = md_path;
    L->json_path     = json_path;
    L->interval_s    = interval_s;
    L->session_start = session_start;
    L->research      = research;
    L->last_ms       = sloth_mono_ms();
}

/* A live file that exists before this session's first live write was
 * left by a session that never signed off; it is that session's only
 * record and the rename below is about to replace it. Give it a second
 * name first. link(2) rather than rename(2) because link refuses an
 * existing target (EEXIST) where rename would silently replace one, and
 * because the live name then stays in place until the new report takes
 * it over in one step. When the old file cannot be set aside the live
 * write is refused: a stale live report is the smaller loss. */
static int adopt_orphan(const char *path, const char *live,
                        char *err, size_t errsz) {
    struct stat st;
    if (lstat(live, &st) != 0) {
        if (errno == ENOENT) return 0;
        snprintf(err, errsz, "%.200s: %s", live, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        snprintf(err, errsz, "%.200s: not a regular file — refusing", live);
        return -1;
    }
    char stem[POSTURE_PATH_MAX], dest[POSTURE_PATH_MAX];
    const char *ext;
    if (stamped_stem(path, st.st_mtime, ".unclean",
                     stem, sizeof(stem), &ext) != 0) {
        snprintf(err, errsz, "%.200s: path too long", live);
        return -1;
    }
    for (int i = 1; i <= 99; i++) {
        int n = i == 1 ? snprintf(dest, sizeof(dest), "%s%s", stem, ext)
                       : snprintf(dest, sizeof(dest), "%s_%d%s", stem, i, ext);
        if (!fits(n, sizeof(dest))) break;
        if (link(live, dest) == 0) {
            fprintf(stderr, "sloth: kept the unfinished session's live "
                            "report as %s\n", dest);
            return 0;
        }
        if (errno != EEXIST) {
            snprintf(err, errsz, "%.200s: could not keep the previous session's "
                     "live report (%s) — not replacing it",
                     live, strerror(errno));
            return -1;
        }
    }
    snprintf(err, errsz, "%.200s: no free name to keep the previous session's "
             "live report under — not replacing it", live);
    return -1;
}

static int live_write_one(posture_live_t *L, const sloth_state_t *s,
                          const char *path, int json, int *adopted,
                          char *err, size_t errsz) {
    char live[POSTURE_PATH_MAX], tmp[POSTURE_PATH_MAX];
    size_t base, ext;
    if (posture_live_path(path, live, sizeof(live)) != 0 ||
        path_split(live, &base, &ext) != 0 ||
        !fits(snprintf(tmp, sizeof(tmp), "%.*s.%s.tmp",
                       (int)base, live, live + base), sizeof(tmp))) {
        snprintf(err, errsz, "%.200s: bad or over-long path", path);
        return -1;
    }
    if (!*adopted) {
        if (adopt_orphan(path, live, err, errsz) != 0) return -1;
        *adopted = 1;
    }
    /* A temporary of this name is ours, left by a crash mid-write (the
     * discovery and handshake writers reason the same way). unlink
     * removes the name without following it; O_EXCL then guarantees the
     * file written is one this call created, 0600. */
    (void)unlink(tmp);
    FILE *fp = sfile_fopen(AT_FDCWD, tmp, SFILE_EXCL, err, errsz);
    if (!fp) return -1;
    if (json) render_json(fp, s, L->session_start, 1);
    else      render_md(fp, s, L->session_start, L->research, 1);
    /* On disk before it is visible: a rename that survives a power cut
     * while the data does not is how a zero-length report appears. */
    int sync_bad = fflush(fp) != 0 || fsync(fileno(fp)) != 0;
    int sync_err = errno;
    if (sfile_fclose(fp, live, err, errsz) != 0) {
        (void)unlink(tmp);
        return -1;
    }
    if (sync_bad) {
        snprintf(err, errsz, "%.200s: write failed: %s", live, strerror(sync_err));
        (void)unlink(tmp);
        return -1;
    }
    if (rename(tmp, live) != 0) {
        snprintf(err, errsz, "%.200s: rename failed: %s", live, strerror(errno));
        (void)unlink(tmp);
        return -1;
    }
    return 0;
}

int posture_live_tick(posture_live_t *L, const sloth_state_t *s, int force) {
    if (!L || !s || (!L->md_path && !L->json_path)) return 0;
    uint64_t now = sloth_mono_ms();
    if (!force && (L->interval_s == 0 ||
                   now - L->last_ms < (uint64_t)L->interval_s * 1000u))
        return 0;
    /* Stamped before the attempt, so a failing write is retried once an
     * interval and not once a poll. */
    L->last_ms = now;
    int wrote = 0, bad = 0;
    char err[SFILE_ERR_MAX];
    if (L->md_path) {
        if (live_write_one(L, s, L->md_path, 0, &L->md_adopted,
                           err, sizeof(err)) == 0) wrote++;
        else { bad = 1; sfile_fail(&L->fail, "live report", err); }
    }
    if (L->json_path) {
        if (live_write_one(L, s, L->json_path, 1, &L->json_adopted,
                           err, sizeof(err)) == 0) wrote++;
        else { bad = 1; sfile_fail(&L->fail, "live report", err); }
    }
    return bad ? -1 : wrote;
}

void posture_live_retire(posture_live_t *L, int json) {
    const char *path = json ? L->json_path : L->md_path;
    int *adopted     = json ? &L->json_adopted : &L->md_adopted;
    char live[POSTURE_PATH_MAX], err[SFILE_ERR_MAX];
    if (!path || posture_live_path(path, live, sizeof(live)) != 0) return;
    /* A session that never wrote a live report does not own the file at
     * the live name: one found there belongs to an earlier session that
     * was killed, and removing it would destroy that session's record
     * on the way out. It is set aside first, exactly as a live write
     * would have done, and left alone if it cannot be. */
    if (!*adopted) {
        if (adopt_orphan(path, live, err, sizeof(err)) != 0) {
            sfile_fail(&L->fail, "live report", err);
            return;
        }
        *adopted = 1;
    }
    (void)unlink(live);
}

int posture_session_record(const char *path, int json,
                           const sloth_state_t *s, time_t session_start,
                           struct rq_handle *research,
                           char *name_out, size_t name_sz,
                           char *err, size_t errsz) {
    char stem[POSTURE_PATH_MAX];
    const char *ext;
    if (stamped_stem(path, session_start, "", stem, sizeof(stem), &ext) != 0) {
        snprintf(err, errsz, "%.200s: bad or over-long path",
                 path ? path : "?");
        return -1;
    }
    /* O_EXCL, then _2 .. _99: two sessions started in the same second
     * each keep their own record. */
    FILE *fp = sfile_fopen_unique(AT_FDCWD, stem, ext, name_out, name_sz,
                                  err, errsz);
    if (!fp) return -1;
    if (json) render_json(fp, s, session_start, 0);
    else      render_md(fp, s, session_start, research, 0);
    if (sfile_fclose(fp, name_out, err, errsz) != 0) {
        (void)unlink(name_out);
        return -1;
    }
    return 0;
}
