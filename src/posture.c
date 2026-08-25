/* Posture report export — roadmap #16 phase 5.
 *
 * Renders a summary of what sloth observed this session into either
 * Markdown (for hand-audit) or JSON (for SIEM diff / CI compare).
 * Reads only sloth_state_t and the alert/cleartext ring snapshots
 * that are already there — no new observation surface. Runs once at
 * shutdown so the file is a signed-off session record. */

#include <string.h>
#include <time.h>
#include "posture.h"
#include "beacon_snoop.h"
#include "db.h"
#include "alerts.h"
#include "wifi_assess.h"
#include "wifi_baseline.h"

static void iso_time(char out[32], time_t t) {
    struct tm *tm = gmtime(&t);
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

int posture_render_md(FILE *out, const sloth_state_t *s, time_t session_start) {
    if (!out || !s) return 0;
    time_t now = time(NULL);
    char ts_start[32], ts_end[32];
    iso_time(ts_start, session_start);
    iso_time(ts_end,   now);

    int n_low = 0, n_warn = 0, n_crit = 0;
    alert_sev_counts(s, &n_low, &n_warn, &n_crit);

    fprintf(out, "# sloth posture report\n\n");
    fprintf(out, "- **Session start**: `%s`\n", ts_start);
    fprintf(out, "- **Session end**:   `%s`\n", ts_end);
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
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     d->mac[0], d->mac[1], d->mac[2],
                     d->mac[3], d->mac[4], d->mac[5]);
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

int posture_render_json(FILE *out, const sloth_state_t *s, time_t session_start) {
    if (!out || !s) return 0;
    time_t now = time(NULL);
    char ts_start[32], ts_end[32];
    iso_time(ts_start, session_start);
    iso_time(ts_end,   now);

    int n_low = 0, n_warn = 0, n_crit = 0;
    alert_sev_counts(s, &n_low, &n_warn, &n_crit);

    fprintf(out, "{\n");
    fprintf(out, "  \"type\": \"posture_report\",\n");
    fprintf(out, "  \"session_start\": \"%s\",\n", ts_start);
    fprintf(out, "  \"session_end\":   \"%s\",\n", ts_end);
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
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 d->mac[0], d->mac[1], d->mac[2],
                 d->mac[3], d->mac[4], d->mac[5]);
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
