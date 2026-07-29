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
