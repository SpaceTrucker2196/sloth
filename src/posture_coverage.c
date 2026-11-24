/* The posture report's "Collection coverage" section (#242 item 3).
 *
 * A report that lists what fired says nothing about what could not
 * have fired. This section puts the coverage assessment beside it: the
 * three counts, every kind that is blind or partly grouped by reason
 * (the first thing to fix first, rule_coverage_live.h), the radio
 * figures the 802.11 statuses were derived from, the newest closed
 * coverage interval, any open SENSOR_SUPPRESSED incident, and the two
 * limits every reader of a status needs (cov_limits[]).
 *
 * When there is no status (before the first sample, or a --replay run)
 * the section says "not assessed" and why, and prints no count: zero
 * blind rules would read as full coverage.
 *
 * Reads only what the daemon already holds (cov_live_*, cov_iv_*, the
 * alert snapshot in the state). Nothing here is a new observation. */

#include <string.h>
#include <time.h>
#include "posture.h"
#include "rule_coverage_live.h"
#include "cov_interval.h"
#include "jsonl_internal.h"

static void cov_iso(char out[32], time_t t) {
    struct tm tm_buf;
    struct tm *tm = gmtime_r(&t, &tm_buf);
    if (tm) strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", tm);
    else    snprintf(out, 32, "?");
}

/* Whole percent of `part` in `whole`, rounded; 0 for an empty whole. */
static unsigned pct(uint64_t part, uint64_t whole) {
    if (!whole) return 0;
    return (unsigned)((part * 100u + whole / 2u) / whole);
}

/* An open SENSOR_SUPPRESSED incident: what the statuses' `suppressed`
 * reason comes from, so the reader sees the loss beside the rules it
 * costs. A resolved one in the snapshot is history, not state. */
static int suppressed_open(const alert_t *a) {
    return a->type == ALERT_TYPE_SENSOR_SUPPRESSED && !a->resolved;
}

/* ── Markdown ───────────────────────────────────────────────────── */

static void md_interval(FILE *out) {
    cov_iv_t iv;
    uint32_t seq = cov_iv_seq();
    if (!seq || !cov_iv_get(seq, &iv)) {
        fprintf(out, "**Last minute**: no coverage interval has closed yet "
                     "(one is written each minute of a live run).\n\n");
        return;
    }
    char ts[32];
    cov_iso(ts, iv.end);
    fprintf(out, "**Last minute** (interval %u, %llu ms to `%s`): radio "
                 "time %llu ms.\n\n",
            (unsigned)iv.seq, (unsigned long long)iv.dur_ms, ts,
            (unsigned long long)iv.radio_ms);
    if (iv.radio_ms) {
        fprintf(out, "| Band | Time (ms) | Share |\n|------|------:|------:|\n");
        for (int b = 0; b < COV_IVB_N; b++) {
            if (!iv.band_ms[b]) continue;
            fprintf(out, "| %s | %llu | %u %% |\n", cov_ivb_name(b),
                    (unsigned long long)iv.band_ms[b],
                    pct(iv.band_ms[b], iv.radio_ms));
        }
        fprintf(out, "\n");
    }
    uint64_t total = 0;
    for (int c = 0; c < COV_FC_N; c++) total += iv.frames[c];
    fprintf(out, "Frames: %llu", (unsigned long long)total);
    int any = 0;
    for (int c = 0; c < COV_FC_N; c++) {
        if (!iv.frames[c]) continue;
        fprintf(out, "%s%s %llu", any ? ", " : " (", cov_fc_name(c),
                (unsigned long long)iv.frames[c]);
        any = 1;
    }
    fprintf(out, "%s.\n\n", any ? ")" : "");
    fprintf(out, "Drops: capture ");
    if (iv.has_cap)
        fprintf(out, "%llu, interface %llu", (unsigned long long)iv.cap_drop,
                (unsigned long long)iv.cap_ifdrop);
    else
        fprintf(out, "not measured");
    fprintf(out, "; monitor ");
    if (iv.has_mon)
        fprintf(out, "%llu, interface %llu", (unsigned long long)iv.mon_drop,
                (unsigned long long)iv.mon_ifdrop);
    else
        fprintf(out, "not measured");
    fprintf(out, ".\n\n");
}

void posture_coverage_md(FILE *out, const sloth_state_t *s) {
    fprintf(out, "## Collection coverage\n\n");
    cov_live_state_t st = cov_live_state();
    if (st != COV_LIVE_VALID) {
        fprintf(out, "Not assessed: %s.\n\n", cov_live_state_why(st));
    } else {
        int ob = 0, pa = 0, bl = 0;
        cov_live_counts(&ob, &pa, &bl);
        fprintf(out, "Which of this sensor's %d rules could fire "
                     "(docs/wiki/coverage-assessment.md).\n\n", ob + pa + bl);
        fprintf(out, "| Status | Rules |\n|--------|------:|\n");
        fprintf(out, "| observable | %d |\n| partly | %d |\n| blind | %d |\n\n",
                ob, pa, bl);

        cov_gap_t gaps[COV_GAP_MAX];
        int ng = cov_live_gaps(gaps, COV_GAP_MAX);
        if (pa + bl == 0)
            fprintf(out, "Every rule is observable.\n\n");
        for (int i = 0; i < ng; i++) {
            fprintf(out, "**%s, `%s`** (%d)\n\n", cov_status_name(gaps[i].st),
                    cov_reason_name(gaps[i].why), gaps[i].n);
            for (int k = 0; k < gaps[i].n; k++) {
                const cov_inputs_t *d = cov_inputs(gaps[i].kind[k]);
                fprintf(out, "- `%s` (%s)\n", cov_kind_name(gaps[i].kind[k]),
                        d ? cov_input_name(d->input) : "?");
            }
            fprintf(out, "\n");
        }

        const cov_env_t *e = cov_live_env();
        char bands[24];
        cov_bands_str(e->bands, bands, sizeof(bands));
        fprintf(out, "Radios: %d; channels: %d; hopping: %s; bands: %s.\n\n",
                e->radios, e->channels, e->hopping ? "yes" : "no",
                bands[0] ? bands : "unknown");

        md_interval(out);

        int nsup = 0;
        for (int i = 0; i < s->alert_count; i++) {
            const alert_t *a = &s->alerts[i];
            if (!suppressed_open(a)) continue;
            if (!nsup++) fprintf(out, "**SENSOR_SUPPRESSED open**\n\n");
            fprintf(out, "- `%s`: %s\n", a->key, a->detail);
        }
        if (nsup) fprintf(out, "\n");
        else      fprintf(out, "SENSOR_SUPPRESSED: none open.\n\n");
    }
    fprintf(out, "**Limits.**");
    for (int i = 0; i < COV_LIMIT_COUNT; i++) fprintf(out, " %s", cov_limits[i]);
    fprintf(out, "\n\n");
}

/* ── JSON ───────────────────────────────────────────────────────── */

static void json_str(FILE *out, const char *v) {
    char buf[ALERT_DETAIL_LEN * 6 + 8];
    int off = 0;
    jsonl_escape(v, buf, (int)sizeof(buf), &off);
    fprintf(out, "\"%s\"", buf);
}

static void json_interval(FILE *out) {
    cov_iv_t iv;
    uint32_t seq = cov_iv_seq();
    if (!seq || !cov_iv_get(seq, &iv)) { fprintf(out, "null"); return; }
    char ts[32];
    cov_iso(ts, iv.end);
    fprintf(out, "{\"seq\":%u,\"end\":\"%s\",\"dur_ms\":%llu,\"radio_ms\":%llu,"
                 "\"band_ms\":{",
            (unsigned)iv.seq, ts, (unsigned long long)iv.dur_ms,
            (unsigned long long)iv.radio_ms);
    for (int b = 0; b < COV_IVB_N; b++)
        fprintf(out, "%s\"%s\":%llu", b ? "," : "", cov_ivb_name(b),
                (unsigned long long)iv.band_ms[b]);
    fprintf(out, "},\"frames\":{");
    for (int c = 0; c < COV_FC_N; c++)
        fprintf(out, "%s\"%s\":%llu", c ? "," : "", cov_fc_name(c),
                (unsigned long long)iv.frames[c]);
    fprintf(out, "}");
    /* Absent, never 0, when a handle was not measured: the record's own
     * rule (cov_interval.h). */
    if (iv.has_cap)
        fprintf(out, ",\"cap_drop\":%llu,\"cap_ifdrop\":%llu",
                (unsigned long long)iv.cap_drop, (unsigned long long)iv.cap_ifdrop);
    if (iv.has_mon)
        fprintf(out, ",\"mon_drop\":%llu,\"mon_ifdrop\":%llu",
                (unsigned long long)iv.mon_drop, (unsigned long long)iv.mon_ifdrop);
    fprintf(out, "}");
}

void posture_coverage_json(FILE *out, const sloth_state_t *s) {
    fprintf(out, "  \"coverage\": {");
    cov_live_state_t st = cov_live_state();
    if (st != COV_LIVE_VALID) {
        fprintf(out, "\"assessed\":false,\"why\":");
        json_str(out, cov_live_state_why(st));
    } else {
        int ob = 0, pa = 0, bl = 0;
        cov_live_counts(&ob, &pa, &bl);
        fprintf(out, "\"assessed\":true,\"rules\":%d,\"observable\":%d,"
                     "\"partly\":%d,\"blind\":%d,\"gaps\":[",
                ob + pa + bl, ob, pa, bl);
        cov_gap_t gaps[COV_GAP_MAX];
        int ng = cov_live_gaps(gaps, COV_GAP_MAX);
        for (int i = 0; i < ng; i++) {
            fprintf(out, "%s{\"status\":\"%s\",\"why\":\"%s\",\"kinds\":[",
                    i ? "," : "", cov_status_name(gaps[i].st),
                    cov_reason_name(gaps[i].why));
            for (int k = 0; k < gaps[i].n; k++) {
                const cov_inputs_t *d = cov_inputs(gaps[i].kind[k]);
                fprintf(out, "%s{\"kind\":\"%s\",\"input\":\"%s\"}", k ? "," : "",
                        cov_kind_name(gaps[i].kind[k]),
                        d ? cov_input_name(d->input) : "");
            }
            fprintf(out, "]}");
        }
        const cov_env_t *e = cov_live_env();
        char bands[24];
        cov_bands_str(e->bands, bands, sizeof(bands));
        fprintf(out, "],\"radios\":%d,\"channels\":%d,\"hopping\":%d,"
                     "\"bands\":\"%s\",\"interval\":",
                e->radios, e->channels, e->hopping, bands);
        json_interval(out);
        fprintf(out, ",\"suppressed\":[");
        int nsup = 0;
        for (int i = 0; i < s->alert_count; i++) {
            const alert_t *a = &s->alerts[i];
            if (!suppressed_open(a)) continue;
            fprintf(out, "%s{\"key\":", nsup++ ? "," : "");
            json_str(out, a->key);
            fprintf(out, ",\"detail\":");
            json_str(out, a->detail);
            fprintf(out, "}");
        }
        fprintf(out, "]");
    }
    fprintf(out, ",\"limits\":[");
    for (int i = 0; i < COV_LIMIT_COUNT; i++) {
        if (i) fprintf(out, ",");
        json_str(out, cov_limits[i]);
    }
    fprintf(out, "]}\n");
}
