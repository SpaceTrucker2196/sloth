#include "sweep.h"
#include "wifi_snapshot.h"
#include "preflight.h"
#include "jsonl.h"
#include "wifi_freq.h"
#include <string.h>

/* The sweep report (#249). Contract: sweep.h. */

/* The fixed limits (#249; issue text, "Limits to state in each
 * report"). Nothing here claims detection from unintentional radiation:
 * that needs a bench measurement first, and until one exists the report
 * does not mention it. */
static const char *const LIMITS[] = {
    "A sweep finds devices that transmit during the sweep in the bands "
    "the radios cover. It does not find a device that is off, that "
    "stores and sends later, or that uses a wire.",
    "Each channel is heard for its dwell only: a device that is silent "
    "while the radio is on its channel is not heard there.",
    "Wi-Fi is heard on 20 MHz channel centres of 2.4 and 5 GHz, and of "
    "6 GHz only when a sensor radio can tune that band; sub-GHz is not "
    "swept.",
    "BLE is heard through the host's own Bluetooth controller (or an "
    "Ubertooth) for the whole sweep; a device that does not advertise "
    "is not found.",
    "A resolvable or non-resolvable private BLE address and a locally "
    "administered Wi-Fi client address change over time: one is compared "
    "only when this sweep resolved it as stable (it associated, or it was "
    "heard for 15 minutes or more), by its own address, never merged with "
    "another; the rest are counted, never new or known.",
};

const char *sweep_end_name(int end_why) {
    switch (end_why) {
    case SW_END_TIME: return "time";
    case SW_END_PASS: return "pass";
    default:          return "stopped";
    }
}

void sweep_bands_not_swept(const sw_cov_t *c, char *out, size_t sz) {
    int b24 = 0, b5 = 0, b6 = 0;
    for (int i = 0; c && i < c->n; i++) {
        if (!c->ch[i].ms) continue;
        if (c->ch[i].band == WIFI_BAND_2GHZ) b24 = 1;
        if (c->ch[i].band == WIFI_BAND_5GHZ) b5 = 1;
        if (c->ch[i].band == WIFI_BAND_6GHZ) b6 = 1;
    }
    snprintf(out, sz, "%s%s%ssub_ghz", b24 ? "" : "2.4ghz,", b5 ? "" : "5ghz,",
             b6 ? "" : "6ghz,");
}

/* Whether the plan held a 6 GHz channel (a sensor radio could tune it). */
static int plan_has_6(const sw_cov_t *c) {
    for (int i = 0; c && i < c->n; i++)
        if (c->ch[i].band == WIFI_BAND_6GHZ) return 1;
    return 0;
}

static const char *band_name(int band) {
    return band == WIFI_BAND_2GHZ ? "2.4 GHz" : band == WIFI_BAND_5GHZ ? "5 GHz"
         : band == WIFI_BAND_6GHZ ? "6 GHz" : "?";
}

static void iso(char out[32], time_t t) {
    struct tm tmv, *tm = gmtime_r(&t, &tmv);
    out[0] = '\0';
    if (tm) strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", tm);
}

static void mac(const uint8_t a[6], char out[20]) {
    snprintf(out, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
             a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* An on-air string for a Markdown table cell: the snapshot file's
 * escape (no control byte reaches the reader raw) and '|' escaped. */
static void md_cell(FILE *out, const char *s) {
    char e[33 * 4 + 1];
    wifi_snapshot_escape(s && s[0] ? s : "", e, sizeof(e));
    if (!s || !s[0]) { fputs("-", out); return; }
    for (const char *p = e; *p; p++) {
        if (*p == '|') fputc('\\', out);
        fputc(*p, out);
    }
}

static const char *what(const sw_emitter_t *e) {
    if (e->kind == SW_K_AP) return e->ssid;
    if (e->kind == SW_K_BLE) return e->name;
    return e->vendor;
}

static void md_row(FILE *out, const sw_emitter_t *e) {
    char a[20];
    mac(e->addr, a);
    fprintf(out, "| %s%s%s | %s | ", sweep_kind_name(e->kind),
            e->kind == SW_K_BLE ? " " : "",
            e->kind == SW_K_BLE ? sweep_ble_type_name(e->ble_type) : "", a);
    if (e->kind == SW_K_AP && !e->ssid[0]) fputs("(hidden)", out);
    else md_cell(out, what(e));
    fputs(" | ", out);
    if (e->has_dbm && e->status != SW_ST_MISSING) fprintf(out, "%d dBm", e->best_dbm);
    else fputs("-", out);
    if (e->channel > 0) fprintf(out, " | %d | ", e->channel);
    else fputs(" | - | ", out);
    int sep = 0;
    if (e->kind == SW_K_AP && e->enc[0]) { md_cell(out, e->enc); sep = 1; }
    if (e->kind == SW_K_BLE && e->cat[0]) { md_cell(out, e->cat); sep = 1; }
    if (e->status == SW_ST_KNOWN && e->kind == SW_K_AP &&
        ((e->base_channel && e->base_channel != e->channel) ||
         (e->base_enc[0] && e->enc[0] && strcmp(e->base_enc, e->enc)))) {
        fprintf(out, "%sbaseline: ch %d ", sep ? "; " : "", e->base_channel);
        md_cell(out, e->base_enc);
        sep = 1;
    }
    if (e->res) {
        fprintf(out, "%sresolved randomised address: %s, confidence %d",
                sep ? "; " : "", sweep_res_name(e->res), e->res_conf);
        sep = 1;
    }
    if (!sep) fputs("-", out);
    fputs(" |\n", out);
}

static void md_section(FILE *out, const sw_cmp_t *c, int st, const char *title) {
    int n = 0;
    for (int i = 0; i < c->n; i++) n += c->row[i].status == st;
    fprintf(out, "\n### %s (%d)\n\n", title, n);
    if (!n) { fputs("None.\n", out); return; }
    fputs("| kind | address | SSID / name / vendor | best signal | channel | note |\n"
          "|---|---|---|---|---|---|\n", out);
    for (int i = 0; i < c->n; i++)
        if (c->row[i].status == st) md_row(out, &c->row[i]);
}

void sweep_report_md(FILE *out, const sw_report_t *r) {
    if (!out || !r || !r->cmp || !r->cov || !r->inv) return;
    char t0[32], t1[32], bands[64];
    iso(t0, r->start);
    iso(t1, r->end);
    const sw_cov_t *cv = r->cov;
    const sw_cmp_t *c = r->cmp;
    fputs("# Sweep: ", out);
    md_cell(out, r->label);
    fprintf(out, "\n\nStart: %s  \nEnd: %s  \nTime given: %u min  \n",
            t0, t1, r->minutes);
    fprintf(out, "Ended: %s\n\n",
            r->end_why == SW_END_TIME ? "the time given ran out"
            : r->end_why == SW_END_PASS ? "every channel visited once (one pass)"
            : "stopped before the pass or the time ended");
    if (r->base_version)
        fprintf(out, "Baseline: `%s` (snapshot v%d%s).\n", r->baseline_path,
                r->base_version,
                r->base_version == 1 ? ": access points only; clients and BLE "
                                       "not compared" : "");
    else
        fputs("Baseline: none accepted for this label: every emitter heard is "
              "new.\n", out);

    fputs("\n## Emitters\n\n| | new | known | missing |\n|---|---|---|---|\n", out);
    static const char *const kn[SW_K_N] = { "access points", "Wi-Fi clients",
                                            "BLE advertisers" };
    for (int k = 0; k < SW_K_N; k++) {
        if (c->compared[k])
            fprintf(out, "| %s | %d | %d | %d |\n", kn[k], c->count[k][SW_ST_NEW],
                    c->count[k][SW_ST_KNOWN], c->count[k][SW_ST_MISSING]);
        else
            fprintf(out, "| %s | %d | not compared | not compared |\n", kn[k],
                    c->count[k][SW_ST_NEW]);
    }
    sw_rand_t rc;
    sweep_rand_counts(r->inv, &rc);
    const char *fl = rc.floor ? "at least " : "";
    fprintf(out, "\nRandomised addresses: %s%d Wi-Fi client address%s with the "
            "locally administered bit, of which %d resolved as stable (compared "
            "above, by address), %d linked by sequence number to a universal "
            "address, %d unresolved (counted, not compared); %s%d private BLE "
            "address%s, of which %d resolved as stable, %d unresolved.\n",
            fl, rc.client_random, rc.client_random == 1 ? "" : "es",
            rc.client_resolved, rc.client_linked, rc.client_unresolved,
            fl, rc.ble_private, rc.ble_private == 1 ? "" : "es",
            rc.ble_resolved, rc.ble_unresolved);
    if (r->inv->cand_dropped)
        fprintf(out, "Not followed for resolution (the table was full): %llu "
                "observation(s); those addresses stay counted.\n",
                (unsigned long long)r->inv->cand_dropped);
    if (c->have_base && !c->compared_resolved && (rc.client_resolved || rc.ble_resolved))
        fputs("The baseline predates resolution: the resolved randomised addresses "
              "are listed as new, not compared.\n", out);
    uint64_t dropped = r->inv->dropped[0] + r->inv->dropped[1] + r->inv->dropped[2];
    if (dropped)
        fprintf(out, "Not inventoried (a kind's table was full): %llu "
                "observation(s).\n", (unsigned long long)dropped);
    md_section(out, c, SW_ST_NEW, "New, strongest first");
    md_section(out, c, SW_ST_KNOWN, "Known");
    md_section(out, c, SW_ST_MISSING, "Missing (in the baseline, not heard)");

    fputs("\n## Cameras, setup mode, hidden names\n\n", out);
    int any = 0;
    for (int i = 0; i < c->n; i++) {
        const sw_emitter_t *e = &c->row[i];
        if (!(e->flags & (SW_F_CAMERA | SW_F_SETUP | SW_F_HIDDEN)) ||
            e->status == SW_ST_MISSING)
            continue;
        if (!any)
            fputs("| kind | address | SSID / name | what | status |\n"
                  "|---|---|---|---|---|\n", out);
        any = 1;
        char a[20];
        mac(e->addr, a);
        fprintf(out, "| %s | %s | ", sweep_kind_name(e->kind), a);
        if (e->kind == SW_K_AP && !e->ssid[0]) fputs("(hidden)", out);
        else md_cell(out, what(e));
        fputs(" | ", out);
        int sep = 0;
        if (e->flags & SW_F_CAMERA) {
            fputs("camera", out);
            if (e->camera[0]) { fputs(" (", out); md_cell(out, e->camera); fputc(')', out); }
            sep = 1;
        }
        if (e->flags & SW_F_SETUP) { fprintf(out, "%ssetup mode", sep ? ", " : ""); sep = 1; }
        if (e->flags & SW_F_HIDDEN) fprintf(out, "%shidden name", sep ? ", " : "");
        fprintf(out, " | %s |\n", sweep_status_name(e->status));
    }
    if (!any) fputs("None heard.\n", out);

    fputs("\n## Coverage\n\n", out);
    int swept = sweep_cov_swept(cv);
    fprintf(out, "Channels in the plan: %d; swept: %d; not swept: %d. "
            "Planned dwell %u ms a channel over %d radio%s.\n\n",
            cv->n, swept, cv->n - swept, cv->planned_dwell_ms, cv->radios,
            cv->radios == 1 ? "" : "s");
    fputs("| band | channel | MHz | time (s) | visits | refused | frames | |\n"
          "|---|---|---|---|---|---|---|---|\n", out);
    for (int i = 0; i < cv->n; i++) {
        const sw_cov_ch_t *e = &cv->ch[i];
        fprintf(out, "| %s | %d | %d | %llu.%03llu | %u | %u | %llu | %s |\n",
                band_name(e->band), e->channel, e->freq_mhz,
                (unsigned long long)(e->ms / 1000), (unsigned long long)(e->ms % 1000),
                e->visits, e->refusals, (unsigned long long)e->frames,
                e->ms ? "swept" : e->refusals ? "not swept: retune refused"
                                              : "not swept: not reached");
    }
    sweep_bands_not_swept(cv, bands, sizeof(bands));
    fputs("\nBands not swept: sub-GHz (no sub-GHz receiver in a sweep)", out);
    if (strstr(bands, "6ghz"))
        fputs(plan_has_6(cv) ? ", 6 GHz (no channel swept)"
                             : ", 6 GHz (no 6 GHz channel in the sweep plan: no "
                               "sensor radio can tune the band)", out);
    if (strstr(bands, "2.4ghz")) fputs(", 2.4 GHz (no channel swept)", out);
    if (strstr(bands, "5ghz,"))  fputs(", 5 GHz (no channel swept)", out);
    fputs(".\n\nSources at the end: monitor radio ", out);
    fputs(r->mon_up ? "up" : "DOWN", out);
    fputs("; BLE ", out);
    fputs(!r->ble_configured ? "not configured (no BLE heard: --bt-monitor or "
                               "--bt-capture)" : r->ble_up ? "up" : "DOWN", out);
    fputs(".\n\n## Limits\n\n", out);
    for (size_t i = 0; i < sizeof(LIMITS) / sizeof(LIMITS[0]); i++)
        fprintf(out, "- %s\n", LIMITS[i]);
    fputs("\n## Baseline\n\n", out);
    if (r->candidate_path)
        fprintf(out, "This sweep's inventory: `%s`. It becomes the label's "
                "baseline only when accepted; nothing here replaced it.\n",
                r->candidate_path);
    else
        fputs("This sweep's inventory was not written: it cannot be accepted "
              "as a baseline.\n", out);
}

static void json_row(FILE *out, const sw_emitter_t *e) {
    char a[20];
    mac(e->addr, a);
    fprintf(out, "{\"kind\":\"%s\",\"addr\":\"%s\",\"status\":\"%s\"",
            sweep_kind_name(e->kind), a, sweep_status_name(e->status));
    if (e->kind == SW_K_BLE)
        fprintf(out, ",\"addr_type\":\"%s\"", sweep_ble_type_name(e->ble_type));
    if (e->kind == SW_K_AP) {
        fputs(",\"ssid\":", out); pf_json_str(out, e->ssid);
        fputs(",\"enc\":", out);  pf_json_str(out, e->enc);
    }
    if (e->kind == SW_K_BLE) {
        fputs(",\"name\":", out); pf_json_str(out, e->name);
        fputs(",\"category\":", out); pf_json_str(out, e->cat);
    }
    if (e->kind == SW_K_CLIENT) { fputs(",\"vendor\":", out); pf_json_str(out, e->vendor); }
    if (e->res)
        fprintf(out, ",\"resolved\":\"%s\",\"confidence\":%d", sweep_res_name(e->res),
                e->res_conf);
    if (e->has_dbm && e->status != SW_ST_MISSING) fprintf(out, ",\"best_dbm\":%d", e->best_dbm);
    if (e->channel > 0) fprintf(out, ",\"channel\":%d", e->channel);
    if (e->status == SW_ST_KNOWN && e->kind == SW_K_AP) {
        fprintf(out, ",\"base_channel\":%d,\"base_enc\":", e->base_channel);
        pf_json_str(out, e->base_enc);
    }
    fprintf(out, ",\"camera\":%s,\"setup\":%s,\"hidden\":%s",
            e->flags & SW_F_CAMERA ? "true" : "false",
            e->flags & SW_F_SETUP ? "true" : "false",
            e->flags & SW_F_HIDDEN ? "true" : "false");
    fputc('}', out);
}

void sweep_report_json(FILE *out, const sw_report_t *r) {
    if (!out || !r || !r->cmp || !r->cov || !r->inv) return;
    const sw_cmp_t *c = r->cmp;
    const sw_cov_t *cv = r->cov;
    char t0[32], t1[32], bands[64];
    iso(t0, r->start);
    iso(t1, r->end);
    fputs("{\"sweep\":{\"label\":", out);
    pf_json_str(out, r->label);
    fprintf(out, ",\"start\":\"%s\",\"end\":\"%s\",\"minutes\":%u,\"end_why\":\"%s\","
            "\"baseline_version\":%d,\"baseline\":", t0, t1, r->minutes,
            sweep_end_name(r->end_why), r->base_version);
    if (r->base_version) pf_json_str(out, r->baseline_path); else fputs("null", out);
    fputs(",\"inventory\":", out);
    if (r->candidate_path) pf_json_str(out, r->candidate_path); else fputs("null", out);
    fputs("},\"counts\":{", out);
    for (int k = 0; k < SW_K_N; k++)
        fprintf(out, "%s\"%s\":{\"compared\":%s,\"new\":%d,\"known\":%d,\"missing\":%d}",
                k ? "," : "", sweep_kind_name(k), c->compared[k] ? "true" : "false",
                c->count[k][SW_ST_NEW], c->count[k][SW_ST_KNOWN],
                c->count[k][SW_ST_MISSING]);
    sw_rand_t rc;
    sweep_rand_counts(r->inv, &rc);
    fprintf(out, ",\"resolved_compared\":%s,\"client_resolved\":%d,"
            "\"client_linked\":%d,\"client_unresolved\":%d,\"ble_resolved\":%d,"
            "\"ble_unresolved\":%d",
            c->compared_resolved ? "true" : "false", rc.client_resolved,
            rc.client_linked, rc.client_unresolved, rc.ble_resolved,
            rc.ble_unresolved);
    fprintf(out, ",\"client_random\":%d,\"client_random_floor\":%s,"
            "\"ble_private\":%d,\"ble_private_floor\":%s,\"dropped\":%llu},",
            sweep_set_count(&r->inv->client_random),
            r->inv->client_random.full ? "true" : "false",
            sweep_set_count(&r->inv->ble_private),
            r->inv->ble_private.full ? "true" : "false",
            (unsigned long long)(r->inv->dropped[0] + r->inv->dropped[1] +
                                 r->inv->dropped[2]));
    fputs("\"emitters\":[", out);
    for (int i = 0; i < c->n; i++) {
        if (i) fputc(',', out);
        json_row(out, &c->row[i]);
    }
    sweep_bands_not_swept(cv, bands, sizeof(bands));
    fprintf(out, "],\"coverage\":{\"planned_dwell_ms\":%u,\"radios\":%d,"
            "\"channels_planned\":%d,\"channels_swept\":%d,\"bands_not_swept\":",
            cv->planned_dwell_ms, cv->radios, cv->n, sweep_cov_swept(cv));
    pf_json_str(out, bands);
    fputs(",\"channels\":[", out);
    for (int i = 0; i < cv->n; i++) {
        const sw_cov_ch_t *e = &cv->ch[i];
        fprintf(out, "%s{\"band\":\"%s\",\"channel\":%d,\"freq_mhz\":%d,\"ms\":%llu,"
                "\"visits\":%u,\"refusals\":%u,\"frames\":%llu,\"swept\":%s}",
                i ? "," : "", band_name(e->band), e->channel, e->freq_mhz,
                (unsigned long long)e->ms, e->visits, e->refusals,
                (unsigned long long)e->frames, e->ms ? "true" : "false");
    }
    fprintf(out, "],\"sources\":{\"monitor\":\"%s\",\"ble\":\"%s\"}},\"limits\":[",
            r->mon_up ? "up" : "down",
            !r->ble_configured ? "not_configured" : r->ble_up ? "up" : "down");
    for (size_t i = 0; i < sizeof(LIMITS) / sizeof(LIMITS[0]); i++) {
        if (i) fputc(',', out);
        pf_json_str(out, LIMITS[i]);
    }
    fputs("]}\n", out);
}

void sweep_report_emit(const sw_report_t *r) {
    if (!r || !r->cmp || !r->cov || !r->inv) return;
    const sw_cmp_t *c = r->cmp;
    const sw_cov_t *cv = r->cov;
    /* The channels not swept, as "band:channel" words: what a consumer
     * needs to say the sweep was partial without the report file. */
    char not_swept[CHANHOP_MAX * 8 + 1] = "";
    size_t o = 0;
    for (int i = 0; i < cv->n; i++) {
        if (cv->ch[i].ms) continue;
        int w = snprintf(not_swept + o, sizeof(not_swept) - o, "%s%s:%d",
                         o ? "," : "",
                         cv->ch[i].band == WIFI_BAND_2GHZ ? "2.4"
                         : cv->ch[i].band == WIFI_BAND_6GHZ ? "6" : "5",
                         cv->ch[i].channel);
        if (w < 0 || (size_t)w >= sizeof(not_swept) - o) break;
        o += (size_t)w;
    }
    char bands[64];
    sweep_bands_not_swept(cv, bands, sizeof(bands));
    const char *end = sweep_end_name(r->end_why);
    jsonl_field_t f[32];
    int n = 0;
#define I(k, v) f[n++] = (jsonl_field_t){ k, JSONL_F_INT, NULL, (long long)(v), 0.0, 0 }
#define S(k, v) f[n++] = (jsonl_field_t){ k, JSONL_F_STR, v, 0, 0.0, 0 }
    S("label", r->label ? r->label : "");
    I("start", r->start);
    I("end", r->end);
    I("minutes", r->minutes);
    S("end_why", end);
    I("baseline_version", r->base_version);
    I("ap_new", c->count[SW_K_AP][SW_ST_NEW]);
    I("ap_known", c->count[SW_K_AP][SW_ST_KNOWN]);
    I("ap_missing", c->count[SW_K_AP][SW_ST_MISSING]);
    I("client_new", c->count[SW_K_CLIENT][SW_ST_NEW]);
    I("client_known", c->count[SW_K_CLIENT][SW_ST_KNOWN]);
    I("client_missing", c->count[SW_K_CLIENT][SW_ST_MISSING]);
    I("ble_new", c->count[SW_K_BLE][SW_ST_NEW]);
    I("ble_known", c->count[SW_K_BLE][SW_ST_KNOWN]);
    I("ble_missing", c->count[SW_K_BLE][SW_ST_MISSING]);
    I("client_random", sweep_set_count(&r->inv->client_random));
    I("ble_private", sweep_set_count(&r->inv->ble_private));
    /* JSONL 2.18.0 (#249 follow-up): the randomised addresses resolved
     * as stable, linked by sequence number, and left unresolved. */
    sw_rand_t rc;
    sweep_rand_counts(r->inv, &rc);
    I("client_resolved", rc.client_resolved);
    I("client_linked", rc.client_linked);
    I("client_unresolved", rc.client_unresolved);
    I("ble_resolved", rc.ble_resolved);
    I("ble_unresolved", rc.ble_unresolved);
    I("channels_planned", cv->n);
    I("channels_swept", sweep_cov_swept(cv));
    S("not_swept", not_swept);
    S("bands_not_swept", bands);
    I("radios", cv->radios);
#undef I
#undef S
    jsonl_emit_fields("sweep_report", r->end, f, n);
}
