#include "web_evidence.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "web_alertasm.h"
#include "web_alertkb.h"
#include "web_history.h"
#include "web_pcap.h"
#include "web_pcapdir.h"
#include "web_series.h"

/* Kept free behind the assessment for /api/alert's history. */
#define WEB_EVIDENCE_RESERVE 8192

long long web_evidence_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* The rule passes a target address to fire(): the rule table's
 * match_ip / port cell names one (docs/views/alerts.md writes "—" for
 * one that does not, "— (L2 only)", "— (no IP)"). */
static int rule_names_ip(const web_akb_t *k) {
    if (!k || !k->match || !k->match[0]) return 0;
    return strncmp(k->match, "\xe2\x80\x94", 3) != 0 && k->match[0] != '-';
}

static int hits_of(const web_m4_t *m, const web_alert_tgt_t *t, web_pcap_hit_t *h) {
    if (!m || !m->pcap || !m->pcap->ndir) return 0;
    return web_pcapdir_for_alert(m->pcap, web_evidence_now_ms(), t->incident_id, t->pcap_name,
                                 t->rule, t->first_seen, t->last_seen, h, WEB_PCAPDIR_HITS);
}

/* Why the page has no capture to show, in sloth's terms: which alerts
 * src/alerts/engine.c dump_new_alert_pcaps() exports (a match_ip, sev
 * at or above pcap.min_severity, default 2, CRIT; outside
 * pcap.key_cooldown_secs, default 3600, of the key's last export), and
 * what src/alert_pcap.c keeps (the 256-packet ring's packets to or
 * from match_ip; none, no file). */
static const char *why_none(const web_m4_t *m, const web_alert_tgt_t *t, const web_akb_t *k) {
    if (!m || !m->pcap || !m->pcap->ndir)
        return "slothweb was not given --pcap-dir, so it reads no capture; sloth may still have "
               "written one on the sensor";
    if (k && !rule_names_ip(k))
        return "this rule names no target address (match_ip), and sloth's --pcap-dir export keeps "
               "only the packets to or from one: an alert of this type never has an IP capture "
               "(a wireless one can, under --eapol-dir with --collect-handshakes)";
    if (t->sev < 2)
        return "below sloth's pcap.min_severity: by default only CRIT alerts get a capture";
    if (t->pcap == 0)
        return "sloth's records say it wrote none for this incident: the key was inside "
               "pcap.key_cooldown_secs (default one hour) of its last capture, or no packet in "
               "the 256-packet ring was to or from its address";
    if (t->pcap == 1)
        return "sloth's record names a file the directory no longer holds (swept after "
               "pcap.retain_days, default 14) or that slothweb cannot open";
    return "no file in the directory's manifests matches it: sloth.db keeps no capture link, "
           "so a row is matched by its rule and time only";
}

/* The detail's numerals, observed: "name=123" and "name=12.5" tokens,
 * at most 8, the name [a-z_]. Only a detail the type admits reaches
 * here (web_alert_detail_ok()); nothing else of it is parsed. */
static int observed(web_jw_t *w, const char *d, int first) {
    int n = 0;
    for (const char *p = d; *p && n < 8; p++) {
        if (!islower((unsigned char)*p) || (p > d && (isalnum((unsigned char)p[-1]) || p[-1] == '_')))
            continue;
        const char *s = p;
        while (islower((unsigned char)*p) || *p == '_' || isdigit((unsigned char)*p)) p++;
        if (*p != '=' || p - s > 24) { if (!*p) break; continue; }
        const char *v = p + 1, *e = v;
        while (isdigit((unsigned char)*e) || (*e == '.' && isdigit((unsigned char)e[1]))) e++;
        if (e == v || e - v > 20) { p = e; if (!*p) break; continue; }
        char k[32], val[32];
        snprintf(k, sizeof(k), "detail %.*s", (int)(p - s), s);
        snprintf(val, sizeof(val), "%.*s", (int)(e - v), v);
        web_jw_raw(w, first && !n ? "[" : ",[");
        web_jw_str(w, k);
        web_jw_raw(w, ",");
        web_jw_str(w, val);
        web_jw_raw(w, "]");
        n++;
        p = e;
        if (!*p) break;
    }
    return n;
}

static void jw_pair(web_jw_t *w, int *first, const char *k, const char *v) {
    web_jw_raw(w, *first ? "[" : ",[");
    web_jw_str(w, k);
    web_jw_raw(w, ",");
    web_jw_str(w, v);
    web_jw_raw(w, "]");
    *first = 0;
}

void web_evidence_alert_json(web_jw_t *w, const web_m4_t *m, const web_alert_tgt_t *t) {
    const web_akb_t *k = web_akb_get(t->type);
    const web_asm_t *a = web_asm_get(t->type);
    web_pcap_hit_t h[WEB_PCAPDIR_HITS];
    int nh = hits_of(m, t, h);

    web_jw_raw(w, ",\"captures\":[");
    for (int i = 0; i < nh; i++) {
        web_jw_raw(w, i ? ",{\"n\":" : "{\"n\":");
        web_jw_int(w, i);
        web_jw_raw(w, ",\"file\":");       web_jw_str(w, h[i].file);
        web_jw_raw(w, ",\"matched_by\":"); web_jw_str(w, h[i].matched_by);
        if (h[i].e) {
            web_jw_raw(w, ",\"sink\":");       web_jw_str(w, h[i].e->sink);
            web_jw_raw(w, ",\"size\":");       web_jw_int(w, h[i].e->size);
            web_jw_raw(w, ",\"sha256\":");     web_jw_str(w, h[i].e->sha256);
            web_jw_raw(w, ",\"written_at\":");
            if (h[i].e->written_at[0]) web_jw_str(w, h[i].e->written_at); else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"rule\":");
            if (h[i].e->rule[0]) web_jw_str(w, h[i].e->rule); else web_jw_raw(w, "null");
            web_jw_raw(w, ",\"manifest\":true}");
        } else {
            web_jw_raw(w, ",\"sink\":null,\"size\":null,\"sha256\":null,\"written_at\":null,"
                          "\"rule\":null,\"manifest\":false}");
        }
    }
    web_jw_raw(w, "],\"captures_note\":");
    char nb[96];
    const char *note = m && m->pcap ? web_pcapdir_note(m->pcap, nb, sizeof(nb)) : "no --pcap-dir";
    if (note) web_jw_str(w, note); else web_jw_raw(w, "null");

    web_jw_raw(w, ",\"evidence\":{\"rule_names_ip\":");
    web_jw_raw(w, !k ? "null" : rule_names_ip(k) ? "true" : "false");
    web_jw_raw(w, ",\"why_no_capture\":");
    if (nh) web_jw_raw(w, "null"); else web_jw_str(w, why_none(m, t, k));
    web_jw_raw(w, ",\"observed\":[");
    int first = 1;
    char v[48];
    snprintf(v, sizeof(v), "%lld", t->count);
    jw_pair(w, &first, "count (evaluations)", v);
    if (t->observations > 0) {
        snprintf(v, sizeof(v), "%lld", t->observations);
        jw_pair(w, &first, "observations", v);
    }
    /* What the two numbers are, in the engine's terms
     * (src/alerts/engine.c, fire_inv()): neither counts packets. */
    jw_pair(w, &first, "reading the counts",
            "count is evaluations: one per poll (at least 4 a second) while the condition "
            "stands, not one per frame, request or attack. observations counts the polls "
            "whose detail differed from the last one emitted, and that one is re-taken only "
            "on a severity change or past the 60 s update floor, so once the detail moves "
            "observations follows evaluations: it is not a count of frames or requests either");
    for (int i = 0; a && i < a->nfm; i++)
        if (!strcmp(a->fm_k[i], "count_semantics"))
            jw_pair(w, &first, "count_semantics (assessment)", a->fm_v[i]);
    if (t->last_seen >= t->first_seen && t->first_seen > 0) {
        snprintf(v, sizeof(v), "%lld s", t->last_seen - t->first_seen);
        jw_pair(w, &first, "span", v);
    }
    if (t->detail[0]) observed(w, t->detail, 0);
    /* The assessment's thresholds, as its front matter writes them:
     * every key naming a threshold, a window or a count, and the
     * "tuning" list the assessments carry them in (each --tune knob
     * with its default and range). */
    web_jw_raw(w, "],\"thresholds\":[");
    first = 1;
    for (int i = 0; a && i < a->nfm; i++) {
        const char *key = a->fm_k[i];
        if (strstr(key, "threshold") || strstr(key, "window") || !strcmp(key, "count") ||
            strstr(key, "min_") || !strcmp(key, "tuning"))
            jw_pair(w, &first, key, a->fm_v[i]);
    }
    web_jw_raw(w, "],\"thresholds_from\":");
    if (a) web_jw_str(w, a->path); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"pcap_policy\":");
    web_jw_str(w, "sloth saves a pcap for an alert that names a target address, at or above "
                  "pcap.min_severity (default CRIT), at most once per alert key per "
                  "pcap.key_cooldown_secs (default 3600 s): the packets of its 256-packet ring "
                  "to or from that address, 64 bytes of each");
    web_jw_raw(w, "}");

    web_jw_raw(w, ",\"assessment\":");
    if (!a) { web_jw_raw(w, "null"); return; }
    /* The whole document goes in the answer's one buffer, before the
     * key's history: one too long for what is left is named, not cut
     * mid-word and not allowed to fail the page (WEB_EVIDENCE_RESERVE
     * kept for the history behind it). Measured by writing it: the
     * worst-case WEB_JW_EXPAND bound priced every real assessment
     * (12-30 KB of prose) past a 64 KiB answer. */
    size_t mark = w->len;
    int was = w->overflow;
    web_jw_raw(w, "{\"path\":");      web_jw_str(w, a->path);
    web_jw_raw(w, ",\"title\":");     web_jw_str(w, a->title);
    web_jw_raw(w, ",\"updated\":");
    if (a->updated[0]) web_jw_str(w, a->updated); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"front_matter\":[");
    first = 1;
    for (int i = 0; i < a->nfm; i++) jw_pair(w, &first, a->fm_k[i], a->fm_v[i]);
    web_jw_raw(w, "],\"sections\":[");
    for (int i = 0; i < a->nsec; i++) {
        web_jw_raw(w, i ? ",{\"heading\":" : "{\"heading\":");
        web_jw_str(w, a->sec[i].heading);
        web_jw_raw(w, ",\"text\":");
        web_jw_str(w, a->sec[i].text);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"bibliography\":[");
    for (int i = 0; i < a->nbib; i++) {
        if (i) web_jw_raw(w, ",");
        web_jw_str(w, a->bib[i]);
    }
    web_jw_raw(w, "],\"bibliography_note\":");
    if (a->bib_note && a->bib_note[0]) web_jw_str(w, a->bib_note); else web_jw_raw(w, "null");
    web_jw_raw(w, "}");
    if (!was && (w->overflow || w->len + WEB_EVIDENCE_RESERVE > w->cap)) {
        w->len = mark;
        w->overflow = 0;
        w->buf[mark] = '\0';
        web_jw_raw(w, "{\"path\":");  web_jw_str(w, a->path);
        web_jw_raw(w, ",\"too_large\":true}");
    }
}

/* ── the two routes ───────────────────────────────────────────────── */

typedef struct {
    web_alert_tgt_t t;
    web_pcap_hit_t  h[WEB_PCAPDIR_HITS];
    int             nh;
} ctx_t;

/* The alert, its file n opened and read whole: 0 with *buf and *size,
 * or an error answered into body (1), or -1. */
static int open_capture(const web_m4_t *m, web_live_t *live, const char *idv, const char *nv,
                        long long now_s, ctx_t *x, const web_pcap_hit_t **hit,
                        unsigned char **buf, long long *size, char *body, size_t cap,
                        size_t *len, int *status) {
    *buf = NULL;
    const char *why = NULL;
    int r = web_alert_locate(m, live, idv, now_s, &x->t, &why);
    if (r < 0) return web_hist_error(503, "sloth_db_unreadable", NULL, body, cap, len, status) ? -1 : 1;
    if (r == 0)
        return web_hist_error(!strcmp(why, "bad_id") ? 400 : 404, why, NULL, body, cap, len,
                              status) ? -1 : 1;
    if (!m || !m->pcap || !m->pcap->ndir)
        return web_hist_error(404, "no_pcap_dir", NULL, body, cap, len, status) ? -1 : 1;
    long long n = -1;
    if (!nv || !nv[0] || strlen(nv) > 2 || !isdigit((unsigned char)nv[0]) ||
        (nv[1] && !isdigit((unsigned char)nv[1])))
        return web_hist_error(400, "bad_n", NULL, body, cap, len, status) ? -1 : 1;
    n = atoi(nv);
    x->nh = hits_of(m, &x->t, x->h);
    if (n >= x->nh)
        return web_hist_error(404, "no_such_capture", NULL, body, cap, len, status) ? -1 : 1;
    *hit = &x->h[n];
    int err = 0;
    int dfd = web_pcapdir_open_dir(m->pcap, (*hit)->dir, &err);
    if (dfd < 0) return web_hist_error(503, "pcap_dir_unreadable", NULL, body, cap, len, status) ? -1 : 1;
    const char *fwhy = NULL;
    int fd = web_pcapdir_open_file(dfd, (*hit)->file, size, &fwhy);
    close(dfd);
    if (fd < 0) {
        int st = !strcmp(fwhy, "too_large") ? 413 : !strcmp(fwhy, "not_found") ? 404 : 403;
        return web_hist_error(st, fwhy, NULL, body, cap, len, status) ? -1 : 1;
    }
    *buf = web_pcapdir_slurp(fd, *size);
    close(fd);
    if (!*buf) return web_hist_error(503, "unreadable", NULL, body, cap, len, status) ? -1 : 1;
    return 0;
}

/* web_pcapdir_verify()'s word as the API spells it. */
static const char *hash_status(const char *v) {
    return !strcmp(v, "verified") ? "verified" : !strcmp(v, "MISMATCH") ? "mismatch"
                                                                        : "no_manifest_entry";
}

int web_pcap_frames_route(const web_m4_t *m, web_live_t *live, const char *query,
                          long long now_s, char *body, size_t cap, size_t *len,
                          int *status) {
    char err[48];
    web_param_t ps[3] = { { "id", "", 0 }, { "n", "", 0 }, { "offset", "", 0 } };
    if (web_params_parse(query, ps, 3, err, sizeof(err)) != 0)
        return web_hist_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen) return web_hist_error(400, "missing_id", NULL, body, cap, len, status);
    long long off = 0;
    if (ps[2].seen) {
        char *e;
        off = strtoll(ps[2].val, &e, 10);
        if (*e || off < 0 || off >= WEB_PCAP_RECORDS || !isdigit((unsigned char)ps[2].val[0]))
            return web_hist_error(400, "bad_offset", NULL, body, cap, len, status);
    }
    ctx_t *x = calloc(1, sizeof(*x));
    if (!x) return -1;
    const web_pcap_hit_t *hit = NULL;
    unsigned char *buf = NULL;
    long long size = 0;
    int r = open_capture(m, live, ps[0].val, ps[1].seen ? ps[1].val : "", now_s, x, &hit, &buf,
                         &size, body, cap, len, status);
    if (r != 0) { free(x); return r < 0 ? -1 : 0; }
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"id\":");          web_jw_str(&w, x->t.id);
    web_jw_raw(&w, ",\"n\":");           web_jw_int(&w, hit - x->h);
    web_jw_raw(&w, ",\"file_name\":");   web_jw_str(&w, hit->file);
    web_jw_raw(&w, ",\"matched_by\":");  web_jw_str(&w, hit->matched_by);
    const char *v = web_pcapdir_verify(buf, (size_t)size, hit->e);
    web_jw_raw(&w, ",\"hash\":{\"status\":");
    web_jw_str(&w, hash_status(v));
    web_jw_raw(&w, ",\"says\":");
    web_jw_str(&w, !strcmp(v, "verified") ? "hash verified" : !strcmp(v, "MISMATCH")
                   ? "HASH MISMATCH" : "no manifest entry");
    web_jw_raw(&w, ",\"algorithm\":\"SHA-256\",\"bytes\":"); web_jw_int(&w, size);
    web_jw_raw(&w, ",\"manifest_sha256\":");
    if (hit->e) web_jw_str(&w, hit->e->sha256); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"manifest_size\":");
    if (hit->e) web_jw_int(&w, hit->e->size); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"written_at\":");
    if (hit->e && hit->e->written_at[0]) web_jw_str(&w, hit->e->written_at);
    else web_jw_raw(&w, "null");
    web_jw_raw(&w, "},");
    const char *why = NULL;
    size_t mark = w.len;
    if (web_pcap_frames_json(buf, (size_t)size, off, &w, &why) != 0) {
        w.len = mark;
        body[w.len] = '\0';
        web_jw_raw(&w, "\"error\":");
        web_jw_str(&w, why);
        web_jw_raw(&w, ",\"message\":");
        web_jw_str(&w, !strcmp(why, "pcapng_not_supported")
                       ? "a pcapng file: sloth writes classic pcap; convert it with "
                         "editcap -F pcap to read it here"
                       : !strcmp(why, "short_file") ? "shorter than a pcap file header"
                       : "not a pcap file: its first four bytes are no pcap magic");
    }
    web_jw_raw(&w, "}\n");
    free(buf);
    free(x);
    if (w.overflow) return -1;
    *len = w.len;
    *status = why ? 415 : 200;
    return 0;
}

int web_pcap_download_route(const web_m4_t *m, web_live_t *live, const char *query,
                            long long now_s, unsigned char **data, size_t *n,
                            char *name, size_t namesz, const char **hash, char *body,
                            size_t cap, size_t *len, int *status) {
    *data = NULL;
    *n = 0;
    *hash = NULL;
    char err[48];
    web_param_t ps[2] = { { "id", "", 0 }, { "n", "", 0 } };
    if (web_params_parse(query, ps, 2, err, sizeof(err)) != 0)
        return web_hist_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen) return web_hist_error(400, "missing_id", NULL, body, cap, len, status);
    ctx_t *x = calloc(1, sizeof(*x));
    if (!x) return -1;
    const web_pcap_hit_t *hit = NULL;
    unsigned char *buf = NULL;
    long long size = 0;
    int r = open_capture(m, live, ps[0].val, ps[1].seen ? ps[1].val : "", now_s, x, &hit, &buf,
                         &size, body, cap, len, status);
    if (r != 0) { free(x); return r < 0 ? -1 : 0; }
    snprintf(name, namesz, "%s", hit->file);
    /* The bytes served, hashed: the page's "hash verified" is of an
     * earlier read (/api/pcap/frames), and a file replaced since would
     * otherwise download with no word of it. */
    *hash = hash_status(web_pcapdir_verify(buf, (size_t)size, hit->e));
    free(x);
    *data = buf;
    *n = (size_t)size;
    *status = 200;
    *len = 0;
    return 0;
}
