#include "web_bundle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "web_alerts.h"
#include "web_assets.h"
#include "web_devices.h"
#include "web_metrics.h"
#include "web_series.h"
#include "web_slothdb.h"

/* The sloth source tree slothweb was built from (the Makefile reads
 * SLOTH_VERSION out of include/sloth.h); slothweb has no version. */
#ifndef SLOTHWEB_BUILD_VERSION
#define SLOTHWEB_BUILD_VERSION "unknown"
#endif

size_t web_bundle_max = WEB_BUNDLE_MAX;
size_t web_bundle_scratch = WEB_BUNDLE_SCRATCH;

enum { K_DEVICE, K_ALERT, K_LOOKUP };
static const char *const KIND_WORD[] = { "device", "alert", "lookup" };

#define BUNDLE_READS 4

struct web_bundle_ctx {
    const web_health_t *h;
    const web_m4_t     *m;
    int        kind;
    char       id[WEB_PARAM_MAX + 1];
    /* The device the bundle is about: the MAC, its sloth.db address,
     * and the stream's binding when it differs. "" when unknown. */
    char       mac[WEB_KEY_MAX + 1];
    char       ip[WEB_KEY_MAX + 1];
    char       ip2[WEB_KEY_MAX + 1];
    /* The spliced bodies, each without its trailing newline. */
    char      *primary;  size_t primary_len;
    char      *nested;   size_t nested_len;    /* the drawer of mac */
    int        nested_status;                  /* 0 not read */
    char      *lookup;   size_t lookup_len;    /* /api/lookup of ip, alert with no MAC */
    int        lookup_status;
    struct { const char *what; long long ms; int status; } reads[BUNDLE_READS];
    int        nreads;
    /* The ticker ring, newest last as the ring gives it. */
    web_live_rec_t *recs;
    int        nrecs;
    unsigned long long latest;
    /* What the optional pass rolled back. */
    const char *truncated[16];
    int         ntrunc;
};

/* ── reading our own writers' output ───────────────────────────────── */

/* A needle written by our own writers is a raw-quoted member name: it
 * cannot match inside a string value, where every quote is escaped. */
static const char *jafter(const char *body, const char *needle) {
    const char *p = body ? strstr(body, needle) : NULL;
    return p ? p + strlen(needle) : NULL;
}

/* The string value at p ("..." of plain ASCII: a MAC, an address, a
 * word) into out; 1, or 0 for null / not a string / too long. */
static int jstr(const char *p, char *out, size_t cap) {
    if (!p || *p != '"') return 0;
    p++;
    size_t n = 0;
    while (p[n] && p[n] != '"' && p[n] != '\\') n++;
    if (p[n] != '"' || n >= cap) return 0;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static int jstr_after(const char *body, const char *needle, char *out, size_t cap) {
    return jstr(jafter(body, needle), out, cap);
}

/* 1 / 0 for true / false at the member, -1 when absent. */
static int jbool_after(const char *body, const char *needle) {
    const char *p = jafter(body, needle);
    if (!p) return -1;
    if (!strncmp(p, "true", 4)) return 1;
    if (!strncmp(p, "false", 5)) return 0;
    return -1;
}

/* The integer at the member into *v; 1, or 0 for null / absent. */
static int jint_after(const char *body, const char *needle, long long *v) {
    const char *p = jafter(body, needle);
    if (!p || !(*p == '-' || (*p >= '0' && *p <= '9'))) return 0;
    *v = strtoll(p, NULL, 10);
    return 1;
}

/* ── the splices ───────────────────────────────────────────────────── */

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void note_read(web_bundle_ctx_t *c, const char *what, long long ms, int st) {
    if (c->nreads >= BUNDLE_READS) return;
    c->reads[c->nreads].what = what;
    c->reads[c->nreads].ms = ms;
    c->reads[c->nreads].status = st;
    c->nreads++;
}

enum { R_DEVICE, R_ALERT, R_LOOKUP };
enum { SPLICE_TOO_LARGE = -1, SPLICE_NO_MEMORY = -2 };

/* One route, rendered into a fresh scratch of the routes' own cap, its
 * trailing newline dropped. *out is the body (malloc'd; the caller
 * frees it even for an error status) and the return the status, or
 * SPLICE_TOO_LARGE when the route could not render into its cap, or
 * SPLICE_NO_MEMORY. */
static int splice_read(web_bundle_ctx_t *c, const char *what, int which,
                       const char *arg, char **out, size_t *outlen) {
    char *buf = malloc(WEB_BUNDLE_SCRATCH);
    if (!buf) return SPLICE_NO_MEMORY;
    size_t bl = 0;
    int st = 0, rc;
    long long t0 = mono_ms();
    if (which == R_DEVICE)
        rc = web_device_route(c->m, arg, "", c->h->wall_s, buf, WEB_BUNDLE_SCRATCH, &bl, &st);
    else if (which == R_ALERT)
        rc = web_alert_route(c->m, c->h->live, arg, c->h->wall_s, buf, WEB_BUNDLE_SCRATCH,
                             &bl, &st);
    else
        rc = web_lookup_route(c->m, arg, c->h->wall_s, buf, WEB_BUNDLE_SCRATCH, &bl, &st);
    long long ms = mono_ms() - t0;
    if (rc != 0 || bl == 0) {
        free(buf);
        note_read(c, what, ms, 503);
        return SPLICE_TOO_LARGE;
    }
    if (buf[bl - 1] == '\n') bl--;
    buf[bl] = '\0';
    note_read(c, what, ms, st);
    *out = buf;
    *outlen = bl;
    return st;
}

static void unavailable(web_jw_t *w, const char *reason) {
    web_jw_raw(w, "{\"available\":false,\"reason\":");
    web_jw_str(w, reason);
    web_jw_raw(w, "}");
}

/* ── the optional sections ─────────────────────────────────────────── */

/* The record's line as the page's ticker shows it under the scope in
 * effect (web_live_json_scoped()), or NULL when the scope holds it
 * not: under Monitor a device row's own line, no address, no name. */
static const char *rec_line(const web_bundle_ctx_t *c, const web_live_rec_t *r) {
    const web_scope_ctx_t *sc = c->h->sc;
    if (!sc || sc->scope == WEB_SCOPE_HYBRID) return r->text;
    if (!web_scope_pass(sc->scope, r->sc)) return NULL;
    if (sc->scope == WEB_SCOPE_MONITOR && !strcmp(r->type, "device")) return r->text_m;
    return r->text;
}

/* The line of the record when the scope holds it and one of its
 * address members is one of keys, else NULL. Never the line itself: it
 * is cut at WEB_LIVE_TEXT_MAX, so 192.0.2.123 at its end reads as
 * 192.0.2.12, and it carries free text an SSID can make look like an
 * address. Under Monitor a device row is matched on what its own line
 * shows, its MAC. */
static const char *rec_match(const web_bundle_ctx_t *c, const web_live_rec_t *r,
                             const char *const keys[3]) {
    const char *t = rec_line(c, r);
    if (!t) return NULL;
    int mon = t == r->text_m;
    for (int k = 0; k < 3; k++)
        if (keys[k] && web_live_rec_names(r, keys[k], mon)) return t;
    return NULL;
}

/* The ticker records that name the bundle's device or address, newest
 * first, by type, as the scope in effect shows them. 0 when the stream
 * has nothing (no socket). */
static size_t fill_records(const web_bundle_ctx_t *c, web_jw_t *w) {
    if (!c->h->live) return 0;
    size_t start = w->len;
    const char *const keys[3] = { c->mac[0] ? c->mac : NULL, c->ip[0] ? c->ip : NULL,
                                  c->ip2[0] ? c->ip2 : NULL };
    int matched = 0;
    /* The types of the matched records and their counts. */
    struct { const char *name; int n; } by[WEB_LIVE_TYPES];
    int nby = 0;
    for (int i = c->nrecs - 1; i >= 0; i--) {
        const web_live_rec_t *r = &c->recs[i];
        if (!rec_match(c, r, keys)) continue;
        matched++;
        int j = 0;
        while (j < nby && strcmp(by[j].name, r->type)) j++;
        if (j == nby && nby < WEB_LIVE_TYPES) { by[nby].name = r->type; by[nby].n = 0; nby++; }
        if (j < nby) by[j].n++;
    }
    long long window = 0;
    if (c->nrecs > 0 && c->recs[c->nrecs - 1].ts >= c->recs[0].ts)
        window = c->recs[c->nrecs - 1].ts - c->recs[0].ts;
    web_jw_raw(w, "{\"available\":true,\"source\":\"ticker ring: the newest ");
    web_jw_int(w, WEB_BUNDLE_RECORDS);
    web_jw_raw(w, " records of every type the stream carried, those the scope in "
                  "effect holds, matched on the device's MAC and addresses in each "
                  "record's address members (mac, bssid, sta_mac, addr, ip, src, src_ip, "
                  "dst, dst_ip, match_ip), never in its text; text is the one-line "
                  "summary as the page's ticker shows it\"");
    web_jw_raw(w, ",\"ring_records\":");  web_jw_int(w, c->nrecs);
    web_jw_raw(w, ",\"ring_full\":");
    web_jw_raw(w, c->latest > (unsigned long long)WEB_BUNDLE_RECORDS ? "true" : "false");
    web_jw_raw(w, ",\"window_s\":");      web_jw_int(w, window);
    web_jw_raw(w, ",\"matched\":");       web_jw_int(w, matched);
    web_jw_raw(w, ",\"by_type\":{");
    for (int j = 0; j < nby; j++) {
        if (j) web_jw_raw(w, ",");
        web_jw_key(w, by[j].name);
        web_jw_int(w, by[j].n);
    }
    web_jw_raw(w, "},\"records\":[");
    int k = 0;
    for (int i = c->nrecs - 1; i >= 0; i--) {
        const web_live_rec_t *r = &c->recs[i];
        const char *line = rec_match(c, r, keys);
        if (!line) continue;
        web_jw_raw(w, k++ ? ",{\"seq\":" : "{\"seq\":");
        web_jw_int(w, (long long)r->seq);
        web_jw_raw(w, ",\"type\":"); web_jw_str(w, r->type);
        web_jw_raw(w, ",\"ts\":");   web_jw_int(w, r->ts);
        web_jw_raw(w, ",\"text\":"); web_jw_str(w, line);
        web_jw_raw(w, ",\"sc\":");   web_jw_int(w, r->sc);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]}");
    return w->overflow ? 0 : w->len - start;
}

/* The alert's observed values beside the rule's trigger text: the KB
 * carries the trigger as prose, so there is no threshold table. */
static size_t fill_observed(const web_bundle_ctx_t *c, web_jw_t *w) {
    size_t start = w->len;
    const char *p = c->primary;
    static const struct { const char *name, *needle; } F[] = {
        { "sev", ",\"sev\":" }, { "count", ",\"count\":" },
        { "latest_count", ",\"latest_count\":" }, { "observations", ",\"observations\":" },
        { "incidents", ",\"incidents\":" }, { "sev_changes", ",\"sev_changes\":" },
    };
    web_jw_raw(w, "{\"observed\":{");
    for (size_t i = 0; i < sizeof(F) / sizeof(F[0]); i++) {
        long long v;
        if (i) web_jw_raw(w, ",");
        web_jw_key(w, F[i].name);
        if (jint_after(p, F[i].needle, &v)) web_jw_int(w, v); else web_jw_raw(w, "null");
    }
    long long first, last;
    web_jw_raw(w, ",\"duration_s\":");
    if (jint_after(p, ",\"first_seen\":", &first) && jint_after(p, ",\"last_seen\":", &last) &&
        last >= first)
        web_jw_int(w, last - first);
    else
        web_jw_raw(w, "null");
    char word[32];
    web_jw_raw(w, ",\"state\":");
    if (jstr_after(p, ",\"state\":", word, sizeof(word))) web_jw_str(w, word);
    else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"reason\":");
    if (jstr_after(p, ",\"reason\":", word, sizeof(word))) web_jw_str(w, word);
    else web_jw_raw(w, "null");
    web_jw_raw(w, "},\"thresholds\":{\"available\":false,\"reason\":\"not_built\","
                  "\"note\":\"the alert KB carries the rule's trigger as prose "
                  "(page.kb.what); no structured threshold table exists\"}}");
    return w->overflow ? 0 : w->len - start;
}

const char *web_bundle_nested_reason(int status, const char *body) {
    char word[48];
    if (status == SPLICE_TOO_LARGE) return "too_large";
    if (status == 400 || status == 404) return "no_data";
    if (status == 503 && body && jstr_after(body, "\"error\":", word, sizeof(word))) {
        if (!strcmp(word, "no_sloth_db")) return "no_sloth_db";
        if (!strcmp(word, "sloth_db_timeout")) return "budget";
    }
    return "read_error";
}

/* The drawer of the device the alert or the Lookup card names. */
static size_t fill_nested_device(const web_bundle_ctx_t *c, web_jw_t *w) {
    if (c->nested_status == 200 && c->nested) {
        web_jw_rawn(w, c->nested, c->nested_len);
        return c->nested_len;
    }
    if (c->nested_status == 0) return 0;          /* no MAC to read */
    unavailable(w, web_bundle_nested_reason(c->nested_status, c->nested));
    return 1;
}

/* The Lookup card of the alert's address, when it names no MAC. */
static size_t fill_nested_lookup(const web_bundle_ctx_t *c, web_jw_t *w) {
    if (c->lookup_status == 200 && c->lookup) {
        web_jw_rawn(w, c->lookup, c->lookup_len);
        return c->lookup_len;
    }
    if (c->lookup_status == 0) return 0;
    unavailable(w, web_bundle_nested_reason(c->lookup_status, c->lookup));
    return 1;
}

/* The stream mix the alert sits in: /api/live's "types" map. A summary
 * that did not render, or carries no map, is not an empty mix: an "{}"
 * here would read as "no records". It is too_large (the summary
 * outgrew the scratch) or no_data, never a map. */
static size_t fill_types(const web_bundle_ctx_t *c, web_jw_t *w) {
    if (!c->h->live) return 0;
    size_t start = w->len;
    char *buf = malloc(web_bundle_scratch);
    if (!buf) return 0;
    size_t n = web_live_json_scoped(c->h->live, c->h->sc, buf, web_bundle_scratch,
                                    c->h->now_ms);
    if (n == 0) {
        free(buf);
        w->overflow = 1;              /* write_section's too_large marker */
        return 0;
    }
    /* A flat map of type to count: no brace inside it. */
    const char *p = jafter(buf, ",\"types\":{");
    const char *e = p ? strchr(p, '}') : NULL;
    if (!e) {
        free(buf);
        return 0;
    }
    web_jw_raw(w, "{");
    web_jw_rawn(w, p, (size_t)(e - p) + 1);
    free(buf);
    return w->overflow ? 0 : w->len - start;
}

const web_bundle_sec_t web_bundle_sections[] = {
    { "device", "signal_history", NULL, "not_built", 32 * 1024 },
    { "device", "distance",       NULL, "not_kept",   1024 },
    { "device", "records_recent", fill_records, NULL, 16 * 1024 },
    { "device", "vendor_research", NULL, "not_built", 16 * 1024 },
    { "device", "frrs",           NULL, "not_built", 160 * 1024 },
    { "device", "comint_report",  NULL, "not_built", 32 * 1024 },
    { "device", "triage",         NULL, "not_built",  8 * 1024 },
    { "device", "location",       NULL, "not_built", 16 * 1024 },
    { "alert",  "observed_vs_thresholds", fill_observed, NULL, 2 * 1024 },
    { "alert",  "assessment",     NULL, "not_built", 48 * 1024 },
    { "alert",  "frrs",           NULL, "not_built", 160 * 1024 },
    { "alert",  "evidence",       NULL, "not_built", 16 * 1024 },
    { "alert",  "records_around", fill_records, NULL, 16 * 1024 },
    { "alert",  "records_by_type_global", fill_types, NULL, 4 * 1024 },
    { "alert",  "device",         fill_nested_device, NULL, WEB_BUNDLE_SCRATCH },
    { "alert",  "lookup",         fill_nested_lookup, NULL, WEB_BUNDLE_SCRATCH },
    { "alert",  "triage",         NULL, "not_built",  8 * 1024 },
    { "alert",  "location",       NULL, "not_built", 16 * 1024 },
    { "lookup", "device",         fill_nested_device, NULL, WEB_BUNDLE_SCRATCH },
};
const size_t web_bundle_sections_n = sizeof(web_bundle_sections) / sizeof(web_bundle_sections[0]);

const char *const web_bundle_reasons[] = {
    "not_built", "no_data", "too_large", "withheld", "budget", "no_sloth_db", "not_kept",
    "read_error",
};
const size_t web_bundle_reasons_n = sizeof(web_bundle_reasons) / sizeof(web_bundle_reasons[0]);

/* ── the analysis aids ─────────────────────────────────────────────── */

static const struct { const char *key, *text; } GLOSSARY[] = {
    { "bundle_schema", "semver of this bundle's shape; fields are only added within a major" },
    { "generated_at", "when the server built this bundle: iso (UTC) and unix (seconds)" },
    { "server.timezone", "the slothweb host's local zone; every *_seen field is unix seconds (UTC); week.cells and week.now_cell are in this local zone" },
    { "server.slothweb.build_version", "the sloth source tree slothweb was built from (its SLOTH_VERSION); slothweb has no version of its own, and the sensor's running sloth is sloth_version" },
    { "server.slothweb.page_etag", "identifies the exact page build this was copied from" },
    { "sensor.state", "ok | degraded (a capture or monitor handle open with its thread not running, or the launch scope not enforced) | not_observing (no handle open) | stale (no sensor_health for 330 s) | unknown (none yet)" },
    { "sensor.capture.linktype", "libpcap DLT of the IP capture; 105/119/127/163 mean 802.11, i.e. the IP capture is itself a monitor radio" },
    { "scope_in_effect", "the viewer's capture-scope filter: hybrid = everything; monitor = only what the passive monitor radio and BLE receivers heard over the air; local = only what the host's own connected interfaces carried. sloth.db rows carry no capture path and count as local" },
    { "withheld", "what the server deliberately left out and why; the page would not show these either" },
    { "unix seconds", "integer seconds since 1970-01-01T00:00:00Z" },
    { "dBm", "received signal strength; -30 very strong, -67 good, -80 weak, -90 at the edge; the fixed visual scale is -95..-20" },
    { "sev", "0 low, 1 warn, 2 crit (sloth's severity)" },
    { "mac", "lower-case xx:xx:xx:xx:xx:xx" },
    { "random", "true when the MAC's locally-administered bit is set: a randomised (privacy) or software-assigned address; the OUI then names no vendor" },
    { "sources", "bitmask of where sloth saw the device: 1 ARP (A), 2 DHCP (D), 4 mDNS, 8 beacon (B), 16 probe request (P), 32 associated station (S), 64 camera signal. The page's glyph string is A D P B S in that order" },
    { "risk", "sloth's device risk level: 0 LOW, 1 MED, 2 HIGH, 3 CRIT, from the weighted sum of risk_signals (weights 1,1,1,1,3,3 in bit order; >=1 MED, >=3 HIGH, >=5 CRIT)" },
    { "risk_signals", "bitmask: 1 random MAC, 2 unknown vendor, 4 no hostname from DHCP/mDNS/NBNS, 8 probe-only (never associated), 16 a cleartext credential was attributed to it, 32 an alert's match_ip was its IP" },
    { "name_src", "D DHCP hostname, m mDNS host, N NBNS name, h sloth's own hostname field, p a PTR answer seen on the wire (passive); names[].where says which store it came from: sloth.db, stream (slothweb's identity table, last 15 min), wire (passive PTR cache)" },
    { "ssid", "display form: printable UTF-8 as is, anything else as \\xNN per octet and a backslash as \\\\; ssid_np 1 means something was escaped (non-printable); ssid_k is the display colour index 0..7 and carries no meaning" },
    { "device_class", "0 unknown, 1 camera vendor, 2 camera, 3 not a camera (sloth's camera classifier)" },
    { "presence", "36 hex digits = 144 cells of 10 minutes ending in the cell containing now; cell 0 (oldest) is the high bit of the first digit; a set bit means the device was seen in that cell; presence_from is cell 0's start" },
    { "week", "168 cells, local Monday 00:00 first, each [share of past weeks the device was present in that hour, n weeks observed]; warm_n is the weeks needed before a cell is trusted; now_cell is the current hour's index" },
    { "z", "the device's largest |z-score| now across its series against its hour-of-week baseline" },
    { "anomalies[]", "slothweb's own anomaly episodes: rule A1 rate (a series far from its baseline), A2 new (a MAC never seen), A3 hours (present at an unusual hour), A4 vendor (unusual vendor), A5/A6 ident (names disagree or a name moved MACs), A7 fanout (a host talking to unusually many peers), A8 dns (NXDOMAIN share), A9 proto (an unusual protocol), A10 sensor; score and peak 0..100; evidence is one line of the numbers" },
    { "alerts[].id / alert.page.id", "opaque: s<handle> is slothweb's handle for a live-stream incident, d<rowid> names sloth.db's newest row of the alert's key. Neither derives from the alert key or sloth's incident_id" },
    { "alert.state", "open (live, unresolved) | closed (resolved on the stream) | recorded (sloth.db only; the stream does not hold it)" },
    { "alert.source", "stream | sloth.db | both" },
    { "count", "rule evaluations that fired while the condition held (about one per evaluation pass), across every incident of the key; not packets or requests; latest_count is the one incident this id names" },
    { "observations", "evaluations at which the rendered detail or severity differed from the last emitted one (stream only); it follows evaluations while detail keeps changing inside the 60 s update floor; not a count of frames or requests" },
    { "incidents", "how many times this key opened (1 + reopens)" },
    { "sev_history[].ev", "create | update | escalate | resolve" },
    { "history.runs", "incidents of the same key less than gap_s apart folded into one run, newest first" },
    { "kb", "what slothweb's build knows about the alert type, from sloth's own docs and research corpus; kb.sev is the rule table's severity cell, kb.what the trigger text, kb.sources the research documents that cite the type" },
    { "technique", "MITRE ATT&CK technique id; null for a posture/exposure finding or sloth's own operational state" },
    { "pcap", "true: sloth saved a pcap of the alert's frames on the sensor; false: none; null: only the live stream says and this came from sloth.db" },
    { "detail_shown", "false: the alert type's detail text can carry a credential or free text and is withheld everywhere" },
    { "oui", "IEEE registry lookup of the MAC's first 24/28/36 bits: registry MA-L/MA-M/MA-S, private = a private registration, local/multicast = the address bits" },
    { "records_recent / records_around", "the last records the live stream carried that mention this device or address, from a ring of the newest 50 of every type; a stopgap, not a per-device history; sc is the record's capture-scope tag (1 monitor, 2 local, 3 both)" },
    { "available:false", "the section's data is not in this bundle; reason: not_built (that feature is not in this build), no_data (built, nothing for this id), too_large (over its cap), withheld (policy), budget (the read ran out of time), no_sloth_db (needs --sloth-db), not_kept (the stream carries it but slothweb does not retain it), read_error (the read failed: sloth.db could not answer)" },
    { "limits", "every cap applied to this bundle and whether it cut anything" },
};

static const char PROMPT[] =
    "You are analysing a JSON bundle copied from slothweb, the web view of sloth: a "
    "PASSIVE network and radio monitor on Linux. sloth never transmits, resolves, probes "
    "or scans; everything here was overheard from one vantage point (one host's "
    "interfaces and, when present, one monitor-mode Wi-Fi radio and BLE receivers). "
    "Treat it as a single sensor's partial view, not ground truth about the network.\n\n"
    "Read \"glossary\" first for units and field meanings, \"scope_in_effect\" for what "
    "this view deliberately excludes, \"withheld\" for what the server removed on "
    "purpose, and \"limits\" for every list that was cut. A section with "
    "\"available\": false is missing for the stated reason; do not infer its "
    "contents.\n\n"
    "Distinguish OBSERVED (timestamps, addresses, signal in dBm, presence cells, the "
    "alert's severity history) from INFERRED (vendor "
    "from OUI, device class, risk level, anomaly scores, any distance estimate, the "
    "KB's prose). An alert's count and observations are evaluations of a standing "
    "condition, not event counts: a large figure is how long the rule kept matching, "
    "not how many frames or requests were seen. Alert ids are opaque handles. SSIDs are in a display form with \\xNN "
    "escapes for non-printable octets; a flagged non-printable SSID may be a "
    "look-alike.\n\n"
    "Give: (1) a one-paragraph assessment of what this device/alert most likely is and "
    "whether it warrants action; (2) your confidence (low/medium/high) and the single "
    "observation that most drives it; (3) the two or three specific next checks an "
    "operator can do passively or on the device itself (what to look for in presence, "
    "names, associations, the stream, sloth.db queries), and what finding would change "
    "your assessment; (4) what you cannot tell from one sensor's view. Be concrete and "
    "terse; cite the bundle's fields by name.";

static void write_aids(web_jw_t *w) {
    web_jw_raw(w, ",\"glossary\":{");
    for (size_t i = 0; i < sizeof(GLOSSARY) / sizeof(GLOSSARY[0]); i++) {
        if (i) web_jw_raw(w, ",");
        web_jw_key(w, GLOSSARY[i].key);
        web_jw_str(w, GLOSSARY[i].text);
    }
    web_jw_raw(w, "},\"prompt\":");
    web_jw_str(w, PROMPT);
}


/* ── the envelope ──────────────────────────────────────────────────── */

static void write_envelope(const web_bundle_ctx_t *c, web_jw_t *w) {
    const web_health_t *h = c->h;
    web_jw_raw(w, "\"bundle_schema\":\"" WEB_BUNDLE_SCHEMA "\",\"kind\":");
    web_jw_str(w, KIND_WORD[c->kind]);
    web_jw_raw(w, ",\"id\":"); web_jw_str(w, c->id);

    char iso[40] = "";
    time_t tt = (time_t)h->wall_s;
    struct tm gt, lt;
    if (gmtime_r(&tt, &gt)) strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", &gt);
    web_jw_raw(w, ",\"generated_at\":{\"iso\":"); web_jw_str(w, iso);
    web_jw_raw(w, ",\"unix\":"); web_jw_int(w, h->wall_s);
    web_jw_raw(w, "}");

    tzset();
    const char *tz = tzname[0];
    if (localtime_r(&tt, &lt) && lt.tm_isdst > 0) tz = tzname[1];
    web_jw_raw(w, ",\"server\":{\"timezone\":{\"name\":"); web_jw_str(w, tz ? tz : "");
    web_jw_raw(w, ",\"utc_offset_s\":"); web_jw_int(w, web_utc_offset(h->wall_s));
    /* No host name: no page shows it, and a bundle is made to be
     * pasted elsewhere (a site or owner name often rides in it). */
    web_jw_raw(w, "},\"slothweb\":{\"build_version\":\"" SLOTHWEB_BUILD_VERSION "\","
                  "\"page_etag\":");
    /* The ETag's hex, without the quotes the header form carries. */
    size_t el = strlen(web_page_etag);
    if (el >= 2 && web_page_etag[0] == '"') web_jw_strn(w, web_page_etag + 1, el - 2);
    else web_jw_str(w, web_page_etag);
    web_jw_raw(w, "},\"uptime_s\":"); web_jw_int(w, h->uptime_s);
    web_jw_raw(w, "}");

    /* sloth's own version: sensor_health carries no version field. */
    web_jw_raw(w, ",\"sensor\":");
    if (h->live) web_live_bundle_sensor(h->live, h->sc, w, h->now_ms);
    else web_jw_raw(w, "{\"socket\":\"none\",\"state\":\"unknown\"}");
    web_jw_raw(w, ",\"sloth_version\":{\"available\":false,\"reason\":\"not_kept\","
                  "\"note\":\"sensor_health carries no version field\"}");
    web_jw_raw(w, ",\"site_label\":{\"available\":false,\"reason\":\"not_built\","
                  "\"note\":\"slothweb has no site label flag\"}");

    /* sloth.db as /api/health reports it. */
    web_jw_raw(w, ",\"sloth_db\":{\"state\":");
    if (!c->m->sdb || !c->m->sdb->configured) {
        web_jw_raw(w, "\"none\",\"schema\":null,\"mode\":null,\"mtime\":null,"
                      "\"age_s\":null,\"stale\":null}");
    } else {
        web_sdb_stats_t st;
        web_slothdb_stats(c->m->sdb, &st);
        int open = st.state == WEB_SDB_OPEN;
        web_jw_str(w, web_slothdb_state_word(st.state));
        web_jw_raw(w, ",\"schema\":");
        if (open) web_jw_int(w, st.schema); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"mode\":");
        if (st.mode[0]) web_jw_str(w, st.mode); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"mtime\":");
        if (open && st.mtime > 0) web_jw_int(w, st.mtime); else web_jw_raw(w, "null");
        long long age;
        int have_age = web_m4_db_age(c->m, h->wall_s, &age);
        web_jw_raw(w, ",\"age_s\":");
        if (have_age) web_jw_int(w, age); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"stale\":");
        if (have_age) {
            int current = 0;
            if (h->live) {
                web_live_sum_t ls;
                web_live_summary(h->live, &ls, h->now_ms);
                current = ls.sock_state == WEB_SOCK_CONNECTED && ls.last_record_age_ms >= 0 &&
                          ls.last_record_age_ms <= WEB_SDB_STREAM_CURRENT_S * 1000LL;
            }
            web_jw_raw(w, web_sdb_is_stale(age, current) ? "true" : "false");
        } else {
            web_jw_raw(w, "null");
        }
        web_jw_raw(w, ",\"stale_after_s\":"); web_jw_int(w, WEB_SDB_STALE_S);
        web_jw_raw(w, "}");
    }

    /* The scope in effect and what it excludes. */
    web_scope_ctx_t sc;
    memset(&sc, 0, sizeof(sc));
    if (h->sc) sc = *h->sc;
    else if (h->live) web_live_scope_ctx(h->live, &sc);
    static const char *const EXCL[WEB_SCOPE_COUNT] = {
        "nothing: every source",
        "everything the host's own interfaces carried: addresses, ARP, DHCP, DNS/mDNS/NBNS "
        "names, flows, the managed card's own scan",
        "everything the passive monitor radio and the BLE receivers heard: beacons, probes, "
        "associations, EAPOL, the 802.11 detectors",
    };
    web_jw_raw(w, ",\"scope_in_effect\":{\"scope\":"); web_jw_str(w, web_scope_word(sc.scope));
    web_jw_raw(w, ",\"given\":"); web_jw_raw(w, sc.given ? "true" : "false");
    web_jw_raw(w, ",\"ip_capture_on_radio\":"); web_jw_raw(w, sc.radio ? "true" : "false");
    web_jw_raw(w, ",\"monitor_ifaces\":[");
    for (int i = 0; i < sc.nmon; i++) {
        if (i) web_jw_raw(w, ",");
        web_jw_str(w, sc.mon[i]);
    }
    web_jw_raw(w, "],\"excludes\":");
    web_jw_str(w, EXCL[sc.scope >= 0 && sc.scope < WEB_SCOPE_COUNT ? sc.scope : 0]);
    web_jw_raw(w, "}");

    /* The page fills these in the browser before copying. */
    web_jw_raw(w, ",\"page\":{\"url\":null,\"view\":null}");

    /* What was left out, and why: the constants, then what the spliced
     * answers flag. */
    web_jw_raw(w, ",\"withheld\":[");
    web_jw_raw(w, "{\"field\":\"alert.key, alert.incident_id\",\"why\":\"opaque ids only: "
                  "the key can hold a username; sloth's incident_id inverts to the key's "
                  "hash (web_live.h)\"}");
    web_jw_raw(w, ",{\"field\":\"sloth.db columns\",\"why\":\"credential-bearing columns "
                  "are refused by the reader's allow-list: cleartext_creds, eapol_events, "
                  "rogue_radius.last_identity, mqtt_flows.last_username, snmp "
                  "last_community, ssh server_banner, rdp cookies (web_slothdb.h, "
                  "web_secret.h)\"}");
    web_jw_raw(w, ",{\"field\":\"records_recent[].raw, records_around[].raw\",\"why\":"
                  "\"stream records are summarised to 80 bytes of named members; raw "
                  "lines are not kept\"}");
    web_jw_raw(w, ",{\"field\":\"page.url\",\"why\":\"filled by the browser, not the "
                  "server\"}");
    if (c->kind == K_ALERT) {
        if (jbool_after(c->primary, ",\"detail_shown\":") == 0)
            web_jw_raw(w, ",{\"field\":\"alert.page.detail\",\"why\":\"this alert type's "
                          "detail is not audited: it can carry a credential or a remote's "
                          "free text (web_alertfmt.h)\"}");
    }
    if (c->kind == K_DEVICE || c->nested_status == 200)
        web_jw_raw(w, ",{\"field\":\"device.drawer.alerts[].detail\",\"why\":\"alert "
                      "detail is not served on device rows\"}");
    if (sc.scope == WEB_SCOPE_MONITOR)
        web_jw_raw(w, ",{\"field\":\"device.drawer.ips, device.drawer.stream, "
                      "device.drawer.names (address-keyed), lookup.card.ips, "
                      "lookup.card.macs\",\"why\":\"excluded by the capture scope in "
                      "effect (monitor): addresses are the host's own interfaces' "
                      "(local)\"}");
    if (sc.scope == WEB_SCOPE_LOCAL)
        web_jw_raw(w, ",{\"field\":\"device.drawer.ssids, device.drawer.assocs\",\"why\":"
                      "\"excluded by the capture scope in effect (local): the PNL and "
                      "the associations are the monitor radio's\"}");
    web_jw_raw(w, "]");
}

/* ── limits ────────────────────────────────────────────────────────── */

static void limit_row(web_jw_t *w, int *k, const char *name, long long cap,
                      int cut, const char *extra_key, long long extra, int have_extra) {
    web_jw_raw(w, (*k)++ ? ",{\"name\":" : "{\"name\":");
    web_jw_str(w, name);
    web_jw_raw(w, ",\"cap\":"); web_jw_int(w, cap);
    web_jw_raw(w, ",\"cut\":");
    web_jw_raw(w, cut > 0 ? "true" : cut == 0 ? "false" : "null");
    if (extra_key) {
        web_jw_raw(w, ",");
        web_jw_key(w, extra_key);
        if (have_extra) web_jw_int(w, extra); else web_jw_raw(w, "null");
    }
    web_jw_raw(w, "}");
}

static void drawer_limits(web_jw_t *w, int *k, const char *prefix, const char *d) {
    char n[64];
    long long v = 0;
    snprintf(n, sizeof(n), "%s.names", prefix);
    limit_row(w, k, n, 12, -1, NULL, 0, 0);
    snprintf(n, sizeof(n), "%s.ssids", prefix);
    limit_row(w, k, n, 24, jbool_after(d, ",\"ssids_more\":"), NULL, 0, 0);
    snprintf(n, sizeof(n), "%s.assocs", prefix);
    limit_row(w, k, n, 12, jbool_after(d, ",\"assocs_more\":"), NULL, 0, 0);
    snprintf(n, sizeof(n), "%s.ips", prefix);
    limit_row(w, k, n, 8, jbool_after(d, ",\"ips_more\":"), NULL, 0, 0);
    snprintf(n, sizeof(n), "%s.alerts", prefix);
    limit_row(w, k, n, 12, jbool_after(d, ",\"alerts_more\":"), "reached", v,
              jint_after(d, ",\"alerts_reached\":", &v));
    snprintf(n, sizeof(n), "%s.anomalies", prefix);
    limit_row(w, k, n, 8, -1, NULL, 0, 0);
}

static void write_limits(const web_bundle_ctx_t *c, web_jw_t *w, size_t bytes_so_far) {
    web_jw_raw(w, ",\"limits\":{\"hard_cap_bytes\":"); web_jw_int(w, (long long)web_bundle_max);
    /* The final size: this member's own bytes added when it is done
     * (the page's note shows the copied size). */
    web_jw_raw(w, ",\"bytes_before_limits\":"); web_jw_int(w, (long long)bytes_so_far);
    web_jw_raw(w, ",\"truncated_sections\":[");
    for (int i = 0; i < c->ntrunc; i++) {
        if (i) web_jw_raw(w, ",");
        web_jw_str(w, c->truncated[i]);
    }
    web_jw_raw(w, "],\"read_budget_ms_per_read\":"); web_jw_int(w, WEB_SDB_HTTP_MS);
    web_jw_raw(w, ",\"reads\":[");
    for (int i = 0; i < c->nreads; i++) {
        web_jw_raw(w, i ? ",{\"what\":" : "{\"what\":");
        web_jw_str(w, c->reads[i].what);
        web_jw_raw(w, ",\"ms\":");     web_jw_int(w, c->reads[i].ms);
        web_jw_raw(w, ",\"status\":"); web_jw_int(w, c->reads[i].status);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"sections\":[");
    int k = 0;
    long long v = 0;
    if (c->kind == K_DEVICE) {
        drawer_limits(w, &k, "device.drawer", c->primary);
    } else if (c->kind == K_ALERT) {
        limit_row(w, &k, "alert.page.history.runs", WEB_ALERT_RUNS,
                  jbool_after(c->primary, ",\"more\":"), NULL, 0, 0);
        limit_row(w, &k, "alert.page.history.incidents", 2000, -1, "read", v,
                  jint_after(c->primary, ",\"incidents_read\":", &v));
        limit_row(w, &k, "alert.page.sev_history", WEB_LIVE_SEVH, -1, "total", v,
                  jint_after(c->primary, ",\"sev_changes\":", &v));
        if (c->nested_status == 200) drawer_limits(w, &k, "alert.device", c->nested);
    } else {
        limit_row(w, &k, "lookup.card.names", 12, -1, NULL, 0, 0);
        limit_row(w, &k, "lookup.card.ips / macs", 8,
                  jbool_after(c->primary, ",\"ips_more\":") > 0 ||
                  jbool_after(c->primary, ",\"macs_more\":") > 0, NULL, 0, 0);
        if (c->nested_status == 200) drawer_limits(w, &k, "lookup.device", c->nested);
    }
    if (c->kind != K_LOOKUP)
        limit_row(w, &k, c->kind == K_DEVICE ? "device.records_recent" : "alert.records_around",
                  WEB_BUNDLE_RECORDS, c->latest > (unsigned long long)WEB_BUNDLE_RECORDS,
                  "ring_records", c->nrecs, 1);
    web_jw_raw(w, "],\"nesting\":\"alert.device and lookup.device are the drawer answer "
                  "only; no bundle nests another bundle\"");
    web_jw_raw(w, ",\"text\":\"every string is the display form the page shows; stream "
                  "strings are cut at the routes' lengths (title 48, detail 128, record "
                  "text 80, names 63)\"}");
}

/* ── the route ─────────────────────────────────────────────────────── */

static int error_body(const web_health_t *h, const char *reason, int status,
                      char **body, size_t *len, int *st) {
    char *buf = malloc(256);
    if (!buf) return -1;
    web_jw_t w;
    web_jw_init(&w, buf, 256);
    web_jw_raw(&w, "{");
    if (h->sc && h->sc->given) {
        web_jw_raw(&w, "\"scope\":"); web_jw_str(&w, web_scope_word(h->sc->scope));
        web_jw_raw(&w, ",");
    }
    web_jw_raw(&w, "\"error\":"); web_jw_str(&w, reason);
    web_jw_raw(&w, "}\n");
    *body = buf;
    *len = w.len;
    *st = status;
    return 0;
}

/* A sub-answer's error word, for the bundle's own status. */
static const char *error_word(const char *body, char *out, size_t cap) {
    if (!jstr_after(body, "\"error\":", out, cap)) snprintf(out, cap, "sloth_db_error");
    return out;
}

static void ctx_free(web_bundle_ctx_t *c) {
    free(c->primary);
    free(c->nested);
    free(c->lookup);
    free(c->recs);
}

/* An optional section: the member, written through its fill, or the
 * unavailable marker it rolls back to. budget is the most the writer
 * may hold after it. */
static void write_section(web_bundle_ctx_t *c, web_jw_t *w, const web_bundle_sec_t *s,
                          size_t budget) {
    web_jw_raw(w, ",");
    web_jw_key(w, s->name);
    size_t start = w->len;
    if (!s->fill) {
        unavailable(w, s->reason);
        return;
    }
    size_t n = s->fill(c, w);
    int over = w->overflow || w->len > budget || w->len - start > s->cap_bytes;
    if (n && !over) return;
    w->len = start;
    w->overflow = 0;
    w->buf[start] = '\0';
    if (n == 0 && !over) {
        unavailable(w, "no_data");
        return;
    }
    web_jw_raw(w, "{\"available\":false,\"reason\":\"too_large\",\"cap_bytes\":");
    web_jw_int(w, (long long)s->cap_bytes);
    web_jw_raw(w, "}");
    if (c->ntrunc < (int)(sizeof(c->truncated) / sizeof(c->truncated[0])))
        c->truncated[c->ntrunc++] = s->name;
}

int web_bundle_route(const web_health_t *h, const char *query,
                     char **body, size_t *len, int *status) {
    static const web_m4_t none;
    web_param_t ps[2] = { { "kind", "", 0 }, { "id", "", 0 } };
    char why[48] = "";
    if (web_params_parse(query, ps, 2, why, sizeof(why)) != 0)
        return error_body(h, why, 400, body, len, status);
    if (!ps[0].seen) return error_body(h, "missing_kind", 400, body, len, status);
    int kind = -1;
    for (int i = 0; i < 3; i++)
        if (!strcmp(ps[0].val, KIND_WORD[i])) kind = i;
    if (kind < 0) {
        /* Reserved for the slices that own them. */
        if (!strcmp(ps[0].val, "ble") || !strcmp(ps[0].val, "platform"))
            return error_body(h, "kind_not_built", 400, body, len, status);
        return error_body(h, "bad_kind", 400, body, len, status);
    }
    if (!ps[1].seen) return error_body(h, "missing_id", 400, body, len, status);

    web_bundle_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->h = h;
    c->m = h->m4 ? h->m4 : &none;
    c->kind = kind;

    /* The id, folded as the route it is for folds it, and refused in
     * the route's own words. */
    char key[WEB_KEY_MAX + 1] = "";
    char sub[WEB_PARAM_MAX + 8];
    int st = -1;
    if (kind == K_DEVICE) {
        if (web_dev_canon_mac(ps[1].val, key) != 0) {
            free(c);
            return error_body(h, "bad_mac", 400, body, len, status);
        }
        snprintf(c->id, sizeof(c->id), "%s", key);
        snprintf(c->mac, sizeof(c->mac), "%s", key);
        st = splice_read(c, "device", R_DEVICE, key, &c->primary, &c->primary_len);
    } else if (kind == K_ALERT) {
        int ik = 0;
        long long rid = 0;
        char sid[WEB_LIVE_HID_MAX + 1];
        /* ps[1].val is decoded already; put back into a query it would
         * be decoded again, and d1%2530 would read as d10. Both id forms
         * are [ds][0-9A-Za-z]+, so anything else is refused here, and
         * the sub-query and the envelope carry the parsed id. */
        int ok = ps[1].val[0] != '\0';
        for (const char *p = ps[1].val; *p && ok; p++)
            ok = (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'z') ||
                 (*p >= 'A' && *p <= 'Z');
        snprintf(sub, sizeof(sub), "id=%s", ps[1].val);
        if (!ok || web_alert_parse_id(sub, &ik, sid, &rid, why, sizeof(why)) != 0) {
            free(c);
            return error_body(h, "bad_id", 400, body, len, status);
        }
        if (ik == 'd') snprintf(c->id, sizeof(c->id), "d%lld", rid);
        else           snprintf(c->id, sizeof(c->id), "s%s", sid);
        snprintf(sub, sizeof(sub), "id=%s", c->id);
        st = splice_read(c, "alert", R_ALERT, sub, &c->primary, &c->primary_len);
    } else {
        int is_mac = web_dev_canon_mac(ps[1].val, key) == 0;
        if (!is_mac && web_key_ip(ps[1].val, key) != 0) {
            free(c);
            return error_body(h, "bad_lookup", 400, body, len, status);
        }
        snprintf(c->id, sizeof(c->id), "%s", key);
        if (is_mac) snprintf(c->mac, sizeof(c->mac), "%s", key);
        else        snprintf(c->ip, sizeof(c->ip), "%s", key);
        snprintf(sub, sizeof(sub), "q=%s", key);
        st = splice_read(c, "lookup", R_LOOKUP, sub, &c->primary, &c->primary_len);
    }
    /* A primary that failed is the bundle's own failure, in the
     * sub-route's words. */
    if (st < 0) {
        ctx_free(c);
        free(c);
        return error_body(h, "sloth_db_error", 503, body, len, status);
    }
    if (st != 200) {
        char word[48];
        error_word(c->primary, word, sizeof(word));
        ctx_free(c);
        free(c);
        return error_body(h, word, st, body, len, status);
    }

    /* The device behind the answer, for the nested drawer and the
     * record match. */
    if (kind == K_DEVICE) {
        const char *rec = jafter(c->primary, ",\"record\":{");
        if (rec) jstr_after(rec, ",\"ip\":", c->ip, sizeof(c->ip));
        jstr_after(c->primary, ",\"stream\":{\"ip\":", c->ip2, sizeof(c->ip2));
        if (c->ip2[0] && !strcmp(c->ip, c->ip2)) c->ip2[0] = '\0';
    } else if (kind == K_ALERT) {
        const char *dev = jafter(c->primary, ",\"device\":{\"mac\":");
        if (dev) {
            jstr(dev, c->mac, sizeof(c->mac));
            jstr_after(dev, ",\"ip\":", c->ip, sizeof(c->ip));
        }
        if (c->mac[0])
            c->nested_status = splice_read(c, "alert.device", R_DEVICE, c->mac, &c->nested,
                                           &c->nested_len);
        else if (c->ip[0]) {
            snprintf(sub, sizeof(sub), "q=%s", c->ip);
            c->lookup_status = splice_read(c, "alert.lookup", R_LOOKUP, sub, &c->lookup,
                                           &c->lookup_len);
        }
    } else {
        const char *dev = jafter(c->primary, ",\"device\":{\"mac\":");
        char mac[WEB_KEY_MAX + 1];
        if (dev && jstr(dev, mac, sizeof(mac))) {
            if (!c->mac[0]) snprintf(c->mac, sizeof(c->mac), "%s", mac);
            c->nested_status = splice_read(c, "lookup.device", R_DEVICE, mac, &c->nested,
                                           &c->nested_len);
            if (c->nested_status == 200) {
                const char *rec = jafter(c->nested, ",\"record\":{");
                if (rec && !c->ip[0]) jstr_after(rec, ",\"ip\":", c->ip, sizeof(c->ip));
            }
        }
    }

    /* The ticker ring, once. */
    if (h->live) {
        c->recs = calloc(WEB_BUNDLE_RECORDS, sizeof(*c->recs));
        if (c->recs)
            c->nrecs = web_live_recent_after(h->live, 0, c->recs, WEB_BUNDLE_RECORDS,
                                             &c->latest);
    }

    /* The tail (glossary and prompt) is constant: rendered first so the
     * cap can hold room for it and for limits. */
    char *tail = malloc(16384);
    char *buf = malloc(web_bundle_max + 1);
    if (!tail || !buf) {
        free(tail); free(buf);
        ctx_free(c); free(c);
        return -1;
    }
    web_jw_t tw;
    web_jw_init(&tw, tail, 16384);
    write_aids(&tw);
    /* Held back as well: every optional row's member name and the
     * longest marker it can roll back to, written past the fills'
     * budget; and the kind's close and the body's. */
    size_t reserve = tw.len + WEB_BUNDLE_LIMITS_MAX + 3;
    for (size_t i = 0; i < web_bundle_sections_n; i++)
        if (!strcmp(web_bundle_sections[i].kind, KIND_WORD[kind]))
            reserve += strlen(web_bundle_sections[i].name) + 4 + WEB_BUNDLE_MARKER_MAX;

    web_jw_t w;
    web_jw_init(&w, buf, web_bundle_max + 1);
    web_jw_raw(&w, "{");
    if (h->sc && h->sc->given) {
        web_jw_raw(&w, "\"scope\":"); web_jw_str(&w, web_scope_word(h->sc->scope));
        web_jw_raw(&w, ",");
    }
    write_envelope(c, &w);
    /* The kind's section: the primary splice, then the registry's rows. */
    web_jw_raw(&w, ",");
    web_jw_key(&w, KIND_WORD[kind]);
    web_jw_raw(&w, "{");
    static const char *const PRIMARY[] = { "drawer", "page", "card" };
    web_jw_key(&w, PRIMARY[kind]);
    web_jw_rawn(&w, c->primary, c->primary_len);
    int required_fit = !w.overflow && !tw.overflow && w.len + reserve <= web_bundle_max;
    if (!required_fit) {
        free(tail); free(buf);
        ctx_free(c); free(c);
        return error_body(h, "bundle_too_large", 413, body, len, status);
    }
    size_t budget = web_bundle_max - reserve;
    for (size_t i = 0; i < web_bundle_sections_n; i++)
        if (!strcmp(web_bundle_sections[i].kind, KIND_WORD[kind]))
            write_section(c, &w, &web_bundle_sections[i], budget);
    web_jw_raw(&w, "}");
    web_jw_rawn(&w, tail, tw.len);
    write_limits(c, &w, w.len);
    web_jw_raw(&w, "}\n");
    free(tail);
    ctx_free(c);
    free(c);
    if (w.overflow) {
        free(buf);
        return error_body(h, "bundle_too_large", 413, body, len, status);
    }
    *body = buf;
    *len = w.len;
    *status = 200;
    return 0;
}
