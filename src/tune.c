#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include "tune.h"

/* Indexed by tune_id_t — the order here must match the enum, which
 * g_specs_match_enum_order in tests/test_tune.c pins by name so a
 * reordering cannot silently remap a detector's threshold onto another
 * rule's value.
 *
 * Bounds are deliberately wide: the point is to let an operator who
 * knows their segment move a threshold, not to second-guess them. They
 * exclude only values that would make the rule meaningless — a count
 * below 1 fires on nothing or everything, a window of 0 seconds has no
 * window. The upper bounds keep a value inside the int fields the
 * detectors store them in. */
static const tune_spec_t g_specs[TUNE_COUNT] = {
    { "karma.ssid_thresh",          3,   2,   64,     "distinct SSIDs from one BSSID" },
    { "dns.tunnel_label_thresh",    30,  8,   255,    "label bytes" },
    { "dns.tunnel_long_hits",       8,   2,   1000,   "long labels per host" },
    { "dns.tunnel_total_thresh",    15,  2,   1000,   "queries per host" },
    { "icmp.tunnel_min_payload",    64,  8,   1472,   "bytes past the echo header" },
    { "icmp.tunnel_threshold",      8,   2,   1000,   "oversized echoes per pair per window" },
    { "icmp.tunnel_window_s",       60,  5,   3600,   "seconds" },
    { "ssid.confusion_thresh",      3,   2,   64,     "confusable SSIDs" },
    { "mgmt.fuzz_warn",             3,   1,   1000,   "malformed mgmt frames (WARN)" },
    { "mgmt.fuzz_crit",             5,   1,   1000,   "malformed mgmt frames (CRIT)" },
    { "twin.proximity_dbm",         15,  1,   100,    "dBm gap between twins" },
    { "deauth.twin_window_s",       5,   1,   600,    "seconds" },
    { "twin.steer_window_s",        300, 10,  3600,   "seconds a BTM steer marks a twin" },
    { "recon.sustain_s",            600, 10,  86400,  "seconds of probing" },
    { "recon.sustain_probes",       20,  2,   10000,  "probes" },
    { "kerb.preauth_burst",         5,   2,   1000,   "pre-auth failures" },
    { "ldap.search_flood",          50,  2,   10000,  "searches" },
    { "bgp.notification_burst",     3,   2,   1000,   "NOTIFICATIONs" },
    { "ssh.brute_force",            10,  2,   1000,   "attempts" },
    { "rdp.brute_force",            10,  2,   1000,   "attempts" },
    { "snmp.community_brute",       5,   2,   1000,   "communities tried" },
    { "mqtt.brute_connects",        10,  2,   1000,   "CONNECTs" },
    { "mqtt.brute_fails",           5,   2,   1000,   "refused CONNECTs" },
    /* lo is 1, not 2 like the counts above: these three inherit the
     * contract alerts_set_wps_* published in d652502, which rejects
     * "zero or less" and accepts 1. Widening a shipped CLI validation
     * would be the contract break this reconciliation exists to avoid. */
    { "wps.pin_brute_cycles",       5,   1,   1000,   "M1-M3-NACK restart cycles per 60 s" },
    { "wps.lockout_cycles",         2,   1,   1000,   "locked-unlocked cycles per hour" },
    { "wps.pbc_concurrent",         2,   1,   1000,   "concurrent PBC enrollees (fires when exceeded)" },
};

/* Lazily seeded from g_specs on first read, so a test that forgets
 * tune_reset() still sees defaults rather than zeroes. */
static long g_val[TUNE_COUNT];
static int  g_seeded;

static void seed(void) {
    if (g_seeded) return;
    for (int i = 0; i < TUNE_COUNT; i++) g_val[i] = g_specs[i].def;
    g_seeded = 1;
}

long tune_val(tune_id_t id) {
    if (id < 0 || id >= TUNE_COUNT) return 0;
    seed();
    return g_val[id];
}

const tune_spec_t *tune_spec(tune_id_t id) {
    if (id < 0 || id >= TUNE_COUNT) return NULL;
    return &g_specs[id];
}

void tune_reset(void) {
    g_seeded = 0;
    seed();
}

int tune_set(const char *spec, char *err, size_t errsz) {
    seed();
    if (!spec || !*spec) {
        if (err && errsz) snprintf(err, errsz, "empty --tune argument");
        return -1;
    }
    const char *eq = strchr(spec, '=');
    if (!eq || eq == spec) {
        if (err && errsz)
            snprintf(err, errsz, "expected name=value, got '%.60s'", spec);
        return -1;
    }

    size_t nlen = (size_t)(eq - spec);
    int idx = -1;
    for (int i = 0; i < TUNE_COUNT; i++) {
        if (strlen(g_specs[i].name) == nlen &&
            strncmp(g_specs[i].name, spec, nlen) == 0) { idx = i; break; }
    }
    if (idx < 0) {
        if (err && errsz)
            snprintf(err, errsz, "unknown knob '%.*s' (see --tune-list)",
                     (int)nlen, spec);
        return -1;
    }

    /* strtol, then insist the whole tail was consumed: "10x" and "" are
     * rejected rather than read as 10 and 0. An operator who mistypes a
     * threshold must not get a silently different one. */
    const char *vs = eq + 1;
    if (!*vs) {
        if (err && errsz)
            snprintf(err, errsz, "%s: missing value", g_specs[idx].name);
        return -1;
    }
    errno = 0;
    char *end = NULL;
    long v = strtol(vs, &end, 10);
    if (errno == ERANGE || !end || *end != '\0') {
        if (err && errsz)
            snprintf(err, errsz, "%s: '%.40s' is not an integer",
                     g_specs[idx].name, vs);
        return -1;
    }
    if (v < g_specs[idx].lo || v > g_specs[idx].hi) {
        if (err && errsz)
            snprintf(err, errsz, "%s: %ld out of range [%ld, %ld]",
                     g_specs[idx].name, v, g_specs[idx].lo, g_specs[idx].hi);
        return -1;
    }
    g_val[idx] = v;
    return 0;
}

int tune_set_id(tune_id_t id, long v) {
    if (id < 0 || id >= TUNE_COUNT) return 0;
    seed();
    if (v < g_specs[id].lo || v > g_specs[id].hi) return 0;
    g_val[id] = v;
    return 1;
}

int tune_non_default(void) {
    seed();
    int n = 0;
    for (int i = 0; i < TUNE_COUNT; i++)
        if (g_val[i] != g_specs[i].def) n++;
    return n;
}

void tune_print_list(FILE *out) {
    if (!out) return;
    seed();
    fprintf(out, "%-28s %8s %8s  %s\n", "knob", "default", "current", "unit");
    for (int i = 0; i < TUNE_COUNT; i++)
        fprintf(out, "%-28s %8ld %8ld  %s\n",
                g_specs[i].name, g_specs[i].def, g_val[i], g_specs[i].unit);
}

void tune_format_non_default(char *buf, size_t n) {
    if (!buf || !n) return;
    buf[0] = '\0';
    seed();
    size_t off = 0;
    for (int i = 0; i < TUNE_COUNT; i++) {
        if (g_val[i] == g_specs[i].def) continue;
        int w = snprintf(buf + off, n - off, "%s%s=%ld",
                         off ? "," : "", g_specs[i].name, g_val[i]);
        if (w < 0 || (size_t)w >= n - off) { buf[off] = '\0'; return; }
        off += (size_t)w;
    }
}
