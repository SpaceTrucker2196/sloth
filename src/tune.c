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
    /* The only rows whose `lo` is 0, and the only ones that are not
     * detector thresholds. 0 means "no floor", which is a meaningful
     * setting here in a way that a count of 0 never is for a rule —
     * and it is the DEFAULT, because refusing to write is a behaviour
     * change every existing deployment would inherit on upgrade, and
     * because the right floor depends on the operator's disk.
     *
     * Both exist because of a measured failure rather than a guess
     * (src/fs_capacity.h has the numbers): on the owner's monitor host
     * --pcap-dir held 15.9M files and had consumed ~93% of the
     * filesystem's inodes while disk sat at 39% used. A byte floor
     * alone would never have fired. Hence two floors, and hence the
     * inode one being checked first. */
    { "storage.min_free_mb",        0,   0,   4194304, "MB that must stay free, or 0 for no absolute floor" },
    { "storage.min_free_inodes",    0,   0,   100000000, "free inodes that must remain, or 0 for no absolute floor" },
    /* The one that is ON by default, and the only one that can be: the
     * floor which protected the host this was measured on was 1.5M
     * inodes — 5% of its 30M-inode filesystem, and enough to refuse
     * every write on a small one. A default has to be relative or it is
     * wrong for one size of deployment or the other.
     *
     * 5% because that is what the measurement supported: at 93% of the
     * host's inodes consumed by one directory, 5% free is roughly
     * 1.5M — still hundreds of thousands of alert pcaps of headroom,
     * while leaving the machine able to create files for anything else.
     * The cap of 50 is there because a floor above half the filesystem
     * is a way to disable writing rather than to protect it. */
    { "storage.min_free_pct",       5,   0,   50,     "percent of the filesystem that must stay free, 0 for none" },
    /* Per-alert pcap export policy (#96). Both default to KEEPING LESS,
     * and both open all the way up, so a full capture is two knobs away
     * rather than a rebuild.
     *
     * These exist because of what the unfiltered behaviour actually
     * produced on a live sensor: 16,131,622 files and 78 GB in
     * --pcap-dir, 17.9 per second, of which 98.6% were one WARN-severity
     * rule (BEACONING) re-exported after every alert-engine eviction.
     * Measured across the whole corpus, those 16.1M files held about
     * 191 distinct (destination, port) pairs — a couple of hundred real
     * findings, written millions of times.
     *
     * min_severity 2 (CRIT) is not a new policy: `--help` has always
     * said "when a critical alert fires", and the export never checked.
     * This makes the code keep the promise the CLI already made. 0 keeps
     * every alert that carries a match_ip, which is the old behaviour.
     *
     * key_cooldown_secs exists because a re-fire is not new evidence.
     * It has to key on the alert KEY rather than the incident: eviction
     * wipes the entry, the next fire for the same key calls
     * incident_id_make() again, so the incident id is fresh even though
     * the finding is not. An hour bounds a recurring finding to 24
     * captures a day instead of 86,400. 0 disables it. */
    { "pcap.min_severity",          2,   0,   2,      "0=any alert, 1=WARN and up, 2=CRIT only" },
    { "pcap.key_cooldown_secs",     3600, 0, 86400,   "seconds before the same alert key exports again, 0 for none" },
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
