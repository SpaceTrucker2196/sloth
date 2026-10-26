#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include "tune.h"

/* The headers that own the #defines the #120 rows default to. The
 * #define stays the shipped value and the single place it is written;
 * the row reads it rather than restating the number, so the two cannot
 * drift apart. */
#include "sloth.h"
#include "action_snoop.h"
#include "alert_pcap.h"
#include "camera_join.h"
#include "beacon_detect.h"
#include "ble_detect.h"
#include "ctrl_frames.h"
#include "db.h"
#include "eapol_log.h"
#include "presence.h"
#include "rf_distance.h"
#include "queue_evict.h"
#include "seqnum_track.h"
#include "transit.h"
#include "wps_track.h"

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
    /* #166, owner ruling 2026-10-26: alert pcaps are kept two weeks.
     * Retention, not a detector threshold. 0 keeps them forever — the
     * pre-#166 behaviour, and the same meaning 0 has on
     * handshake.retention_days, so the two sweeps read alike. The cap is
     * ten years: a window longer than that is "forever" said less
     * clearly, and 0 already says it. */
    { "pcap.retain_days",           ALERT_PCAP_DEFAULT_RETAIN_DAYS, 0, ALERT_PCAP_MAX_RETAIN_DAYS, "days alert pcaps in --pcap-dir are kept, 0 for forever" },
    /* Data-socket hygiene (#135). Neither is a detector threshold.
     *
     * max_per_peer bounds how many of the listener's 16 client slots one
     * peer may hold at once — one uid on `unix:` (SO_PEERCRED), one
     * address on `tcp:` (getpeername), and one shared bucket for any
     * peer the kernel cannot identify, which fails closed rather than
     * open. Before it, one local account (or, with
     * --data-socket-allow-remote, one host) could take every slot and
     * every other consumer got ECONNREFUSED-by-neglect (CWE-770). 16 is
     * MAX_CLIENTS, i.e. no per-peer limit at all.
     *
     * idle_secs closes a client that has made no progress — accepted,
     * offered a record, or had bytes taken by the kernel — for that
     * long, WHATEVER its queue holds. The 30 s stall timer only ran
     * while bytes were queued, so a client sloth never needed to write
     * to held its slot forever. 900 is three JSONL heartbeats
     * (3 × JSONL_HEARTBEAT_SECS): a live consumer is offered a record at
     * least every 300 s, so one that has seen nothing for three of them
     * is not a consumer any more. 0 = off, a meaningful setting the way
     * storage.min_free_* 0 is; a dropped client that reconnects gets
     * the full baseline again (#47), so the cost of a false positive is
     * one reconnect, not lost data. */
    { "socket.max_per_peer",        4,   1,   16,     "concurrent data-socket clients one peer may hold (16 = no per-peer cap)" },
    { "socket.idle_secs",           900, 0,   86400,  "seconds without progress before a data-socket client is closed, 0 for never" },
    /* ── #120: the five flags that parsed with atoi() ─────────────
     *
     * Retention and cadence, not detector thresholds. The flags are now
     * aliases onto these rows via tune_set_value(), so "--db-max-mb 5x"
     * is refused instead of read as 5 and "--db-retain-days abc" is
     * refused instead of read as 0 (which silently meant "default").
     *
     * Bounds keep each shipped contract where one was published:
     * handshake.retention_days is exactly what --handshake-retention
     * already accepted (0 = keep forever, 100 y cap); db.max_mb keeps 0
     * as "unlimited". correlate.retain_secs and the two db windows had
     * no upper bound at all — atoi() accepted anything — so the caps
     * here are new, and wide: a week of correlation evidence, a century
     * of rows, a day between writes. */
    { "correlate.retain_secs",      SEQNUM_CORR_RETAIN_S, 1, 604800, "seconds a seqnum correlation's evidence stays current" },
    { "handshake.retention_days",   EAPOL_DEFAULT_RETENTION_DAYS, 0, EAPOL_MAX_RETENTION_DAYS, "days exported crackable material is kept, 0 for forever" },
    { "db.interval_secs",           DB_DEFAULT_INTERVAL_S, 1, 86400, "seconds between --db write ticks" },
    { "db.retain_days",             DB_DEFAULT_RETAIN_DAYS, 1, 36500, "days observation rows are kept in --db (entities 3x, findings 12x)" },
    { "db.max_mb",                  DB_DEFAULT_MAX_MB, 0, 4194304, "MiB size target for --db, 0 for unlimited" },
    /* ── #120: compile-time detector thresholds ───────────────────
     *
     * Each default IS the #define it replaced at the use site. Where a
     * count is stored in a fixed ring, `hi` is that ring's size: a
     * threshold above the number of events the detector can hold would
     * never fire, which is a way to disable a rule rather than tune it.
     * The 256 / 512 literals are rings private to beacon_snoop.c
     * (BEACON_NEW_TS_RING), assoc_track.c (ASSOC_REQ_RING),
     * action_snoop.c (BTM_EVT_RING) and auth_track.c (AUTH_RING). */
    { "scan.port_thresh",           SCAN_PORT_THRESH, 2, MAX_SCAN_PORTS, "distinct local service ports from one IP" },
    { "deauth.flood_thresh",        DEAUTH_FLOOD_THRESH, 2, FLOOD_WIN_CAP, "distinct deauth/disassoc frames per window" },
    { "deauth.flood_window_s",      DEAUTH_FLOOD_WIN_SECS, 1, 600, "seconds (sliding)" },
    { "beacon.flood_thresh",        BEACON_FLOOD_THRESH, 2, 256, "distinct new BSSIDs per window" },
    { "beacon.flood_window_s",      BEACON_FLOOD_WIN_SECS, 1, 3600, "seconds" },
    { "auth.flood_thresh",          AUTH_FLOOD_THRESH, 2, 512, "auth frames to one BSSID per window" },
    { "auth.flood_window_s",        AUTH_FLOOD_WIN_SECS, 1, 3600, "seconds" },
    { "assoc.flood_thresh",         ASSOC_FLOOD_THRESH, 2, 256, "(re)assoc requests to one BSSID per window" },
    { "assoc.flood_window_s",       ASSOC_FLOOD_WIN_SECS, 1, 3600, "seconds" },
    { "probe.flood_frames",         PROBE_FLOOD_FRAMES, 2, FLOOD_WIN_CAP, "probe requests from one TA per window" },
    { "probe.flood_window_s",       PROBE_FLOOD_WIN_SECS, 1, 600, "seconds (sliding)" },
    { "btm.abuse_thresh",           BTM_ABUSE_THRESH, 2, 256, "disassoc-imminent BTM requests per (BSSID, STA) per window" },
    { "btm.abuse_window_s",         BTM_ABUSE_WIN_SECS, 1, 3600, "seconds" },
    { "saq.flood_thresh",           SAQ_FLOOD_THRESH, 2, SAQ_FLOOD_THRESH * 4, "SA Query frames per (BSSID, STA) per window" },
    { "saq.flood_window_s",         SAQ_FLOOD_WIN_SECS, 1, 3600, "seconds" },
    { "rts.flood_rate",             RTS_FLOOD_RATE, 1, 100000, "RTS frames per second from one TA" },
    { "rts.flood_sustain_s",        RTS_FLOOD_SUSTAIN_S, 1, 3600, "seconds the rate must be held" },
    /* Beaconing (C2) detector. The two ratios are whole percent because
     * the registry is integer-only; BD_*_RATIO are defined from these,
     * and 25/100.0 and 60/100.0 are the same doubles 0.25 and 0.60
     * were. Sample counts cap at BD_MAX_SAMPLES, the per-flow ring. */
    { "bd.min_samples",             BD_MIN_SAMPLES, 3, BD_MAX_SAMPLES, "samples before the v1 low-jitter test" },
    { "bd.min_interval_s",          BD_MIN_INTERVAL_S, 1, 86400, "seconds; shorter mean/median periods are heartbeats" },
    { "bd.max_jitter_pct",          BD_MAX_JITTER_PCT, 1, 100, "v1: stddev/mean, percent" },
    { "bd.min_samples_v2",          BD_MIN_SAMPLES_V2, 3, BD_MAX_SAMPLES, "samples before the v2 concentration test" },
    { "bd.min_concentration_pct",   BD_MIN_CONCENTRATION_PCT, 1, 100, "v2: gaps within 30% of the median, percent" },
    /* #148: a cap on findings, not a threshold — it decides how many
     * strong tracks get their own incident, never whether one is strong.
     * Ceiling BD_MAX_FINDINGS_HI; see beacon_detect.h for both numbers. */
    { "bd.max_findings",            BD_MAX_FINDINGS, 1, BD_MAX_FINDINGS_HI, "open per-destination BEACONING findings; the rest are one overflow finding" },
    { "queue_evict.window_ms",      QUEUE_EVICT_WINDOW_MS, 1, 10000, "ms after a session change that counts as a release" },
    { "queue_evict.min_frames",     QUEUE_EVICT_MIN_FRAMES, 2, 1000, "distinct downlink frames in that window" },
    { "queue_evict.report_secs",    QUEUE_EVICT_REPORT_SECS, 1, 86400, "seconds a release stays reportable" },
    { "transit.gap_secs",           TRANSIT_GAP_SECS, 1, 86400, "seconds between observations that make separate passes" },
    { "transit.window_secs",        TRANSIT_WINDOW_SECS, 60, 604800, "seconds passes are counted over" },
    { "transit.recur_thresh",       TRANSIT_RECUR_THRESH, 2, MAX_TRANSIT_PASSES, "passes in the window" },
    /* Presence classification. No ordering is enforced between the
     * dwell thresholds: visitor above resident only makes VISITOR
     * unreachable, which is the operator's call, not a crash. */
    { "presence.swing_dbm",         PRESENCE_SWING_DBM, 1, 100, "dB rise and fall around a transit peak" },
    { "presence.transient_max_s",   PRESENCE_TRANSIENT_MAX_S, 1, 86400, "max dwell, seconds, for a transit verdict" },
    { "presence.visitor_min_s",     PRESENCE_VISITOR_MIN_S, 1, 86400, "dwell seconds for VISITOR" },
    { "presence.resident_min_s",    PRESENCE_RESIDENT_MIN_S, 1, 604800, "dwell seconds for RESIDENT" },
    { "presence.min_samples",       PRESENCE_MIN_SAMPLES, 3, RSSI_WIN_SAMPLES, "RSSI samples before a trajectory claim" },
    { "seqnum.corr_seq_window",     SEQNUM_CORR_SEQ_WINDOW, 1, 4095, "forward sequence-number advance across a MAC change" },
    { "seqnum.corr_dt_max_s",       SEQNUM_CORR_DT_MAX_S, 1, 3600, "seconds between the two trails" },
    /* #82 Pixie-Dust. The silence floor is 1, not 0: zero would call an
     * attempt abandoned in the same second its M3 arrived, before M4
     * could. The success window floor is the silence ceiling, so the
     * look-back can always cover at least one abandoned attempt; a week
     * is the ceiling because the session table's LRU, not this knob,
     * is what bounds memory. */
    { "wps.pixie_silence_s",        WPS_PIXIE_SILENCE_S, 1, 3600, "seconds of silence after M3 with no M4" },
    { "wps.pixie_success_window_s", WPS_PIXIE_SUCCESS_WINDOW_S, 3600, 604800, "seconds an abandoned M3 run is correlated with a completed registration" },
    /* #106 round 2. An IP is only a key while the address has not
     * changed hands; the floor is one SSDP max-age half-period, the
     * ceiling a week (the reuse risk the operator takes on). */
    { "camera.join_fresh_secs",     CAM_JOIN_FRESH_SECS, 900, 604800, "seconds a LAN camera row stays joinable to the device holding its IP" },
    /* #144 slice 4. The address gate counts FRESH addresses (review:
     * a crowd of genuine advertisers is many addresses, few of them
     * new). Its ceiling stays BLE_FLOOD_ADDR_CAP: the fresh count is
     * Bloom-backed and under-counts as a window fills, so a gate far
     * above the exact set's size would be judged on the lossy part. The rotation window floor is one
     * minute and its ceiling a day; the address floor is 2, since one
     * new address is not a rotation. */
    { "ble.flood_window_s",         BLE_FLOOD_WINDOW_S, 1, 600, "seconds per BLE_ADV_FLOOD window (tumbling)" },
    { "ble.flood_distinct_addrs",   BLE_FLOOD_DISTINCT_ADDRS, 2, BLE_FLOOD_ADDR_CAP, "advertiser addresses new to one spam-listed key per window (not heard on it in the two windows before)" },
    { "ble.flood_rate",             BLE_FLOOD_RATE, 1, 10000, "advertisements per second on that key, over the whole window" },
    { "ble.hid_rotate_addrs",       BLE_HID_ROTATE_ADDRS, 2, MAX_BLE_DEVICES, "new random addresses advertising a HID appearance on one sensor per window" },
    { "ble.hid_rotate_window_s",    BLE_HID_ROTATE_WINDOW_S, 60, 86400, "seconds in the BLE_HID_UNEXPECTED rotation window; also how long a sensor listens before the form can fire" },
    /* RSSI distance (2026-10-26). N x 10 from ITU-R P.1238-10 Table 2
     * (residential); the bounds bracket its corridor ~18 and its worst
     * ~44 rows. ref_dist_dm 0 is "no calibration", which is why it alone
     * among these may be 0. research/papers/rssi-distance-estimation.md. */
    { "rf.path_loss_n_2g",          RF_N_2G_X10, RF_N_X10_LO, RF_N_X10_HI, "distance power loss coefficient N x10, 2.4 GHz Wi-Fi and BLE (ITU-R P.1238-10 residential 28)" },
    { "rf.path_loss_n_5g",          RF_N_5G_X10, RF_N_X10_LO, RF_N_X10_HI, "N x10, 5 GHz (P.1238-10 5.2 GHz residential 30)" },
    { "rf.path_loss_n_6g",          RF_N_6G_X10, RF_N_X10_LO, RF_N_X10_HI, "N x10, 6 GHz (no P.1238 row; the 5 GHz value)" },
    { "rf.median_k",                RF_MEDIAN_K, 1, RF_RAW_MAX, "RSSI samples the distance median takes" },
    { "rf.ref_dist_dm",             0, 0, RF_REF_DIST_DM_HI, "decimetres from the sensor to the --my-bssid AP for distance calibration, 0 for none" },
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

    return tune_set_value((tune_id_t)idx, eq + 1, err, errsz);
}

int tune_set_value(tune_id_t id, const char *vs, char *err, size_t errsz) {
    if (id < 0 || id >= TUNE_COUNT) {
        if (err && errsz) snprintf(err, errsz, "no such knob");
        return -1;
    }
    seed();
    /* strtol, then insist the whole tail was consumed: "10x" and "" are
     * rejected rather than read as 10 and 0. An operator who mistypes a
     * threshold must not get a silently different one. */
    if (!vs || !*vs) {
        if (err && errsz)
            snprintf(err, errsz, "%s: missing value", g_specs[id].name);
        return -1;
    }
    errno = 0;
    char *end = NULL;
    long v = strtol(vs, &end, 10);
    if (errno == ERANGE || !end || *end != '\0') {
        if (err && errsz)
            snprintf(err, errsz, "%s: '%.40s' is not an integer",
                     g_specs[id].name, vs);
        return -1;
    }
    if (v < g_specs[id].lo || v > g_specs[id].hi) {
        if (err && errsz)
            snprintf(err, errsz, "%s: %ld out of range [%ld, %ld]",
                     g_specs[id].name, v, g_specs[id].lo, g_specs[id].hi);
        return -1;
    }
    g_val[id] = v;
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
