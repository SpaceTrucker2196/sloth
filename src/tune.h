#ifndef SLOTH_TUNE_H
#define SLOTH_TUNE_H

#include <stdio.h>
#include <stddef.h>

/* ── Operator-tunable detector thresholds (#82) ───────────────────
 *
 * Every behavioural threshold in src/alerts.c was a #define, so the
 * owner's "each behind a config knob" (2026-09-30, #82) had nothing to
 * hang on. One flag per threshold would mean ~20 new permanent CLI
 * contracts and one more for every future detector, so the surface is
 * a single repeatable flag over a named registry instead (owner
 * decision, 2026-10-04):
 *
 *     sloth --tune dns.tunnel_label_thresh=40 --tune ssh.brute_force=20
 *     sloth --tune-list
 *
 * Adding a detector threshold costs a registry row and an enum member,
 * not a flag. An unknown name or an out-of-range value is a startup
 * error, never a silently ignored argument — a threshold the operator
 * believes they set but did not is worse than no knob at all.
 *
 * The id is what detectors use, so the hot path is an array index and
 * not a string compare; the name exists for the CLI, --tune-list and
 * the export.
 *
 * Deliberately NOT tunable: the RECON_CONF_* confidence weights in
 * src/alerts/rules_wifi_mgmt.c. Those decide how much a corroborator is worth, not
 * when a rule fires — retuning them rewrites what a confidence
 * percentage means in the export, which is #89/#90 territory and not
 * an operator dial.
 *
 * A raised threshold can silence a detector, so a run with any knob
 * off its default says so in sensor_health (`tuned`) and in the TUI
 * health strip: a quiet sensor and a detuned one must not look alike
 * to whoever reads the export. */

typedef enum {
    TUNE_KARMA_SSID_THRESH = 0,
    TUNE_DNS_TUNNEL_LABEL_THRESH,
    TUNE_DNS_TUNNEL_LONG_HITS,
    TUNE_DNS_TUNNEL_TOTAL_THRESH,
    TUNE_ICMP_TUNNEL_MIN_PAYLOAD,
    TUNE_ICMP_TUNNEL_THRESHOLD,
    TUNE_ICMP_TUNNEL_WINDOW_S,
    TUNE_SSID_CONFUSION_THRESH,
    TUNE_MGMT_FUZZ_WARN,
    TUNE_MGMT_FUZZ_CRIT,
    TUNE_EVIL_TWIN_PROXIMITY_DBM,
    TUNE_DEAUTH_TWIN_WIN_SECS,
    TUNE_TWIN_STEER_WINDOW_S,
    TUNE_RECON_SUSTAIN_S,
    TUNE_RECON_SUSTAIN_PROBES,
    TUNE_KERB_PREAUTH_BURST,
    TUNE_LDAP_SEARCH_FLOOD,
    TUNE_BGP_NOTIFICATION_BURST,
    TUNE_SSH_BRUTE_FORCE,
    TUNE_RDP_BRUTE_FORCE,
    TUNE_SNMP_COMMUNITY_BRUTE,
    TUNE_MQTT_BRUTE_CONNECTS,
    TUNE_MQTT_BRUTE_FAILS,
    /* #82's own three, folded in 2026-10-05. They shipped first as
     * --wps-pin-brute-cycles / --wps-lockout-cycles /
     * --wps-pbc-concurrent in d652502, which answered the same owner
     * decision the other way. Those flags still work and are now
     * aliases onto these rows, so the registry is the single source of
     * truth and — the part that was actually broken — a WPS threshold
     * moved by flag now reaches `tuned` and the health strip instead of
     * silencing a detector with no record in the export. */
    TUNE_WPS_PIN_BRUTE_CYCLES,
    TUNE_WPS_LOCKOUT_CYCLES,
    TUNE_WPS_PBC_CONCURRENT,
    /* Storage floors, not detector thresholds. See the note beside
       their rows in tune.c for why these alone may be 0. */
    TUNE_STORAGE_MIN_FREE_MB,
    TUNE_STORAGE_MIN_FREE_INODES,
    TUNE_STORAGE_MIN_FREE_PCT,
    /* Per-alert pcap export policy (#96). See the rows in tune.c. */
    TUNE_PCAP_MIN_SEVERITY,
    TUNE_PCAP_KEY_COOLDOWN_SECS,
    /* Data-socket hygiene (#135): per-peer slot cap and idle timeout.
       Neither is a detector threshold. See the rows in tune.c. */
    TUNE_SOCKET_MAX_PER_PEER,
    TUNE_SOCKET_IDLE_SECS,
    /* #120: the five runtime flags that parsed with atoi() or a private
       strtol, now aliases onto these rows so the flag and --tune share
       one validation and both reach `tuned`. Retention and cadence, not
       detector thresholds — see the rows in tune.c. */
    TUNE_CORRELATE_RETAIN_SECS,
    TUNE_HANDSHAKE_RETENTION_DAYS,
    TUNE_DB_INTERVAL_SECS,
    TUNE_DB_RETAIN_DAYS,
    TUNE_DB_MAX_MB,
    /* #120: the compile-time detector thresholds that were still
       #defines outside this registry. The #define stays as the shipped
       default (tune.c reads it); the use site reads the knob. */
    TUNE_SCAN_PORT_THRESH,
    TUNE_DEAUTH_FLOOD_THRESH,
    TUNE_DEAUTH_FLOOD_WINDOW_S,
    TUNE_BEACON_FLOOD_THRESH,
    TUNE_BEACON_FLOOD_WINDOW_S,
    TUNE_AUTH_FLOOD_THRESH,
    TUNE_AUTH_FLOOD_WINDOW_S,
    TUNE_ASSOC_FLOOD_THRESH,
    TUNE_ASSOC_FLOOD_WINDOW_S,
    TUNE_PROBE_FLOOD_FRAMES,
    TUNE_PROBE_FLOOD_WINDOW_S,
    TUNE_BTM_ABUSE_THRESH,
    TUNE_BTM_ABUSE_WINDOW_S,
    TUNE_SAQ_FLOOD_THRESH,
    TUNE_SAQ_FLOOD_WINDOW_S,
    TUNE_RTS_FLOOD_RATE,
    TUNE_RTS_FLOOD_SUSTAIN_S,
    TUNE_BD_MIN_SAMPLES,
    TUNE_BD_MIN_INTERVAL_S,
    TUNE_BD_MAX_JITTER_PCT,
    TUNE_BD_MIN_SAMPLES_V2,
    TUNE_BD_MIN_CONCENTRATION_PCT,
    TUNE_QUEUE_EVICT_WINDOW_MS,
    TUNE_QUEUE_EVICT_MIN_FRAMES,
    TUNE_QUEUE_EVICT_REPORT_SECS,
    TUNE_TRANSIT_GAP_SECS,
    TUNE_TRANSIT_WINDOW_SECS,
    TUNE_TRANSIT_RECUR_THRESH,
    TUNE_PRESENCE_SWING_DBM,
    TUNE_PRESENCE_TRANSIENT_MAX_S,
    TUNE_PRESENCE_VISITOR_MIN_S,
    TUNE_PRESENCE_RESIDENT_MIN_S,
    TUNE_PRESENCE_MIN_SAMPLES,
    TUNE_SEQNUM_CORR_SEQ_WINDOW,
    TUNE_SEQNUM_CORR_DT_MAX_S,
    /* #82, 2026-10-19 ruling: the two Pixie-Dust windows. Windows, not
       counts — unlike the three WPS rows above, the owner put these on
       the registry explicitly. See src/wps_track.h. */
    TUNE_WPS_PIXIE_SILENCE_S,
    TUNE_WPS_PIXIE_SUCCESS_WINDOW_S,
    TUNE_COUNT
} tune_id_t;

typedef struct {
    const char *name;   /* CLI name, "family.knob" */
    long        def;    /* shipped default — the value before #82 */
    long        lo;     /* inclusive bounds; outside them is a startup error */
    long        hi;
    const char *unit;   /* for --tune-list; never parsed */
} tune_spec_t;

/* Current value. O(1) — detectors call this per packet. An id outside
   the enum returns 0, which no caller can produce. */
long tune_val(tune_id_t id);

/* Registry row, or NULL for an out-of-range id. */
const tune_spec_t *tune_spec(tune_id_t id);

/* Apply one "name=value". Returns 0, or -1 with a reason in err (unknown
   name, missing '=', non-numeric, trailing garbage, out of range). */
int tune_set(const char *spec, char *err, size_t errsz);

/* How many knobs sit off their default. 0 on an untouched run. */
int tune_non_default(void);

/* Every knob, one per line: name, default, current, unit. --tune-list. */
void tune_print_list(FILE *out);

/* Comma-joined "name=value" for the knobs off default, "" when none.
   Truncates cleanly at n. Feeds sensor_health's `tuned`. */
void tune_format_non_default(char *buf, size_t n);

/* Parse `value` strictly and set knob `id` — the --tune validation for
   a flag that aliases one row (#120). Returns 0, or -1 with a reason in
   err that names the knob (missing value, non-numeric, trailing
   garbage, out of range); on -1 the previous value stands. This is what
   replaced atoi() behind --correlate-retain, --db-* and --wps-*: "10x"
   and "" are refused, not read as 10 and 0. */
int tune_set_value(tune_id_t id, const char *value, char *err, size_t errsz);

/* Set by id, bypassing name lookup. Returns 1 when accepted, 0 when out
   of range and the previous value stands — the 1/0 shape the
   alerts_set_wps_* aliases already published, so folding them onto the
   registry did not change their contract. */
int tune_set_id(tune_id_t id, long v);

/* Back to shipped defaults. Tests only; main() never calls it. */
void tune_reset(void);

#endif /* SLOTH_TUNE_H */
