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
 * src/alerts.c. Those decide how much a corroborator is worth, not
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

/* Back to shipped defaults. Tests only; main() never calls it. */
void tune_reset(void);

#endif /* SLOTH_TUNE_H */
