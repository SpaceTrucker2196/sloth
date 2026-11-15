#ifndef SLOTH_VICTRON_H
#define SLOTH_VICTRON_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* ── Victron devices: --victron (2026-11-15) ──────────────────────
 *
 * sloth tails the JSONL file sloth-va appends to
 * (/var/lib/sloth-va/victron.jsonl; docs/wiki/victron.md) and keeps one
 * row per device address with the latest of each reading. It is a file
 * source like --rtl433: sloth opens no Bluetooth socket for it, decrypts
 * nothing and connects to nothing. sloth-va did those things, as a
 * separate helper under its own account (ADR 0011); MISSION.md §2 still
 * describes sloth.
 *
 *   --victron /var/lib/sloth-va/victron.jsonl
 *   --victron file:///var/lib/sloth-va/victron.jsonl
 *
 * The record (one object per line) is the one sloth-va's writer,
 * va_record_jsonl() under src/va, produces: "type":"victron", "source" readout|gatt, "mac",
 * "serial", "model", "record", "rssi", "session", "values":{...}. The
 * file is still treated as hostile - another account could have written
 * it, and "label" carries a name the device chose - so:
 *
 *   - a value is kept only under a name on the allow-list below, inside
 *     its bound; out of range is absent and counted (bad_values), never
 *     clamped; any other name is counted (other_keys) and dropped;
 *   - strings are cleaned to a small charset and cut; "label" (the
 *     device's own name) and "services" are not stored;
 *   - the row is keyed by the address, which must be aa:bb:cc:dd:ee:ff;
 *   - the table holds VICTRON_MAX_DEVICES rows and REFUSES a 17th
 *     address (counted, table_full) rather than evicting: the owner has
 *     a handful of devices, and a file that names more is wrong, not a
 *     busier band.
 *
 * Timestamps are the host clock at the read, as for --rtl433: "t" is
 * sloth-va's and is not trusted to agree with sloth's. */

#define VICTRON_POLL_MS     1000
#define VICTRON_POLL_BYTES  (64u * 1024u)
#define VICTRON_MAX_LINE    2048         /* sloth-va's buffer */

/* Parse one line into a message. 1 a record, 0 a blank line, -1 bad
 * with the reason in *why (victron_reject_t). */
typedef struct {
    char     mac[18];
    char     serial[24];
    char     model[32];
    char     record[24];
    char     session[24];
    int      gatt;             /* source "gatt"; 0 "readout" */
    int      has_rssi;
    int      rssi;
    int      nvals;
    victron_val_t vals[VICTRON_MAX_VALS];
    uint32_t bad_values;
    uint32_t other_keys;
} victron_msg_t;

int  victron_line_parse(const char *line, size_t n, victron_msg_t *out, int *why);

/* "oversize", "not_object", "malformed", "not_victron", "no_mac". */
const char *victron_reject_name(int why);

/* The value allow-list: 1 and *unit set when `name` is on it. */
int  victron_value_known(const char *name, const char **unit);

/* Absolute path or file:///path, as rtl433_spec_parse(). */
int  victron_spec_parse(const char *spec, char *path, size_t pathsz,
                        char *err, size_t errsz);

/* ── The table (one mutex: the reader feeds, the poll copies) ───── */
void victron_set_source(const char *label);
int  victron_feed_line(const char *line, size_t n, time_t wall);
void victron_note_read(time_t wall, uint64_t bytes, int rotated, int truncated);
void victron_note_missing(void);
void victron_note_read_error(const char *err);
void victron_note_bad_line(void);
void victron_health_poll(sloth_state_t *s, time_t wall);
void victron_reset(void);
const char *victron_state_name(int state);   /* "none", "waiting", "live", "error" */

/* The victron_device record's change signature: the key, first_seen,
 * the discrete facts (serial, model, record, session, which values are
 * present) and each value as a band - voltages to 0.1 V, currents and
 * Ah to 1, SOC to 1 %, power to 10 W, temperature to 1 C, TTG to 10
 * min; the enumerations (state, error, off reason, alarm, aux input)
 * exactly. Never readings, sessions, last_seen or rssi: each moves on
 * every record (agents/AGENTS.md). */
uint64_t victron_device_sig(const victron_device_t *d);
/* The band of one value, as the signature uses it. */
long long victron_value_band(const char *name, double v);

#endif /* SLOTH_VICTRON_H */
