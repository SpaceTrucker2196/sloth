#ifndef SLOTH_RTL433_H
#define SLOTH_RTL433_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* ── rtl_433 sub-GHz devices: --rtl433 (#208, 2026-11-14) ─────────
 *
 * sloth tails the JSON event log a local, already-running rtl_433
 * writes (`rtl_433 -F json`, redirected to a file) and turns each line
 * into a typed message (rtl433_msg_t, include/sloth.h) and a per-device
 * row keyed (model, id). It never opens, tunes, hops or runs the SDR,
 * and uses no network: the source is a file path. Receive-only, as the
 * decoder is — MISSION.md §2 is unaffected for the same reason --aprs
 * and --adsb are.
 *
 *   --rtl433 /var/lib/rtl_433/events.jsonl
 *   --rtl433 file:///var/lib/rtl_433/events.jsonl
 *
 * This file is the pure half - the line parser, the spec parser, and
 * the table the reader (src/capture/rtl433_reader.c) feeds and the poll
 * copies out. Nothing here does I/O.
 *
 * Sources, and they are the only two this parser is allowed to claim a
 * field from:
 *
 *   - rtl_433 `docs/DATA_FORMAT.md` (merbanan/rtl_433) for the field
 *     semantics: `time`, `type`, `model`, `subtype`, `id`, `channel`
 *     and `mic` under "Message Data" — model and id both bounded there
 *     ("less than 32" / "less than 16 characters"), mic one of "CRC",
 *     "CHECKSUM" or "PARITY"; `battery_ok` (0 empty .. 1 full) under
 *     "Common Device Data"; `temperature_C` / `temperature_F`,
 *     `humidity` and `pressure_hPa` / `pressure_psi` under "Sensor
 *     Data", whose stated rule is `<Type>_<Unit>` "in sensors native
 *     units insofar possible with no conversion".
 *   - rtl_433 `src/r_api.c` for the metadata the host's `-M protocol`
 *     and `-M level` add: `protocol`, and then `mod` with either one
 *     `freq` (the ASK and LoRa branches) or `freq1` and `freq2` (the
 *     FSK branch), plus `rssi`, `snr` and `noise` in dB. Those three
 *     branches are an if / else-if chain, so no line carries both
 *     `freq` and `freq1`.
 *
 * The output shape is rtl_433 `src/output_file.c`: one JSON object per
 * line, written by print_json_* and flushed per record. Doubles go out
 * as "%.3f" and integers as "%d", so no exponent and no bare `.5`
 * appears from the writer - this parser still accepts RFC 8259 numbers,
 * because the file is not trusted to have been written by that writer.
 * Strings are escaped for `"`, `\`, CR, LF and TAB and NOTHING else:
 * no `\u`, and any other control byte passes through raw. So a model
 * name is not safe to print by virtue of having been quoted, and every
 * string field here is cleaned to printable ASCII.
 *
 * Every line is hostile. Anyone with a 433 MHz transmitter chooses what
 * a decoder writes about them, including the model string and the id,
 * and the id "is a unique sequence of alphanumeric characters" by
 * convention only - a sender may reuse another device's. A row is a
 * hypothesis about a transmitter, never an identification of a vehicle
 * or a person (#94's rule, which applies here for the same reason: a
 * TPMS id is fixed to a wheel for years).
 *
 * WHAT IS NOT PARSED, and why - so the gap is stated rather than left
 * to read as "rtl_433 does not send it":
 *
 *   - The PER-MODEL keys (`state`, `code`, `flags`, `learn`, `moving`,
 *     `repeat`, `maybe_battery`, ...). They are each one decoder's
 *     field, not a documented one, and their JSON TYPE is not a
 *     property of the name: `flags` is DATA_INT in
 *     `src/devices/tpms_citroen.c` and DATA_STRING in
 *     `src/devices/tpms_renault.c`. Typing them from one site's
 *     observation would be the invention this comment exists to
 *     prevent; they are counted as other_keys until a per-key survey
 *     of the decoders says what each one is.
 *   - `time`. Its format follows rtl_433's `-M time[:...]` options and,
 *     by default, the host's locale, and the file carries no statement
 *     of which were used - so a stamp read out of it would be a guess
 *     at a clock. It is recognised and skipped (not counted as an
 *     unknown key, since `-M time` puts it on every line), and a row's
 *     first_seen / last_seen are the host's clock at the read.
 *   - `msg`, `codes`, `bits`, `description`, `tag`, and the LoRa
 *     metadata `sf` / `bw` / `cr` / `sync`: counted, not stored.
 *
 * An OPTIONAL value that is present but out of range leaves its field
 * absent and is counted in bad_values; it is never clamped, and it does
 * not refuse the line, because the key and the signal metadata on that
 * line are still a real observation. Only the line's own structure and
 * its key refuse it: see rtl433_reject_t. */

#define RTL433_POLL_MS     1000  /* the reader checks the file this often */
#define RTL433_POLL_BYTES  (256u * 1024u)  /* read at most this much a poll */
/* A longer line is one bad line, skipped to its newline. A decode with
 * `-M level -M protocol` and a weather station's full field set runs to
 * a few hundred bytes; 1 KiB leaves room above that without admitting
 * the unbounded `-M bits` dump as a single line. */
#define RTL433_MAX_LINE    1024

/* ── One line ──────────────────────────────────────────────────── */

/* Parse one line (no newline; a trailing CR is ignored) into *out.
 * 1 a message, 0 a line to skip (blank), -1 bad with the reason in
 * *why (a rtl433_reject_t; may be NULL).
 *
 * Bounds are wide sanity bounds, not spec limits: DATA_FORMAT.md states
 * units, never ranges, so the job of the bound is to refuse a value
 * that cannot be a reading rather than to second-guess a sensor.
 * Locale-free: no strtod. */
int  rtl433_line_parse(const char *line, size_t n, rtl433_msg_t *out, int *why);

/* "oversize", "not_object", "malformed", "no_model", "no_id"; part of
 * the sensor_health contract (`rtl433_rej_<name>`). "" for anything
 * else. */
const char *rtl433_reject_name(int why);

/* "", "C", "F" and "", "kPa", "hPa", "psi": the unit a stored value
 * came in, which is the suffix of the key it arrived under. */
const char *rtl433_temp_unit_name(int unit);
const char *rtl433_pres_unit_name(int unit);

/* ── The --rtl433 SPEC ─────────────────────────────────────────── */

/* An absolute path, or file:///absolute/path (file://HOST/ refused);
 * any other scheme or a relative path is refused. 0 with the path, -1
 * with a reason in err. The same contract as aprs_spec_parse(). */
int  rtl433_spec_parse(const char *spec, char *path, size_t pathsz,
                       char *err, size_t errsz);

/* ── The table ─────────────────────────────────────────────────── *
 * One mutex: the reader feeds, the main thread polls. */

/* Declare the source and its label ("file:/var/lib/rtl_433/events.jsonl");
 * the state is WAITING until the file is read. */
void rtl433_set_source(const char *label);

/* One complete line read at host `wall`: counted, parsed, and a message
 * fed. Returns rtl433_line_parse()'s answer. */
int  rtl433_feed_line(const char *line, size_t n, time_t wall);

/* A parsed message merged into its device, keyed (model, id). The table
 * holds RTL433_MAX_DEVICES rows and drops the least recently heard to
 * make room (STAB_OLDEST, tallied as `rtl433`): the key space belongs to
 * whatever is transmitting, so a spray of invented models must churn the
 * table and never make sloth allocate. Sticky merge: a value is replaced
 * only by a line that carries one, so a TPMS line with no temperature
 * does not erase the temperature of the line before it. */
void rtl433_feed_msg(const rtl433_msg_t *m, time_t wall);

/* The reader's poll outcome. A good poll clears the error and the
 * missing flag; `missing` is the file not there (rtl_433 creates it on
 * its first decode, or the shell redirect does on start), a state, not
 * an error; a read error counts. */
void rtl433_note_read(time_t wall, uint64_t bytes, int rotated, int truncated);
void rtl433_note_missing(void);
void rtl433_note_read_error(const char *err);
/* An overlong line, skipped by the reader: one bad line, RTL433_REJ_OVERSIZE. */
void rtl433_note_bad_line(void);

/* Copy the health and the device table into s. PH_PLATFORM, after
 * aprs_health_poll(). Rows are not retired by age - a device heard once
 * and never again is a real observation of the band, and the only thing
 * that removes a row is the table filling. */
void rtl433_health_poll(sloth_state_t *s, time_t wall);

/* Back to nothing configured. Tests and a reconfigure. */
void rtl433_reset(void);

/* "none", "waiting", "live", "error". */
const char *rtl433_state_name(int state);

/* ── Change-only (agents/AGENTS.md: a continuous value enters a
 * signature as its band, never itself) ─────────────────────────────
 *
 * The rtl433_device record's change signature: the key, first_seen (an
 * evicted row that comes back is a new row), the discrete facts (type,
 * subtype, channel, mic, mod, protocol and which values are present),
 * and every continuous value as a band:
 *
 *   - rssi in RTL433_RSSI_STEP_DB steps, the issue's figure;
 *   - the frequency in whole MHz. The band is what the number is for -
 *     433.92 against 868 or 915 - and the per-decode spread of
 *     rtl_433's own estimator is tens of kHz, so a finer bucket would
 *     flap on a stationary transmitter without saying anything;
 *   - temperature, pressure and humidity rounded to one unit;
 *   - battery_ok to a tenth (it is 0 or 1 from a binary sensor).
 *
 * NEVER: msgs, last_seen, other_keys, snr, noise, or freq2. The first
 * three move on every line a working sensor hears; snr and noise move
 * with each decode and are written without being signed, the way the
 * APRS level is; freq2 is the other half of the FSK pair and moves with
 * freq, so signing both bands would count one change twice. */
#define RTL433_RSSI_STEP_DB 3

uint64_t rtl433_device_sig(const rtl433_device_t *d);

/* The bands themselves, so the record writer and the tests agree on one
 * definition. rssi_band is only meaningful when the row has an rssi. */
int rtl433_rssi_band(double rssi_db);
int rtl433_freq_band(double freq_mhz);

#endif /* SLOTH_RTL433_H */
