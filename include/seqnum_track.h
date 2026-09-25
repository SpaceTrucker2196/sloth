#ifndef SLOTH_SEQNUM_TRACK_H
#define SLOTH_SEQNUM_TRACK_H

#include <stdint.h>
#include "sloth.h"

/* Sequence-number-based device correlation.
 *
 * 802.11 frames carry a 12-bit per-station sequence counter that many
 * stacks do not randomise (it lives at the chipset level below the OS's
 * MAC-randomisation logic). Two "different" MACs whose sequence numbers
 * fall on one forward-running counter are *consistent with* a single
 * physical radio rotating its address.
 *
 * Consistent with, not proof of — and the distinction is the whole
 * point of this module's contract (#94):
 *
 *   - A 12-bit counter has 4096 positions. Two independent radios land
 *     inside any fixed window often enough that an any-pair match over
 *     many histories produces coincidences at a rate worth measuring
 *     rather than asserting. `tests/test_seqnum_track.c ::
 *     test_dense_environment_false_pair_rate` measures it against a
 *     dense fixture and prints the number.
 *   - So the module reports a **calibrated confidence** and the
 *     **evidence window** it rests on, never a categorical verdict.
 *   - A correlation is a statement about a *radio*. It is never a
 *     statement about a person, and nothing here may be presented as
 *     one. See `docs/wiki/mac-randomisation.md` for the limits on use.
 *
 * For each observed MAC the module keeps a small history of recent
 * sequence numbers + timestamps. On snapshot it emits
 * seqnum_correlation_t pairs that survive every test below.           */

/* seqnum_client_t, seqnum_correlation_t and the related capacities
 * live in sloth.h alongside the other data types embedded in
 * sloth_state_t. */

/* ── Correlation thresholds ─────────────────────────────────── */

/* Forward counter advance permitted across a MAC transition. A radio
 * that rotates its address mid-burst advances its counter by the frames
 * it sent in between; more than this and the two trails are not one
 * counter, they are two counters that happen to be near each other. */
#define SEQNUM_CORR_SEQ_WINDOW   64

/* Wall-clock gap permitted between the earlier MAC's last frame and the
 * later MAC's first. */
#define SEQNUM_CORR_DT_MAX_S     30

/* Default evidence retention for correlation: a pair is only reported
 * while *both* sides have been seen inside this window, counted from
 * now. Before #94 nothing expired — two histories that were once close
 * kept producing "same device" suggestions for the life of the process,
 * long after either device had left. Operator-settable
 * (`--correlate-retain`), because it is a retention decision and not
 * only a tuning one. */
#define SEQNUM_CORR_RETAIN_S     300

/* Per-MAC records are dropped once this stale, on snapshot — the table
 * no longer waits to fill before forgetting anybody. The effective
 * value is max(this, retain), so raising the correlation window never
 * starves it of candidates. */
#define SEQNUM_CLIENT_RETAIN_S   3600

/* Confidence ceiling, in percent. A shared counter position is
 * circumstantial evidence; there is no observation that closes the gap
 * to certainty, so the scale does not reach 100. */
#define SEQNUM_CORR_CONF_MAX     90

/* Floor for a reported pair. Anything scoring below this is coincidence
 * at the rate the dense fixture measures, and is not emitted. */
#define SEQNUM_CORR_CONF_MIN     20

/* At or above this the numeric evidence is as strong as passive
 * observation gets: a close forward seam, an immediate transition, deep
 * trails both sides. Necessary but not sufficient — see
 * seqnum_corr_is_strong(). It is still a hypothesis either way. */
#define SEQNUM_CORR_CONF_STRONG  70

/* ── Observation ────────────────────────────────────────────── */

/* Record an observation. `seqnum` is the 12-bit value extracted from
 * the 802.11 SeqCtl field (bits 4..15 of the 16-bit SC). MAC must be a
 * 6-byte buffer. The `_at` form takes the timestamp as a parameter so
 * expiry and ordering are testable without waiting; the bare form is
 * the production wrapper and reads the clock. */
void seqnum_track_observe_at(const uint8_t mac[6], uint16_t seqnum, time_t now);
void seqnum_track_observe(const uint8_t mac[6], uint16_t seqnum);

/* Snapshot the per-MAC table + computed correlations into the state
 * vector, expiring anything outside its retention window first.
 * Correlations are sorted by descending confidence (most likely
 * first). */
void seqnum_snapshot_at(sloth_state_t *s, time_t now);
void seqnum_snapshot(sloth_state_t *s);

/* ── Longitudinal correlation configuration (#94) ───────────── */

/* Correlating addresses across a rotation is longitudinal tracking of a
 * device, which is a different purpose from observing what is on the
 * air right now — so it is switched and retained separately rather than
 * riding along with capture. Enabled by default (it is a shipped
 * capability, see MISSION §3); `--no-correlate` turns it off, and with
 * it off the per-MAC histories are still shown but no pair is linked,
 * stored, or exported. */
void seqnum_corr_set_enabled(int on);
int  seqnum_corr_enabled(void);

/* Evidence retention, seconds. Values below 1 are ignored. */
void seqnum_corr_set_retain_secs(int secs);
int  seqnum_corr_retain_secs(void);

/* The strongest reading the module offers, and it is deliberately
 * *structural* as well as numeric: a high score **and** exactly one
 * randomised address.
 *
 * A threshold alone is not enough. The dense fixture measures
 * coincidences that score into the upper band — a close forward seam
 * between two independent radios looks exactly like a rotation, and no
 * number derived from the same evidence can separate them. What can is
 * the *shape*: address randomisation produces one rotating address
 * beside one anchor identity, and a pair of two randomised addresses has
 * no anchor to distinguish it from two of the many devices that
 * randomise. Such a pair is still reported with its score; it is not
 * presented as the strongest case. */
int seqnum_corr_is_strong(const seqnum_correlation_t *c);

/* Calibration hook: run the production acceptance test over every pair
 * in the live table and report how many were accepted and the highest
 * confidence any of them scored, ignoring MAX_SEQNUM_CORRELATIONS.
 * Returns the number of pairs compared.
 *
 * Exists so the false-pair rate can be *measured* against a fixture
 * instead of quoted from a uniform-independence estimate that real,
 * dependent histories do not obey. Either out-pointer may be NULL. */
int seqnum_corr_candidate_pairs(time_t now, int *out_accepted,
                                int *out_max_conf);

/* Drop everything — tests only. Also restores the default
 * configuration, so one test's `--no-correlate` cannot leak into the
 * next. */
void seqnum_clear(void);

/* Direct introspection for tests. */
int  seqnum_client_count(void);

#endif /* SLOTH_SEQNUM_TRACK_H */
