/* Per-channel RF quality accounting — roadmap B3.
 *
 * Retries and FCS failures are the passive signature of a channel in
 * trouble: interference, a hidden node, or a jammer. Both signals were
 * already arriving and being discarded — the retry bit sits in every
 * 802.11 frame's Frame Control field, and the FCS-failed flag sits in
 * the radiotap header that probe.c was stepping over.
 *
 * This counts what arrives, per channel. It makes no claim about
 * *cause*: a high retry ratio is equally consistent with a microwave
 * oven, a distant client at the edge of range, and a deliberate jammer.
 * The number is the observation; the operator supplies the context.
 *
 * Deliberately no clock of its own — every timestamp is a parameter,
 * so windowing is testable without waiting. */

#ifndef SLOTH_RF_QUALITY_H
#define SLOTH_RF_QUALITY_H

#include "sloth.h"

/* Channels tracked concurrently. 2.4 GHz has 14, 5 GHz ~25 usable,
 * 6 GHz 59 — but a single radio only ever visits a hop list, so this
 * is sized for the realistic working set rather than the band. */
#define MAX_RF_CHANNELS 64

/* Below this many frames a ratio is noise, not a measurement. A single
 * retried frame out of three is 33% and means nothing. */
#define RF_MIN_FRAMES 100

/* Retry ratio, in percent, at which a channel is worth flagging.
 * Ordinary 802.11 runs 5-15% retries; sustained traffic above this is
 * a channel that is not working. */
#define RF_RETRY_DEGRADED_PCT 40

/* Observations older than this stop counting toward the live ratio, so
 * a channel that recovers stops being reported as degraded. */
#define RF_WINDOW_SECS 300

/* Record one observed frame on `channel`. `retry` is the 802.11 Frame
 * Control retry bit; `bad_fcs` the radiotap FCS-failed flag. A frame
 * with a failed FCS still counts as a frame — it is evidence about the
 * channel even though its contents are untrustworthy. */
void rf_quality_observe(int channel, int retry, int bad_fcs, time_t now);

/* Retry percentage for `channel` over the window, or -1 when fewer
 * than RF_MIN_FRAMES have been seen (i.e. "not enough to say"). */
int rf_quality_retry_pct(int channel, time_t now);

/* FCS-failure percentage, same contract. */
int rf_quality_badfcs_pct(int channel, time_t now);

/* True when the channel has enough traffic to judge and its retry
 * ratio is at or above RF_RETRY_DEGRADED_PCT. */
int rf_quality_is_degraded(int channel, time_t now);

/* Merge the live counters into `s->channels[]`, which the [m] Channel
 * view renders. Rows for channels with no beacon are not created —
 * this annotates the existing summary rather than owning it. */
void rf_quality_snapshot(sloth_state_t *s, time_t now);

/* Drop everything — tests, and channel-view clears. */
void rf_quality_clear(void);

#endif /* SLOTH_RF_QUALITY_H */
