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
 * so windowing is testable without waiting.
 *
 * Thread safety (#95): every function here may be called from any
 * thread. rf_quality_observe() runs on the probe thread while
 * rf_quality_snapshot() runs on the poll loop; one mutex private to
 * rf_quality.c serialises them all. It is a leaf — never held across a
 * call out of the module — so callers may hold their own locks. */

#ifndef SLOTH_RF_QUALITY_H
#define SLOTH_RF_QUALITY_H

#include "sloth.h"
#include "radiotap.h"   /* wifi_band_t */

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

/* Record one observed frame on `channel`/`band`. `retry` is the 802.11
 * Frame Control retry bit; `bad_fcs` the radiotap FCS-failed flag. A
 * frame with a failed FCS still counts as a frame — it is evidence
 * about the channel even though its contents are untrustworthy.
 *
 * `band`, keyed alongside `channel` (#149): 5 GHz and 6 GHz channel
 * numbers overlap (37, 149, 165, …), so a bare channel number pools
 * two physically different radio channels into one counter and one
 * ageing window — a degraded 6 GHz network's retry ratio diluted by an
 * unrelated healthy 5 GHz one sharing the number, and worse, a stale
 * window kept artificially "live" by the other band's unrelated
 * traffic rather than rolling to unknown on its own schedule. `band`
 * comes from radiotap_freq_to_band() at the one call site that has a
 * real frequency (capture/probe.c) — it is a fact about the radio, not
 * a guess from an IE that may or may not be present. */
void rf_quality_observe(int channel, wifi_band_t band,
                        int retry, int bad_fcs, time_t now);

/* Retry percentage for `channel`/`band` over the window, or -1 when
 * fewer than RF_MIN_FRAMES have been seen (i.e. "not enough to say"). */
int rf_quality_retry_pct(int channel, wifi_band_t band, time_t now);

/* FCS-failure percentage, same contract. */
int rf_quality_badfcs_pct(int channel, wifi_band_t band, time_t now);

/* True when channel/band has enough traffic to judge and its retry
 * ratio is at or above RF_RETRY_DEGRADED_PCT. */
int rf_quality_is_degraded(int channel, wifi_band_t band, time_t now);

/* Merge the live counters into `s->channels[]`, which the [m] Channel
 * view renders. Rows for channels with no beacon are not created —
 * this annotates the existing summary rather than owning it.
 *
 * channel_summary_t has one row per channel NUMBER, not per band
 * (channel.c's own band-identification question is a separate,
 * harder problem — see #149's tracking comment — because a beacon's
 * channel_source IE is sometimes absent even on the band it would
 * have named, where a frame's radiotap frequency never is). So this
 * sums every band this module has measured under that number into the
 * row's frames/retry_pct/badfcs_pct, which is exactly what it already
 * read before bands were tracked separately — the fix below is that
 * each band now ages out of that sum on its own schedule instead of
 * being kept alive by an unrelated band's traffic. */
void rf_quality_snapshot(sloth_state_t *s, time_t now);

/* Drop everything — tests, and channel-view clears. */
void rf_quality_clear(void);

#endif /* SLOTH_RF_QUALITY_H */
