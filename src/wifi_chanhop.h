#ifndef WIFI_CHANHOP_H
#define WIFI_CHANHOP_H

#include <stdint.h>
#include "sloth.h"
#include "wifi_freq.h"

/* Adaptive passive channel scheduler (issue #22).
 *
 * A single monitor radio can only listen on one channel at a time. This
 * module decides, from sloth's OWN passive observations, how long to dwell
 * on each channel and when to move on — spending more airtime where frames
 * are actually arriving while still guaranteeing every channel is revisited.
 *
 * The scheduler itself is pure logic: it never touches hardware. The
 * caller reads chanhop_target_freq() after chanhop_tick() returns 1,
 * asks the platform to retune the radio, and reports the result back
 * through chanhop_confirm_retune() — chanhop_service() below is that
 * loop, written once so a test can drive it through the fake platform.
 * Retuning is a kernel-state write gated behind
 * --hop; see src/platform/linux_wifi.h for the others and why this
 * comment no longer gives a total (#84). Keeping the policy hardware-free
 * makes it unit-testable with a synthetic clock and no live radio.
 *
 * Model: rotate through a static channel list (this alone guarantees every
 * channel is revisited each cycle). The DWELL on each channel scales with
 * its recently-observed activity, clamped to [min,max] so a busy channel
 * gets more time but can never starve the rest. Activity decays each visit,
 * making it a rolling window rather than an all-time count. */

#define CHANHOP_MAX 32

typedef struct {
    int      channel;    /* 802.11 channel number */
    /* Which band that number means (#167). A bare channel number cannot
     * carry a 6 GHz slot — 6 GHz runs 1-233, so every 2.4 and 5 GHz
     * number has a 6 GHz twin — so the band is stored alongside it and
     * freq_mhz below is derived from the pair, never from the number. */
    wifi_band_t band;
    int      freq_mhz;   /* center frequency (for nl80211 SET_CHANNEL) */
    uint32_t activity;   /* rolling observation count; decays each cycle */
    /* Lifetime hop-activity accounting (#91). `activity` above is the
     * scheduler's own decaying input and answers "where should I spend
     * airtime"; these never decay and answer the operator's question
     * instead — "is this radio actually visiting this channel, and does
     * anything live there". A channel with visits but no frames across
     * a whole run is the shape of a retune that silently didn't take. */
    uint32_t visits;     /* dwells begun on this channel */
    uint64_t frames;     /* monitor frames attributed to those dwells */
    /* Retunes to this channel the platform refused (#91). A refused
     * channel accrues no visit, dwell or frame — the radio never got
     * there — so without this a channel the driver always rejects
     * would simply never appear to have been tried. */
    uint32_t refusals;
} chanhop_slot_t;

typedef struct {
    chanhop_slot_t slots[CHANHOP_MAX];
    int      count;
    int      cur;             /* index of the channel currently dwelt on —
                               * the last one the platform ACKNOWLEDGED */
    uint64_t dwell_until_ms;  /* monotonic ms when the current dwell ends */
    int      started;
    /* Retune handshake (#91). The dwell used to be stamped inside
     * chanhop_tick(), before the caller had even issued the retune, so
     * a refused retune still credited the unreached channel with a
     * visit, a dwell and every frame heard afterwards. Now tick only
     * proposes `pending`; chanhop_confirm_retune() commits it. */
    int      pending;         /* slot asked for and not yet answered, -1 none */
    int      next;            /* slot the next proposal targets */
    int      tuned;           /* 1 once any retune has been acknowledged */
    /* tunables (chanhop_init sets sensible defaults) */
    uint32_t base_dwell_ms;   /* dwell for a quiet channel */
    uint32_t min_dwell_ms;    /* floor */
    uint32_t max_dwell_ms;    /* cap — one busy channel never starves the rest */
    uint32_t ms_per_obs;      /* extra dwell ms per observation carried in */
    /* Dwell measurement (#91). Written by chanhop_tick() only. */
    uint64_t dwell_began_ms;
    uint32_t dwell_planned_ms;
    uint32_t last_planned_ms;
    uint32_t last_measured_ms;
    uint32_t worst_overshoot_ms;
    uint64_t dwells_completed;
    uint64_t planned_total_ms;
    uint64_t measured_total_ms;
} chanhop_t;

/* Map a BAND-QUALIFIED 802.11 channel to its center frequency in MHz
 * (0 if the pair names no channel). This is the form that can express
 * 6 GHz: chanhop_band_freq(WIFI_BAND_6GHZ, 1) is 5955 MHz, which no
 * bare channel number could ever have meant (#167). */
int chanhop_band_freq(wifi_band_t band, int channel);

/* The same, for a bare channel number, with the band inferred the way
 * every pre-#167 caller meant it: 1-14 is 2.4 GHz and 32-177 is 5 GHz.
 * Returns 0 for anything else — including every 6 GHz-only channel,
 * because a bare number cannot distinguish one. Use
 * chanhop_band_freq() when the band is known. */
int chanhop_freq(int channel);

/* Initialise with an explicit channel list. Channels that don't map to a
 * known frequency are skipped. Returns the number accepted (0 = none).
 * Bare numbers, so 2.4/5 GHz only — see chanhop_init_bands(). */
int chanhop_init(chanhop_t *h, const int *channels, int n);

/* A band-qualified channel for chanhop_init_bands(). */
typedef struct {
    wifi_band_t band;
    int         channel;
} chanhop_chan_t;

/* Initialise with a band-qualified list, the only form that can hold a
 * 6 GHz channel. Same skipping and return convention as chanhop_init(),
 * which is this function with the band inferred — they share one
 * slot-filling path so the band cannot be set by one and missed by the
 * other. */
int chanhop_init_bands(chanhop_t *h, const chanhop_chan_t *chans, int n);

/* Initialise with the built-in safe 2.4/5 GHz list (1,6,11 + common UNII). */
int chanhop_init_default(chanhop_t *h);

/* Record activity observed on the current channel during this poll.
 *
 * The caller must pass frames heard by the MONITOR radio, not the
 * general capture counter: until #91 this was fed s->pkt_total, so
 * traffic on a wired management interface lengthened the dwell of
 * whatever channel the radio happened to be parked on. Feeds both the
 * decaying scheduler input and the lifetime per-channel tally. */
void chanhop_observe(chanhop_t *h, uint32_t observations);

/* Hop-activity summary (#91) — enough to tell "hopping normally" from
 * "stuck" or "tuned but deaf", without exporting a per-channel array.
 * Pure; safe on a NULL/empty scheduler (all zeroes). */
typedef struct {
    int      channels;        /* channels in the rotation */
    uint32_t visits;          /* dwells begun, all channels, lifetime */
    uint64_t frames;          /* monitor frames attributed, lifetime */
    int      silent_channels; /* visited at least once, never heard a frame */
    uint32_t cur_visits;      /* visits to the channel dwelt on now */
    uint64_t cur_frames;      /* frames attributed to it */
} chanhop_activity_t;

void chanhop_activity(const chanhop_t *h, chanhop_activity_t *out);

/* Measured vs configured dwell (#91) — the fifth problem bullet: a
 * dwell is only ever serviced when the poll loop next runs, so the time
 * the radio actually spends on a channel is the planned dwell rounded
 * up to the poll interval. With a 250 ms plan and a 1 s poll the radio
 * sits four times as long as the scheduler believes, every channel's
 * airtime is wrong, and nothing in the UI says so.
 *
 * Measured spans run start-of-dwell to start-of-next, so the figure
 * includes the servicing delay rather than hiding it. Means are
 * lifetime; last_* is the most recent completed dwell. Pure. */
typedef struct {
    uint32_t last_planned_ms;
    uint32_t last_measured_ms;
    uint32_t worst_overshoot_ms;  /* largest measured-minus-planned seen */
    uint64_t completed;           /* dwells that have ended */
    uint32_t mean_planned_ms;     /* 0 until one dwell completes */
    uint32_t mean_measured_ms;
} chanhop_dwell_t;

void chanhop_dwell(const chanhop_t *h, chanhop_dwell_t *out);

/* Advance the dwell clock. Returns 1 when the caller should retune the
 * radio to chanhop_target_freq() (first call, the dwell elapsed, or a
 * proposal is still unanswered); 0 to keep listening where it is.
 *
 * Proposes only. Nothing about the dwell, the visit count or frame
 * attribution moves until chanhop_confirm_retune() reports the result:
 * the radio has not moved yet when this returns. */
int chanhop_tick(chanhop_t *h, uint64_t now_ms);

/* Report the outcome of the retune chanhop_tick() asked for (#91).
 *
 * ok: the radio is on the target. The dwell that was running closes
 * out (measured start-of-dwell to now, so time lost to refused retunes
 * lands inside it), the target becomes current, gets its visit and a
 * dwell stamped at now_ms, and frames attribute to it from here on.
 *
 * !ok: the radio is still where it was. The target gets a refusal and
 * nothing else; current, its open dwell and frame attribution are
 * unchanged, and the next proposal skips to the channel after the
 * refused one after min_dwell_ms — so one channel the driver always
 * rejects cannot wedge the rotation, and a radio refusing everything
 * retries at a bounded rate instead of every poll.
 *
 * No-op when nothing is pending. */
void chanhop_confirm_retune(chanhop_t *h, int ok, uint64_t now_ms);

/* The channel the radio is on: the last acknowledged retune. Before
 * the first acknowledgement this is slot 0 by construction, which is
 * why chanhop_export() and frame attribution key on `tuned`. */
int chanhop_current_channel(const chanhop_t *h);
int chanhop_current_freq(const chanhop_t *h);
/* Which band that channel number is in; WIFI_BAND_UNKNOWN on an empty
 * scheduler. Needed to report the current channel unambiguously once a
 * rotation can hold 6 GHz (#167). */
wifi_band_t chanhop_current_band(const chanhop_t *h);

/* The channel chanhop_tick() is asking for; 0 when nothing is pending. */
int chanhop_target_channel(const chanhop_t *h);
int chanhop_target_freq(const chanhop_t *h);
wifi_band_t chanhop_target_band(const chanhop_t *h);

/* Copy the channel list (channel numbers) into out[max]; return the count.
 * *cur_idx receives the index of the channel currently dwelt on (-1 if
 * none). For the UI scan bar. */
int chanhop_export(const chanhop_t *h, int *out, int max, int *cur_idx);

/* Record the outcome of a retune the caller issued after chanhop_tick()
 * returned 1 (issue #91 slice 1: "healthy, no detections" and "not
 * observing" were indistinguishable because the caller never looked at
 * set_channel()'s return code). Pure bookkeeping, no hardware — testable
 * without a live radio, matching the rest of this module.
 *
 * *requested_out always takes requested_channel. *confirmed_out only
 * advances when retune_ok is true, so a failed retune leaves it pointing
 * at the last channel the platform actually acknowledged rather than the
 * one sloth merely asked for; *failures_out counts every failure seen
 * (lifetime, never reset — a flapping radio should stay visible). Any of
 * the three output pointers may be NULL. */
void chanhop_record_retune(int requested_channel, int retune_ok,
                            int *requested_out, int *confirmed_out,
                            int *failures_out);

/* The same bookkeeping, carrying the reason (#91). `err` is 0 for an
 * acknowledged retune or the positive errno the platform reported —
 * the nl80211 ack's own error for a kernel refusal. *last_errno_out
 * takes it on failure and keeps it across later successes: it names
 * the cause of the failures *failures_out is counting, and a radio
 * that recovered should still say why it had been failing. 0 means no
 * retune has ever failed. */
void chanhop_record_retune_err(int requested_channel, int err,
                               int *requested_out, int *confirmed_out,
                               int *failures_out, int *last_errno_out);

/* Bucketed name for a retune errno, for the TUI and JSONL: the errno
 * macro name for the reasons a set_channel() actually returns, "other"
 * for the rest, "none" for 0. A fixed, small vocabulary so a consumer
 * can switch on it, and a stable value under a persistent failure so
 * it can sit in the change-only signature. Never NULL. */
const char *chanhop_retune_reason(int err);
/* The bucket chanhop_retune_reason() names, as a bit index (0 = none,
 * "other" last), for the sticky reason mask in sloth_state_t. */
int chanhop_retune_reason_bit(int err);

/* One poll's worth of hopping, against g_platform (#91): attribute
 * `mon_frames` (monitor-radio frames since the last call) to the
 * confirmed channel, tick, issue the retune through
 * g_platform.set_channel, feed the result back, and publish the
 * requested/confirmed pair, failure count and reason, scan bar,
 * activity and dwell into `s`. main.c's chanhop_drive() is this plus
 * the --hop gate and the frame-counter delta; it lives here so a test
 * can run it against tests/fake_platform.c with an injected errno. */
void chanhop_service(chanhop_t *h, sloth_state_t *s, uint64_t now_ms,
                     uint32_t mon_frames);

#endif /* WIFI_CHANHOP_H */
