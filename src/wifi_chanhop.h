#ifndef WIFI_CHANHOP_H
#define WIFI_CHANHOP_H

#include <stdint.h>

/* Adaptive passive channel scheduler (issue #22).
 *
 * A single monitor radio can only listen on one channel at a time. This
 * module decides, from sloth's OWN passive observations, how long to dwell
 * on each channel and when to move on — spending more airtime where frames
 * are actually arriving while still guaranteeing every channel is revisited.
 *
 * It is pure logic: it never touches hardware. The caller reads
 * chanhop_current_freq() after chanhop_tick() returns 1 and asks the
 * platform to retune the radio (the only kernel-state write sloth performs,
 * gated behind --hop; see MISSION.md §2). Keeping the policy hardware-free
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
} chanhop_slot_t;

typedef struct {
    chanhop_slot_t slots[CHANHOP_MAX];
    int      count;
    int      cur;             /* index of the channel currently dwelt on */
    uint64_t dwell_until_ms;  /* monotonic ms when the current dwell ends */
    int      started;
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

/* Map an 802.11 channel to its center frequency in MHz (0 if unknown).
 * Covers 2.4 GHz (1-14) and 5 GHz (>=36). */
int chanhop_freq(int channel);

/* Initialise with an explicit channel list. Channels that don't map to a
 * known frequency are skipped. Returns the number accepted (0 = none). */
int chanhop_init(chanhop_t *h, const int *channels, int n);

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
 * radio to chanhop_current_freq() (first call, or the dwell elapsed);
 * 0 to keep listening on the current channel. */
int chanhop_tick(chanhop_t *h, uint64_t now_ms);

int chanhop_current_channel(const chanhop_t *h);
int chanhop_current_freq(const chanhop_t *h);

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

#endif /* WIFI_CHANHOP_H */
