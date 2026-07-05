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
} chanhop_t;

/* Map an 802.11 channel to its center frequency in MHz (0 if unknown).
 * Covers 2.4 GHz (1-14) and 5 GHz (>=36). */
int chanhop_freq(int channel);

/* Initialise with an explicit channel list. Channels that don't map to a
 * known frequency are skipped. Returns the number accepted (0 = none). */
int chanhop_init(chanhop_t *h, const int *channels, int n);

/* Initialise with the built-in safe 2.4/5 GHz list (1,6,11 + common UNII). */
int chanhop_init_default(chanhop_t *h);

/* Record activity observed on the current channel during this poll. */
void chanhop_observe(chanhop_t *h, uint32_t observations);

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

#endif /* WIFI_CHANHOP_H */
