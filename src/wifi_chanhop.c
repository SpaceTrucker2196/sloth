#include "wifi_chanhop.h"

/* Safe default channel list: the three non-overlapping 2.4 GHz channels
 * plus the common UNII-1 / UNII-3 5 GHz channels. Deliberately conservative
 * — no DFS channels, no 6 GHz — so enabling --hop never wanders into a band
 * the adapter may not be permitted to sit on. */
static const int DEFAULT_CHANNELS[] = { 1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161 };

int chanhop_freq(int channel) {
    if (channel >= 1 && channel <= 13) return 2407 + channel * 5;
    if (channel == 14)                 return 2484;
    if (channel >= 36 && channel <= 177) return 5000 + channel * 5;
    return 0;
}

static uint32_t dwell_for(const chanhop_t *h, uint32_t activity) {
    uint64_t d = (uint64_t)h->base_dwell_ms + (uint64_t)activity * h->ms_per_obs;
    if (d < h->min_dwell_ms) d = h->min_dwell_ms;
    if (d > h->max_dwell_ms) d = h->max_dwell_ms;
    return (uint32_t)d;
}

int chanhop_init(chanhop_t *h, const int *channels, int n) {
    if (!h) return 0;
    /* zero everything, then set tunables */
    for (int i = 0; i < CHANHOP_MAX; i++) {
        h->slots[i].channel = h->slots[i].freq_mhz = 0;
        h->slots[i].activity = 0;
    }
    h->count = h->cur = 0;
    h->dwell_until_ms = 0;
    h->started = 0;
    h->base_dwell_ms = 250;
    h->min_dwell_ms  = 100;
    h->max_dwell_ms  = 2000;
    h->ms_per_obs    = 8;

    if (!channels) return 0;
    for (int i = 0; i < n && h->count < CHANHOP_MAX; i++) {
        int f = chanhop_freq(channels[i]);
        if (!f) continue;               /* skip channels we can't tune */
        h->slots[h->count].channel  = channels[i];
        h->slots[h->count].freq_mhz = f;
        h->count++;
    }
    return h->count;
}

int chanhop_init_default(chanhop_t *h) {
    return chanhop_init(h, DEFAULT_CHANNELS,
                        (int)(sizeof(DEFAULT_CHANNELS) / sizeof(DEFAULT_CHANNELS[0])));
}

void chanhop_observe(chanhop_t *h, uint32_t observations) {
    if (!h || h->count == 0) return;
    h->slots[h->cur].activity += observations;
}

int chanhop_tick(chanhop_t *h, uint64_t now_ms) {
    if (!h || h->count == 0) return 0;

    if (!h->started) {
        h->started = 1;
        h->cur = 0;
        h->dwell_until_ms = now_ms + dwell_for(h, h->slots[0].activity);
        return 1;   /* first retune: park on the first channel */
    }

    if (now_ms < h->dwell_until_ms) return 0;   /* still dwelling */

    /* Decay the channel we're leaving so `activity` is a rolling window,
     * not an all-time tally — a channel that was busy an hour ago should
     * not hold a long dwell forever. */
    h->slots[h->cur].activity >>= 1;

    h->cur = (h->cur + 1) % h->count;           /* rotation → guaranteed revisit */
    h->dwell_until_ms = now_ms + dwell_for(h, h->slots[h->cur].activity);
    return 1;
}

int chanhop_current_channel(const chanhop_t *h) {
    if (!h || h->count == 0) return 0;
    return h->slots[h->cur].channel;
}

int chanhop_current_freq(const chanhop_t *h) {
    if (!h || h->count == 0) return 0;
    return h->slots[h->cur].freq_mhz;
}

int chanhop_export(const chanhop_t *h, int *out, int max, int *cur_idx) {
    if (cur_idx) *cur_idx = -1;
    if (!h || !out || max <= 0) return 0;
    int n = h->count < max ? h->count : max;
    for (int i = 0; i < n; i++) out[i] = h->slots[i].channel;
    if (cur_idx && h->started && h->cur < n) *cur_idx = h->cur;
    return n;
}
