#include "sweep.h"
#include <string.h>

/* The sweep's coverage accounting (#249). Contract: sweep.h. Main
 * thread, like the schedulers it reads. */

static sw_cov_ch_t *chan_of(sw_cov_t *c, int freq, int channel, int band) {
    for (int i = 0; i < c->n; i++)
        if (c->ch[i].freq_mhz == freq) return &c->ch[i];
    /* Not in the plan: a scheduler only ever holds plan channels, so
     * this is a share dealt from another list; still counted. */
    if (c->n >= SW_COV_MAX) return NULL;
    sw_cov_ch_t *e = &c->ch[c->n++];
    memset(e, 0, sizeof(*e));
    e->freq_mhz = freq;
    e->channel = channel;
    e->band = band;
    return e;
}

void sweep_cov_init(sw_cov_t *c, const chanhop_t *full, uint64_t now_ms) {
    if (!c) return;
    memset(c, 0, sizeof(*c));
    c->start_ms = c->last_ms = now_ms;
    if (!full) return;
    for (int i = 0; i < full->count && i < CHANHOP_MAX; i++)
        (void)chan_of(c, full->slots[i].freq_mhz, full->slots[i].channel,
                      (int)full->slots[i].band);
    c->planned_dwell_ms = chanhop_sweep_dwell_ms(full);
    c->sweep_ms = full->sweep_ms;
}

static uint64_t since(uint64_t now, uint64_t then, int same) {
    return same && now >= then ? now - then : now;
}

void sweep_cov_sample(sw_cov_t *c, int radio, const chanhop_t *h, uint64_t now_ms) {
    if (!c || !h || radio < 0 || radio >= SW_COV_RADIOS) return;
    if (now_ms > c->last_ms) c->last_ms = now_ms;
    if (radio + 1 > c->radios && h->count > 0) c->radios = radio + 1;
    int n = h->count < CHANHOP_MAX ? h->count : CHANHOP_MAX;
    for (int i = 0; i < n; i++) {
        const chanhop_slot_t *sl = &h->slots[i];
        uint64_t ms = chanhop_slot_time_ms(h, i, now_ms);
        int same = i < c->base[radio].n && c->base[radio].freq[i] == sl->freq_mhz &&
                   ms >= c->base[radio].ms[i] && sl->frames >= c->base[radio].fr[i] &&
                   sl->visits >= c->base[radio].vis[i] &&
                   sl->refusals >= c->base[radio].ref[i];
        sw_cov_ch_t *e = chan_of(c, sl->freq_mhz, sl->channel, (int)sl->band);
        if (e) {
            e->ms       += since(ms, c->base[radio].ms[i], same);
            e->frames   += since(sl->frames, c->base[radio].fr[i], same);
            e->visits   += (uint32_t)since(sl->visits, c->base[radio].vis[i], same);
            e->refusals += (uint32_t)since(sl->refusals, c->base[radio].ref[i], same);
        }
        c->base[radio].freq[i] = sl->freq_mhz;
        c->base[radio].ms[i]   = ms;
        c->base[radio].fr[i]   = sl->frames;
        c->base[radio].vis[i]  = sl->visits;
        c->base[radio].ref[i]  = sl->refusals;
    }
    c->base[radio].n = n;
}

int sweep_cov_swept(const sw_cov_t *c) {
    int k = 0;
    for (int i = 0; c && i < c->n; i++) k += c->ch[i].ms > 0;
    return k;
}
