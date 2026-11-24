#include "wifi_chanhop.h"
#include <errno.h>
#include <string.h>
#include "cov_timeline.h"
#include "sloth_clock.h"

/* Safe default channel list: the three non-overlapping 2.4 GHz channels
 * plus the common UNII-1 / UNII-3 5 GHz channels. Deliberately conservative
 * — no DFS channels, no 6 GHz — so enabling --hop never wanders into a band
 * the adapter may not be permitted to sit on. */
static const int DEFAULT_CHANNELS[] = { 1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161 };

int chanhop_band_freq(wifi_band_t band, int channel) {
    return wifi_freq_mhz(band, channel);
}

int chanhop_freq(int channel) {
    /* #167: this used to be a fourth copy of the band plan, and the only
     * one with no 6 GHz case at all — 5955 MHz was unreachable through
     * the whole scheduler because a bare channel number cannot say which
     * band it means. The inference is kept for the bare-number callers;
     * the band-qualified entry point above is the one that can express
     * 6 GHz. Widens 5 GHz from 36-177 to the band plan's 32-177, so an
     * explicit --hop 34 now tunes instead of being silently dropped. */
    return wifi_freq_mhz(wifi_freq_infer_band(channel), channel);
}

static uint32_t dwell_for(const chanhop_t *h, uint32_t activity) {
    uint64_t d = (uint64_t)h->base_dwell_ms + (uint64_t)activity * h->ms_per_obs;
    if (d < h->min_dwell_ms) d = h->min_dwell_ms;
    if (d > h->max_dwell_ms) d = h->max_dwell_ms;
    return (uint32_t)d;
}

/* Slot t's cued plan at now_ms: CHANHOP_CUE_MULT x its normal plan,
 * clamped to what the cap and the floor (wifi_chanhop.h, "Cued dwell")
 * leave once every other cued slot has its own cued plan, and never
 * shorter than its normal plan. With cue_cap_pm at 500 the cap is
 * "cued plans <= uncued plans", the single-radio rule; the floor is
 * "cued plans <= 2 x cued normal plans + uncued plans". */
static uint32_t cued_plan(const chanhop_t *h, int t, uint64_t now_ms) {
    uint64_t d = dwell_for(h, h->slots[t].activity);
    uint64_t uncued = 0, other_n = 0;
    for (int j = 0; j < h->count; j++) {
        if (j == t) continue;
        uint64_t dj = dwell_for(h, h->slots[j].activity);
        if (h->slots[j].cue_until_ms > now_ms) other_n += dj;
        else                                   uncued += dj;
    }
    uint64_t other_cued = CHANHOP_CUE_MULT * other_n;
    uint64_t total = 2 * (other_n + d) + uncued;                 /* floor */
    uint32_t pm = h->cue_cap_pm;
    if (pm < 1000) {                                              /* cap */
        uint64_t cap = uncued * pm / (1000u - pm);
        if (cap < total) total = cap;
    }
    uint64_t want = CHANHOP_CUE_MULT * d;
    uint64_t budget = total > other_cued ? total - other_cued : 0;
    uint64_t p = want < budget ? want : budget;
    if (p < d) p = d;
    return (uint32_t)p;
}

/* Reset to defaults with no slots. Split out so the bare-number and
 * band-qualified initialisers cannot drift in what they zero. */
static void chanhop_reset(chanhop_t *h) {
    /* Zero the whole scheduler, not field by field. This used to name
     * the handful of members that existed at the time, and every field
     * added since (#91's per-slot visit/frame counters, then the dwell
     * measurements) silently started life as stack garbage. Callers
     * declare chanhop_t on the stack, so that is the default. */
    memset(h, 0, sizeof(*h));
    h->base_dwell_ms = 250;
    h->min_dwell_ms  = 100;
    h->max_dwell_ms  = 2000;
    h->ms_per_obs    = 8;
    h->pending       = -1;
    h->cue_cap_pm    = 500;
}

/* The one slot-filling path (#167). Both initialisers come through here
 * so a slot's band and its frequency are always set together. */
static int chanhop_add(chanhop_t *h, wifi_band_t band, int channel) {
    int f = chanhop_band_freq(band, channel);
    if (!f) return 0;                   /* skip channels we can't tune */
    if (h->count >= CHANHOP_MAX) return 0;
    h->slots[h->count].channel  = channel;
    h->slots[h->count].band     = band;
    h->slots[h->count].freq_mhz = f;
    h->count++;
    return 1;
}

int chanhop_init(chanhop_t *h, const int *channels, int n) {
    if (!h) return 0;
    chanhop_reset(h);
    if (!channels) return 0;
    for (int i = 0; i < n && h->count < CHANHOP_MAX; i++)
        chanhop_add(h, wifi_freq_infer_band(channels[i]), channels[i]);
    return h->count;
}

int chanhop_init_bands(chanhop_t *h, const chanhop_chan_t *chans, int n) {
    if (!h) return 0;
    chanhop_reset(h);
    if (!chans) return 0;
    for (int i = 0; i < n && h->count < CHANHOP_MAX; i++)
        chanhop_add(h, chans[i].band, chans[i].channel);
    return h->count;
}

int chanhop_init_default(chanhop_t *h) {
    return chanhop_init(h, DEFAULT_CHANNELS,
                        (int)(sizeof(DEFAULT_CHANNELS) / sizeof(DEFAULT_CHANNELS[0])));
}

void chanhop_observe(chanhop_t *h, uint32_t observations) {
    /* Before the first acknowledged retune the radio is on whatever
     * channel it was left on, which need not be in the rotation at all;
     * crediting slot 0 with those frames would make a radio that never
     * tuned look like it hears channel 1. */
    if (!h || h->count == 0 || !h->tuned) return;
    h->slots[h->cur].activity += observations;
    h->slots[h->cur].frames   += observations;
}

int chanhop_tick(chanhop_t *h, uint64_t now_ms) {
    if (!h || h->count == 0) return 0;

    if (!h->started) {
        h->started = 1;
        h->next    = 0;
        h->pending = 0;
        return 1;   /* first retune: park on the first channel */
    }

    /* An unanswered proposal is asked for again rather than replaced:
     * advancing past it would skip a channel the radio was never told
     * about, and the caller has done nothing wrong yet. */
    if (h->pending >= 0) return 1;

    if (now_ms < h->dwell_until_ms) return 0;   /* still dwelling */

    h->pending = h->next;                       /* rotation → guaranteed revisit */
    return 1;
}

void chanhop_confirm_retune(chanhop_t *h, int ok, uint64_t now_ms) {
    if (!h || h->count == 0 || h->pending < 0) return;
    int t = h->pending;
    h->pending = -1;

    if (!ok) {
        /* The radio did not move. Everything that describes where it
         * is - cur, the open dwell, frame attribution - stays put. */
        h->slots[t].refusals++;
        h->next           = (t + 1) % h->count;
        h->dwell_until_ms = now_ms + h->min_dwell_ms;
        return;
    }

    if (h->tuned) {
        /* Decay the channel we're leaving so `activity` is a rolling
         * window, not an all-time tally - a channel that was busy an
         * hour ago should not hold a long dwell forever. */
        h->slots[h->cur].activity >>= 1;

        /* Close out the dwell that just ended before starting the next.
         * Measured runs start-of-dwell to start-of-next, so the
         * poll-loop servicing delay - and any refused retunes in
         * between - land inside the figure instead of vanishing. */
        uint32_t measured = (uint32_t)(now_ms - h->dwell_began_ms);
        h->last_planned_ms   = h->dwell_planned_ms;
        h->last_measured_ms  = measured;
        h->planned_total_ms += h->dwell_planned_ms;
        h->measured_total_ms += measured;
        h->dwells_completed++;
        h->slots[h->cur].dwell_ms += measured;
        if (h->dwell_cued) {
            h->cued_dwells++;
            h->cued_total_ms += measured;
        }
        if (measured > h->dwell_planned_ms) {
            uint32_t over = measured - h->dwell_planned_ms;
            if (over > h->worst_overshoot_ms) h->worst_overshoot_ms = over;
        }
    }

    h->cur   = t;
    h->tuned = 1;
    h->next  = (t + 1) % h->count;
    h->slots[t].visits++;
    h->dwell_cued       = h->slots[t].cue_until_ms > now_ms;
    h->dwell_planned_ms = h->dwell_cued ? cued_plan(h, t, now_ms)
                                        : dwell_for(h, h->slots[t].activity);
    h->dwell_began_ms   = now_ms;
    h->dwell_until_ms   = now_ms + h->dwell_planned_ms;
}

uint32_t chanhop_slot_plan_ms(const chanhop_t *h, int i) {
    if (!h || i < 0 || i >= h->count) return 0;
    return dwell_for(h, h->slots[i].activity);
}

int chanhop_find_freq(const chanhop_t *h, int mhz) {
    if (!h || mhz <= 0) return -1;
    for (int i = 0; i < h->count; i++)
        if (h->slots[i].freq_mhz == mhz) return i;
    return -1;
}

int chanhop_slot_cued(const chanhop_t *h, int i, uint64_t now_ms) {
    if (!h || i < 0 || i >= h->count) return 0;
    return h->slots[i].cue_until_ms > now_ms;
}

int chanhop_cue_fits(const chanhop_t *h, int i, uint64_t now_ms) {
    if (!h || i < 0 || i >= h->count) return 0;
    uint64_t cued = 0, uncued = 0;
    for (int j = 0; j < h->count; j++) {
        uint64_t dj = dwell_for(h, h->slots[j].activity);
        if (j == i || h->slots[j].cue_until_ms > now_ms)
            cued += CHANHOP_CUE_MULT * dj;
        else
            uncued += dj;
    }
    return cued <= uncued;
}

void chanhop_cue_load(const chanhop_t *h, int extra, int with_cued, uint64_t now_ms,
                      uint64_t *cued, uint64_t *uncued) {
    uint64_t c = 0, u = 0;
    for (int j = 0; h && j < h->count; j++) {
        uint64_t dj = dwell_for(h, h->slots[j].activity);
        if (j == extra || (with_cued && h->slots[j].cue_until_ms > now_ms)) c += dj;
        else                                                               u += dj;
    }
    if (cued) *cued = c;
    if (uncued) *uncued = u;
}

double chanhop_cue_share(uint64_t cued, uint64_t uncued) {
    if (!cued) return 0.0;
    double c = (double)CHANHOP_CUE_MULT * (double)cued;
    return c / (c + (double)uncued);
}

int chanhop_cue_floor_ok(uint64_t cued, uint64_t uncued) {
    /* cued plans + uncued <= 2 x (cued + uncued), cued plans = MULT x cued */
    return (CHANHOP_CUE_MULT - 2) * cued <= uncued;
}

int chanhop_cue_fits_alone(const chanhop_t *h, int i) {
    if (!h || i < 0 || i >= h->count) return 0;
    uint64_t cued = 0, uncued = 0;
    for (int j = 0; j < h->count; j++) {
        uint64_t dj = dwell_for(h, h->slots[j].activity);
        if (j == i) cued = CHANHOP_CUE_MULT * dj;
        else        uncued += dj;
    }
    return cued <= uncued;
}

void chanhop_set_cue(chanhop_t *h, int i, uint64_t until_ms, uint64_t now_ms) {
    if (!h || i < 0 || i >= h->count) return;
    h->slots[i].cue_until_ms = until_ms > now_ms ? until_ms : 0;
    /* The radio is on the channel now: the dwell under way becomes the
     * cued one, from when it began, instead of waiting a rotation. */
    if (!h->slots[i].cue_until_ms || !h->tuned || i != h->cur || h->dwell_cued)
        return;
    uint32_t p = cued_plan(h, i, now_ms);
    if (p <= h->dwell_planned_ms) return;
    h->dwell_cued       = 1;
    h->dwell_planned_ms = p;
    h->dwell_until_ms   = h->dwell_began_ms + p;
}

void chanhop_dwell(const chanhop_t *h, chanhop_dwell_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!h) return;
    out->last_planned_ms    = h->last_planned_ms;
    out->last_measured_ms   = h->last_measured_ms;
    out->worst_overshoot_ms = h->worst_overshoot_ms;
    out->completed          = h->dwells_completed;
    if (h->dwells_completed) {
        out->mean_planned_ms =
            (uint32_t)(h->planned_total_ms / h->dwells_completed);
        out->mean_measured_ms =
            (uint32_t)(h->measured_total_ms / h->dwells_completed);
    }
}

uint64_t chanhop_slot_time_ms(const chanhop_t *h, int i, uint64_t now_ms) {
    if (!h || i < 0 || i >= h->count || !h->tuned) return 0;
    uint64_t t = h->slots[i].dwell_ms;
    if (i == h->cur && now_ms > h->dwell_began_ms) t += now_ms - h->dwell_began_ms;
    return t;
}

void chanhop_activity(const chanhop_t *h, chanhop_activity_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!h || h->count == 0) return;
    out->channels = h->count;
    for (int i = 0; i < h->count; i++) {
        out->visits += h->slots[i].visits;
        out->frames += h->slots[i].frames;
        /* Only a channel that was actually visited can be silent; an
         * unvisited one is simply not measured yet, and counting it
         * would make every fresh run look deaf. */
        if (h->slots[i].visits > 0 && h->slots[i].frames == 0)
            out->silent_channels++;
    }
    out->cur_visits = h->slots[h->cur].visits;
    out->cur_frames = h->slots[h->cur].frames;
}

int chanhop_current_channel(const chanhop_t *h) {
    if (!h || h->count == 0) return 0;
    return h->slots[h->cur].channel;
}

int chanhop_current_freq(const chanhop_t *h) {
    if (!h || h->count == 0) return 0;
    return h->slots[h->cur].freq_mhz;
}

wifi_band_t chanhop_current_band(const chanhop_t *h) {
    if (!h || h->count == 0) return WIFI_BAND_UNKNOWN;
    return h->slots[h->cur].band;
}

int chanhop_target_channel(const chanhop_t *h) {
    if (!h || h->count == 0 || h->pending < 0) return 0;
    return h->slots[h->pending].channel;
}

int chanhop_target_freq(const chanhop_t *h) {
    if (!h || h->count == 0 || h->pending < 0) return 0;
    return h->slots[h->pending].freq_mhz;
}

wifi_band_t chanhop_target_band(const chanhop_t *h) {
    if (!h || h->count == 0 || h->pending < 0) return WIFI_BAND_UNKNOWN;
    return h->slots[h->pending].band;
}

int chanhop_export(const chanhop_t *h, int *out, int max, int *cur_idx) {
    if (cur_idx) *cur_idx = -1;
    if (!h || !out || max <= 0) return 0;
    int n = h->count < max ? h->count : max;
    for (int i = 0; i < n; i++) out[i] = h->slots[i].channel;
    /* Marked only once a retune has been acknowledged: before that
     * slot 0 is cur by construction, not because the radio is there. */
    if (cur_idx && h->tuned && h->cur < n) *cur_idx = h->cur;
    return n;
}

void chanhop_record_retune(int requested_channel, int retune_ok,
                            int *requested_out, int *confirmed_out,
                            int *failures_out) {
    if (requested_out) *requested_out = requested_channel;
    if (retune_ok) {
        if (confirmed_out) *confirmed_out = requested_channel;
    } else if (failures_out) {
        (*failures_out)++;
    }
}

void chanhop_record_retune_err(int requested_channel, int err,
                               int *requested_out, int *confirmed_out,
                               int *failures_out, int *last_errno_out) {
    chanhop_record_retune(requested_channel, err == 0,
                          requested_out, confirmed_out, failures_out);
    if (err != 0 && last_errno_out) *last_errno_out = err;
}

const char *chanhop_retune_reason(int err) {
    /* The reasons NL80211_CMD_SET_CHANNEL and its setup path really
     * return, plus the two the platform layer synthesises (ETIMEDOUT
     * for a missing ack, EOPNOTSUPP for no nl80211 / no radio). */
    switch (err) {
    case 0:          return "none";
    case EPERM:      return "EPERM";
    case EACCES:     return "EACCES";
    case EBUSY:      return "EBUSY";
    case EINVAL:     return "EINVAL";
    case ENODEV:     return "ENODEV";
    case ENOENT:     return "ENOENT";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case ETIMEDOUT:  return "ETIMEDOUT";
    case EIO:        return "EIO";
    default:         return "other";
    }
}

int chanhop_retune_reason_bit(int err) {
    switch (err) {
    case 0:          return 0;
    case EPERM:      return 1;
    case EACCES:     return 2;
    case EBUSY:      return 3;
    case EINVAL:     return 4;
    case ENODEV:     return 5;
    case ENOENT:     return 6;
    case EOPNOTSUPP: return 7;
    case ETIMEDOUT:  return 8;
    case EIO:        return 9;
    default:         return 10;
    }
}

int chanhop_split(chanhop_t *h, const chanhop_t *full, int radios, int k) {
    if (!h) return 0;
    chanhop_reset(h);
    if (!full || radios < 1 || k < 0 || k >= radios) return 0;
    for (int i = k; i < full->count && i < CHANHOP_MAX; i += radios)
        chanhop_add(h, full->slots[i].band, full->slots[i].channel);
    return h->count;
}

int chanhop_step(chanhop_t *h, const char *iface, uint64_t now_ms,
                 uint32_t mon_frames, int *requested, int *err) {
    if (!h) return 0;
    chanhop_observe(h, mon_frames);
    if (!chanhop_tick(h, now_ms)) return 0;
    /* #91: the vtable returns 0 or a negative errno. A missing
     * set_channel is a platform that cannot retune, which is what
     * EOPNOTSUPP says; a stray positive return is a contract
     * violation and is reported as EIO rather than as success. */
    int req = chanhop_target_channel(h);
    int rc = g_platform.set_channel
           ? g_platform.set_channel(iface, chanhop_target_freq(h))
           : -EOPNOTSUPP;
    int e = rc == 0 ? 0 : (rc < 0 ? -rc : EIO);
    chanhop_confirm_retune(h, e == 0, now_ms);
    if (requested) *requested = req;
    if (err) *err = e;
    return 1;
}

void chanhop_service(chanhop_t *h, sloth_state_t *s, uint64_t now_ms,
                     uint32_t mon_frames) {
    if (!h || !s) return;
    int requested = 0, err = 0;
    if (chanhop_step(h, s->probe_iface, now_ms, mon_frames, &requested, &err)) {
        /* Radio 0's dwell history (#246, src/cov_timeline.h): where it
         * sat, from when, on the clock frame capture times are on. */
        if (!err) cov_tl_hop_note(0, chanhop_current_freq(h), sloth_wall_ms());
        chanhop_record_retune_err(requested, err, &s->chan_requested,
                                  &s->chan_confirmed, &s->chan_retune_failures,
                                  &s->chan_retune_last_errno);
        if (err)
            s->chan_retune_reason_mask |= 1u << chanhop_retune_reason_bit(err);
    }
    /* Which slots have ever refused. Recomputed rather than OR-ed in on
     * each refusal so the mask cannot drift from the per-slot tally. */
    uint32_t refused = 0;
    for (int i = 0; i < h->count && i < 32; i++)
        if (h->slots[i].refusals) refused |= 1u << i;
    s->chan_refused_mask = refused;
    /* Surface the scan state for the interface view's channel bar. */
    s->scan_chan_count = chanhop_export(h, s->scan_chans,
                                        (int)(sizeof(s->scan_chans) / sizeof(s->scan_chans[0])),
                                        &s->scan_cur_idx);
    /* The hop-activity summary, so "visiting but deaf" is separable
     * from "not hopping" in the log and the view. Copied field by field
     * rather than memcpy'd: sloth.h deliberately does not include
     * wifi_chanhop.h, so the two structs are distinct types that happen
     * to agree. */
    chanhop_activity_t ha;
    chanhop_activity(h, &ha);
    s->hop_activity.channels        = ha.channels;
    s->hop_activity.visits          = ha.visits;
    s->hop_activity.frames          = ha.frames;
    s->hop_activity.silent_channels = ha.silent_channels;
    s->hop_activity.cur_visits      = ha.cur_visits;
    s->hop_activity.cur_frames      = ha.cur_frames;
    chanhop_dwell_t hd;
    chanhop_dwell(h, &hd);
    s->hop_dwell.last_planned_ms    = hd.last_planned_ms;
    s->hop_dwell.last_measured_ms   = hd.last_measured_ms;
    s->hop_dwell.worst_overshoot_ms = hd.worst_overshoot_ms;
    s->hop_dwell.completed          = hd.completed;
    s->hop_dwell.mean_planned_ms    = hd.mean_planned_ms;
    s->hop_dwell.mean_measured_ms   = hd.mean_measured_ms;
}
