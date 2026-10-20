#include "wifi_chanhop.h"
#include <errno.h>
#include <string.h>

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
        if (measured > h->dwell_planned_ms) {
            uint32_t over = measured - h->dwell_planned_ms;
            if (over > h->worst_overshoot_ms) h->worst_overshoot_ms = over;
        }
    }

    h->cur   = t;
    h->tuned = 1;
    h->next  = (t + 1) % h->count;
    h->slots[t].visits++;
    h->dwell_planned_ms = dwell_for(h, h->slots[t].activity);
    h->dwell_began_ms   = now_ms;
    h->dwell_until_ms   = now_ms + h->dwell_planned_ms;
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

int chanhop_target_channel(const chanhop_t *h) {
    if (!h || h->count == 0 || h->pending < 0) return 0;
    return h->slots[h->pending].channel;
}

int chanhop_target_freq(const chanhop_t *h) {
    if (!h || h->count == 0 || h->pending < 0) return 0;
    return h->slots[h->pending].freq_mhz;
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

void chanhop_service(chanhop_t *h, sloth_state_t *s, uint64_t now_ms,
                     uint32_t mon_frames) {
    if (!h || !s) return;
    chanhop_observe(h, mon_frames);
    if (chanhop_tick(h, now_ms)) {
        /* #91: the vtable returns 0 or a negative errno. A missing
         * set_channel is a platform that cannot retune, which is what
         * EOPNOTSUPP says; a stray positive return is a contract
         * violation and is reported as EIO rather than as success. */
        int requested = chanhop_target_channel(h);
        int rc = g_platform.set_channel
               ? g_platform.set_channel(s->probe_iface, chanhop_target_freq(h))
               : -EOPNOTSUPP;
        int err = rc == 0 ? 0 : (rc < 0 ? -rc : EIO);
        chanhop_confirm_retune(h, err == 0, now_ms);
        chanhop_record_retune_err(requested, err, &s->chan_requested,
                                  &s->chan_confirmed, &s->chan_retune_failures,
                                  &s->chan_retune_last_errno);
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
