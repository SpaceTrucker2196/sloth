/* Passive cueing policy (#248). See chancue.h. */
#include "chancue.h"

#include <stdio.h>
#include <string.h>

#include "wifi_freq.h"

const char *chancue_reason_name(cue_result_t r) {
    switch (r) {
    case CUE_REFUSE_NO_CHANNEL: return "no_channel";
    case CUE_REFUSE_NOT_HOPPED: return "not_hopped";
    case CUE_REFUSE_ACTIVE:     return "active_cap";
    case CUE_REFUSE_RATE:       return "rate_cap";
    case CUE_REFUSE_SHARE:      return "share_cap";
    case CUE_REFUSE_SHARE_SMALL: return "share_small";
    case CUE_STARTED: case CUE_NOT_CUEING: case CUE_ABSORBED: break;
    }
    return "";
}

int chancue_is_limit(cue_result_t r) {
    return r == CUE_REFUSE_ACTIVE || r == CUE_REFUSE_RATE || r == CUE_REFUSE_SHARE;
}

int chancue_kind_cues(alert_type_t t) {
    switch (t) {
    case ALERT_TYPE_EVIL_TWIN:
    case ALERT_TYPE_KARMA_AP:
    case ALERT_TYPE_KARMA_PROBE_FORGE:
    case ALERT_TYPE_DEAUTH_FLOOD:
    case ALERT_TYPE_PMKID_HARVEST:
    case ALERT_TYPE_HANDSHAKE_HARVEST:
        return 1;
    default:
        return 0;
    }
}

void chancue_init(chancue_t *c) {
    if (c) memset(c, 0, sizeof(*c));
}

static void push(chancue_t *c, const cue_event_t *e) {
    if (c->nev >= CUE_EVENTS_MAX) { c->ev_dropped++; return; }
    c->ev[c->nev++] = *e;
}

static void ev_fill(cue_event_t *e, cue_ev_state_t st, alert_type_t ty,
                    int freq_mhz, int radio, const char *incident_id) {
    memset(e, 0, sizeof(*e));
    e->state    = st;
    e->ty       = ty;
    e->freq_mhz = freq_mhz;
    e->channel  = freq_mhz > 0 ? wifi_freq_channel(freq_mhz, NULL) : 0;
    e->radio    = radio;
    snprintf(e->incident_id, sizeof(e->incident_id), "%s",
             incident_id ? incident_id : "");
}

static cue_result_t refuse(chancue_t *c, cue_result_t r, alert_type_t ty,
                           int freq_mhz, const char *incident_id,
                           uint64_t now_ms) {
    c->refused++;
    if (chancue_is_limit(r)) c->refused_limit++;
    /* The count is every refusal; the record is the first of a burst,
     * so a flood of false triggers is one line a minute per channel and
     * reason, not one per trigger. */
    for (int i = 0; i < (int)(sizeof(c->quiet) / sizeof(c->quiet[0])); i++) {
        if (c->quiet[i].used && c->quiet[i].ty == ty &&
            c->quiet[i].freq_mhz == freq_mhz && c->quiet[i].reason == r &&
            now_ms - c->quiet[i].at_ms < CUE_REFUSED_QUIET_MS)
            return r;
    }
    int q = c->quiet_head;
    c->quiet_head = (q + 1) % (int)(sizeof(c->quiet) / sizeof(c->quiet[0]));
    c->quiet[q].used = 1;
    c->quiet[q].ty = ty;
    c->quiet[q].freq_mhz = freq_mhz;
    c->quiet[q].reason = r;
    c->quiet[q].at_ms = now_ms;
    cue_event_t e;
    ev_fill(&e, CUE_EV_REFUSED, ty, freq_mhz, -1, incident_id);
    e.reason = r;
    push(c, &e);
    return r;
}

/* The sensor radios the cap is taken over: the schedulers that hold a
 * share. A radio with none (lost, or fixed on a channel) is no part of
 * the cueable time. */
static int radios_n(chanhop_t *const *sched, int nsched) {
    int n = 0;
    for (int k = 0; sched && k < nsched && k < CUE_SCHED_MAX; k++)
        n += sched[k] && sched[k]->count > 0;
    return n;
}

/* The all-radios cap (owner ruling of 2026-11-24): the cued share of
 * each radio at full plans, summed, at most half the radios. Radio
 * `radio` also counts slot `slot` cued (-1: none); with_cued 0 counts
 * that slot alone, as if nothing else were cued. A little slack for
 * the division, so an exact half on one radio (4 x 2 against 8) is
 * admitted as the single-radio integer rule admits it. */
static int cap_ok(chanhop_t *const *sched, int nsched, int radio, int slot,
                  int with_cued, uint64_t now_ms) {
    double sum = 0.0;
    for (int k = 0; sched && k < nsched && k < CUE_SCHED_MAX; k++) {
        if (!sched[k] || sched[k]->count <= 0) continue;
        uint64_t c, u;
        chanhop_cue_load(sched[k], k == radio ? slot : -1, with_cued, now_ms, &c, &u);
        sum += chanhop_cue_share(c, u);
    }
    return sum <= (double)radios_n(sched, nsched) / 2.0 + 1e-9;
}

/* Hand each scheduler its part of the cap for the clamp in
 * wifi_chanhop.c cued_plan(): its own cued share at full plans plus an
 * equal part of what the radios together leave below half of their
 * time, in thousandths, rounded down. The parts sum to at most half
 * the radios, so the clamp keeps the cap however activity moves after
 * a cue is admitted; on one radio the part is always 500. */
static void share_out(chanhop_t *const *sched, int nsched, uint64_t now_ms) {
    int n = radios_n(sched, nsched);
    if (n <= 0) return;
    double f[CUE_SCHED_MAX] = { 0 }, sum = 0.0;
    for (int k = 0; k < nsched && k < CUE_SCHED_MAX; k++) {
        if (!sched[k] || sched[k]->count <= 0) continue;
        uint64_t c, u;
        chanhop_cue_load(sched[k], -1, 1, now_ms, &c, &u);
        f[k] = chanhop_cue_share(c, u);
        sum += f[k];
    }
    double slack = ((double)n / 2.0 - sum) / (double)n;
    for (int k = 0; k < nsched && k < CUE_SCHED_MAX; k++) {
        if (!sched[k]) continue;
        double a = n == 1 ? 0.5 : f[k] + slack;
        if (a < 0.0) a = 0.0;
        if (a > 0.999) a = 0.999;
        sched[k]->cue_cap_pm = (uint32_t)(a * 1000.0 + 1e-9);
    }
}

int chancue_active(const chancue_t *c) {
    int n = 0;
    for (int i = 0; c && i < CUE_MAX_ACTIVE; i++) n += c->cue[i].used;
    return n;
}

cue_result_t chancue_request(chancue_t *c, chanhop_t *const *sched, int nsched,
                             alert_type_t ty, int freq_mhz,
                             const char *incident_id, uint64_t now_ms) {
    if (!c || !chancue_kind_cues(ty)) return CUE_NOT_CUEING;
    if (freq_mhz <= 0)
        return refuse(c, CUE_REFUSE_NO_CHANNEL, ty, 0, incident_id, now_ms);

    int radio = -1, slot = -1;
    for (int k = 0; sched && k < nsched && k < CUE_SCHED_MAX && radio < 0; k++) {
        int i = sched[k] ? chanhop_find_freq(sched[k], freq_mhz) : -1;
        if (i >= 0) { radio = k; slot = i; }
    }
    if (radio < 0)
        return refuse(c, CUE_REFUSE_NOT_HOPPED, ty, freq_mhz, incident_id, now_ms);

    for (int i = 0; i < CUE_MAX_ACTIVE; i++)
        if (c->cue[i].used && c->cue[i].freq_mhz == freq_mhz) return CUE_ABSORBED;

    /* A share that could hold this cue with nothing else cued anywhere
     * fails neither rule for any load, so a refusal here is the radio
     * layout, not airtime taken: no limit and no SENSOR_SUPPRESSED input
     * (#248 review). Under the all-radios cap of 2026-11-24 it is a
     * radio holding two channels or fewer, or a single radio of fewer
     * than five at equal dwell. Checked before the caps so it is never
     * counted as one of them. */
    {
        uint64_t cu, un;
        chanhop_cue_load(sched[radio], slot, 0, now_ms, &cu, &un);
        if (!chanhop_cue_floor_ok(cu, un) ||
            !cap_ok(sched, nsched, radio, slot, 0, now_ms))
            return refuse(c, CUE_REFUSE_SHARE_SMALL, ty, freq_mhz, incident_id, now_ms);
    }

    if (chancue_active(c) >= CUE_MAX_ACTIVE)
        return refuse(c, CUE_REFUSE_ACTIVE, ty, freq_mhz, incident_id, now_ms);

    int recent = 0;
    for (int i = 0; i < CUE_RATE_MAX; i++)
        if (c->starts[i] && now_ms - c->starts[i] < CUE_RATE_WINDOW_MS) recent++;
    if (recent >= CUE_RATE_MAX)
        return refuse(c, CUE_REFUSE_RATE, ty, freq_mhz, incident_id, now_ms);

    {
        uint64_t cu, un;
        chanhop_cue_load(sched[radio], slot, 1, now_ms, &cu, &un);
        if (!chanhop_cue_floor_ok(cu, un) ||
            !cap_ok(sched, nsched, radio, slot, 1, now_ms))
            return refuse(c, CUE_REFUSE_SHARE, ty, freq_mhz, incident_id, now_ms);
    }

    cue_t *q = NULL;
    for (int i = 0; i < CUE_MAX_ACTIVE && !q; i++)
        if (!c->cue[i].used) q = &c->cue[i];
    if (!q)   /* unreachable: chancue_active() said there was room */
        return CUE_NOT_CUEING;
    memset(q, 0, sizeof(*q));
    q->used     = 1;
    q->ty       = ty;
    q->freq_mhz = freq_mhz;
    q->channel  = wifi_freq_channel(freq_mhz, NULL);
    q->radio    = radio;
    q->start_ms = now_ms;
    q->until_ms = now_ms + CUE_DURATION_MS;
    snprintf(q->incident_id, sizeof(q->incident_id), "%s",
             incident_id ? incident_id : "");
    /* A start time of 0 reads as an empty ring entry; a clock that
     * starts at 0 (a test's) still counts its first start. */
    c->starts[c->start_head] = now_ms ? now_ms : 1;
    c->start_head = (c->start_head + 1) % CUE_RATE_MAX;
    c->started++;
    /* Mark the slot, hand out the cap's parts with it counted, then set
     * it again so a dwell under way on it is planned with its part. */
    sched[radio]->slots[slot].cue_until_ms = q->until_ms;
    share_out(sched, nsched, now_ms);
    sched[radio]->slots[slot].cue_until_ms = 0;
    chanhop_set_cue(sched[radio], slot, q->until_ms, now_ms);

    cue_event_t e;
    ev_fill(&e, CUE_EV_STARTED, ty, freq_mhz, radio, q->incident_id);
    e.duration_s = CUE_DURATION_MS / 1000u;
    push(c, &e);
    return CUE_STARTED;
}

void chancue_tick(chancue_t *c, chanhop_t *const *sched, int nsched, uint64_t now_ms) {
    if (!c) return;
    for (int i = 0; i < CUE_MAX_ACTIVE; i++) {
        cue_t *q = &c->cue[i];
        if (!q->used || now_ms < q->until_ms) continue;
        cue_event_t e;
        ev_fill(&e, CUE_EV_ENDED, q->ty, q->freq_mhz, q->radio, q->incident_id);
        e.duration_s = (uint32_t)((now_ms - q->start_ms) / 1000u);
        push(c, &e);
        c->ended++;
        q->used = 0;
    }
    for (int k = 0; sched && k < nsched && k < CUE_SCHED_MAX; k++) {
        chanhop_t *h = sched[k];
        if (!h) continue;
        for (int s = 0; s < h->count; s++) {
            uint64_t until = 0;
            for (int i = 0; i < CUE_MAX_ACTIVE; i++)
                if (c->cue[i].used && c->cue[i].freq_mhz == h->slots[s].freq_mhz) {
                    until = c->cue[i].until_ms;
                    c->cue[i].radio = k;
                }
            if (until != h->slots[s].cue_until_ms)
                chanhop_set_cue(h, s, until, now_ms);
        }
    }
    share_out(sched, nsched, now_ms);
}

int chancue_drain(chancue_t *c, cue_event_t *out, int max) {
    if (!c || !out || max <= 0) return 0;
    int n = c->nev < max ? c->nev : max;
    memcpy(out, c->ev, (size_t)n * sizeof(*out));
    memmove(c->ev, c->ev + n, (size_t)(c->nev - n) * sizeof(*out));
    c->nev -= n;
    return n;
}
