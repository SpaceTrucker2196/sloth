#include <stdio.h>
#include <string.h>
#include "alert_quality.h"
#include "cov_timeline.h"
#include "rule_coverage_live.h"

/* The judgement and the stamp of alert_quality.h. Reads the coverage
 * status rule_coverage_live.c derived this tick; the frames themselves
 * are the capture side's (aq_evidence_fn). */

aq_complete_t aq_judge(const aq_in_t *in, cov_reason_t *why) {
    cov_reason_t r = COV_R_NONE;
    aq_complete_t c = AQ_COMPLETE_FULL;
    if (!in) {
        c = AQ_COMPLETE_NONE;
    } else if (in->st == COV_BLIND) {
        /* A rule that fired while its source reads down fired on what
         * it held from before. Blind for any other reason (no source,
         * no band, a configuration it needs) contradicts the fire: the
         * environment is not one that can be judged, so no claim. */
        if (in->why == COV_R_SOURCE_DOWN) { c = AQ_COMPLETE_PARTIAL; r = COV_R_SOURCE_DOWN; }
        else                               c = AQ_COMPLETE_NONE;
    } else if (in->st == COV_PARTLY &&
               (in->why == COV_R_SOURCE_STALE || in->why == COV_R_SUPPRESSED)) {
        c = AQ_COMPLETE_PARTIAL; r = in->why;
    } else if (in->lost) {
        /* A cited frame has left the evidence ring: the window the
         * frames still held span is not the incident's, so neither a
         * drop nor a hop gap inside it can be ruled out. A flood that
         * turns the ring over must not buy a `full`. Only the rule's
         * own hop status, which needs no window, still decides. */
        if (in->st == COV_PARTLY && in->why == COV_R_HOP) { c = AQ_COMPLETE_PARTIAL; r = COV_R_HOP; }
        else                                               c = AQ_COMPLETE_NONE;
    } else if (in->window && in->drops == 1) {
        c = AQ_COMPLETE_PARTIAL; r = COV_R_DROPS;
    } else if (in->window) {
        /* The window decides, whatever the rule's shape: a hopping
         * radio either stayed on every channel the cited frames are on
         * for the whole span, or it did not. A window the dwell history
         * does not reach cannot be shown covered. */
        if (in->hopping && (in->uncovered_ms < 0 || in->uncovered_ms > COV_TL_SLACK_MS)) {
            c = AQ_COMPLETE_PARTIAL; r = COV_R_HOP;
        }
    } else if (in->st == COV_PARTLY && in->why == COV_R_HOP) {
        /* No frames to place in time: the rule's own status is the
         * finest grain there is. */
        c = AQ_COMPLETE_PARTIAL; r = COV_R_HOP;
    }
    if (why) *why = r;
    return c;
}

static uint8_t src_of(cov_avail_t av) {
    switch (av) {
    case COV_AV_UP:    return AQ_SRC_OK;
    case COV_AV_STALE: return AQ_SRC_STALE;
    case COV_AV_DOWN:  return AQ_SRC_DOWN;
    case COV_AV_NONE:
    default:           return AQ_SRC_NONE;
    }
}

void alert_quality_stamp(alert_t *a, int opening, int64_t fire_ms,
                         aq_evidence_fn fn) {
    if (!a) return;
    alert_quality_t *q = &a->quality;
    cov_status_t st  = COV_OBSERVABLE;
    cov_reason_t why = COV_R_NONE;
    cov_live_state_t live = cov_live_state();
    int assessed = live == COV_LIVE_VALID &&
                   cov_live_get(a->type, &st, &why);
    /* A partial finding stays partial: the window it was judged on is
     * not the one the rule cites now, but it was this incident's. */
    int judge = assessed && q->complete != AQ_COMPLETE_PARTIAL;

    aq_evidence_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.uncovered_ms = -1;
    ev.drops = -1;
    int cited = 0;
    if (fn && a->evidence_id_count > 0) {
        cited = a->evidence_id_count < ALERT_EVIDENCE_IDS
              ? a->evidence_id_count : ALERT_EVIDENCE_IDS;
        fn(a->evidence_ids, cited, judge, &ev);
    }
    /* A replayed frame's radio is the replay's, not one of this
     * sensor's monitor radios: no count was taken, so none is kept. */
    if (live == COV_LIVE_DECLINED) q->radio_mask = 0;
    else                           q->radio_mask |= ev.radio_mask;
    if (!assessed) return;
    /* Some cited frame is gone from the ring: the span the rest cover
     * is not the incident's. */
    int lost = cited > 0 && ev.n < cited;

    const cov_env_t    *env = cov_live_env();
    const cov_inputs_t *in  = cov_inputs(a->type);
    q->src_state = env && in ? src_of(env->input[in->input]) : AQ_SRC_NONE;

    if (opening && !lost && ev.n > 0 && fire_ms >= ev.first_ms) {
        int64_t l = fire_ms - ev.first_ms;
        q->latency_ms  = l > (int64_t)UINT32_MAX ? UINT32_MAX : (uint32_t)l;
        q->has_latency = 1;
    }

    if (judge) {
        aq_in_t ai;
        memset(&ai, 0, sizeof(ai));
        ai.st           = st;
        ai.why          = why;
        ai.hopping      = env ? env->hopping : 0;
        ai.window       = ev.n > 0;
        ai.lost         = lost;
        ai.uncovered_ms = ev.uncovered_ms;
        ai.drops        = ev.drops;
        cov_reason_t r = COV_R_NONE;
        aq_complete_t c = aq_judge(&ai, &r);
        /* An evaluation that cannot judge (the rule now reads blind, or
         * the cited frames are gone) leaves an earlier `full` standing:
         * it was judged on this incident's evidence, and sloth.db's
         * upsert keeps it the same way (COALESCE), so the stream and
         * the row agree. */
        if (c != AQ_COMPLETE_NONE) {
            q->complete     = (uint8_t)c;
            q->complete_why = (uint8_t)r;
        }
    }
}

const char *aq_complete_name(int c) {
    switch (c) {
    case AQ_COMPLETE_FULL:    return "full";
    case AQ_COMPLETE_PARTIAL: return "partial";
    default:                  return "";
    }
}

const char *aq_src_name(int s) {
    switch (s) {
    case AQ_SRC_OK:    return "ok";
    case AQ_SRC_STALE: return "stale";
    case AQ_SRC_DOWN:  return "down";
    default:           return "";
    }
}

int aq_corroboration(const alert_quality_t *q) {
    int n = 0;
    if (q)
        for (unsigned m = q->radio_mask; m; m &= m - 1u) n++;
    return n;
}

int alert_quality_line(const alert_quality_t *q, char *out, size_t sz) {
    if (!out || sz == 0) return 0;
    out[0] = '\0';
    if (!q) return 0;
    size_t off = 0;
    const char *sep = "";
#define AQ_PUT(...) do { \
        if (off < sz) { \
            int w_ = snprintf(out + off, sz - off, __VA_ARGS__); \
            if (w_ > 0) off += (size_t)w_; \
            if (off >= sz) off = sz - 1; \
        } \
    } while (0)
    if (q->complete == AQ_COMPLETE_FULL) {
        AQ_PUT("complete full");
        sep = ", ";
    } else if (q->complete == AQ_COMPLETE_PARTIAL) {
        AQ_PUT("complete partial (%s)", cov_reason_name((cov_reason_t)q->complete_why));
        sep = ", ";
    }
    if (q->has_latency) {
        AQ_PUT("%slatency %lu ms", sep, (unsigned long)q->latency_ms);
        sep = ", ";
    }
    int c = aq_corroboration(q);
    if (c > 0) {
        AQ_PUT("%scorroboration %d radio%s", sep, c, c == 1 ? "" : "s");
        sep = ", ";
    }
    if (q->src_state != AQ_SRC_NONE)
        AQ_PUT("%ssource %s", sep, aq_src_name(q->src_state));
#undef AQ_PUT
    return (int)off;
}

const char *alert_quality_title_tag(const alert_quality_t *q, char *buf, size_t sz) {
    if (!buf || sz == 0) return "";
    buf[0] = '\0';
    if (q && q->complete == AQ_COMPLETE_PARTIAL)
        snprintf(buf, sz, " (partial: %s)", cov_reason_name((cov_reason_t)q->complete_why));
    return buf;
}
