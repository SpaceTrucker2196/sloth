#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "deauth_snoop.h"
#include "flood_window.h"
#include "sloth_clock.h"
#include "dot11_frame.h"
#include "tune.h"
#include "stab.h"

/* deauth.flood_thresh / deauth.flood_window_s (#120). Read per frame:
 * tune_val() is an array index. */
#define WIN_MS  ((uint32_t)tune_val(TUNE_DEAUTH_FLOOD_WINDOW_S) * 1000u)
#define THRESH  ((int)tune_val(TUNE_DEAUTH_FLOOD_THRESH))
#define HOLD_MS ((uint32_t)DEAUTH_FLOOD_HOLD_SECS * 1000u)
#define AGE_MS  ((uint64_t)DEAUTH_AGE_SECS        * 1000u)

/* Observation rows, keyed (BSSID, TA, RA, subtype). The window and the
 * duplicate-detection state stay private; the exported row carries
 * what the operator and the sinks need. */
typedef struct {
    deauth_event_t ev;
    flood_window_t win;
    time_t         last_ms;     /* monotonic ms (see below), drives ageing and eviction */
    uint16_t       last_seq;
} obs_t;

/* (BSSID, victim) impact aggregates.
 *
 * `ids` is a ring of evidence-ring event IDs for this aggregate's
 * distinct frames (#92), kept private the way the window is: the
 * exported row gets a flat oldest-first copy at snapshot.
 *
 * It keeps the *newest* IDs, not the first ones. The frames that opened
 * a burst are the better evidence in principle, but the evidence ring
 * is itself a FIFO: a flood of thousands of frames evicts its own
 * opening frames long before an operator reads the alert, and a cited
 * ID whose record is gone resolves to nothing. Citing the newest keeps
 * the citations retrievable, which is the whole point of carrying
 * them. */
typedef struct {
    deauth_victim_t v;
    flood_window_t  win;
    time_t          last_ms;    /* monotonic ms, as obs_t */
    uint64_t        ids[DEAUTH_EVIDENCE_IDS];
    int             id_count;   /* stored, saturating at the array size */
    int             id_head;    /* next slot to write */
} vic_t;

/* Both tables are stab_t STAB_OLDEST (#143), so a full table's loss
 * reaches sensor_health as evict_deauth_obs / evict_deauth_victim
 * instead of going unmeasured.
 *
 * Recency here is the monotonic millisecond clock, not wall seconds:
 * the flood windows are sub-second, and a wall-clock step must neither
 * age out a live row nor pick it for eviction. stab_t's stamp is a
 * time_t, so `last_ms` is declared time_t and carries the monotonic ms
 * count — stab_t only orders and subtracts the stamp, it never reads it
 * as a calendar time. That needs a time_t at least as wide as the
 * uint64_t clock, or the ordering would wrap after 24.8 days of uptime
 * on a 32-bit time_t; the typedef below fails the build there rather
 * than let it. Least-recent-first by strict `<`, lowest slot on a tie:
 * the same victim the hand-written evict_obs()/evict_vic() chose. */
typedef char deauth_ms_fits_time_t[sizeof(time_t) >= sizeof(uint64_t) ? 1 : -1];

typedef struct {
    const uint8_t *bssid, *src, *dst;
    uint8_t        subtype;
} obs_key_t;

typedef struct {
    const uint8_t *bssid, *victim;
} vic_key_t;

static int obs_eq(const void *row, const void *key) {
    const deauth_event_t *e = &((const obs_t *)row)->ev;
    const obs_key_t      *k = key;
    return e->subtype == k->subtype &&
           memcmp(e->bssid, k->bssid, 6) == 0 &&
           memcmp(e->src,   k->src,   6) == 0 &&
           memcmp(e->dst,   k->dst,   6) == 0;
}

static int vic_eq(const void *row, const void *key) {
    const deauth_victim_t *v = &((const vic_t *)row)->v;
    const vic_key_t       *k = key;
    return memcmp(v->bssid,  k->bssid,  6) == 0 &&
           memcmp(v->victim, k->victim, 6) == 0;
}

/* mu NULL: g_mu is held across every get-and-update below. */
STAB_DECL(g_obs, obs_t, MAX_DEAUTH_ENTRIES, last_ms, STAB_OLDEST,
          SH_EVICT_DEAUTH_OBS, NULL, obs_eq);
STAB_DECL(g_vic, vic_t, MAX_DEAUTH_VICTIMS, last_ms, STAB_OLDEST,
          SH_EVICT_DEAUTH_VICTIM, NULL, vic_eq);
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* ── 802.11 frame parser ─────────────────────────────────── */

/* The byte entry point stays for the tests and fuzz harnesses written
 * against it (#130); it decodes once and hands the view on. */
int deauth_parse(const uint8_t *dot11, int len, deauth_frame_t *out)
{
    dot11_frame_t f;
    dot11_frame_decode(dot11, len, NULL, &f);
    return deauth_parse_frame(&f, out);
}

int deauth_parse_frame(const dot11_frame_t *f, deauth_frame_t *out)
{
    if (!f || !f->p || f->len < 24) return 0;

    if (f->type != 0) return 0;                         /* management only */
    if (f->subtype != 10 && f->subtype != 12) return 0; /* disassoc or deauth only */

    /* +HTC: the Order bit in a management frame announces a 4-octet HT
     * Control field between Sequence Control and the body (IEEE
     * 802.11-2020 9.2.4.1.10, 9.3.3.2). Without it the body offset is
     * wrong and the "reason" is HT Control bytes.
     *
     * This file had it right and the other three management parsers did
     * not, so the rule moved to one place — dot11_mgmt_hdr_len() first,
     * the frame view's hdr_len since #122 — and they all read it there. */
    int hdr = f->hdr_len;
    if (hdr < 0) return 0;

    memset(out, 0, sizeof(*out));
    memcpy(out->dst,   f->da,    6);     /* addr1 */
    memcpy(out->src,   f->sa,    6);     /* addr2 */
    memcpy(out->bssid, f->bssid, 6);     /* addr3 (§9.3.3.1) */
    out->subtype    = f->subtype;
    out->fc_flags   = f->fc1;
    out->retry      = f->retry;
    out->protected_ = f->protected_;
    out->frag = (uint8_t)f->frag_num;
    out->seq  = (uint16_t)f->seq_num;

    /* Protected Frame first. On a PMF link an individually addressed
     * deauth/disassoc body is CCMP/GCMP ciphertext (12.5.3): the two
     * octets after the header are the low packet-number bytes, not a
     * reason. Group-addressed ones use BIP, leave the reason in clear
     * and do not set this bit. */
    if (out->protected_) return 1;
    if (f->len < hdr + 2) { out->truncated = 1; return 1; }
    out->reason       = (uint16_t)(f->p[hdr] | ((uint16_t)f->p[hdr + 1] << 8));
    out->reason_valid = 1;
    return 1;
}

/* ── Keys ────────────────────────────────────────────────── */

/* The station a frame acts on. A frame to the AP (Address 1 = BSSID)
 * acts on its transmitter — "the station is leaving", possibly spoofed;
 * otherwise on its receiver, which for a group address means every
 * station of the BSS. */
static const uint8_t *victim_of(const uint8_t src[6], const uint8_t dst[6],
                                const uint8_t bssid[6]) {
    return memcmp(dst, bssid, 6) == 0 ? src : dst;
}

/* stab_get() zeroes a new row and stamps last_ms; the key fields and
 * first_seen are this module's to fill. */
static obs_t *obs_get(const deauth_frame_t *f, uint64_t now_ms, time_t wall,
                      int *fresh) {
    obs_key_t k = { f->bssid, f->src, f->dst, f->subtype };
    obs_t *o = stab_get(&g_obs, &k, (time_t)now_ms, fresh);
    if (*fresh) {
        memcpy(o->ev.src,   f->src,   6);
        memcpy(o->ev.dst,   f->dst,   6);
        memcpy(o->ev.bssid, f->bssid, 6);
        o->ev.subtype    = f->subtype;
        o->ev.first_seen = wall;
    }
    return o;
}

static vic_t *vic_get(const uint8_t bssid[6], const uint8_t victim[6],
                      uint64_t now_ms, time_t wall) {
    vic_key_t k = { bssid, victim };
    int fresh;
    vic_t *v = stab_get(&g_vic, &k, (time_t)now_ms, &fresh);
    if (fresh) {
        memcpy(v->v.bssid,  bssid,  6);
        memcpy(v->v.victim, victim, 6);
        v->v.first_seen = wall;
    }
    return v;
}

/* ── Event tables ────────────────────────────────────────── */

void deauth_record(const deauth_frame_t *f)
{
    uint64_t now_ms = sloth_mono_ms();
    time_t   wall   = sloth_wall();
    pthread_mutex_lock(&g_mu);

    int fresh;
    /* STAB_OLDEST never refuses, so neither getter returns NULL. */
    obs_t *o = obs_get(f, now_ms, wall, &fresh);
    deauth_event_t *e = &o->ev;

    /* Retry=1 repeating this stream's previous sequence number is the
     * same MPDU sent again for want of an ACK; the receiver's duplicate
     * filter discards it (10.3.2.14). Observed, but not a new frame. */
    int dup = !fresh && f->retry && f->seq == o->last_seq;

    e->count++;
    if (dup)           e->retries++;
    if (f->protected_) e->protected_count++;
    if (f->truncated)  e->truncated_count++;
    e->fc_flags     = f->fc_flags;
    e->reason       = f->reason;
    e->reason_valid = f->reason_valid;
    e->last_seen    = wall;
    o->last_ms      = (time_t)now_ms;
    o->last_seq     = f->seq;

    if (dup) { pthread_mutex_unlock(&g_mu); return; }

    if (flood_window_note(&o->win, now_ms, THRESH, WIN_MS))
        e->flood_last = wall;

    vic_t *v = vic_get(f->bssid, victim_of(f->src, f->dst, f->bssid), now_ms, wall);
    v->v.frames++;
    if (f->protected_) v->v.protected_count++;
    /* A protected or truncated frame says nothing about the reason; it
     * must not overwrite one that a cleartext frame did state. */
    if (f->reason_valid) { v->v.reason = f->reason; v->v.reason_valid = 1; }
    v->v.last_seen = wall;
    v->last_ms     = (time_t)now_ms;
    if (flood_window_note(&v->win, now_ms, THRESH, WIN_MS))
        v->v.flood_last = wall;
    int in_win = flood_window_count(&v->win, now_ms, WIN_MS);
    if (in_win > v->v.peak_win) v->v.peak_win = in_win;
    /* Inside the lock and after the duplicate bail above, so a
     * retransmission cites nothing: it is the same MPDU and already has
     * an ID in here. 0 means the capture path retained no bytes for
     * this frame (ring down), and 0 is not a valid event ID — storing
     * it would hand the alert a citation that can never resolve. */
    if (f->event_id != 0) {
        v->ids[v->id_head] = f->event_id;
        v->id_head = (v->id_head + 1) % DEAUTH_EVIDENCE_IDS;
        if (v->id_count < DEAUTH_EVIDENCE_IDS) v->id_count++;
    }

    pthread_mutex_unlock(&g_mu);
}

static uint64_t idle_ms(uint64_t now_ms, time_t last_ms) {
    return now_ms > (uint64_t)last_ms ? now_ms - (uint64_t)last_ms : 0;
}

void deauth_snapshot(sloth_state_t *s)
{
    uint64_t now_ms = sloth_mono_ms();
    pthread_mutex_lock(&g_mu);

    /* Age out on monotonic idle time: a wall-clock step must neither
     * drop a live row nor keep a dead one. A row aged out is retired,
     * not lost — nothing has been heard from it for DEAUTH_AGE_SECS —
     * so stab_del(), which does not tally.
     *
     * Walked upward, re-examining slot i after each removal, rather than
     * with stab_expire()'s downward walk: stab_del() moves the last row
     * into the hole exactly as the hand-written loop did, and walking
     * the same direction keeps the surviving rows in the same slots, so
     * the view and the snapshot order are unchanged. */
    int i = 0;
    while (i < stab_count(&g_obs)) {
        obs_t *o = stab_at(&g_obs, i);
        if (idle_ms(now_ms, o->last_ms) > AGE_MS) stab_del(&g_obs, o);
        else i++;
    }
    i = 0;
    while (i < stab_count(&g_vic)) {
        vic_t *v = stab_at(&g_vic, i);
        if (idle_ms(now_ms, v->last_ms) > AGE_MS) stab_del(&g_vic, v);
        else i++;
    }

    /* Flood status is recomputed against now, so it decays with no
     * further frame needed. */
    int n = stab_count(&g_obs);
    for (i = 0; i < n; i++) {
        obs_t *o = stab_at(&g_obs, i);
        o->ev.flood     = flood_window_active(&o->win, now_ms, HOLD_MS);
        o->ev.win_count = flood_window_count(&o->win, now_ms, WIN_MS);
        s->deauth_events[i] = o->ev;
    }
    s->deauth_count = n;
    if (s->deauth_sel >= n) s->deauth_sel = n > 0 ? n - 1 : 0;

    int flood = 0;
    int vn = stab_count(&g_vic);
    for (i = 0; i < vn; i++) {
        vic_t *v = stab_at(&g_vic, i);
        v->v.flood     = flood_window_active(&v->win, now_ms, HOLD_MS);
        v->v.win_count = flood_window_count(&v->win, now_ms, WIN_MS);
        v->v.streams   = 0;
        for (int k = 0; k < n; k++) {
            const deauth_event_t *e = &((obs_t *)stab_at(&g_obs, k))->ev;
            if (memcmp(e->bssid, v->v.bssid, 6) == 0 &&
                memcmp(victim_of(e->src, e->dst, e->bssid), v->v.victim, 6) == 0)
                v->v.streams++;
        }
        if (v->v.flood) flood = 1;
        /* Published on the row here rather than at record time so the
         * exported struct and the private ring cannot drift. Flattened
         * oldest-first: a consumer reading evidence_ids[] in order
         * should not have to know where the head happened to be. */
        memset(v->v.evidence_ids, 0, sizeof(v->v.evidence_ids));
        for (int e = 0; e < v->id_count; e++) {
            int src = v->id_count < DEAUTH_EVIDENCE_IDS
                    ? e
                    : (v->id_head + e) % DEAUTH_EVIDENCE_IDS;
            v->v.evidence_ids[e] = v->ids[src];
        }
        v->v.evidence_id_count = v->id_count;
        s->deauth_victims[i] = v->v;
    }
    s->deauth_victim_count = vn;
    s->deauth_flood_active = flood;

    pthread_mutex_unlock(&g_mu);
}

void deauth_clear(void)
{
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_obs);
    stab_clear(&g_vic);
    pthread_mutex_unlock(&g_mu);
}
