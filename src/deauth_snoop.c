#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "deauth_snoop.h"
#include "flood_window.h"

#define WIN_MS  ((uint32_t)DEAUTH_FLOOD_WIN_SECS  * 1000u)
#define HOLD_MS ((uint32_t)DEAUTH_FLOOD_HOLD_SECS * 1000u)
#define AGE_MS  ((uint64_t)DEAUTH_AGE_SECS        * 1000u)

/* Observation rows, keyed (BSSID, TA, RA, subtype). The window and the
 * duplicate-detection state stay private; the exported row carries
 * what the operator and the sinks need. */
typedef struct {
    deauth_event_t ev;
    flood_window_t win;
    uint64_t       last_ms;     /* monotonic, drives ageing */
    uint16_t       last_seq;
} obs_t;

/* (BSSID, victim) impact aggregates. */
typedef struct {
    deauth_victim_t v;
    flood_window_t  win;
    uint64_t        last_ms;
} vic_t;

static obs_t           g_obs[MAX_DEAUTH_ENTRIES];
static int             g_count = 0;
static vic_t           g_vic[MAX_DEAUTH_VICTIMS];
static int             g_vcount = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── 802.11 frame parser ─────────────────────────────────── */

int deauth_parse(const uint8_t *dot11, int len, deauth_frame_t *out)
{
    if (len < 24) return 0;

    uint8_t fc0  = dot11[0];
    uint8_t fc1  = dot11[1];
    uint8_t type = (fc0 >> 2) & 0x03;
    uint8_t sub  = (fc0 >> 4) & 0x0f;

    if (type != 0) return 0;                /* management only */
    if (sub != 10 && sub != 12) return 0;   /* disassoc or deauth only */

    /* +HTC: the Order bit in a management frame announces a 4-octet HT
     * Control field between Sequence Control and the body (IEEE
     * 802.11-2020 9.2.4.1.10, 9.3.3.2). Without it the body offset is
     * wrong and the "reason" is HT Control bytes. */
    int hdr = (fc1 & 0x80) ? 28 : 24;
    if (len < hdr) return 0;

    memset(out, 0, sizeof(*out));
    memcpy(out->dst,   dot11 + 4,  6);
    memcpy(out->src,   dot11 + 10, 6);
    memcpy(out->bssid, dot11 + 16, 6);
    out->subtype    = sub;
    out->fc_flags   = fc1;
    out->retry      = (fc1 & 0x08) ? 1 : 0;
    out->protected_ = (fc1 & 0x40) ? 1 : 0;
    uint16_t sc = (uint16_t)(dot11[22] | ((uint16_t)dot11[23] << 8));
    out->frag = (uint8_t)(sc & 0x0f);
    out->seq  = (uint16_t)(sc >> 4);

    /* Protected Frame first. On a PMF link an individually addressed
     * deauth/disassoc body is CCMP/GCMP ciphertext (12.5.3): the two
     * octets after the header are the low packet-number bytes, not a
     * reason. Group-addressed ones use BIP, leave the reason in clear
     * and do not set this bit. */
    if (out->protected_) return 1;
    if (len < hdr + 2) { out->truncated = 1; return 1; }
    out->reason       = (uint16_t)(dot11[hdr] | ((uint16_t)dot11[hdr + 1] << 8));
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

/* Least recently active slot, by monotonic time. */
static int evict_obs(void) {
    int slot = 0;
    for (int i = 1; i < g_count; i++)
        if (g_obs[i].last_ms < g_obs[slot].last_ms) slot = i;
    return slot;
}

static int evict_vic(void) {
    int slot = 0;
    for (int i = 1; i < g_vcount; i++)
        if (g_vic[i].last_ms < g_vic[slot].last_ms) slot = i;
    return slot;
}

static obs_t *obs_find_or_add(const deauth_frame_t *f, time_t wall, int *fresh) {
    for (int i = 0; i < g_count; i++) {
        deauth_event_t *e = &g_obs[i].ev;
        if (e->subtype == f->subtype &&
            memcmp(e->bssid, f->bssid, 6) == 0 &&
            memcmp(e->src,   f->src,   6) == 0 &&
            memcmp(e->dst,   f->dst,   6) == 0) {
            *fresh = 0;
            return &g_obs[i];
        }
    }
    int slot = g_count < MAX_DEAUTH_ENTRIES ? g_count++ : evict_obs();
    obs_t *o = &g_obs[slot];
    memset(o, 0, sizeof(*o));
    memcpy(o->ev.src,   f->src,   6);
    memcpy(o->ev.dst,   f->dst,   6);
    memcpy(o->ev.bssid, f->bssid, 6);
    o->ev.subtype    = f->subtype;
    o->ev.first_seen = wall;
    *fresh = 1;
    return o;
}

static vic_t *vic_find_or_add(const uint8_t bssid[6], const uint8_t victim[6],
                              time_t wall) {
    for (int i = 0; i < g_vcount; i++)
        if (memcmp(g_vic[i].v.bssid,  bssid,  6) == 0 &&
            memcmp(g_vic[i].v.victim, victim, 6) == 0)
            return &g_vic[i];
    int slot = g_vcount < MAX_DEAUTH_VICTIMS ? g_vcount++ : evict_vic();
    vic_t *v = &g_vic[slot];
    memset(v, 0, sizeof(*v));
    memcpy(v->v.bssid,  bssid,  6);
    memcpy(v->v.victim, victim, 6);
    v->v.first_seen = wall;
    return v;
}

/* ── Event tables ────────────────────────────────────────── */

void deauth_record(const deauth_frame_t *f)
{
    uint64_t now_ms = flood_mono_ms();
    time_t   wall   = flood_wall();
    pthread_mutex_lock(&g_mu);

    int fresh;
    obs_t *o = obs_find_or_add(f, wall, &fresh);
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
    o->last_ms      = now_ms;
    o->last_seq     = f->seq;

    if (dup) { pthread_mutex_unlock(&g_mu); return; }

    if (flood_window_note(&o->win, now_ms, DEAUTH_FLOOD_THRESH, WIN_MS))
        e->flood_last = wall;

    vic_t *v = vic_find_or_add(f->bssid, victim_of(f->src, f->dst, f->bssid), wall);
    v->v.frames++;
    if (f->protected_) v->v.protected_count++;
    /* A protected or truncated frame says nothing about the reason; it
     * must not overwrite one that a cleartext frame did state. */
    if (f->reason_valid) { v->v.reason = f->reason; v->v.reason_valid = 1; }
    v->v.last_seen = wall;
    v->last_ms     = now_ms;
    if (flood_window_note(&v->win, now_ms, DEAUTH_FLOOD_THRESH, WIN_MS))
        v->v.flood_last = wall;
    int in_win = flood_window_count(&v->win, now_ms, WIN_MS);
    if (in_win > v->v.peak_win) v->v.peak_win = in_win;

    pthread_mutex_unlock(&g_mu);
}

static uint64_t idle_ms(uint64_t now_ms, uint64_t last_ms) {
    return now_ms > last_ms ? now_ms - last_ms : 0;
}

void deauth_snapshot(sloth_state_t *s)
{
    uint64_t now_ms = flood_mono_ms();
    pthread_mutex_lock(&g_mu);

    /* Age out on monotonic idle time: a wall-clock step must neither
     * drop a live row nor keep a dead one. */
    int i = 0;
    while (i < g_count) {
        if (idle_ms(now_ms, g_obs[i].last_ms) > AGE_MS) g_obs[i] = g_obs[--g_count];
        else i++;
    }
    i = 0;
    while (i < g_vcount) {
        if (idle_ms(now_ms, g_vic[i].last_ms) > AGE_MS) g_vic[i] = g_vic[--g_vcount];
        else i++;
    }

    /* Flood status is recomputed against now, so it decays with no
     * further frame needed. */
    int n = g_count;
    for (i = 0; i < n; i++) {
        obs_t *o = &g_obs[i];
        o->ev.flood     = flood_window_active(&o->win, now_ms, HOLD_MS);
        o->ev.win_count = flood_window_count(&o->win, now_ms, WIN_MS);
        s->deauth_events[i] = o->ev;
    }
    s->deauth_count = n;
    if (s->deauth_sel >= n) s->deauth_sel = n > 0 ? n - 1 : 0;

    int flood = 0;
    int vn = g_vcount;
    for (i = 0; i < vn; i++) {
        vic_t *v = &g_vic[i];
        v->v.flood     = flood_window_active(&v->win, now_ms, HOLD_MS);
        v->v.win_count = flood_window_count(&v->win, now_ms, WIN_MS);
        v->v.streams   = 0;
        for (int k = 0; k < g_count; k++) {
            const deauth_event_t *e = &g_obs[k].ev;
            if (memcmp(e->bssid, v->v.bssid, 6) == 0 &&
                memcmp(victim_of(e->src, e->dst, e->bssid), v->v.victim, 6) == 0)
                v->v.streams++;
        }
        if (v->v.flood) flood = 1;
        s->deauth_victims[i] = v->v;
    }
    s->deauth_victim_count = vn;
    s->deauth_flood_active = flood;

    pthread_mutex_unlock(&g_mu);
}

void deauth_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_count  = 0;
    g_vcount = 0;
    pthread_mutex_unlock(&g_mu);
}
