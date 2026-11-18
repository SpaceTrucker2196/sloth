/* PMKID and 4-way-handshake harvesting (#172). What is tracked, the
 * bounds and the thresholds are argued in harvest_track.h. */
#include <pthread.h>
#include <string.h>
#include "harvest_track.h"
#include "eapol_log.h"     /* EAPOL_PAIR_WINDOW_S */
#include "queue_evict.h"   /* the QUEUE_EVICT correlation */
#include "rsn_ie.h"        /* RSN_AKM_PSK_FAMILY */
#include "sloth_clock.h"

typedef struct {
    uint8_t  bssid[6];
    uint64_t asked_ms;     /* newest (re)association request */
    uint64_t m1_ms;        /* newest M1 to the station, 0 none */
    uint64_t last_ms;      /* newest of anything above */
    int      pmkid;        /* an M1 in this window carried a PMKID KDE */
    int      m2;           /* the station sent this BSSID an M2 */
    uint64_t m1_ev;
} tgt_t;

typedef struct {
    uint8_t  sta[6];
    tgt_t    tgt[HARVEST_MAX_TGT];
    int      n_tgt;
    int      dropped;
    uint64_t last_ms;
    time_t   first_seen, last_seen;
    uint32_t id;
} sta_row_t;

typedef struct {
    uint8_t  bssid[6];
    uint8_t  victim[6];
    int      frames;       /* distinct frames in the current burst */
    uint64_t first_ms, last_ms;
    uint64_t ev[HARVEST_EV_IDS];
    int      ev_n;
} deauth_note_t;

typedef struct {
    harvest_chain_t row;
    uint64_t        victim_ms[HARVEST_MAX_VICTIMS];
    uint64_t        last_ms;
} chain_row_t;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static sta_row_t       g_sta[HARVEST_MAX_STA];
static int             g_sta_n;
static deauth_note_t   g_dn[HARVEST_MAX_DEAUTH];
static int             g_dn_n;
static chain_row_t     g_chain[HARVEST_MAX_CHAIN];
static int             g_chain_n;
static unsigned long   g_evict;
/* Harvest-friendly posture: BSSIDs heard sending the PMKID KDE in M1. */
typedef struct { uint8_t bssid[6]; uint64_t last_ms; } ap_row_t;
static ap_row_t        g_ap[HARVEST_MAX_AP];
static int             g_ap_n;
/* The next cluster id; 0 is "none" and is skipped on wrap. */
static uint32_t        g_next_id = 1;

static uint32_t next_id(void) {
    uint32_t id = g_next_id++;
    if (g_next_id == 0) g_next_id = 1;
    return id;
}

/* QUEUE_EVICT's rows, read before g_mu is taken (its lock and this one
 * never nest), on the poll thread only. File-static: 128 rows are too
 * large for the stack of a function the tests call from deep frames. */
static queue_evict_t   g_qe[MAX_QUEUE_EVICT_ENTRIES];

/* Per-poll copies the state points at. Written only by
 * harvest_snapshot() on the poll thread, which is also the reader. */
static harvest_sta_t   g_sta_copy[HARVEST_MAX_STA];
static harvest_chain_t g_chain_copy[HARVEST_MAX_CHAIN];

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

static int mac_unicast(const uint8_t m[6]) {
    if (m[0] & 0x01) return 0;
    for (int i = 0; i < 6; i++) if (m[i]) return 1;
    return 0;
}

static int mac_is_bcast(const uint8_t m[6]) {
    for (int i = 0; i < 6; i++) if (m[i] != 0xff) return 0;
    return 1;
}

void harvest_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_sta, 0, sizeof g_sta);   g_sta_n = 0;
    memset(g_dn, 0, sizeof g_dn);     g_dn_n = 0;
    memset(g_chain, 0, sizeof g_chain); g_chain_n = 0;
    memset(g_ap, 0, sizeof g_ap);     g_ap_n = 0;
    g_evict = 0;
    g_next_id = 1;
    pthread_mutex_unlock(&g_mu);
}

unsigned long harvest_evictions(void) {
    pthread_mutex_lock(&g_mu);
    unsigned long n = g_evict;
    pthread_mutex_unlock(&g_mu);
    return n;
}

static int m1_targets(const sta_row_t *r) {
    int n = 0;
    for (int i = 0; i < r->n_tgt; i++) if (r->tgt[i].m1_ms) n++;
    return n;
}

/* Caller holds g_mu. */
static sta_row_t *sta_find(const uint8_t sta[6]) {
    for (int i = 0; i < g_sta_n; i++)
        if (mac_eq(g_sta[i].sta, sta)) return &g_sta[i];
    return NULL;
}

static sta_row_t *sta_get(const uint8_t sta[6], uint64_t now_ms,
                          time_t wall) {
    sta_row_t *r = sta_find(sta);
    if (r) return r;
    if (g_sta_n < HARVEST_MAX_STA) {
        r = &g_sta[g_sta_n++];
    } else {
        /* Least harvest evidence first, then least recent. */
        r = &g_sta[0];
        int best = m1_targets(r);
        for (int i = 1; i < g_sta_n; i++) {
            int m = m1_targets(&g_sta[i]);
            if (m < best || (m == best && g_sta[i].last_ms < r->last_ms)) {
                r = &g_sta[i];
                best = m;
            }
        }
        g_evict++;
    }
    memset(r, 0, sizeof *r);
    memcpy(r->sta, sta, 6);
    r->first_seen = wall;
    r->last_ms    = now_ms;
    r->id         = next_id();
    return r;
}

static tgt_t *tgt_find(sta_row_t *r, const uint8_t bssid[6]) {
    for (int i = 0; i < r->n_tgt; i++)
        if (mac_eq(r->tgt[i].bssid, bssid)) return &r->tgt[i];
    return NULL;
}

static tgt_t *tgt_get(sta_row_t *r, const uint8_t bssid[6]) {
    tgt_t *t = tgt_find(r, bssid);
    if (t) return t;
    if (r->n_tgt < HARVEST_MAX_TGT) {
        t = &r->tgt[r->n_tgt++];
    } else {
        /* An answered target first, so the unanswered ones that are the
         * finding are the last to go; least recent within each. */
        t = NULL;
        for (int pass = 0; pass < 2 && !t; pass++)
            for (int i = 0; i < r->n_tgt; i++) {
                tgt_t *c = &r->tgt[i];
                if (pass == 0 && !c->m2) continue;
                if (!t || c->last_ms < t->last_ms) t = c;
            }
        r->dropped++;
        g_evict++;
    }
    memset(t, 0, sizeof *t);
    memcpy(t->bssid, bssid, 6);
    return t;
}

void harvest_note_assoc_req(const uint8_t sta[6], const uint8_t bssid[6]) {
    if (!sta || !bssid || !mac_unicast(sta) || !mac_unicast(bssid)) return;
    uint64_t now_ms = sloth_mono_ms();
    time_t   wall   = sloth_wall();
    pthread_mutex_lock(&g_mu);
    sta_row_t *r = sta_get(sta, now_ms, wall);
    tgt_t *t = tgt_get(r, bssid);
    t->asked_ms  = now_ms;
    t->last_ms   = now_ms;
    r->last_ms   = now_ms;
    r->last_seen = wall;
    pthread_mutex_unlock(&g_mu);
}

/* Caller holds g_mu. The deauth note that can explain a fresh pair on
 * (bssid, sta): one to the station itself or to broadcast, with enough
 * distinct frames, the last of them recent enough. */
static deauth_note_t *deauth_explaining(const uint8_t bssid[6],
                                        const uint8_t sta[6],
                                        uint64_t now_ms) {
    uint64_t win = HARVEST_RECONNECT_S * 1000u;
    deauth_note_t *best = NULL;
    for (int i = 0; i < g_dn_n; i++) {
        deauth_note_t *d = &g_dn[i];
        if (!mac_eq(d->bssid, bssid)) continue;
        if (!mac_eq(d->victim, sta) && !mac_is_bcast(d->victim)) continue;
        if (d->frames < HARVEST_DEAUTH_MIN) continue;
        if (d->last_ms > now_ms || now_ms - d->last_ms > win) continue;
        if (!best || d->last_ms > best->last_ms) best = d;
    }
    return best;
}

/* Caller holds g_mu. Record `sta` as a victim on `bssid`'s chain; the
 * chain's cluster id, or 0 when the victim was left out by the cap. */
static uint32_t chain_note(const uint8_t bssid[6], const uint8_t sta[6],
                       const deauth_note_t *d, uint64_t now_ms,
                       time_t wall) {
    chain_row_t *c = NULL;
    for (int i = 0; i < g_chain_n; i++)
        if (mac_eq(g_chain[i].row.bssid, bssid)) { c = &g_chain[i]; break; }
    if (!c) {
        if (g_chain_n < HARVEST_MAX_CHAIN) {
            c = &g_chain[g_chain_n++];
        } else {
            c = &g_chain[0];
            for (int i = 1; i < g_chain_n; i++)
                if (g_chain[i].last_ms < c->last_ms) c = &g_chain[i];
            g_evict++;
        }
        memset(c, 0, sizeof *c);
        memcpy(c->row.bssid, bssid, 6);
        c->row.first_seen = wall;
        c->row.cluster_id = next_id();
    }
    harvest_chain_t *r = &c->row;
    c->last_ms   = now_ms;
    r->last_seen = wall;

    int k = -1;
    for (int i = 0; i < r->victims; i++)
        if (mac_eq(r->victim[i], sta)) { k = i; break; }
    if (k < 0) {
        if (r->victims >= HARVEST_MAX_VICTIMS) {
            r->dropped++;
            g_evict++;
            return 0;
        }
        k = r->victims++;
        memcpy(r->victim[k], sta, 6);
        r->deauth_frames += d->frames;
    }
    c->victim_ms[k] = now_ms;
    for (int i = 0; i < d->ev_n; i++) {
        if (r->ev_n < HARVEST_EV_IDS) {
            r->ev[r->ev_n++] = d->ev[i];
        } else {
            memmove(r->ev, r->ev + 1, (HARVEST_EV_IDS - 1) * sizeof r->ev[0]);
            r->ev[HARVEST_EV_IDS - 1] = d->ev[i];
        }
    }
    return r->cluster_id;
}

/* Caller holds g_mu. */
static void ap_note(const uint8_t bssid[6], uint64_t now_ms) {
    ap_row_t *a = NULL;
    for (int i = 0; i < g_ap_n; i++)
        if (mac_eq(g_ap[i].bssid, bssid)) { a = &g_ap[i]; break; }
    if (!a) {
        if (g_ap_n < HARVEST_MAX_AP) {
            a = &g_ap[g_ap_n++];
        } else {
            a = &g_ap[0];
            for (int i = 1; i < g_ap_n; i++)
                if (g_ap[i].last_ms < a->last_ms) a = &g_ap[i];
            g_evict++;
        }
        memcpy(a->bssid, bssid, 6);
    }
    a->last_ms = now_ms;
}

int harvest_ap_posture(const uint8_t bssid[6]) {
    if (!bssid) return 0;
    int hit = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_ap_n && !hit; i++)
        if (mac_eq(g_ap[i].bssid, bssid)) hit = 1;
    pthread_mutex_unlock(&g_mu);
    return hit;
}

int harvest_posture_psk(const uint8_t bssid[6], uint32_t akm_bits) {
    if (!harvest_ap_posture(bssid)) return -1;
    return (akm_bits & RSN_AKM_PSK_FAMILY) ? 1 : 0;
}

uint32_t harvest_note_eapol(const uint8_t bssid[6], const uint8_t sta[6],
                            int msg, int pmkid, int fresh_pair, uint64_t ev) {
    if (!bssid || !sta || msg < 1 || msg > 4) return 0;
    if (!mac_unicast(sta) || !mac_unicast(bssid)) return 0;
    uint64_t now_ms = sloth_mono_ms();
    time_t   wall   = sloth_wall();
    uint32_t id     = 0;
    pthread_mutex_lock(&g_mu);

    /* The AP's posture, whoever asked: a station that never solicited
     * (one already associated, rekeying) was handed the same value. */
    if (msg == 1 && pmkid) ap_note(bssid, now_ms);

    /* Shape A: only stations that solicited, only BSSIDs they asked. */
    sta_row_t *r = sta_find(sta);
    tgt_t *t = r ? tgt_find(r, bssid) : NULL;
    if (t && msg == 1) {
        t->m1_ms   = now_ms;
        t->last_ms = now_ms;
        if (pmkid) t->pmkid = 1;
        if (ev) t->m1_ev = ev;
        r->last_ms   = now_ms;
        r->last_seen = wall;
        id = r->id;
    } else if (t && msg == 2) {
        t->m2      = 1;
        t->last_ms = now_ms;
        r->last_ms = now_ms;
        id = r->id;
    }

    /* Shape B: a fresh pair right after deauths claimed from this AP.
     * Its cluster wins: the victim's own row (it reassociated, so it
     * has one) holds this M2 as an answer, which is no finding, while
     * the chain holds it as the captured handshake. */
    if (msg == 2 && fresh_pair) {
        deauth_note_t *d = deauth_explaining(bssid, sta, now_ms);
        if (d) {
            uint32_t cid = chain_note(bssid, sta, d, now_ms, wall);
            if (cid) id = cid;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return id;
}

void harvest_note_deauth(const uint8_t bssid[6], const uint8_t src[6],
                         const uint8_t victim[6], uint64_t ev) {
    if (!bssid || !src || !victim) return;
    if (!mac_unicast(bssid) || !mac_eq(src, bssid)) return;
    if (!mac_unicast(victim) && !mac_is_bcast(victim)) return;
    uint64_t now_ms = sloth_mono_ms();
    uint64_t win    = HARVEST_RECONNECT_S * 1000u;
    pthread_mutex_lock(&g_mu);
    deauth_note_t *d = NULL;
    for (int i = 0; i < g_dn_n; i++)
        if (mac_eq(g_dn[i].bssid, bssid) && mac_eq(g_dn[i].victim, victim)) {
            d = &g_dn[i];
            break;
        }
    if (!d) {
        if (g_dn_n < HARVEST_MAX_DEAUTH) {
            d = &g_dn[g_dn_n++];
        } else {
            d = &g_dn[0];
            for (int i = 1; i < g_dn_n; i++)
                if (g_dn[i].last_ms < d->last_ms) d = &g_dn[i];
            g_evict++;
        }
        memset(d, 0, sizeof *d);
        memcpy(d->bssid, bssid, 6);
        memcpy(d->victim, victim, 6);
    } else if (now_ms > d->last_ms && now_ms - d->last_ms > win) {
        /* A new burst: frames from an old one do not add to it. */
        d->frames = 0;
        d->ev_n   = 0;
    }
    if (d->frames == 0) d->first_ms = now_ms;
    d->frames++;
    d->last_ms = now_ms;
    if (ev) {
        if (d->ev_n < HARVEST_EV_IDS) {
            d->ev[d->ev_n++] = ev;
        } else {
            memmove(d->ev, d->ev + 1, (HARVEST_EV_IDS - 1) * sizeof d->ev[0]);
            d->ev[HARVEST_EV_IDS - 1] = ev;
        }
    }
    pthread_mutex_unlock(&g_mu);
}

/* Is QUEUE_EVICT row `q` a release on (bssid, sta) inside the window?
 * Its stamp is the capture's wall second (queue_evict.h), so the window
 * is measured on the wall clock, both ways: a channel-hopping radio can
 * hear the release after the harvest it belongs to, or before. */
static int qe_pair(const queue_evict_t *q, const uint8_t bssid[6],
                   const uint8_t sta[6], time_t wall, long win_s) {
    if (!mac_eq(q->bssid, bssid) || !mac_eq(q->sta, sta)) return 0;
    long d = (long)(wall >= q->last_release_ts ? wall - q->last_release_ts
                                               : q->last_release_ts - wall);
    return d <= win_s;
}

void harvest_snapshot(sloth_state_t *s) {
    if (!s) return;
    uint64_t now_ms = sloth_mono_ms();
    uint64_t win    = HARVEST_WINDOW_S * 1000u;
    uint64_t grace  = (uint64_t)EAPOL_PAIR_WINDOW_S * 1000u;
    uint64_t recon  = HARVEST_RECONNECT_S * 1000u;
    time_t   wall   = sloth_wall();
    long     win_s  = (long)HARVEST_WINDOW_S;

    /* Releases only, read before g_mu: this lock stays a leaf. */
    int n_qe = queue_evict_snapshot(g_qe, MAX_QUEUE_EVICT_ENTRIES);
    {
        int k = 0;
        for (int q = 0; q < n_qe; q++)
            if (g_qe[q].release_count > 0 && g_qe[q].last_release_ts > 0)
                g_qe[k++] = g_qe[q];
        n_qe = k;
    }
    pthread_mutex_lock(&g_mu);

    /* Station rows: targets idle past the window go, then rows left
     * with none. */
    int i = 0;
    while (i < g_sta_n) {
        sta_row_t *r = &g_sta[i];
        int k = 0;
        while (k < r->n_tgt) {
            tgt_t *t = &r->tgt[k];
            if (now_ms > t->last_ms && now_ms - t->last_ms > win)
                r->tgt[k] = r->tgt[--r->n_tgt];
            else
                k++;
        }
        if (r->n_tgt == 0) g_sta[i] = g_sta[--g_sta_n];
        else i++;
    }
    int n_out = 0;
    for (i = 0; i < g_sta_n; i++) {
        const sta_row_t *r = &g_sta[i];
        harvest_sta_t *o = &g_sta_copy[n_out++];
        memset(o, 0, sizeof *o);
        memcpy(o->sta, r->sta, 6);
        o->dropped    = r->dropped;
        o->first_seen = r->first_seen;
        o->last_seen  = r->last_seen;
        o->cluster_id = r->id;
        time_t qe_newest = 0;
        for (int k = 0; k < r->n_tgt; k++) {
            const tgt_t *t = &r->tgt[k];
            for (int q = 0; q < n_qe; q++) {
                if (!qe_pair(&g_qe[q], t->bssid, r->sta, wall, win_s))
                    continue;
                /* One pair, one row in queue_evict's table. */
                o->qevict++;
                if (g_qe[q].last_release_ts >= qe_newest) {
                    qe_newest = g_qe[q].last_release_ts;
                    memcpy(o->qevict_bssid, t->bssid, 6);
                }
                break;
            }
            if (t->asked_ms) o->solicited++;
            if (t->m2) o->answered++;
            if (!t->m1_ms || !t->asked_ms) continue;
            o->m1_bssids++;
            /* Unanswered only once the M1 is older than any M2 could
             * still be: the collector's own pairing window. */
            if (!t->m2 && now_ms > t->m1_ms && now_ms - t->m1_ms > grace) {
                o->unanswered++;
                if (t->pmkid) o->pmkid_unanswered++;
                if (t->m1_ev && o->ev_n < HARVEST_EV_IDS)
                    o->ev[o->ev_n++] = t->m1_ev;
            }
        }
    }
    s->harvest_sta       = g_sta_copy;
    s->harvest_sta_count = n_out;

    /* Deauth notes outlive their reconnect window by nothing. */
    i = 0;
    while (i < g_dn_n) {
        if (now_ms > g_dn[i].last_ms && now_ms - g_dn[i].last_ms > recon)
            g_dn[i] = g_dn[--g_dn_n];
        else
            i++;
    }

    /* Chain victims age out of the window, then empty rows. */
    i = 0;
    while (i < g_chain_n) {
        chain_row_t *c = &g_chain[i];
        harvest_chain_t *r = &c->row;
        int k = 0;
        while (k < r->victims) {
            if (now_ms > c->victim_ms[k] && now_ms - c->victim_ms[k] > win) {
                int last = r->victims - 1;
                memcpy(r->victim[k], r->victim[last], 6);
                c->victim_ms[k] = c->victim_ms[last];
                r->victims--;
            } else {
                k++;
            }
        }
        if (r->victims == 0) g_chain[i] = g_chain[--g_chain_n];
        else i++;
    }
    for (i = 0; i < g_chain_n; i++) {
        harvest_chain_t *o = &g_chain_copy[i];
        *o = g_chain[i].row;
        o->qevict = 0;
        memset(o->qevict_sta, 0, 6);
        time_t qe_newest = 0;
        for (int k = 0; k < o->victims; k++)
            for (int q = 0; q < n_qe; q++) {
                if (!qe_pair(&g_qe[q], o->bssid, o->victim[k], wall, win_s))
                    continue;
                o->qevict++;
                if (g_qe[q].last_release_ts >= qe_newest) {
                    qe_newest = g_qe[q].last_release_ts;
                    memcpy(o->qevict_sta, o->victim[k], 6);
                }
                break;
            }
    }
    s->harvest_chain       = g_chain_copy;
    s->harvest_chain_count = g_chain_n;
    pthread_mutex_unlock(&g_mu);
}

const harvest_sta_t *harvest_find_sta_cluster(const sloth_state_t *s,
                                              uint32_t id) {
    if (!s || !id) return NULL;
    for (int i = 0; s->harvest_sta && i < s->harvest_sta_count; i++)
        if (s->harvest_sta[i].cluster_id == id) return &s->harvest_sta[i];
    return NULL;
}

const harvest_chain_t *harvest_find_chain_cluster(const sloth_state_t *s,
                                                  uint32_t id) {
    if (!s || !id) return NULL;
    for (int i = 0; s->harvest_chain && i < s->harvest_chain_count; i++)
        if (s->harvest_chain[i].cluster_id == id) return &s->harvest_chain[i];
    return NULL;
}
