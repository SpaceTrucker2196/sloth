#include "web_fleetid.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rf_model.h"
#include "web_alertkb.h"
#include "web_ble.h"
#include "web_chain.h"
#include "web_frrs.h"
#include "web_gnss.h"
#include "web_jsonl.h"
#include "web_series.h"
#include "web_store.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#define T_MAX 4102444800LL

/* src into dst whole, or "" when it does not fit: a key cut short would
 * name something else. */
static void scpy(char *dst, size_t cap, const char *src) {
    size_t n = src ? strlen(src) : 0;
    if (n >= cap) n = 0;
    if (n) memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ── the words ─────────────────────────────────────────────────────── */

static const char *const CLASS_WORD[WEB_FID_NCLASS] = { "I2", "I3", "I4", "I8" };
static const char *const SUB_WORD[WEB_FID_NSUB] = {
    "probe_other_site", "own_bssid_elsewhere", "own_ssid_foreign_bssid",
    "bssid_two_places", "tool_travel", "verdict_conflict",
};
static const int SUB_CLASS[WEB_FID_NSUB] = {
    WEB_FID_I2, WEB_FID_I3, WEB_FID_I3, WEB_FID_I3, WEB_FID_I4, WEB_FID_I8,
};

const char *web_fid_class_word(int c) {
    return c >= 0 && c < WEB_FID_NCLASS ? CLASS_WORD[c] : "";
}

const char *web_fid_sub_word(int s) {
    return s >= 0 && s < WEB_FID_NSUB ? SUB_WORD[s] : "";
}

int web_fid_class_find(const char *s, size_t n) {
    for (int c = 0; c < WEB_FID_NCLASS; c++)
        if (strlen(CLASS_WORD[c]) == n && !strncmp(CLASS_WORD[c], s, n)) return c;
    return -1;
}

/* ── the attacks naming a BSSID ────────────────────────────────────── */

/* The words of the WEB_FID_ATK_* bits, in bit order. */
static const char *const ATK_WORD[3] = { "EVIL_TWIN", "KARMA_AP", "TWIN_UNATTRIBUTED" };

void web_fid_atk_words(unsigned types, char *out, size_t cap) {
    size_t o = 0;
    out[0] = '\0';
    for (int i = 0; i < 3; i++) {
        if (!(types & (1u << i))) continue;
        int k = snprintf(out + o, cap - o, "%s%s", o ? "," : "", ATK_WORD[i]);
        if (k < 0 || (size_t)k >= cap - o) { out[0] = '\0'; return; }
        o += (size_t)k;
    }
}

int web_fid_atk_parse(const char *s, unsigned *types) {
    *types = 0;
    if (!s || !s[0]) return -1;
    for (const char *p = s;;) {
        size_t n = strcspn(p, ",");
        int hit = -1;
        for (int i = 0; i < 3; i++)
            if (strlen(ATK_WORD[i]) == n && !strncmp(ATK_WORD[i], p, n)) hit = i;
        if (hit < 0 || (*types & (1u << hit))) return -1;
        *types |= 1u << hit;
        p += n;
        if (!*p) break;
        p++;
    }
    /* One pair's half is either attributed the impostor or not. */
    if ((*types & WEB_FID_ATK_TWIN) && (*types & WEB_FID_ATK_UNATTR)) return -1;
    return 0;
}

typedef struct {
    web_fid_atk_t *a;
    int            n;
} atk_acc_t;

static int atk_take(void *ctx, const web_sdb_item_t *it) {
    atk_acc_t *x = ctx;
    char mac[WEB_KEY_MAX + 1];
    if (web_key_mac(it->a, mac) != 0) return 0;
    int t = it->n1 == WEB_ALERT_EVIL_TWIN ? 0 : it->n1 == WEB_ALERT_KARMA_AP ? 1 : -1;
    if (t < 0) return 0;
    /* Rows come by BSSID then type: one BSSID's types are adjacent. */
    web_fid_atk_t *e = x->n > 0 && !strcmp(x->a[x->n - 1].bssid, mac) ? &x->a[x->n - 1] : NULL;
    if (!e) {
        if (x->n >= WEB_FID_ATK_MAX) return 1;
        e = &x->a[x->n++];
        memset(e, 0, sizeof(*e));
        scpy(e->bssid, sizeof(e->bssid), mac);
    }
    if (!e->tl[t] || it->first_seen < e->tf[t]) e->tf[t] = it->first_seen;
    if (!e->tl[t] || it->last_seen > e->tl[t]) e->tl[t] = it->last_seen;
    if (e->tf[t] > e->tl[t]) e->tf[t] = e->tl[t];
    return 0;
}

static int by_atk(const void *pa, const void *pb) {
    return strcmp(((const web_fid_atk_t *)pa)->bssid, ((const web_fid_atk_t *)pb)->bssid);
}

/* An EVIL_TWIN BSSID's part, by the stream's attribution of the pairs
 * naming it since from: WEB_FID_ATK_TWIN when one attributed pair names
 * it the impostor, 0 when the attributed pairs name it only the real AP,
 * WEB_FID_ATK_UNATTR when no pair naming it is attributed. */
static unsigned twin_part(struct web_chain *chain, const char *bssid, long long from) {
    if (!chain) return WEB_FID_ATK_UNATTR;
    web_chain_pair_t lk[WEB_CHAIN_LINKS];
    long long since = 0;
    int nl = web_chain_links(chain, bssid, from, T_MAX, lk, WEB_CHAIN_LINKS, &since);
    int real = 0;
    for (int i = 0; i < nl; i++) {
        if (!lk[i].attributed) continue;
        if (!strcmp(lk[i].twin, bssid)) return WEB_FID_ATK_TWIN;
        if (!strcmp(lk[i].real, bssid)) real = 1;
    }
    return real ? 0 : WEB_FID_ATK_UNATTR;
}

int web_fid_atk_read(web_sdb_conn_t *c, long long from, struct web_chain *chain,
                     web_fid_atk_t **out) {
    *out = NULL;
    atk_acc_t x;
    x.a = malloc(sizeof(web_fid_atk_t) * WEB_FID_ATK_MAX);
    x.n = 0;
    if (!x.a) return -1;
    /* Two items a BSSID at most, so twice the cap covers it. */
    int r = web_sdb_ap_attacks(c, from, T_MAX, 2 * WEB_FID_ATK_MAX, atk_take, &x);
    if (r < 0) { free(x.a); return -1; }
    int o = 0;
    for (int i = 0; i < x.n; i++) {
        web_fid_atk_t *e = &x.a[i];
        unsigned tw = e->tl[0] ? twin_part(chain, e->bssid, from) : 0;
        e->types = tw | (e->tl[1] ? WEB_FID_ATK_KARMA : 0u);
        if (!e->types) continue;          /* only the real half of a twin pair */
        /* The times of the kinds kept: the real half's twin alert is not
         * this AP's attack. */
        int t0 = tw != 0, t1 = e->tl[1] != 0;
        e->first = t0 && t1 ? (e->tf[0] < e->tf[1] ? e->tf[0] : e->tf[1]) : t0 ? e->tf[0] : e->tf[1];
        e->last = t0 && t1 ? (e->tl[0] > e->tl[1] ? e->tl[0] : e->tl[1]) : t0 ? e->tl[0] : e->tl[1];
        x.a[o++] = *e;
    }
    x.n = o;
    qsort(x.a, (size_t)x.n, sizeof(x.a[0]), by_atk);
    *out = x.a;
    return x.n;
}

const web_fid_atk_t *web_fid_atk_find(const web_fid_atk_t *a, int n, const char *bssid) {
    if (!a || n <= 0 || !bssid) return NULL;
    web_fid_atk_t k;
    memset(&k, 0, sizeof(k));
    scpy(k.bssid, sizeof(k.bssid), bssid);
    return bsearch(&k, a, (size_t)n, sizeof(a[0]), by_atk);
}

/* ── reach ─────────────────────────────────────────────────────────── */

int web_fid_floor(const web_fid_site_t *s) {
    int have = 0, f = 0;
    for (int i = 0; i < s->nap; i++) {
        const web_fid_ap_t *a = &s->ap[i];
        if (!a->has_rssi || a->rssi >= 0 || a->rssi < -150) continue;
        if (!have || a->rssi < f) f = a->rssi;
        have = 1;
    }
    if (!have) return WEB_FID_FLOOR_DEF;
    if (f < WEB_FID_FLOOR_MIN) f = WEB_FID_FLOOR_MIN;
    if (f > WEB_FID_FLOOR_MAX) f = WEB_FID_FLOOR_MAX;
    return f;
}

/* An AP at sloth's assumed power heard at rssi less the margin, by the
 * P.1238 model at 2.4 GHz (the band that carries furthest): the
 * farthest it can plausibly be. */
static double model_m(int rssi) {
    if (rssi > -1) rssi = -1;
    if (rssi < -127) rssi = -127;
    double d = rf_distance_m(RF_PTX_AP_ASSUMED, rssi - (int)WEB_FID_MARGIN_DB, 2437,
                             RF_N_2G_X10, 0.0);
    return isfinite(d) && d > 0 ? d : 0.0;
}

double web_fid_reach_m(int floor_dbm) {
    return model_m(floor_dbm);
}

double web_fid_upper_m(int rssi_dbm) {
    return model_m(rssi_dbm);
}

/* ── the findings ──────────────────────────────────────────────────── */

static int by_ap(const void *pa, const void *pb) {
    return strcmp(((const web_fid_ap_t *)pa)->bssid, ((const web_fid_ap_t *)pb)->bssid);
}

static const web_fid_ap_t *ap_find(const web_fid_site_t *s, const char *bssid) {
    if (!s->ap || s->nap <= 0) return NULL;
    web_fid_ap_t k;
    memset(&k, 0, sizeof(k));
    scpy(k.bssid, sizeof(k.bssid), bssid);
    return bsearch(&k, s->ap, (size_t)s->nap, sizeof(s->ap[0]), by_ap);
}

static int by_ver(const void *pa, const void *pb) {
    return strcmp(((const web_fid_ver_t *)pa)->addr, ((const web_fid_ver_t *)pb)->addr);
}

static const web_fid_ver_t *ver_find(const web_fid_site_t *s, const char *addr) {
    if (!s->ver || s->nver <= 0) return NULL;
    web_fid_ver_t k;
    memset(&k, 0, sizeof(k));
    scpy(k.addr, sizeof(k.addr), addr);
    return bsearch(&k, s->ver, (size_t)s->nver, sizeof(s->ver[0]), by_ver);
}

static int ver_state(const web_fid_site_t *s, const char *addr) {
    const web_fid_ver_t *v = ver_find(s, addr);
    return v ? v->state : -1;
}

static int own_bssid(const web_fid_site_t *s, const char *b) {
    for (int i = 0; i < s->mine.nbssid; i++)
        if (!strcmp(s->mine.bssid[i], b)) return 1;
    return 0;
}

static int own_ssid(const web_fid_site_t *s, const char *ssid) {
    for (int i = 0; i < s->mine.nssid; i++)
        if (!strcmp(s->mine.ssid[i], ssid)) return 1;
    return 0;
}

/* The distance between two sites: 1 and *d, or 0 when either has no
 * position. */
static int site_dist(const web_fid_site_t *a, const web_fid_site_t *b, double *d) {
    if (!a->has_pos || !b->has_pos) return 0;
    *d = web_fleet_dist_m(a->lat, a->lon, b->lat, b->lon);
    return isfinite(*d);
}

typedef struct {
    web_fid_t *out;
    int        max, n, found;
} acc_t;

static web_fid_t *add(acc_t *x, int sub, const char *key) {
    x->found++;
    if (x->n >= x->max) return NULL;
    web_fid_t *f = &x->out[x->n++];
    memset(f, 0, sizeof(*f));
    f->sub = sub;
    f->cls = SUB_CLASS[sub];
    scpy(f->key, sizeof(f->key), key);
    f->applicable = 1;
    return f;
}

static web_fid_leg_t *leg(web_fid_t *f, int site, const char *key, const char *role) {
    if (f->nleg >= WEB_FID_SITES) return NULL;
    web_fid_leg_t *l = &f->leg[f->nleg++];
    memset(l, 0, sizeof(*l));
    l->site = site;
    scpy(l->key, sizeof(l->key), key);
    scpy(l->role, sizeof(l->role), role);
    l->state = -1;
    return l;
}

static void leg_ap(web_fid_leg_t *l, const web_fid_ap_t *a) {
    if (!l || !a) return;
    l->has_t = 1;
    l->first = a->first;
    l->last = a->last;
    l->has_rssi = a->has_rssi;
    l->rssi = a->rssi;
    l->atk = a->atk;
}

/* Distance judged: applicable when the sites are further apart than
 * bound, else not ("co_located"); "no_position" without one. */
static void judge(web_fid_t *f, const web_fid_site_t *a, const web_fid_site_t *b, double bound) {
    double d;
    f->bound_m = bound;
    if (!site_dist(a, b, &d)) {
        f->applicable = 0;
        f->reason = "no_position";
        return;
    }
    f->has_dist = 1;
    f->dist_m = d;
    if (d <= bound) {
        f->applicable = 0;
        f->reason = "co_located";
    }
}

/* Every other site's verdict on key, as legs. */
static void verdict_legs(web_fid_t *f, const web_fid_site_t *s, int n, const char *key) {
    for (int i = 0; i < n; i++) {
        int seen = 0;
        for (int j = 0; j < f->nleg; j++)
            if (f->leg[j].site == i) { f->leg[j].state = ver_state(&s[i], key); seen = 1; }
        if (seen) continue;
        int st = ver_state(&s[i], key);
        if (st < 0) continue;
        web_fid_leg_t *l = leg(f, i, key, "verdict");
        if (l) l->state = st;
    }
}

static int known_anywhere(const web_fid_site_t *s, int n, const char *key) {
    for (int i = 0; i < n; i++)
        if (ver_state(&s[i], key) == WEB_TRI_KNOWN) return 1;
    return 0;
}

static int out_anywhere(const web_fid_site_t *s, int n, const char *key) {
    for (int i = 0; i < n; i++)
        if (web_frrs_state_out(ver_state(&s[i], key))) return 1;
    return 0;
}

static int own_anywhere(const web_fid_site_t *s, int n, const char *bssid) {
    for (int i = 0; i < n; i++)
        if (own_bssid(&s[i], bssid)) return 1;
    return 0;
}

/* I2: a client at a probing for an SSID b names as its own. */
static void run_i2(const web_fid_site_t *s, int n, acc_t *x) {
    for (int a = 0; a < n; a++)
    for (int b = 0; b < n; b++) {
        if (a == b) continue;
        for (int k = 0; k < s[b].mine.nssid; k++) {
            const char *ssid = s[b].mine.ssid[k];
            /* Also a's own network: a's own sensor's question
             * (MY_NETWORK_RECON), not a cross-site one. */
            if (own_ssid(&s[a], ssid)) continue;
            for (int p = 0; p < s[a].nprobe; p++) {
                const web_fid_probe_t *pr = &s[a].probe[p];
                if (strcmp(pr->ssid, ssid)) continue;
                web_fid_t *f = add(x, WEB_FID_PROBE_OTHER, pr->mac);
                if (!f) continue;
                scpy(f->ssid, sizeof(f->ssid), ssid);
                f->first = pr->first;
                f->last = pr->last;
                web_fid_leg_t *l = leg(f, a, pr->mac, "prober");
                if (l) { l->has_t = 1; l->first = pr->first; l->last = pr->last; }
                leg(f, b, ssid, "owner");
                verdict_legs(f, s, n, pr->mac);
                f->exonerated = known_anywhere(s, n, pr->mac);
                /* A lead: an SSID names a network only as uniquely as
                 * its name, and at sites within each other's reach a
                 * client near one is near the other, so it says nothing
                 * about having been at b. */
                f->lead = 1;
                f->note = "a lead: the client has joined a network of this name, which is "
                          "the other site's only if the name is unique to it";
                double d;
                if (site_dist(&s[a], &s[b], &d)) {
                    f->has_dist = 1;
                    f->dist_m = d;
                    f->bound_m = web_fid_reach_m(web_fid_floor(&s[a])) +
                                 web_fid_reach_m(web_fid_floor(&s[b]));
                    if (d <= f->bound_m) {
                        f->applicable = 0;
                        f->reason = "co_located";
                        f->note = "the client may live at or near both sites; probing "
                                  "the other's network is then the norm";
                    }
                }
            }
        }
    }
}

/* The farthest a's own network reaches from a's sensor: the upper bound
 * of each own BSSID a hears, else a's whole reach. */
static double own_extent(const web_fid_site_t *a) {
    double m = 0;
    int any = 0;
    for (int i = 0; i < a->mine.nbssid; i++) {
        const web_fid_ap_t *ap = ap_find(a, a->mine.bssid[i]);
        if (!ap || !ap->has_rssi) continue;
        double u = web_fid_upper_m(ap->rssi);
        if (u > m) m = u;
        any = 1;
    }
    return any ? m : web_fid_reach_m(web_fid_floor(a));
}

/* I3: a's own network heard at b. */
static void run_i3(const web_fid_site_t *s, int n, acc_t *x) {
    for (int a = 0; a < n; a++)
    for (int b = 0; b < n; b++) {
        if (a == b) continue;
        const web_fid_site_t *A = &s[a], *B = &s[b];
        double reach_b = web_fid_reach_m(web_fid_floor(B));
        /* (i) one of a's own BSSIDs. */
        for (int k = 0; k < A->mine.nbssid; k++) {
            const web_fid_ap_t *hb = ap_find(B, A->mine.bssid[k]);
            if (!hb) continue;
            const web_fid_ap_t *ha = ap_find(A, A->mine.bssid[k]);
            web_fid_t *f = add(x, WEB_FID_OWN_BSSID, hb->bssid);
            if (!f) continue;
            scpy(f->ssid, sizeof(f->ssid), hb->ssid);
            f->first = hb->first;
            f->last = hb->last;
            leg_ap(leg(f, a, hb->bssid, "owner"), ha);
            leg_ap(leg(f, b, hb->bssid, "observer"), hb);
            judge(f, A, B, (ha && ha->has_rssi ? web_fid_upper_m(ha->rssi)
                                               : web_fid_reach_m(web_fid_floor(A))) + reach_b);
        }
        /* (ii) one of a's own SSIDs from a BSSID a does not name. */
        if (!A->mine.nssid) continue;
        for (int i = 0; i < B->nap; i++) {
            const web_fid_ap_t *hb = &B->ap[i];
            if (!hb->ssid[0] || !own_ssid(A, hb->ssid) || own_bssid(A, hb->bssid)) continue;
            /* b's own network of the same name: b's business. */
            if (own_bssid(B, hb->bssid)) continue;
            const web_fid_ap_t *ha = ap_find(A, hb->bssid);
            int unlisted = ha && !strcmp(ha->ssid, hb->ssid);
            web_fid_t *f = add(x, unlisted ? WEB_FID_OWN_BSSID : WEB_FID_FOREIGN_BSSID, hb->bssid);
            if (!f) continue;
            scpy(f->ssid, sizeof(f->ssid), hb->ssid);
            f->first = hb->first;
            f->last = hb->last;
            leg_ap(leg(f, a, hb->bssid, "owner"), ha);
            leg_ap(leg(f, b, hb->bssid, "observer"), hb);
            if (unlisted) {
                f->note = "not named by --my-bssid, but carrying the owner's SSID at the owner";
                judge(f, A, B, (ha->has_rssi ? web_fid_upper_m(ha->rssi)
                                             : web_fid_reach_m(web_fid_floor(A))) + reach_b);
            } else if (!A->mine.nbssid) {
                double d;
                f->applicable = 0;
                f->reason = "no_own_bssid";
                if (site_dist(A, B, &d)) { f->has_dist = 1; f->dist_m = d; }
            } else {
                judge(f, A, B, own_extent(A) + reach_b);
            }
        }
    }
}

/* I3: one BSSID heard at two sites at once, the sites beyond both
 * reaches. Listed only then: at co-located sites it is the norm. */
static void run_two_places(const web_fid_site_t *s, int n, acc_t *x) {
    for (int a = 0; a < n; a++)
    for (int b = a + 1; b < n; b++) {
        const web_fid_site_t *A = &s[a], *B = &s[b];
        double d;
        if (!site_dist(A, B, &d)) continue;
        double bound = web_fid_reach_m(web_fid_floor(A)) + web_fid_reach_m(web_fid_floor(B));
        if (d <= bound) continue;
        for (int i = 0, j = 0; i < A->nap && j < B->nap;) {
            int c = strcmp(A->ap[i].bssid, B->ap[j].bssid);
            if (c < 0) { i++; continue; }
            if (c > 0) { j++; continue; }
            const web_fid_ap_t *ha = &A->ap[i], *hb = &B->ap[j];
            i++;
            j++;
            /* One site's own BSSID is (i)'s finding. */
            if (own_bssid(A, ha->bssid) || own_bssid(B, ha->bssid)) continue;
            long long dt = ha->last > hb->last ? ha->last - hb->last : hb->last - ha->last;
            if (dt > WEB_FID_SIMUL_S) continue;
            web_fid_t *f = add(x, WEB_FID_TWO_PLACES, ha->bssid);
            if (!f) continue;
            scpy(f->ssid, sizeof(f->ssid), hb->ssid[0] ? hb->ssid : ha->ssid);
            f->first = ha->first < hb->first ? ha->first : hb->first;
            f->last = ha->last > hb->last ? ha->last : hb->last;
            leg_ap(leg(f, a, ha->bssid, "observer"), ha);
            leg_ap(leg(f, b, hb->bssid, "observer"), hb);
            f->has_dist = 1;
            f->dist_m = d;
            f->bound_m = bound;
        }
    }
}

/* I4: one fingerprint with an attack alert at two or more sites. */
typedef struct {
    char  fp[WEB_FID_KEY];
    int   site;
    const web_fid_ap_t *ap;
} cand_t;

static int by_cand(const void *pa, const void *pb) {
    const cand_t *a = pa, *b = pb;
    int c = strcmp(a->fp, b->fp);
    if (c) return c;
    if (a->site != b->site) return a->site - b->site;
    if (a->ap->atk_first != b->ap->atk_first) return a->ap->atk_first < b->ap->atk_first ? -1 : 1;
    return strcmp(a->ap->bssid, b->ap->bssid);
}

static int by_leg_time(const void *pa, const void *pb) {
    const web_fid_leg_t *a = pa, *b = pb;
    if (a->first != b->first) return a->first < b->first ? -1 : 1;
    return a->site - b->site;
}

static void run_i4(const web_fid_site_t *s, int n, acc_t *x) {
    int total = 0;
    for (int i = 0; i < n; i++) total += s[i].nap;
    if (!total) return;
    cand_t *c = malloc(sizeof(cand_t) * (size_t)total);
    if (!c) return;
    int nc = 0;
    for (int i = 0; i < n; i++)
        for (int k = 0; k < s[i].nap; k++) {
            const web_fid_ap_t *a = &s[i].ap[k];
            /* No attack alert at this site: the fingerprint counts for
             * nothing here. An own BSSID, or one any site triaged out,
             * is not a tool. */
            if (!a->ie[0] || !(a->atk & WEB_FID_ATK_ATTACKER) || own_anywhere(s, n, a->bssid) ||
                out_anywhere(s, n, a->bssid))
                continue;
            cand_t *e = &c[nc++];
            snprintf(e->fp, sizeof(e->fp), "%s/%s", a->ie, a->vie[0] ? a->vie : "-");
            e->site = i;
            e->ap = a;
        }
    qsort(c, (size_t)nc, sizeof(c[0]), by_cand);
    for (int g = 0; g < nc;) {
        int h = g, sites = 0, last_site = -1;
        while (h < nc && !strcmp(c[h].fp, c[g].fp)) {
            if (c[h].site != last_site) { sites++; last_site = c[h].site; }
            h++;
        }
        if (sites >= 2) {
            web_fid_t *f = add(x, WEB_FID_TOOL, c[g].fp);
            if (f) {
                f->lead = 1;
                f->note = "a lead, not a detection: the same beacon fingerprint on an AP "
                          "sloth named the attacker at each site; confirm it on the air";
                f->first = T_MAX;
                last_site = -1;
                for (int k = g; k < h; k++) {
                    /* Each site's earliest attack (the sort put it first). */
                    if (c[k].site == last_site) continue;
                    last_site = c[k].site;
                    web_fid_leg_t *l = leg(f, c[k].site, c[k].ap->bssid, "tool");
                    if (!l) break;
                    l->has_t = 1;
                    l->first = c[k].ap->atk_first;
                    l->last = c[k].ap->atk_last;
                    l->has_rssi = c[k].ap->has_rssi;
                    l->rssi = c[k].ap->rssi;
                    l->atk = c[k].ap->atk;
                    if (l->first < f->first) f->first = l->first;
                    if (l->last > f->last) f->last = l->last;
                }
                qsort(f->leg, (size_t)f->nleg, sizeof(f->leg[0]), by_leg_time);
                /* Travel needs distance: one pair of the sites beyond
                 * both reaches. */
                int far = 0, nopos = 0;
                for (int i = 0; i < f->nleg; i++)
                    for (int j = i + 1; j < f->nleg; j++) {
                        const web_fid_site_t *A = &s[f->leg[i].site], *B = &s[f->leg[j].site];
                        double d;
                        if (!site_dist(A, B, &d)) { nopos = 1; continue; }
                        double bound = web_fid_reach_m(web_fid_floor(A)) +
                                       web_fid_reach_m(web_fid_floor(B));
                        if (!f->has_dist || d > f->dist_m) {
                            f->has_dist = 1;
                            f->dist_m = d;
                            f->bound_m = bound;
                        }
                        if (d > bound) far = 1;
                    }
                if (!far) {
                    f->applicable = 0;
                    f->reason = nopos && !f->has_dist ? "no_position" : "co_located";
                }
            }
        }
        g = h;
    }
    free(c);
}

/* I8: one address known at one site and incident at another. */
typedef struct {
    const web_fid_ver_t *v;
    int site;
} vref_t;

static int by_vref(const void *pa, const void *pb) {
    const vref_t *a = pa, *b = pb;
    int c = strcmp(a->v->addr, b->v->addr);
    return c ? c : a->site - b->site;
}

static void run_i8(const web_fid_site_t *s, int n, acc_t *x) {
    int total = 0;
    for (int i = 0; i < n; i++) total += s[i].nver;
    if (!total) return;
    vref_t *r = malloc(sizeof(vref_t) * (size_t)total);
    if (!r) return;
    int nr = 0;
    for (int i = 0; i < n; i++)
        for (int k = 0; k < s[i].nver; k++) { r[nr].v = &s[i].ver[k]; r[nr].site = i; nr++; }
    qsort(r, (size_t)nr, sizeof(r[0]), by_vref);
    for (int g = 0; g < nr;) {
        int h = g, known = 0, inc = 0;
        while (h < nr && !strcmp(r[h].v->addr, r[g].v->addr)) {
            known |= r[h].v->state == WEB_TRI_KNOWN;
            inc |= r[h].v->state == WEB_TRI_INCIDENT;
            h++;
        }
        if (known && inc) {
            web_fid_t *f = add(x, WEB_FID_CONFLICT, r[g].v->addr);
            if (f) {
                long long newest = 0;
                f->first = T_MAX;
                for (int k = g; k < h; k++) {
                    web_fid_leg_t *l = leg(f, r[k].site, r[k].v->addr, "verdict");
                    if (!l) break;
                    l->state = r[k].v->state;
                    l->has_t = 1;
                    l->first = l->last = r[k].v->ts;
                    if (r[k].v->ts < f->first) f->first = r[k].v->ts;
                    if (r[k].v->ts > f->last) f->last = r[k].v->ts;
                    if (r[k].v->ts >= newest) {
                        newest = r[k].v->ts;
                        scpy(f->vtype, sizeof(f->vtype), r[k].v->type);
                    }
                }
            }
        }
        g = h;
    }
    free(r);
}

static int rank(const web_fid_t *f) {
    return f->applicable && !f->exonerated ? 0 : f->exonerated ? 2 : 1;
}

static int by_rank(const void *pa, const void *pb) {
    const web_fid_t *a = pa, *b = pb;
    int ra = rank(a), rb = rank(b);
    if (ra != rb) return ra - rb;
    if (a->last != b->last) return a->last < b->last ? 1 : -1;
    if (a->cls != b->cls) return a->cls - b->cls;
    return strcmp(a->key, b->key);
}

int web_fid_run(const web_fid_site_t *sites, int n, web_fid_t *out, int max) {
    acc_t x;
    memset(&x, 0, sizeof(x));
    x.out = out;
    x.max = max;
    if (!sites || n <= 0 || !out || max <= 0) return 0;
    run_i2(sites, n, &x);
    run_i3(sites, n, &x);
    run_two_places(sites, n, &x);
    run_i4(sites, n, &x);
    run_i8(sites, n, &x);
    for (int i = 0; i < x.n; i++) {
        web_fid_t *f = &out[i];
        if (f->first > f->last) f->first = f->last;
        if (f->has_dist && (!isfinite(f->dist_m) || !isfinite(f->bound_m))) f->has_dist = 0;
    }
    qsort(out, (size_t)x.n, sizeof(out[0]), by_rank);
    return x.found;
}

/* ── the sites ─────────────────────────────────────────────────────── */

typedef struct {
    web_fid_site_t s[WEB_FID_SITES];
    long long      skew[WEB_FID_SITES];
    long long      own_n[WEB_FID_SITES];   /* the peer's newest ident answer's count */
    int            n;
    const char    *local;                  /* sloth.db: open, partial, unavailable, none */
    int            store, partial;
} fctx_t;

static void ctx_free(fctx_t *x) {
    for (int i = 0; i < x->n; i++) {
        free(x->s[i].ap);
        free(x->s[i].probe);
        free(x->s[i].ver);
    }
}

/* Every site's own SSIDs but site i's: the probes worth reading there. */
static int wanted_ssids(const fctx_t *x, int i, const char **out, int max) {
    int n = 0;
    for (int j = 0; j < x->n; j++) {
        if (j == i) continue;
        for (int k = 0; k < x->s[j].mine.nssid; k++) {
            const char *ss = x->s[j].mine.ssid[k];
            if (own_ssid(&x->s[i], ss)) continue;
            int dup = 0;
            for (int m = 0; m < n; m++) if (!strcmp(out[m], ss)) dup = 1;
            if (!dup && n < max) out[n++] = ss;
        }
    }
    return n;
}

static int probe_push(web_fid_site_t *s, int *cap, const char *mac, const char *ssid,
                      long long first, long long last) {
    if (s->nprobe >= *cap) {
        int nc = *cap ? *cap * 2 : 64;
        web_fid_probe_t *p = realloc(s->probe, sizeof(*p) * (size_t)nc);
        if (!p) return -1;
        s->probe = p;
        *cap = nc;
    }
    web_fid_probe_t *p = &s->probe[s->nprobe++];
    memset(p, 0, sizeof(*p));
    scpy(p->mac, sizeof(p->mac), mac);
    scpy(p->ssid, sizeof(p->ssid), ssid);
    p->first = first;
    p->last = last;
    return 0;
}

static int ver_push(web_fid_site_t *s, const char *addr, const char *type, int state,
                    long long ts) {
    if (s->nver >= WEB_FID_VER_MAX) return 1;
    web_fid_ver_t *v = &s->ver[s->nver++];
    memset(v, 0, sizeof(*v));
    scpy(v->addr, sizeof(v->addr), addr);
    scpy(v->type, sizeof(v->type), type ? type : "");
    v->state = state;
    v->ts = ts;
    return 0;
}

static int by_ver_ts(const void *pa, const void *pb) {
    const web_fid_ver_t *a = pa, *b = pb;
    int c = strcmp(a->addr, b->addr);
    if (c) return c;
    return a->ts < b->ts ? 1 : a->ts > b->ts ? -1 : 0;
}

/* Sorted by address, the newest verdict on each kept. */
static void ver_settle(web_fid_site_t *s) {
    if (!s->ver || s->nver <= 0) return;
    qsort(s->ver, (size_t)s->nver, sizeof(s->ver[0]), by_ver_ts);
    int o = 0;
    for (int i = 0; i < s->nver; i++)
        if (!o || strcmp(s->ver[o - 1].addr, s->ver[i].addr)) s->ver[o++] = s->ver[i];
    s->nver = o;
}


/* This site: sloth.db (APs, the attacks, the probes of the others' own
 * SSIDs) through the M4 reader, the beacon ledger's fingerprints, and
 * triage's current verdicts. */
typedef struct {
    web_fid_site_t *s;
    int             cap;
    long long       from;
    struct web_frrs *frrs;
    const web_fid_atk_t *atk;
    int             natk;
} self_t;

static int self_ap(void *ctx, const web_sdb_ap_t *a) {
    self_t *x = ctx;
    if (a->last_seen < x->from) return 0;
    if (x->s->nap >= WEB_FID_AP_MAX) return 1;
    char mac[WEB_KEY_MAX + 1];
    if (web_key_mac(a->bssid, mac) != 0) return 0;
    web_fid_ap_t *o = &x->s->ap[x->s->nap++];
    memset(o, 0, sizeof(*o));
    scpy(o->bssid, sizeof(o->bssid), mac);
    if (strlen(a->ssid) <= WEB_FLEET_SSID_MAX) scpy(o->ssid, sizeof(o->ssid), a->ssid);
    o->has_rssi = a->has_signal && a->signal_dbm < 0 && a->signal_dbm >= -150;
    o->rssi = a->signal_dbm;
    o->first = a->first_seen;
    o->last = a->last_seen;
    web_frrs_fp_t fp;
    if (web_frrs_fp(x->frrs, mac, &fp)) {
        scpy(o->ie, sizeof(o->ie), strlen(fp.ie) <= WEB_FID_HASH_MAX ? fp.ie : "");
        scpy(o->vie, sizeof(o->vie), strlen(fp.vie) <= WEB_FID_HASH_MAX ? fp.vie : "");
        scpy(o->wps[0], sizeof(o->wps[0]), fp.wps_manuf);
        scpy(o->wps[1], sizeof(o->wps[1]), fp.wps_model);
        scpy(o->wps[2], sizeof(o->wps[2]), fp.wps_num);
    }
    const web_fid_atk_t *at = web_fid_atk_find(x->atk, x->natk, mac);
    if (at) {
        o->atk = at->types;
        o->atk_first = at->first;
        o->atk_last = at->last;
    }
    return 0;
}

typedef struct {
    web_fid_site_t *s;
    int            *cap;
    const char     *ssid;
} prober_t;

static int self_probe(void *ctx, const web_sdb_item_t *it) {
    prober_t *p = ctx;
    char mac[WEB_KEY_MAX + 1];
    if (web_key_mac(it->a, mac) != 0) return 0;
    return probe_push(p->s, p->cap, mac, p->ssid, it->first_seen, it->last_seen) != 0;
}

static int self_ver(void *ctx, const web_frrs_verdict_t *v) {
    web_fid_site_t *s = ctx;
    char a[WEB_KEY_MAX + 1];
    if (!v->addr[0] || (web_key_mac(v->addr, a) != 0 && web_key_ip(v->addr, a) != 0)) return 0;
    const web_akb_t *k = web_akb_get(v->type);
    return ver_push(s, a, k ? k->name : "", v->state, v->ts);
}

static void self_site(fctx_t *x, web_fleet_t *f, const web_fleet_src_t *src, long long now_s) {
    web_fid_site_t *s = &x->s[0];
    snprintf(s->name, sizeof(s->name), "self");
    s->self = 1;
    s->offered = 1;
    s->own_ts = now_s;
    if (src && src->mine) s->mine = *src->mine;
    else if (f) s->mine = f->mine;
    if (src && src->gnss) {
        web_loc_t loc;
        web_gnss_sh_t sh;
        web_gnss_site(src->gnss, &loc, &sh);
        if (loc.has && isfinite(loc.lat) && isfinite(loc.lon)) {
            s->has_pos = 1;
            s->lat = loc.lat;
            s->lon = loc.lon;
        }
    }
}

static void self_rows(fctx_t *x, const web_fleet_src_t *src, long long now_s) {
    web_fid_site_t *s = &x->s[0];
    s->ver = malloc(sizeof(web_fid_ver_t) * WEB_FID_VER_MAX);
    if (s->ver && src && src->frrs) {
        if (web_frrs_verdicts(src->frrs, 0, -1, 0, WEB_FID_VER_MAX, self_ver, s) < 0)
            x->partial = 1;
        ver_settle(s);
    }
    if (!src || !src->sdb || !src->sdb->configured) return;
    web_sdb_conn_t c;
    memset(&c, 0, sizeof(c));
    char err[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(src->sdb, &c, WEB_SDB_OVERVIEW_MS, now_s, err, sizeof(err)) != 0) {
        web_slothdb_close(&c);
        x->local = "unavailable";
        return;
    }
    x->local = "open";
    web_sdb_session_t ss;
    if (web_sdb_sessions(&c, &ss, 1) == 1 && strlen(ss.label) <= WEB_FLEET_STR_MAX)
        scpy(s->label, sizeof(s->label), ss.label);
    long long from = now_s - WEB_FID_WINDOW_S;
    web_fid_atk_t *atk = NULL;
    int natk = web_fid_atk_read(&c, from, src->chain, &atk);
    if (natk < 0) { natk = 0; x->local = "partial"; }
    s->ap = malloc(sizeof(web_fid_ap_t) * WEB_FID_AP_MAX);
    if (s->ap) {
        self_t st = { s, 0, from, src->frrs, atk, natk };
        if (web_sdb_aps(&c, WEB_AP_SORT_LAST, WEB_FID_AP_MAX + 1, 0, self_ap, &st) < 0 ||
            c.timed_out)
            x->local = "partial";
        qsort(s->ap, (size_t)s->nap, sizeof(s->ap[0]), by_ap);
    }
    free(atk);
    const char *want[WEB_FID_SITES * WEB_FLEET_MINE_MAX];
    int nw = wanted_ssids(x, 0, want, (int)(sizeof(want) / sizeof(want[0])));
    int cap = 0;
    for (int i = 0; i < nw && !c.timed_out; i++) {
        long long nr = 0;
        prober_t p = { s, &cap, want[i] };
        if (web_sdb_ssid_probers(&c, want[i], from, WEB_FID_PROBE_MAX, self_probe, &p, &nr) < 0)
            x->local = "partial";
        s->randomised += nr;
    }
    if (c.timed_out) x->local = "partial";
    web_slothdb_close(&c);
}

#ifdef WITH_SQLITE
/* A MAC whose first octet's locally administered bit is set: a
 * randomised probe address, not one device. */
static int mac_random(const char *mac) {
    char c = mac[1];
    int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : 0;
    return (v & 2) != 0;
}

/* A stored extra (an object the importer wrote) as a record. */
static int extra_rec(const unsigned char *ex, web_jrec_t *rec) {
    if (!ex || ex[0] != '{') return -1;
    char buf[2400];
    int k = snprintf(buf, sizeof(buf), "{\"type\":\"x\"%s%s", ex[1] == '}' ? "" : ",",
                     (const char *)ex + 1);
    if (k < 0 || (size_t)k >= sizeof(buf)) return -1;
    return web_jl_parse(buf, (size_t)k, rec) == WEB_JL_OK ? 0 : -1;
}

static void copy_str(const web_jrec_t *r, const char *k, char *out, size_t cap) {
    const char *s = web_jl_str(r, k);
    out[0] = '\0';
    if (s && strlen(s) < cap) memcpy(out, s, strlen(s) + 1);
}

static int digits(const char *s) {
    return s[0] && strspn(s, "0123456789") == strlen(s);
}

static void text_of(sqlite3_stmt *st, int col, char *out, size_t cap) {
    const unsigned char *t = sqlite3_column_text(st, col);
    out[0] = '\0';
    if (t && strlen((const char *)t) < cap) memcpy(out, t, strlen((const char *)t) + 1);
}

/* Each peer's site row and own networks (first pass: what every site
 * names is needed before the probes are read). */
static void peer_heads(fctx_t *x, web_store_t *st, long long now_s) {
    pthread_mutex_lock(&st->rmu);
    sqlite3_stmt *ps = NULL, *mt = NULL, *on = NULL;
    int ok = sqlite3_prepare_v2(st->rd, "SELECT label,lat,lon,remote_ts,last_ok FROM peer_sites"
                                " WHERE peer=?1", -1, &ps, NULL) == SQLITE_OK &&
             sqlite3_prepare_v2(st->rd, "SELECT value FROM meta WHERE name=?1", -1, &mt,
                                NULL) == SQLITE_OK &&
             sqlite3_prepare_v2(st->rd, "SELECT key,label FROM peer_sightings WHERE peer=?1"
                                " AND kind='own_net' ORDER BY key LIMIT 64", -1, &on,
                                NULL) == SQLITE_OK;
    if (!ok) x->partial = 1;
    for (int i = 1; ok && i < x->n; i++) {
        web_fid_site_t *s = &x->s[i];
        sqlite3_reset(ps);
        sqlite3_bind_text(ps, 1, s->name, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(ps) == SQLITE_ROW) {
            text_of(ps, 0, s->label, sizeof(s->label));
            if (sqlite3_column_type(ps, 1) != SQLITE_NULL &&
                sqlite3_column_type(ps, 2) != SQLITE_NULL) {
                s->lat = sqlite3_column_double(ps, 1);
                s->lon = sqlite3_column_double(ps, 2);
                s->has_pos = isfinite(s->lat) && isfinite(s->lon) && fabs(s->lat) <= 90 &&
                             fabs(s->lon) <= 180;
            }
            long long rts = sqlite3_column_int64(ps, 3), lok = sqlite3_column_int64(ps, 4);
            x->skew[i] = rts > 0 && lok > 0 ? rts - lok : 0;
        }
        char nm[96];
        snprintf(nm, sizeof(nm), "fleet.ident.%s", s->name);
        sqlite3_reset(mt);
        sqlite3_bind_text(mt, 1, nm, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(mt) == SQLITE_ROW) {
            const unsigned char *v = sqlite3_column_text(mt, 0);
            long long g = 0, cnt = 0;
            if (v && sscanf((const char *)v, "%lld %lld", &g, &cnt) == 2 && g > 0 && g <= T_MAX) {
                s->offered = 1;
                s->own_ts = g - x->skew[i];
                x->own_n[i] = cnt;
                /* Named more than a day ago and not since (#196): the
                 * peer stopped offering them or stopped answering; its
                 * networks are no longer taken as its own. */
                s->own_expired = now_s - s->own_ts > WEB_FLEET_OWN_STALE_S;
            }
        }
        if (s->own_expired) continue;
        sqlite3_reset(on);
        sqlite3_bind_text(on, 1, s->name, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(on) == SQLITE_ROW) {
            char key[WEB_FLEET_STR_MAX + 8], lab[WEB_FLEET_STR_MAX + 1];
            text_of(on, 0, key, sizeof(key));
            text_of(on, 1, lab, sizeof(lab));
            char mac[WEB_KEY_MAX + 1];
            if (!strncmp(key, "ssid:", 5) && web_fleet_ssid_ok(lab) &&
                s->mine.nssid < WEB_FLEET_MINE_MAX)
                scpy(s->mine.ssid[s->mine.nssid++], WEB_FLEET_SSID_MAX + 1, lab);
            else if (!strncmp(key, "bssid:", 6) && web_key_mac(key + 6, mac) == 0 &&
                     s->mine.nbssid < WEB_FLEET_MINE_MAX)
                scpy(s->mine.bssid[s->mine.nbssid++], WEB_FLEET_MAC_SZ, mac);
        }
    }
    sqlite3_finalize(ps);
    sqlite3_finalize(mt);
    sqlite3_finalize(on);
    pthread_mutex_unlock(&st->rmu);
}

/* Each peer's APs, the probes of the other sites' own SSIDs, and its
 * verdicts; every time less the peer's skew. */
static void peer_rows(fctx_t *x, web_store_t *st, long long now_s) {
    web_jrec_t *rec = malloc(sizeof(*rec));
    if (!rec) { x->partial = 1; return; }
    pthread_mutex_lock(&st->rmu);
    sqlite3_stmt *ap = NULL, *pr = NULL, *vr = NULL;
    int ok = sqlite3_prepare_v2(st->rd, "SELECT key,label,rssi,first_seen,last_seen,extra FROM"
                                " peer_sightings WHERE peer=?1 AND kind='ap' AND last_seen>=?2"
                                " ORDER BY last_seen DESC LIMIT ?3", -1, &ap, NULL) == SQLITE_OK &&
             sqlite3_prepare_v2(st->rd, "SELECT key,first_seen,last_seen FROM peer_sightings"
                                " WHERE peer=?1 AND kind='probe' AND label=?2 AND last_seen>=?3"
                                " ORDER BY last_seen DESC LIMIT ?4", -1, &pr, NULL) == SQLITE_OK &&
             sqlite3_prepare_v2(st->rd, "SELECT label,last_seen,extra FROM peer_sightings WHERE"
                                " peer=?1 AND kind='verdict' ORDER BY last_seen DESC LIMIT ?2",
                                -1, &vr, NULL) == SQLITE_OK;
    if (!ok) x->partial = 1;
    for (int i = 1; ok && i < x->n; i++) {
        web_fid_site_t *s = &x->s[i];
        long long sk = x->skew[i];
        s->ap = malloc(sizeof(web_fid_ap_t) * WEB_FID_AP_MAX);
        s->ver = malloc(sizeof(web_fid_ver_t) * WEB_FID_VER_MAX);
        if (!s->ap || !s->ver) { x->partial = 1; continue; }
        sqlite3_reset(ap);
        sqlite3_bind_text(ap, 1, s->name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(ap, 2, now_s + sk - WEB_FID_WINDOW_S);
        sqlite3_bind_int(ap, 3, WEB_FID_AP_MAX);
        while (sqlite3_step(ap) == SQLITE_ROW) {
            char mac[WEB_KEY_MAX + 1], k[WEB_FLEET_STR_MAX + 1];
            text_of(ap, 0, k, sizeof(k));
            if (web_key_mac(k, mac) != 0) continue;
            web_fid_ap_t *o = &s->ap[s->nap++];
            memset(o, 0, sizeof(*o));
            scpy(o->bssid, sizeof(o->bssid), mac);
            text_of(ap, 1, o->ssid, sizeof(o->ssid));
            if (sqlite3_column_type(ap, 2) != SQLITE_NULL) {
                long long r = sqlite3_column_int64(ap, 2);
                o->has_rssi = r < 0 && r >= -150;
                o->rssi = (int)r;
            }
            o->first = sqlite3_column_int64(ap, 3) - sk;
            o->last = sqlite3_column_int64(ap, 4) - sk;
            if (extra_rec(sqlite3_column_text(ap, 5), rec) != 0) continue;
            copy_str(rec, "ie_fp", o->ie, sizeof(o->ie));
            copy_str(rec, "vie_fp", o->vie, sizeof(o->vie));
            if (!digits(o->ie)) o->ie[0] = '\0';
            if (!digits(o->vie)) o->vie[0] = '\0';
            copy_str(rec, "wps_manuf", o->wps[0], sizeof(o->wps[0]));
            copy_str(rec, "wps_model", o->wps[1], sizeof(o->wps[1]));
            copy_str(rec, "wps_num", o->wps[2], sizeof(o->wps[2]));
            const char *at = web_jl_str(rec, "attacks");
            unsigned types = 0;
            double af, al;
            if (at && web_fid_atk_parse(at, &types) == 0 && web_jl_num(rec, "attack_first", &af) &&
                web_jl_num(rec, "attack_last", &al) && af >= 0 && af <= al && al <= T_MAX) {
                o->atk = types;
                o->atk_first = (long long)af - sk;
                o->atk_last = (long long)al - sk;
            }
        }
        qsort(s->ap, (size_t)s->nap, sizeof(s->ap[0]), by_ap);
        const char *want[WEB_FID_SITES * WEB_FLEET_MINE_MAX];
        int nw = wanted_ssids(x, i, want, (int)(sizeof(want) / sizeof(want[0])));
        int cap = 0;
        for (int w = 0; w < nw; w++) {
            sqlite3_reset(pr);
            sqlite3_bind_text(pr, 1, s->name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(pr, 2, want[w], -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(pr, 3, now_s + sk - WEB_FID_WINDOW_S);
            sqlite3_bind_int(pr, 4, WEB_FID_PROBE_MAX);
            while (sqlite3_step(pr) == SQLITE_ROW) {
                char k[2 * WEB_FLEET_STR_MAX + 4], mac[WEB_KEY_MAX + 1];
                text_of(pr, 0, k, sizeof(k));
                char *bar = strchr(k, '|');
                if (!bar) continue;
                *bar = '\0';
                if (web_key_mac(k, mac) != 0) continue;
                if (mac_random(mac)) { s->randomised++; continue; }
                if (probe_push(s, &cap, mac, want[w], sqlite3_column_int64(pr, 1) - sk,
                               sqlite3_column_int64(pr, 2) - sk) != 0) {
                    x->partial = 1;
                    break;
                }
            }
        }
        sqlite3_reset(vr);
        sqlite3_bind_text(vr, 1, s->name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(vr, 2, WEB_FID_VER_MAX);
        while (sqlite3_step(vr) == SQLITE_ROW) {
            char lab[16];
            text_of(vr, 0, lab, sizeof(lab));
            int state = web_frrs_filter_find(lab);
            if (state < 0 || state >= WEB_TRI_COUNT) continue;
            if (extra_rec(sqlite3_column_text(vr, 2), rec) != 0) continue;
            const char *ad = web_jl_str(rec, "addr"), *ty = web_jl_str(rec, "alert_type");
            char a[WEB_KEY_MAX + 1];
            if (!ad || (web_key_mac(ad, a) != 0 && web_key_ip(ad, a) != 0)) continue;
            if (ver_push(s, a, ty && strlen(ty) < 48 ? ty : "", state,
                         sqlite3_column_int64(vr, 1) - sk))
                break;
        }
        ver_settle(s);
    }
    sqlite3_finalize(ap);
    sqlite3_finalize(pr);
    sqlite3_finalize(vr);
    pthread_mutex_unlock(&st->rmu);
    free(rec);
}
#endif

static int build(web_fleet_t *f, const web_fleet_src_t *src, long long now_s, fctx_t *x) {
    memset(x, 0, sizeof(*x));
    x->local = "none";
    x->n = 1;
    self_site(x, f, src, now_s);
    for (int i = 0; f && i < f->npeer && x->n < WEB_FID_SITES; i++)
        scpy(x->s[x->n++].name, WEB_FLEET_NAME_MAX + 1, f->peer[i].cfg.name);
#ifdef WITH_SQLITE
    web_store_t *st = f ? f->store : NULL;
    if (st && st->rd) {
        x->store = 1;
        if (x->n > 1) peer_heads(x, st, now_s);
    }
#endif
    self_rows(x, src, now_s);
#ifdef WITH_SQLITE
    if (st && st->rd && x->n > 1) peer_rows(x, st, now_s);
#endif
    return 0;
}

/* ── the answer ────────────────────────────────────────────────────── */

static void jnum(web_jw_t *w, int has, double v, int dp) {
    if (!has || !isfinite(v)) { web_jw_raw(w, "null"); return; }
    char b[48];
    snprintf(b, sizeof(b), "%.*f", dp, v);
    web_jw_raw(w, b);
}

static void jstr(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s); else web_jw_raw(w, "null");
}

static void counts(const web_fid_t *g, int n, int c[WEB_FID_NCLASS], int *na, int *ex) {
    memset(c, 0, sizeof(int) * WEB_FID_NCLASS);
    *na = *ex = 0;
    for (int i = 0; i < n; i++) {
        if (g[i].exonerated) (*ex)++;
        else if (!g[i].applicable) (*na)++;
        else c[g[i].cls]++;
    }
}

static void counts_json(web_jw_t *w, const web_fid_t *g, int n) {
    int c[WEB_FID_NCLASS], na, ex;
    counts(g, n, c, &na, &ex);
    for (int k = 0; k < WEB_FID_NCLASS; k++) {
        web_jw_raw(w, k ? ",\"" : "{\"");
        web_jw_raw(w, CLASS_WORD[k]);
        web_jw_raw(w, "\":");
        web_jw_int(w, c[k]);
    }
    web_jw_raw(w, ",\"not_applicable\":"); web_jw_int(w, na);
    web_jw_raw(w, ",\"exonerated\":");     web_jw_int(w, ex);
    web_jw_raw(w, "}");
}

static int any_named(const fctx_t *x) {
    for (int i = 0; i < x->n; i++)
        if (x->s[i].mine.nssid || x->s[i].mine.nbssid) return 1;
    return 0;
}

static const char CONFIGURE[] =
    "no site names its own networks: give the slothweb at each site --my-ssid and "
    "--my-bssid (repeatable; the values its sloth is given, since slothweb does not "
    "read sloth's), so a peer can tell your networks from any other (docs/wiki/fleet.md)";

void web_fid_overview_json(web_fleet_t *f, const web_fleet_src_t *src, long long now_s,
                           web_jw_t *w) {
    fctx_t *x = malloc(sizeof(*x));
    web_fid_t *g = malloc(sizeof(web_fid_t) * WEB_FID_FIND_MAX);
    if (!x || !g) { free(x); free(g); web_jw_raw(w, "null"); return; }
    build(f, src, now_s, x);
    int found = web_fid_run(x->s, x->n, g, WEB_FID_FIND_MAX);
    int n = found < WEB_FID_FIND_MAX ? found : WEB_FID_FIND_MAX;
    web_jw_raw(w, "{\"counts\":");
    counts_json(w, g, n);
    web_jw_raw(w, ",\"total\":");        web_jw_int(w, found);
    web_jw_raw(w, ",\"own_named\":");    web_jw_raw(w, any_named(x) ? "true" : "false");
    web_jw_raw(w, ",\"partial\":");
    web_jw_raw(w, x->partial || found > n ? "true" : "false");
    web_jw_raw(w, "}");
    ctx_free(x);
    free(x);
    free(g);
}

static void site_json(web_jw_t *w, const fctx_t *x, int i, long long now_s) {
    const web_fid_site_t *s = &x->s[i];
    int fl = web_fid_floor(s);
    web_jw_raw(w, "{\"site\":");        web_jw_str(w, s->name);
    web_jw_raw(w, ",\"label\":");       jstr(w, s->label);
    web_jw_raw(w, ",\"lat\":");         jnum(w, s->has_pos, s->lat, 7);
    web_jw_raw(w, ",\"lon\":");         jnum(w, s->has_pos, s->lon, 7);
    /* offered: the site's own networks reached this one (an older peer
     * build never sends them). */
    web_jw_raw(w, ",\"offered\":");     web_jw_raw(w, s->offered ? "true" : "false");
    web_jw_raw(w, ",\"own_age_s\":");
    if (s->offered && !s->self) web_jw_int(w, now_s > s->own_ts ? now_s - s->own_ts : 0);
    else web_jw_raw(w, s->self ? "0" : "null");
    web_jw_raw(w, ",\"own_expired\":"); web_jw_raw(w, s->own_expired ? "true" : "false");
    web_jw_raw(w, ",\"own_ssids\":[");
    for (int k = 0; k < s->mine.nssid; k++) {
        if (k) web_jw_raw(w, ",");
        web_jw_str(w, s->mine.ssid[k]);
    }
    web_jw_raw(w, "],\"own_bssids\":[");
    for (int k = 0; k < s->mine.nbssid; k++) {
        if (k) web_jw_raw(w, ",");
        web_jw_str(w, s->mine.bssid[k]);
    }
    web_jw_raw(w, "],\"aps\":");        web_jw_int(w, s->nap);
    int fp = 0, atk = 0;
    for (int k = 0; k < s->nap; k++) { fp += s->ap[k].ie[0] != 0; atk += (s->ap[k].atk & WEB_FID_ATK_ATTACKER) != 0; }
    web_jw_raw(w, ",\"fingerprinted\":"); web_jw_int(w, fp);
    web_jw_raw(w, ",\"attacked\":");    web_jw_int(w, atk);
    web_jw_raw(w, ",\"probes\":");      web_jw_int(w, s->nprobe);
    web_jw_raw(w, ",\"randomised\":");  web_jw_int(w, s->randomised);
    web_jw_raw(w, ",\"verdicts\":");    web_jw_int(w, s->nver);
    web_jw_raw(w, ",\"floor_dbm\":");   web_jw_int(w, fl);
    web_jw_raw(w, ",\"reach_m\":");     jnum(w, 1, web_fid_reach_m(fl), 0);
    web_jw_raw(w, ",\"skew_s\":");
    if (s->self) web_jw_raw(w, "null"); else web_jw_int(w, x->skew[i]);
    web_jw_raw(w, "}");
}

static const char *const BASIS[WEB_FID_NSUB] = {
    /* probe_other_site */
    "A directed probe request names a network the client has joined, in the clear "
    "(docs/wiki/alert-assessments/MY_NETWORK_RECON.md), so a client at one site "
    "probing another site's own SSID has joined a network of that name: the other "
    "site's, if the name is unique to it. A lead, not a detection; tracking a target "
    "by its preferred networks is reconnaissance (research/mitre/T1595.md). Not "
    "applicable where the sites are within each other's reach. Randomised probe "
    "addresses are left out: one handset mints many (docs/wiki/mac-randomisation.md).",
    /* own_bssid_elsewhere */
    "A site's own AP is fixed at that site; heard at a site its signal cannot reach "
    "(src/rf_model.h, research/papers/rssi-distance-estimation.md), the address is "
    "being transmitted by something else: a cloned BSSID (research/mitre/T1557.md).",
    /* own_ssid_foreign_bssid */
    "An SSID is not bound to anything (research/cve/2023-52424.md); the owner's own SSID "
    "broadcast by a BSSID that is not the owner's, where the owner's network cannot "
    "reach, is the evil-twin or KARMA lure of that network (research/mitre/T1557.md, "
    "research/mitre/T1557-004.md).",
    /* bssid_two_places */
    "One transmitter cannot be heard at two places further apart than its signal "
    "reaches (src/rf_model.h, research/papers/rssi-distance-estimation.md): one BSSID "
    "heard at both within 10 minutes is two transmitters sharing it.",
    /* tool_travel */
    "The same beacon fingerprint (IE order and vendor IEs) on an AP that sloth names "
    "the attacker (KARMA_AP, or the impostor half of an EVIL_TWIN pair the stream "
    "attributed) at two sites, in order: possibly the same hardware and configuration "
    "at both. A lead, not a detection. A fingerprint is weak alone "
    "(research/papers/mbssid-per-bss-ie-variation.md: uniform configuration is the "
    "default), so a site counts only where an attack alert names the AP the attacker; "
    "an unattributed twin pair names both halves and counts at neither.",
    /* verdict_conflict */
    "The operator triaged the same address known at one site and incident at the "
    "other: one of the two judgements needs a second look. Shown, never applied here.",
};

static void finding_json(web_jw_t *w, const fctx_t *x, const web_fid_t *f) {
    char idsrc[256], id[17];
    snprintf(idsrc, sizeof(idsrc), "%d|%s|%s|%s|%s", f->sub, f->key, f->ssid,
             f->nleg > 0 ? x->s[f->leg[0].site].name : "",
             f->nleg > 1 ? x->s[f->leg[1].site].name : "");
    web_ble_key_hash(idsrc, id);
    web_jw_raw(w, "{\"id\":\"");
    web_jw_raw(w, CLASS_WORD[f->cls]);
    web_jw_raw(w, "-");
    web_jw_raw(w, id);
    web_jw_raw(w, "\",\"class\":");     web_jw_str(w, CLASS_WORD[f->cls]);
    web_jw_raw(w, ",\"kind\":");        web_jw_str(w, SUB_WORD[f->sub]);
    web_jw_raw(w, ",\"key\":");         web_jw_str(w, f->key);
    web_jw_raw(w, ",\"ssid\":");        jstr(w, f->ssid);
    web_jw_raw(w, ",\"alert_type\":");  jstr(w, f->vtype);
    web_jw_raw(w, ",\"sites\":[");
    for (int i = 0; i < f->nleg; i++) {
        int dup = 0;
        for (int j = 0; j < i; j++) dup |= f->leg[j].site == f->leg[i].site;
        if (dup) continue;
        if (i) web_jw_raw(w, ",");
        web_jw_str(w, x->s[f->leg[i].site].name);
    }
    web_jw_raw(w, "],\"first_seen\":"); web_jw_int(w, f->first);
    web_jw_raw(w, ",\"last_seen\":");   web_jw_int(w, f->last);
    web_jw_raw(w, ",\"applicable\":");  web_jw_raw(w, f->applicable ? "true" : "false");
    web_jw_raw(w, ",\"lead\":");        web_jw_raw(w, f->lead ? "true" : "false");
    web_jw_raw(w, ",\"reason\":");      jstr(w, f->reason);
    web_jw_raw(w, ",\"note\":");        jstr(w, f->note);
    web_jw_raw(w, ",\"exonerated\":");  web_jw_raw(w, f->exonerated ? "true" : "false");
    web_jw_raw(w, ",\"distance_m\":");  jnum(w, f->has_dist, f->dist_m, 1);
    web_jw_raw(w, ",\"bound_m\":");     jnum(w, f->bound_m > 0, f->bound_m, 0);
    web_jw_raw(w, ",\"evidence\":[");
    for (int i = 0; i < f->nleg; i++) {
        const web_fid_leg_t *l = &f->leg[i];
        web_jw_raw(w, i ? ",{\"site\":" : "{\"site\":");
        web_jw_str(w, x->s[l->site].name);
        web_jw_raw(w, ",\"role\":");       web_jw_str(w, l->role);
        web_jw_raw(w, ",\"key\":");        web_jw_str(w, l->key);
        web_jw_raw(w, ",\"first_seen\":");
        if (l->has_t) web_jw_int(w, l->first); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"last_seen\":");
        if (l->has_t) web_jw_int(w, l->last); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"rssi\":");
        if (l->has_rssi) web_jw_int(w, l->rssi); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"verdict\":");
        jstr(w, l->state >= 0 ? web_frrs_state_word(l->state) : NULL);
        char aw[WEB_FID_ATK_STR];
        web_fid_atk_words(l->atk, aw, sizeof(aw));
        web_jw_raw(w, ",\"attacks\":");    jstr(w, aw);
        /* The fingerprint's WPS strings where the site holds them. */
        const web_fid_ap_t *ap = f->cls == WEB_FID_I4 ? ap_find(&x->s[l->site], l->key) : NULL;
        web_jw_raw(w, ",\"wps\":");
        if (ap && (ap->wps[0][0] || ap->wps[1][0] || ap->wps[2][0])) {
            web_jw_raw(w, "[");
            for (int k = 0; k < 3; k++) {
                if (k) web_jw_raw(w, ",");
                jstr(w, ap->wps[k]);
            }
            web_jw_raw(w, "]");
        } else {
            web_jw_raw(w, "null");
        }
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"basis\":");     web_jw_str(w, BASIS[f->sub]);
    web_jw_raw(w, "}");
}

/* Every address a peer holds a verdict on, beside this site's, the
 * newest first: shown, never applied. */
typedef struct {
    const web_fid_ver_t *v;
    int site;
} sv_t;

static int by_sv_ts(const void *pa, const void *pb) {
    const sv_t *a = pa, *b = pb;
    if (a->v->ts != b->v->ts) return a->v->ts < b->v->ts ? 1 : -1;
    return strcmp(a->v->addr, b->v->addr);
}

static int by_sv_addr(const void *pa, const void *pb) {
    const sv_t *a = pa, *b = pb;
    int c = strcmp(a->v->addr, b->v->addr);
    if (c) return c;
    return a->v->ts < b->v->ts ? 1 : a->v->ts > b->v->ts ? -1 : a->site - b->site;
}

static void shared_json(web_jw_t *w, const fctx_t *x, int limit) {
    int total = 0;
    for (int i = 1; i < x->n; i++) total += x->s[i].nver;
    sv_t *v = total ? malloc(sizeof(sv_t) * (size_t)total) : NULL;
    int nv = 0;
    for (int i = 1; v && i < x->n; i++)
        for (int k = 0; k < x->s[i].nver; k++) { v[nv].v = &x->s[i].ver[k]; v[nv].site = i; nv++; }
    /* One row an address, at its newest peer verdict. */
    if (v) {
        qsort(v, (size_t)nv, sizeof(v[0]), by_sv_addr);
        int o = 0;
        for (int k = 0; k < nv; k++)
            if (!o || strcmp(v[o - 1].v->addr, v[k].v->addr)) v[o++] = v[k];
        nv = o;
        qsort(v, (size_t)nv, sizeof(v[0]), by_sv_ts);
    }
    web_jw_raw(w, "[");
    int out = 0;
    for (int k = 0; k < nv && out < limit; k++) {
        if (out++) web_jw_raw(w, ",");
        web_jw_raw(w, "{\"addr\":");
        web_jw_str(w, v[k].v->addr);
        web_jw_raw(w, ",\"states\":[");
        int ns = 0;
        for (int i = 0; i < x->n; i++) {
            const web_fid_ver_t *e = ver_find(&x->s[i], v[k].v->addr);
            if (!e) continue;
            web_jw_raw(w, ns++ ? ",{\"site\":" : "{\"site\":");
            web_jw_str(w, x->s[i].name);
            web_jw_raw(w, ",\"state\":");      web_jw_str(w, web_frrs_state_word(e->state));
            web_jw_raw(w, ",\"alert_type\":"); jstr(w, e->type);
            web_jw_raw(w, ",\"ts\":");         web_jw_int(w, e->ts);
            web_jw_raw(w, "}");
        }
        web_jw_raw(w, "]}");
    }
    web_jw_raw(w, "]");
    free(v);
}

static int parse_q(const char *q, int *kind, int *limit, const char **why) {
    *limit = WEB_FID_LIMIT_DEF;
    *kind = -1;
    if (!q || !q[0]) return 0;
    int seen_l = 0, seen_k = 0;
    for (const char *p = q; *p;) {
        size_t n = strcspn(p, "&");
        if (n > 6 && !strncmp(p, "limit=", 6) && !seen_l) {
            seen_l = 1;
            long long v = 0;
            for (size_t i = 6; i < n; i++) {
                if (p[i] < '0' || p[i] > '9' || v > 100000) { *why = "bad_limit"; return -1; }
                v = v * 10 + (p[i] - '0');
            }
            if (v < 1 || v > WEB_FID_LIMIT_MAX) { *why = "bad_limit"; return -1; }
            *limit = (int)v;
        } else if (n > 5 && !strncmp(p, "kind=", 5) && !seen_k) {
            seen_k = 1;
            *kind = web_fid_class_find(p + 5, n - 5);
            if (*kind < 0) { *why = "bad_kind"; return -1; }
        } else {
            *why = "unknown_parameter";
            return -1;
        }
        p += n;
        if (*p == '&') p++;
    }
    return 0;
}

#define BODY_MAX (2u << 20)

int web_fleet_findings_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                             long long now_s, char **body, size_t *len, int *status) {
    *body = NULL;
    *len = 0;
    int kind, limit;
    const char *why = NULL;
    char *buf = malloc(BODY_MAX);
    if (!buf) return -1;
    if (parse_q(query, &kind, &limit, &why) != 0) {
        *len = web_series_error_json(why, buf, BODY_MAX);
        *status = 400;
        *body = buf;
        return *len ? 0 : -1;
    }
    fctx_t *x = malloc(sizeof(*x));
    web_fid_t *g = malloc(sizeof(web_fid_t) * WEB_FID_FIND_MAX);
    if (!x || !g) { free(x); free(g); free(buf); return -1; }
    build(f, src, now_s, x);
    int found = web_fid_run(x->s, x->n, g, WEB_FID_FIND_MAX);
    int n = found < WEB_FID_FIND_MAX ? found : WEB_FID_FIND_MAX;
    web_jw_t w;
    web_jw_init(&w, buf, BODY_MAX);
    web_jw_raw(&w, "{\"now\":");          web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"local\":");        web_jw_str(&w, x->local);
    web_jw_raw(&w, ",\"store\":");        web_jw_raw(&w, x->store ? "true" : "false");
    web_jw_raw(&w, ",\"window_s\":");     web_jw_int(&w, WEB_FID_WINDOW_S);
    web_jw_raw(&w, ",\"simul_s\":");      web_jw_int(&w, WEB_FID_SIMUL_S);
    web_jw_raw(&w, ",\"margin_db\":");    jnum(&w, 1, WEB_FID_MARGIN_DB, 0);
    web_jw_raw(&w, ",\"configure\":");    jstr(&w, any_named(x) ? NULL : CONFIGURE);
    web_jw_raw(&w, ",\"sites\":[");
    for (int i = 0; i < x->n; i++) {
        if (i) web_jw_raw(&w, ",");
        site_json(&w, x, i, now_s);
    }
    /* Each pair: whether the checks that need distance apply. */
    web_jw_raw(&w, "],\"pairs\":[");
    int np = 0;
    for (int a = 0; a < x->n; a++)
        for (int b = a + 1; b < x->n; b++) {
            double d = 0, ra = web_fid_reach_m(web_fid_floor(&x->s[a])),
                   rb = web_fid_reach_m(web_fid_floor(&x->s[b]));
            int has = site_dist(&x->s[a], &x->s[b], &d);
            web_jw_raw(&w, np++ ? ",{\"a\":" : "{\"a\":");
            web_jw_str(&w, x->s[a].name);
            web_jw_raw(&w, ",\"b\":");          web_jw_str(&w, x->s[b].name);
            web_jw_raw(&w, ",\"distance_m\":"); jnum(&w, has, d, 1);
            web_jw_raw(&w, ",\"reach_a_m\":");  jnum(&w, 1, ra, 0);
            web_jw_raw(&w, ",\"reach_b_m\":");  jnum(&w, 1, rb, 0);
            web_jw_raw(&w, ",\"co_located\":");
            web_jw_raw(&w, !has ? "null" : d <= ra + rb ? "true" : "false");
            web_jw_raw(&w, "}");
        }
    web_jw_raw(&w, "],\"counts\":");
    counts_json(&w, g, n);
    web_jw_raw(&w, ",\"findings\":[");
    int out = 0, matched = 0;
    for (int i = 0; i < n; i++) {
        if (kind >= 0 && g[i].cls != kind) continue;
        matched++;
        if (out >= limit) continue;
        if (out++) web_jw_raw(&w, ",");
        finding_json(&w, x, &g[i]);
    }
    web_jw_raw(&w, "],\"total\":");       web_jw_int(&w, matched);
    web_jw_raw(&w, ",\"partial\":");
    web_jw_raw(&w, x->partial || found > n ? "true" : "false");
    web_jw_raw(&w, ",\"verdicts\":");
    shared_json(&w, x, limit);
    web_jw_raw(&w, ",\"basis\":{");
    for (int k = 0; k < WEB_FID_NSUB; k++) {
        web_jw_raw(&w, k ? ",\"" : "\"");
        web_jw_raw(&w, SUB_WORD[k]);
        web_jw_raw(&w, "\":");
        web_jw_str(&w, BASIS[k]);
    }
    web_jw_raw(&w, ",\"thresholds\":");
    web_jw_str(&w, "Choices, no source: a site's reach is an AP at sloth's assumed 20 dBm "
                   "heard down to the weakest AP signal that site holds (-100 dBm when none) "
                   "less a 20 dB margin, twice the 2.4 GHz shadow-fading and assumed-power "
                   "sigmas (8 and 6 dB) root-sum-squared (src/rf_model.h), at 2.4 GHz; an AP's distance from a "
                   "sensor that hears it, the same model at its signal less the margin; one "
                   "BSSID at two sites within 600 s is simultaneous; the last 30 days of "
                   "rows; a fingerprint is the IE-order and vendor-IE hashes together; "
                   "conflict is known against incident.");
    web_jw_raw(&w, "}}\n");
    ctx_free(x);
    free(x);
    free(g);
    if (w.overflow) {
        *len = web_series_error_json("too_large", buf, BODY_MAX);
        *status = 503;
    } else {
        *len = w.len;
        *status = 200;
    }
    *body = buf;
    return *len ? 0 : -1;
}
