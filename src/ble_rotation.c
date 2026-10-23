#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include "ble_rotation.h"
#include "siphash.h"

/* Contract, grades, guards and sources in ble_rotation.h. */

#define ENT_EXCLUDED  0x01   /* Fast Pair discoverable, or heard under an active flood gate */

enum { LINK_NONE = 0, LINK_PENDING, LINK_COMMITTED };

typedef struct {
    uint8_t  used;
    uint8_t  addr[6];        /* display order */
    uint8_t  sub;            /* Address[47:46]: 0 NRPA, 1 RPA */
    uint8_t  flags;
    uint64_t first_ord, last_ord;
    time_t   first_ts, last_ts;
    /* Shape (grade C), from the last report that was not a scan
     * response: an ADV_IND and its SCAN_RSP carry different AD
     * structures by design. */
    uint8_t  has_shape;
    uint8_t  evt, fam;
    uint16_t id;
    int16_t  subtype;
    uint32_t ad_shape;
    /* Grade A: digests only, never the token. */
    uint64_t dig[BLE_ROT_TOKENS];
    uint8_t  ndig, dig_next;
    /* The link INTO this entry (this entry the newer address). */
    int16_t  pred;
    uint8_t  basis;          /* ble_hint_basis_t */
    uint8_t  state;          /* LINK_* */
    uint8_t  conf;
    uint8_t  has_link_dig;
    uint64_t link_dig;
    /* The link OUT of it. */
    int16_t  succ;
    /* Chain, set at commit. */
    uint32_t chain;
    uint8_t  hops;
    time_t   root_ts;
} ent_t;

typedef struct {
    uint64_t dig;
    time_t   until;
} poison_t;

typedef struct {
    uint8_t  used;
    uint8_t  kind;
    char     iface[24];
    uint16_t adapter;
    uint64_t ord;            /* arrival order of reports on this sensor */
    time_t   now;            /* newest frame time heard on it */
    ent_t    e[BLE_ROT_SEAM];
    poison_t poison[BLE_ROT_POISON_MAX];
} rot_sensor_t;

static int       g_on;
static uint8_t   g_key[16];
static rot_sensor_t *g_tabs;     /* BLE_ROT_SENSORS, allocated on first use while on */
static uint32_t  g_chain;
static ble_rot_stats_t g_st;

/* ── Pure parts ────────────────────────────────────────────────────── */

int ble_rot_addr_candidate(uint8_t addr_type, const uint8_t addr[6]) {
    if (addr_type != 1 || !addr) return 0;
    uint8_t sub = (uint8_t)(addr[0] >> 6);
    return sub == 0 || sub == 1;
}

/* Apple Continuity: a sequence of (type, length, body) after the
 * company ID (the layout both Martin et al. 2019 §4 and Celosia and
 * Cunche 2020 §3 describe). */
static int apple_handoff(const ble_adv_report_t *r, ble_token_t *t) {
    const uint8_t *p = r->mfr_data;
    size_t n = r->mfr_data_len, off = 0;
    while (off + 2 <= n) {
        uint8_t type = p[off], len = p[off + 1];
        if (off + 2 + len > n) return 0;
        /* Handoff: type 0x0C, a 14-octet body (Celosia and Cunche 2020
         * Fig. 9: version/clipboard 1, IV 2, AES-GCM tag 1, payload 10).
         * The first body octet is a near-constant and is left out, so
         * two devices never match on it. */
        if (type == 0x0C && len == 14) {
            t->kind  = BLE_TOK_APPLE_HANDOFF;
            t->bytes = p + off + 3;
            t->len   = 13;
            return 1;
        }
        off += 2 + (size_t)len;
    }
    return 0;
}

int ble_rot_tokens(const ble_adv_report_t *r, ble_token_t *out, int max,
                   int *fp_discoverable) {
    int n = 0;
    if (fp_discoverable) *fp_discoverable = 0;
    if (!r || !out || max <= 0) return 0;

    if (r->has_mfr_data && !r->mfr_data_clipped) {
        /* [MS-CDP] 2.2.2.2.3: Scenario_Type 1, Version_and_Device_Type,
         * Version_and_Flags, Flags_and_Device_Status, Salt (4),
         * Device_Hash (19). The whole beacon is 27 octets after the
         * company ID (Length 0x1E = type + ID + 27), whatever the
         * page's "Beacon Data (24 bytes)" label says. */
        if (r->mfr_id == 0x0006 && r->mfr_data_len == 27 &&
            r->mfr_data[0] == 0x01 && n < max) {
            out[n].kind  = BLE_TOK_MS_CDP;
            out[n].bytes = r->mfr_data + 4;
            out[n].len   = 23;
            n++;
        }
        if (r->mfr_id == 0x004C && n < max && apple_handoff(r, &out[n])) n++;
    }

    if (r->has_svc_data16 && r->svc_data_uuid16 == 0xFE2C &&
        !r->svc_data_clipped) {
        const uint8_t *d = r->svc_data;
        size_t len = r->svc_data_len;
        /* Fast Pair Provider Advertising signal. Discoverable: the
         * 24-bit Model ID alone, or the LE Audio Sharing form whose
         * first field is type 0b0111 (Model ID). The address "shall not
         * be rotated" there, so the advertisement is never a candidate. */
        if (len == 3 || (len >= 2 && d[0] == 0x00 && (d[1] & 0x0F) == 0x07)) {
            if (fp_discoverable) *fp_discoverable = 1;
        } else if (len >= 2 && d[0] == 0x00) {
            /* Not discoverable: version 0x00, then the Account Key
             * Filter's 0bLLLLTTTT (T 0b0000 show UI, 0b0010 hide UI),
             * the filter, then 0b00100001 and the 2-octet Salt. A
             * filter is (1.2 n + 3) octets for n >= 1 keys, so at least
             * 4: under that it is not this form. */
            uint8_t flen = (uint8_t)(d[1] >> 4), ftype = (uint8_t)(d[1] & 0x0F);
            size_t salt_hdr = 2 + (size_t)flen;
            if ((ftype == 0x00 || ftype == 0x02) && flen >= 4 &&
                salt_hdr + 3 <= len && d[salt_hdr] == 0x21 && n < max) {
                /* Filter and salt together: equal only when the salt
                 * did not change across the rotation. */
                out[n].kind  = BLE_TOK_FAST_PAIR_ACCOUNT;
                out[n].bytes = d + 2;
                out[n].len   = (uint8_t)(flen + 3);
                n++;
            }
        }
    }
    return n;
}

/* ── Key and lifecycle ─────────────────────────────────────────────── */

static int draw_key(uint8_t k[16]) {
    size_t got = 0;
    while (got < 16) {
        ssize_t r = getrandom(k + got, 16 - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        got += (size_t)r;
    }
    if (got == 16) return 0;
    /* A kernel without getrandom(2): the same pool through the device. */
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    got = 0;
    while (got < 16) {
        ssize_t r = read(fd, k + got, 16 - got);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            break;
        }
        got += (size_t)r;
    }
    close(fd);
    return got == 16 ? 0 : -1;
}

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

static void free_tabs(void) {
    if (g_tabs) {
        wipe(g_tabs, sizeof(rot_sensor_t) * BLE_ROT_SENSORS);
        free(g_tabs);
        g_tabs = NULL;
    }
}

int ble_rot_set_enabled(int on) {
    free_tabs();
    memset(&g_st, 0, sizeof(g_st));
    g_chain = 0;
    wipe(g_key, sizeof(g_key));
    g_on = 0;
    if (!on) return 0;
    if (draw_key(g_key) != 0) return -1;
    g_on = 1;
    return 0;
}

int ble_rot_enabled(void) { return g_on; }

void ble_rot_drop_tables(void) { free_tabs(); }

void ble_rot_reset(void) { (void)ble_rot_set_enabled(0); }

/* ── Table ─────────────────────────────────────────────────────────── */

static rot_sensor_t *sensor_for(uint8_t kind, const char *iface, uint16_t adapter) {
    if (!g_tabs) {
        g_tabs = calloc(BLE_ROT_SENSORS, sizeof(rot_sensor_t));
        if (!g_tabs) return NULL;
    }
    rot_sensor_t *spare = NULL;
    for (int i = 0; i < BLE_ROT_SENSORS; i++) {
        rot_sensor_t *s = &g_tabs[i];
        if (!s->used) { if (!spare) spare = s; continue; }
        if (s->kind == kind && s->adapter == adapter &&
            strncmp(s->iface, iface, sizeof(s->iface)) == 0)
            return s;
    }
    /* A ninth (kind, iface, adapter) gets no table: never linked,
     * which is the quiet side. */
    if (!spare) return NULL;
    memset(spare, 0, sizeof(*spare));
    spare->used    = 1;
    spare->kind    = kind;
    spare->adapter = adapter;
    size_t l = strnlen(iface, sizeof(spare->iface) - 1);
    memcpy(spare->iface, iface, l);
    spare->iface[l] = '\0';
    for (int i = 0; i < BLE_ROT_SEAM; i++) spare->e[i].pred = spare->e[i].succ = -1;
    return spare;
}

static const rot_sensor_t *sensor_find(uint8_t kind, const char *iface, uint16_t adapter) {
    if (!g_tabs) return NULL;
    for (int i = 0; i < BLE_ROT_SENSORS; i++) {
        const rot_sensor_t *s = &g_tabs[i];
        if (s->used && s->kind == kind && s->adapter == adapter &&
            strncmp(s->iface, iface, sizeof(s->iface)) == 0)
            return s;
    }
    return NULL;
}

static int ent_find(const rot_sensor_t *S, const uint8_t addr[6]) {
    for (int i = 0; i < BLE_ROT_SEAM; i++)
        if (S->e[i].used && memcmp(S->e[i].addr, addr, 6) == 0) return i;
    return -1;
}

/* Re-derive chain, hops and root along the committed successors of
 * `start`, which becomes a chain root (hops 0) unless it has a committed
 * predecessor, in which case its fields are already right. */
static void chain_relabel(rot_sensor_t *S, int start, uint32_t chain) {
    int cur = start;
    for (int guard = 0; cur >= 0 && guard < BLE_ROT_SEAM; guard++) {
        ent_t *c = &S->e[cur];
        int nx = c->succ;
        if (nx < 0 || S->e[nx].state != LINK_COMMITTED) break;
        ent_t *n = &S->e[nx];
        n->chain   = chain;
        n->hops    = (uint8_t)(c->hops + 1);
        n->root_ts = c->root_ts;
        cur = nx;
    }
}

/* Break the link into entry `ei`. A committed one splits its chain: the
 * newer half becomes a chain of its own, or of nothing. */
static void rot_revoke(rot_sensor_t *S, int ei) {
    ent_t *E = &S->e[ei];
    if (E->pred < 0) return;
    ent_t *F = &S->e[E->pred];
    int was_committed = E->state == LINK_COMMITTED;
    F->succ = -1;
    E->pred = -1;
    E->basis = BLE_HINT_NONE;
    E->state = LINK_NONE;
    E->conf  = 0;
    E->has_link_dig = 0;
    if (!was_committed) return;
    if (F->pred < 0 || S->e[F->pred].state != LINK_COMMITTED) {
        F->chain = 0; F->hops = 0; F->root_ts = 0;
    }
    int has_next = E->succ >= 0 && S->e[E->succ].state == LINK_COMMITTED;
    E->hops = 0;
    if (has_next) {
        E->chain = ++g_chain;
        E->root_ts = E->first_ts;
        chain_relabel(S, ei, E->chain);
    } else {
        E->chain = 0;
        E->root_ts = 0;
    }
}

/* Free entry `i` (evicted or past retention). A link through it is cut
 * without un-chaining what was committed: the chain id already on the
 * survivors stays the right grouping. A pending link that loses its
 * predecessor can never commit and is dropped. */
static void ent_free(rot_sensor_t *S, int i) {
    ent_t *X = &S->e[i];
    if (X->succ >= 0) {
        ent_t *N = &S->e[X->succ];
        if (N->state == LINK_PENDING) {
            N->basis = BLE_HINT_NONE; N->state = LINK_NONE; N->conf = 0;
            N->has_link_dig = 0;
        }
        N->pred = -1;
    }
    if (X->pred >= 0) S->e[X->pred].succ = -1;
    wipe(X, sizeof(*X));
    X->pred = X->succ = -1;
}

static int ent_alloc(rot_sensor_t *S) {
    int oldest = -1;
    for (int i = 0; i < BLE_ROT_SEAM; i++) {
        if (!S->e[i].used) return i;
        if (oldest < 0 || S->e[i].last_ord < S->e[oldest].last_ord) oldest = i;
    }
    ent_free(S, oldest);
    g_st.seam_evictions++;
    return oldest;
}

static int is_poisoned(const rot_sensor_t *S, uint64_t dig, time_t now) {
    for (int i = 0; i < BLE_ROT_POISON_MAX; i++)
        if (S->poison[i].until && S->poison[i].dig == dig && now <= S->poison[i].until)
            return 1;
    return 0;
}

static void poison(rot_sensor_t *S, uint64_t dig, time_t now) {
    int slot = -1, oldest = 0;
    for (int i = 0; i < BLE_ROT_POISON_MAX; i++) {
        poison_t *p = &S->poison[i];
        if (p->until && p->dig == dig) { slot = i; break; }
        if (p->until < S->poison[oldest].until) oldest = i;
    }
    if (slot < 0 || now > S->poison[slot].until) g_st.poisoned++;
    if (slot < 0) slot = oldest;
    S->poison[slot].dig   = dig;
    S->poison[slot].until = now + BLE_ROT_POISON_S;
    for (int i = 0; i < BLE_ROT_SEAM; i++)
        if (S->e[i].used && S->e[i].has_link_dig && S->e[i].link_dig == dig)
            rot_revoke(S, i);
}

static int shape_eq(const ent_t *a, const ent_t *b) {
    return a->has_shape && b->has_shape && a->evt == b->evt &&
           a->fam == b->fam && a->id == b->id && a->subtype == b->subtype &&
           a->ad_shape == b->ad_shape;
}

static int has_dig(const ent_t *e, uint64_t d) {
    for (int i = 0; i < e->ndig; i++) if (e->dig[i] == d) return 1;
    return 0;
}

/* Grade B: could F (older) have been replaced by E (newer)? */
static int seam_ok(const rot_sensor_t *S, int fi, int ei) {
    const ent_t *F = &S->e[fi], *E = &S->e[ei];
    if (fi == ei || !F->used || (F->flags & ENT_EXCLUDED)) return 0;
    if (F->succ >= 0 && F->succ != ei) return 0;
    if (F->sub != E->sub) return 0;
    if (F->last_ord >= E->first_ord) return 0;            /* overlap */
    time_t gap = E->first_ts - F->last_ts;
    if (gap < 0 || gap > BLE_ROT_DSWAP_S) return 0;
    return 1;     /* the hop and age caps are commit()'s, on the whole chain */
}

static uint8_t confidence(const ent_t *F, const ent_t *E, int basis) {
    time_t gap = E->first_ts - F->last_ts;
    int c;
    if (basis == BLE_HINT_PAYLOAD) {
        c = 40 + (gap <= 2 ? 10 : 5) + (shape_eq(F, E) ? 10 : 0);
        if (c > BLE_ROT_CONF_PAYLOAD_MAX) c = BLE_ROT_CONF_PAYLOAD_MAX;
    } else {
        c = 10 + (gap <= 2 ? 10 : 5);
        if (c > BLE_ROT_CONF_TIMING_MAX) c = BLE_ROT_CONF_TIMING_MAX;
    }
    return (uint8_t)c;
}

static void rot_link(rot_sensor_t *S, int fi, int ei, int basis, uint64_t dig) {
    ent_t *F = &S->e[fi], *E = &S->e[ei];
    E->pred  = (int16_t)fi;
    F->succ  = (int16_t)ei;
    E->basis = (uint8_t)basis;
    E->state = LINK_PENDING;
    E->has_link_dig = basis == BLE_HINT_PAYLOAD;
    E->link_dig = basis == BLE_HINT_PAYLOAD ? dig : 0;
    E->conf  = confidence(F, E, basis);
}

static void try_link(rot_sensor_t *S, int ei, time_t now) {
    ent_t *E = &S->e[ei];
    if (E->state == LINK_COMMITTED) return;
    if (E->state == LINK_PENDING && E->basis == BLE_HINT_PAYLOAD) return;

    /* Grade A + B: the newest departed address holding one of E's
     * digests, not poisoned. */
    int best = -1;
    uint64_t best_dig = 0;
    for (int f = 0; f < BLE_ROT_SEAM; f++) {
        if (!seam_ok(S, f, ei)) continue;
        for (int k = 0; k < E->ndig; k++) {
            uint64_t d = E->dig[k];
            if (!has_dig(&S->e[f], d) || is_poisoned(S, d, now)) continue;
            if (best < 0 || S->e[f].last_ord > S->e[best].last_ord) {
                best = f;
                best_dig = d;
            }
        }
    }
    if (best >= 0) {
        if (E->pred >= 0) rot_revoke(S, ei);      /* a pending timing link gives way */
        rot_link(S, best, ei, BLE_HINT_PAYLOAD, best_dig);
        return;
    }
    if (E->pred >= 0) return;

    /* B + C: exactly one departed address of the same shape. */
    int only = -1, count = 0;
    for (int f = 0; f < BLE_ROT_SEAM; f++) {
        if (!seam_ok(S, f, ei) || !shape_eq(&S->e[f], E)) continue;
        count++;
        only = f;
    }
    if (count == 1) rot_link(S, only, ei, BLE_HINT_TIMING, 0);
}

/* A timing link is ambiguous when another arrival fits the same seam. */
static int timing_ambiguous(const rot_sensor_t *S, int ei) {
    const ent_t *E = &S->e[ei];
    int fi = E->pred;
    const ent_t *F = &S->e[fi];
    for (int g = 0; g < BLE_ROT_SEAM; g++) {
        const ent_t *G = &S->e[g];
        if (g == ei || g == fi || !G->used || (G->flags & ENT_EXCLUDED)) continue;
        if (G->sub != F->sub || G->first_ord <= F->last_ord) continue;
        time_t gap = G->first_ts - F->last_ts;
        if (gap < 0 || gap > BLE_ROT_DSWAP_S) continue;
        if (shape_eq(G, F)) return 1;
    }
    return 0;
}

/* Committed links already hanging off `ei`. */
static int tail_len(const rot_sensor_t *S, int ei) {
    int n = 0, cur = S->e[ei].succ;
    while (cur >= 0 && S->e[cur].state == LINK_COMMITTED && n < BLE_ROT_SEAM) {
        n++;
        cur = S->e[cur].succ;
    }
    return n;
}

static void commit(rot_sensor_t *S, int ei) {
    ent_t *E = &S->e[ei];
    ent_t *F = &S->e[E->pred];
    /* The caps, judged here on the chain the commit would make, not
     * when the link was proposed: a newer address may have committed
     * onto E in between, and the joined chain is what must fit. */
    int f_hops = F->chain ? F->hops : 0;
    time_t root = F->chain ? F->root_ts : F->first_ts;
    if (f_hops + 1 + tail_len(S, ei) > BLE_ROT_MAX_HOPS ||
        S->now - root > BLE_ROT_RETAIN_S) {
        rot_revoke(S, ei);
        return;
    }
    E->state = LINK_COMMITTED;
    if (E->basis == BLE_HINT_PAYLOAD) g_st.hints_payload++;
    else                              g_st.hints_timing++;
    if (!F->chain) {
        F->chain   = ++g_chain;
        F->hops    = 0;
        F->root_ts = F->first_ts;
    }
    E->chain   = F->chain;
    E->hops    = (uint8_t)(F->hops + 1);
    E->root_ts = F->root_ts;
    chain_relabel(S, ei, E->chain);
}

static void tick(rot_sensor_t *S) {
    time_t now = S->now;
    for (int i = 0; i < BLE_ROT_SEAM; i++)
        if (S->e[i].used && now - S->e[i].last_ts > BLE_ROT_RETAIN_S)
            ent_free(S, i);
    for (int i = 0; i < BLE_ROT_SEAM; i++) {
        ent_t *E = &S->e[i];
        if (!E->used || E->state != LINK_PENDING) continue;
        if (now - E->first_ts < BLE_ROT_DSWAP_S) continue;
        if (E->basis == BLE_HINT_TIMING && timing_ambiguous(S, i)) {
            rot_revoke(S, i);
            continue;
        }
        commit(S, i);
    }
}

static uint64_t digest(uint8_t kind, const uint8_t *b, size_t len) {
    uint8_t m[1 + 32];
    if (len > 32) len = 32;
    m[0] = kind;
    memcpy(m + 1, b, len);
    uint64_t d = siphash24(g_key, m, 1 + len);
    wipe(m, sizeof(m));
    return d;
}

void ble_rot_observe(const ble_adv_report_t *r, uint8_t sensor_kind,
                     const char *iface, uint16_t adapter,
                     const uint8_t addr[6], time_t ts, int flooded) {
    if (!r || !addr) return;
    rot_sensor_t *S = sensor_for(sensor_kind, iface ? iface : "", adapter);
    if (!S) return;
    if (ts > S->now) S->now = ts;
    uint64_t ord = ++S->ord;
    if (!ble_rot_addr_candidate(r->addr_type, addr)) { tick(S); return; }

    ble_token_t tok[3];
    int fp_disc = 0;
    int nt = ble_rot_tokens(r, tok, 3, &fp_disc);

    int i = ent_find(S, addr);
    if (i < 0) {
        i = ent_alloc(S);
        ent_t *n = &S->e[i];
        n->used = 1;
        memcpy(n->addr, addr, 6);
        n->sub = (uint8_t)(addr[0] >> 6);
        n->first_ord = ord;
        n->first_ts  = ts;
        n->pred = n->succ = -1;
    } else if (S->e[i].succ >= 0) {
        /* The older address heard again after its successor appeared:
         * the two interleave, so the link is wrong. A payload link's
         * token was on both at once: poisoned. */
        int k = S->e[i].succ;
        int payload = S->e[k].has_link_dig;
        uint64_t d = S->e[k].link_dig;
        rot_revoke(S, k);
        if (payload) poison(S, d, ts);
    }
    ent_t *A = &S->e[i];
    A->last_ord = ord;
    A->last_ts  = ts;
    if (fp_disc || flooded) {
        A->flags |= ENT_EXCLUDED;
        if (A->pred >= 0) rot_revoke(S, i);
    }
    if (r->event_type != 0x04 && r->event_type != BLE_EVT_EXT_SCAN_RSP) {
        A->has_shape = 1;
        A->evt = r->event_type;
        if (r->has_mfr_data) {
            A->fam = BLE_FAM_MFR; A->id = r->mfr_id;
            A->subtype = r->mfr_data_len ? r->mfr_data[0] : -1;
        } else if (r->has_svc_data16) {
            A->fam = BLE_FAM_SVC_DATA; A->id = r->svc_data_uuid16; A->subtype = -1;
        } else {
            A->fam = 0; A->id = 0; A->subtype = -1;
        }
        A->ad_shape = r->ad_shape;
    }
    for (int t = 0; t < nt; t++) {
        uint64_t d = digest(tok[t].kind, tok[t].bytes, tok[t].len);
        /* The same token on another address heard since this one first
         * appeared: two addresses at once carrying it. */
        for (int g = 0; g < BLE_ROT_SEAM; g++) {
            const ent_t *G = &S->e[g];
            if (g == i || !G->used || !has_dig(G, d)) continue;
            if (G->last_ord > A->first_ord) { poison(S, d, ts); break; }
        }
        A = &S->e[i];
        if (!has_dig(A, d)) {
            A->dig[A->dig_next] = d;
            A->dig_next = (uint8_t)((A->dig_next + 1) % BLE_ROT_TOKENS);
            if (A->ndig < BLE_ROT_TOKENS) A->ndig++;
        }
    }
    if (!(A->flags & ENT_EXCLUDED) && ts - A->first_ts <= BLE_ROT_DSWAP_S)
        try_link(S, i, ts);
    tick(S);
}

void ble_rot_snapshot(sloth_state_t *s) {
    if (!s) return;
    if (!g_on) {
        memset(&s->ble_rot, 0, sizeof(s->ble_rot));
        return;
    }
    if (g_tabs)
        for (int k = 0; k < BLE_ROT_SENSORS; k++)
            if (g_tabs[k].used) tick(&g_tabs[k]);
    for (int i = 0; i < s->ble_device_count && i < MAX_BLE_DEVICES; i++) {
        ble_device_t *d = &s->ble_devices[i];
        memset(&d->hint, 0, sizeof(d->hint));
        if (d->addr_type != 1) continue;
        const rot_sensor_t *S = sensor_find(d->sensor_kind, d->sensor_iface, d->adapter);
        if (!S) continue;
        int e = ent_find(S, d->addr);
        if (e < 0 || !S->e[e].chain) continue;
        const ent_t *E = &S->e[e];
        d->hint.chain      = E->chain;
        d->hint.hops       = E->hops;
        d->hint.root_first = E->root_ts;
        if (E->state == LINK_COMMITTED) {
            d->hint.basis      = E->basis;
            d->hint.confidence = E->conf;
        }
    }
    s->ble_rot = g_st;
    s->ble_rot.enabled = 1;
}

int ble_rot_distinct(const sloth_state_t *s,
                     int (*keep)(const ble_device_t *d, void *ctx),
                     void *ctx) {
    int n = 0;
    if (!s) return 0;
    for (int i = 0; i < s->ble_device_count && i < MAX_BLE_DEVICES; i++) {
        const ble_device_t *d = &s->ble_devices[i];
        if (keep && !keep(d, ctx)) continue;
        int dup = 0;
        if (d->hint.chain)
            for (int j = 0; j < i && !dup; j++) {
                const ble_device_t *o = &s->ble_devices[j];
                if (o->hint.chain == d->hint.chain && (!keep || keep(o, ctx)))
                    dup = 1;
            }
        if (!dup) n++;
    }
    return n;
}

int ble_rot_test_allocated(void) { return g_tabs != NULL; }

uint64_t ble_rot_test_digest(uint8_t kind, const uint8_t *bytes, size_t len) {
    return digest(kind, bytes, len);
}

void ble_rot_test_set_key(const uint8_t key[16]) {
    memcpy(g_key, key, sizeof(g_key));
}
