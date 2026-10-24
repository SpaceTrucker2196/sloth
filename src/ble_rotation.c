#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include "ble_rotation.h"
#include "siphash.h"
#include "sloth_clock.h"

/* Contract, grades, guards and sources in ble_rotation.h. */

#define ENT_EXCLUDED  0x01   /* Fast Pair discoverable, or its key under an active flood gate */

enum { LINK_NONE = 0, LINK_PENDING, LINK_COMMITTED };

/* The BLE_ADV_FLOOD payload key of one report, less the sensor kind and
 * iface the seam table already fixes (src/ble_flood.c key_of()). */
typedef struct {
    uint8_t  set, evt, fam;
    uint16_t id;
    int16_t  sub;
} fkey_t;

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
    fkey_t   tkey;           /* flood key of the last report that carried a token */
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
    uint64_t mono_last;      /* sloth_mono_ms() at that report */
    uint8_t  blind;          /* last report: controller duplicate filter on or unknown */
    time_t   poison_full_until;  /* a poison found every slot live: no payload link until */
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
    memset(out, 0, sizeof(*out) * (size_t)max);

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
                salt_hdr + 3 <= len && d[salt_hdr] == 0x21) {
                /* The form, but a token only from a 5-octet filter up.
                 * A filter sets at most 8 bits per key, so a 4-octet one
                 * (n = 1) holds at most log2(sum C(32, 1..8)) ~ 23.8
                 * bits and with the salt ~ 39.8, under the 40-bit bound;
                 * a 5-octet one (n = 2) at most ~ 37.1 + 16 ~ 53.1.
                 * Those are ceilings, not the entropy: the bits come
                 * from the keys' hashes. Filter and salt together, the
                 * fixed 0x21 header between them left out: equal only
                 * when the salt did not change across the rotation. */
                if (flen >= BLE_ROT_FP_FILTER_MIN && n < max) {
                    out[n].kind  = BLE_TOK_FAST_PAIR_ACCOUNT;
                    out[n].bytes = d + 2;
                    out[n].len   = flen;
                    out[n].bytes2 = d + salt_hdr + 1;
                    out[n].len2   = 2;
                    n++;
                }
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
    /* F keeps its chain only through a committed link into F itself;
     * its one successor was E. */
    if (F->state != LINK_COMMITTED) {
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

static void hint_of(const ent_t *E, ble_identity_hint_t *h) {
    memset(h, 0, sizeof(*h));
    if (!E->chain) return;
    h->chain      = E->chain;
    h->hops       = E->hops;
    h->root_first = E->root_ts;
    if (E->state == LINK_COMMITTED) {
        h->basis      = E->basis;
        h->confidence = E->conf;
    }
}

/* Free entry `i` (evicted or past retention). Links are window-scoped:
 * one exists only while both its entries are held, so both of X's links
 * go as a revocation does. The survivors' chains are re-derived, and
 * ble_rot_update_row() zeroes the row of an address with no entry, so
 * no hint outlives either side and no link is left that a later poison
 * could not reach.
 *
 * Which side goes first depends on the caller. Eviction (ent_alloc())
 * only ever frees the older side of a live link: F -> E stands only
 * while F's last report precedes E's first, and the least recently
 * heard entry is the one taken. Retention (tick()) goes by last_ts,
 * which a frame clock stepped back can leave earlier on E than on F, so
 * there the newer side can go alone and the pred-side revoke is what
 * stops F keeping a succ into a wiped, reusable slot. */
static void ent_free(rot_sensor_t *S, int i) {
    ent_t *X = &S->e[i];
    if (X->pred >= 0) rot_revoke(S, i);
    if (X->succ >= 0) rot_revoke(S, X->succ);
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
    if (S->poison_full_until && now <= S->poison_full_until) return 1;
    for (int i = 0; i < BLE_ROT_POISON_MAX; i++)
        if (S->poison[i].until && S->poison[i].dig == dig && now <= S->poison[i].until)
            return 1;
    return 0;
}

/* A full list never overwrites a live slot: that would re-arm the
 * token in it early. It fails closed instead, every payload link on the
 * sensor refused for the window the unrecorded poison would have had. */
static void poison(rot_sensor_t *S, uint64_t dig, time_t now) {
    /* Counted once per poisoning: a digest already held, or covered by
     * a live overflow refusal, is not counted again. */
    int already = is_poisoned(S, dig, now);
    int slot = -1, spare = -1;
    for (int i = 0; i < BLE_ROT_POISON_MAX; i++) {
        poison_t *p = &S->poison[i];
        int live = p->until && now <= p->until;
        if (live && p->dig == dig) { slot = i; break; }
        if (!live && spare < 0) spare = i;
    }
    if (!already) g_st.poisoned++;
    if (slot < 0) slot = spare;
    if (slot >= 0) {
        S->poison[slot].dig   = dig;
        S->poison[slot].until = now + BLE_ROT_POISON_S;
    } else {
        S->poison_full_until = now + BLE_ROT_POISON_S;
    }
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

static void commit(rot_sensor_t *S, int ei, time_t now) {
    ent_t *E = &S->e[ei];
    ent_t *F = &S->e[E->pred];
    /* The caps, judged here on the chain the commit would make, not
     * when the link was proposed: a newer address may have committed
     * onto E in between, and the joined chain is what must fit. And
     * the flood gate, judged on everything since the proposal: either
     * end's key seen under it (flood_sweep()) refuses the link, so a
     * spray whose first addresses came before the gate tripped does
     * not commit them under it. */
    int f_hops = F->chain ? F->hops : 0;
    time_t root = F->chain ? F->root_ts : F->first_ts;
    if (((E->flags | F->flags) & ENT_EXCLUDED) ||
        f_hops + 1 + tail_len(S, ei) > BLE_ROT_MAX_HOPS ||
        now - root > BLE_ROT_RETAIN_S) {
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

/* What an unlinked entry silent for BLE_ROT_FORGET_S no longer needs:
 * it can no longer be a seam's older side (gap > d_swap), so its
 * digests and its shape go. Kept until BLE_ROT_RETAIN_S: the address,
 * its arrival bounds and its chain fields, which the interleave guard
 * and the chain caps read. An entry a pending or committed link rests
 * on, either side, keeps everything until the link goes or ent_free():
 * the older address heard again must still poison the link's token,
 * and poison() must still find every link resting on it. */
static void ent_forget(ent_t *X) {
    if (X->pred >= 0 || X->succ >= 0) return;
    wipe(X->dig, sizeof(X->dig));
    X->ndig = X->dig_next = 0;
    X->has_link_dig = 0;
    X->link_dig = 0;
    wipe(&X->tkey, sizeof(X->tkey));
    X->has_shape = 0;
    X->evt = X->fam = 0;
    X->id = 0;
    X->subtype = 0;
    X->ad_shape = 0;
}

static void tick(rot_sensor_t *S, time_t now) {
    for (int i = 0; i < BLE_ROT_POISON_MAX; i++)
        if (S->poison[i].until && now > S->poison[i].until)
            wipe(&S->poison[i], sizeof(S->poison[i]));
    if (S->poison_full_until && now > S->poison_full_until) S->poison_full_until = 0;
    for (int i = 0; i < BLE_ROT_SEAM; i++)
        if (S->e[i].used && now - S->e[i].last_ts > BLE_ROT_RETAIN_S)
            ent_free(S, i);
    for (int i = 0; i < BLE_ROT_SEAM; i++) {
        ent_t *E = &S->e[i];
        if (!E->used || E->state != LINK_PENDING) continue;
        if (now - E->first_ts < BLE_ROT_DSWAP_S) continue;
        if (S->blind ||
            (E->basis == BLE_HINT_TIMING && timing_ambiguous(S, i))) {
            rot_revoke(S, i);
            continue;
        }
        commit(S, i, now);
    }
    /* After the commits: timing_ambiguous() reads the shapes. */
    for (int i = 0; i < BLE_ROT_SEAM; i++)
        if (S->e[i].used && now - S->e[i].last_ts > BLE_ROT_FORGET_S)
            ent_forget(&S->e[i]);
}

/* The frame clock, carried forward by the monotonic time since the
 * sensor's last report: a radio gone quiet, or a --bt-capture file that
 * ended, still expires what it left. */
static time_t sensor_now(const rot_sensor_t *S) {
    uint64_t m = sloth_mono_ms();
    if (m <= S->mono_last) return S->now;
    return S->now + (time_t)((m - S->mono_last) / 1000u);
}

static uint64_t digest(uint8_t kind, const uint8_t *b, size_t len,
                       const uint8_t *b2, size_t len2) {
    uint8_t m[1 + 32];
    if (len > 32) len = 32;
    if (!b2) len2 = 0;
    if (len2 > 32 - len) len2 = 32 - len;
    m[0] = kind;
    memcpy(m + 1, b, len);
    if (len2) memcpy(m + 1 + len, b2, len2);
    uint64_t d = siphash24(g_key, m, 1 + len + len2);
    wipe(m, sizeof(m));
    return d;
}

static int report_key(const ble_adv_report_t *r, fkey_t *k) {
    memset(k, 0, sizeof(*k));
    k->evt = r->event_type;
    if (r->has_mfr_data) {
        k->fam = BLE_FAM_MFR;
        k->id  = r->mfr_id;
        k->sub = r->mfr_data_len >= 1 ? r->mfr_data[0] : -1;
    } else if (r->has_svc_data16) {
        k->fam = BLE_FAM_SVC_DATA;
        k->id  = r->svc_data_uuid16;
        k->sub = -1;
    } else {
        return 0;
    }
    k->set = 1;
    return 1;
}

static int fkey_eq(const fkey_t *a, const fkey_t *b) {
    return a->set && b->set && a->evt == b->evt && a->fam == b->fam &&
           a->id == b->id && a->sub == b->sub;
}

static int ent_on_key(const ent_t *X, const fkey_t *k) {
    if (fkey_eq(&X->tkey, k)) return 1;
    return X->has_shape && X->fam && X->evt == k->evt && X->fam == k->fam &&
           X->id == k->id && X->subtype == k->sub;
}

/* A report the flood gate holds active on its key: every entry on that
 * key, on every adapter of this sensor (the gate is per sensor kind and
 * iface, not per adapter), is excluded, so a link proposed before the
 * gate tripped is refused at commit. The reporting address need not be
 * a candidate: a spam tool on static addresses trips the gate too. */
static void flood_sweep(uint8_t kind, const char *iface, const fkey_t *k) {
    for (int t = 0; t < BLE_ROT_SENSORS; t++) {
        rot_sensor_t *S = &g_tabs[t];
        if (!S->used || S->kind != kind ||
            strncmp(S->iface, iface, sizeof(S->iface)) != 0)
            continue;
        for (int i = 0; i < BLE_ROT_SEAM; i++)
            if (S->e[i].used && ent_on_key(&S->e[i], k))
                S->e[i].flags |= ENT_EXCLUDED;
    }
}

void ble_rot_observe(const ble_adv_report_t *r, uint8_t sensor_kind,
                     const char *iface, uint16_t adapter,
                     const uint8_t addr[6], time_t ts, int flooded,
                     int blind) {
    if (!r || !addr) return;
    if (!iface) iface = "";
    rot_sensor_t *S = sensor_for(sensor_kind, iface, adapter);
    if (!S) return;
    if (ts > S->now) S->now = ts;
    S->mono_last = sloth_mono_ms();
    S->blind = blind ? 1 : 0;
    uint64_t ord = ++S->ord;
    fkey_t rk;
    int keyed = report_key(r, &rk);
    if (flooded && keyed) flood_sweep(sensor_kind, iface, &rk);
    if (!ble_rot_addr_candidate(r->addr_type, addr)) { tick(S, S->now); return; }

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
    if (nt > 0 && keyed) A->tkey = rk;
    for (int t = 0; t < nt; t++) {
        uint64_t d = digest(tok[t].kind, tok[t].bytes, tok[t].len,
                            tok[t].bytes2, tok[t].len2);
        /* The same token on another address heard since this one first
         * appeared: two addresses at once carrying it. Or on
         * BLE_ROT_SPRAY_ADDRS addresses first heard inside one d_swap,
         * this one included: no single advertiser rotates that fast, a
         * replay sprayed on fresh addresses one after another does, and
         * a sequential spray never interleaves. */
        int fresh = A->first_ts >= ts - BLE_ROT_DSWAP_S;
        for (int g = 0; g < BLE_ROT_SEAM; g++) {
            const ent_t *G = &S->e[g];
            if (g == i || !G->used || !has_dig(G, d)) continue;
            if (G->last_ord > A->first_ord) { fresh = -1; break; }
            if (G->first_ts >= ts - BLE_ROT_DSWAP_S) fresh++;
        }
        if (fresh < 0 || fresh >= BLE_ROT_SPRAY_ADDRS) poison(S, d, ts);
        A = &S->e[i];
        if (!has_dig(A, d)) {
            A->dig[A->dig_next] = d;
            A->dig_next = (uint8_t)((A->dig_next + 1) % BLE_ROT_TOKENS);
            if (A->ndig < BLE_ROT_TOKENS) A->ndig++;
        }
    }
    /* A controller filtering duplicates reports an address once, so an
     * older address heard again after the newer one - what both the
     * exclusivity guard and token poisoning rest on - never reaches
     * here: propose nothing on such a stream. */
    if (!S->blind && !(A->flags & ENT_EXCLUDED) && ts - A->first_ts <= BLE_ROT_DSWAP_S)
        try_link(S, i, ts);
    tick(S, S->now);
}

void ble_rot_tick_all(void) {
    if (!g_on || !g_tabs) return;
    for (int k = 0; k < BLE_ROT_SENSORS; k++)
        if (g_tabs[k].used) tick(&g_tabs[k], sensor_now(&g_tabs[k]));
}

void ble_rot_update_row(ble_device_t *d) {
    if (!g_on || !d || d->addr_type != 1) return;
    const rot_sensor_t *S = sensor_find(d->sensor_kind, d->sensor_iface, d->adapter);
    int e = S ? ent_find(S, d->addr) : -1;
    /* No entry (evicted, expired, or never a candidate): no hint. A
     * link lasts only while both its addresses are in the window. */
    if (e < 0) memset(&d->hint, 0, sizeof(d->hint));
    else       hint_of(&S->e[e], &d->hint);
}

void ble_rot_snapshot(sloth_state_t *s) {
    if (!s) return;
    if (!g_on) {
        memset(&s->ble_rot, 0, sizeof(s->ble_rot));
        return;
    }
    s->ble_rot = g_st;
    s->ble_rot.enabled = 1;
}

int ble_rot_distinct(const sloth_state_t *s) {
    int n = 0;
    if (!s) return 0;
    for (int i = 0; i < s->ble_device_count && i < MAX_BLE_DEVICES; i++) {
        uint32_t id = s->ble_devices[i].hint.chain;
        int dup = 0;
        if (id)
            for (int j = 0; j < i && !dup; j++)
                dup = s->ble_devices[j].hint.chain == id;
        if (!dup) n++;
    }
    return n;
}

int ble_rot_test_allocated(void) { return g_tabs != NULL; }

int ble_rot_test_held(void) {
    int n = 0;
    if (!g_tabs) return 0;
    for (int k = 0; k < BLE_ROT_SENSORS; k++) {
        const rot_sensor_t *S = &g_tabs[k];
        for (int i = 0; i < BLE_ROT_SEAM; i++) {
            const ent_t *E = &S->e[i];
            if (E->used) n++;
            n += E->ndig + E->has_link_dig + E->has_shape + E->tkey.set;
        }
        for (int i = 0; i < BLE_ROT_POISON_MAX; i++)
            if (S->poison[i].until || S->poison[i].dig) n++;
        if (S->poison_full_until) n++;
    }
    return n;
}

int ble_rot_test_digests(void) {
    int n = 0;
    if (!g_tabs) return 0;
    for (int k = 0; k < BLE_ROT_SENSORS; k++)
        for (int i = 0; i < BLE_ROT_SEAM; i++) {
            const ent_t *E = &g_tabs[k].e[i];
            n += E->ndig + E->has_link_dig;
        }
    return n;
}

uint64_t ble_rot_test_digest(uint8_t kind, const uint8_t *bytes, size_t len,
                             const uint8_t *bytes2, size_t len2) {
    return digest(kind, bytes, len, bytes2, len2);
}

void ble_rot_test_set_key(const uint8_t key[16]) {
    memcpy(g_key, key, sizeof(g_key));
}
