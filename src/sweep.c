#include "sweep.h"
#include "camera_vendor.h"
#include "oui.h"
#include "seqnum_track.h"
#include <stdlib.h>
#include <string.h>

/* The inventory of a sweep (#249). Contract: sweep.h. Main thread. */

sw_inv_t *sweep_inv_new(void) {
    return calloc(1, sizeof(sw_inv_t));
}

void sweep_inv_free(sw_inv_t *inv) { free(inv); }

void sweep_inv_clear(sw_inv_t *inv) {
    if (inv) memset(inv, 0, sizeof(*inv));
}

const char *sweep_kind_name(int kind) {
    switch (kind) {
    case SW_K_AP:     return "ap";
    case SW_K_CLIENT: return "client";
    case SW_K_BLE:    return "ble";
    default:          return "";
    }
}

const char *sweep_ble_type_name(int t) {
    return t == SW_BLE_STATIC ? "static" : t == SW_BLE_PRIVATE ? "private" : "public";
}

const char *sweep_res_name(int res) {
    return res == SW_RES_ASSOC ? "assoc" : res == SW_RES_PERSIST ? "persistent" : "";
}

/* A private BLE address as received (Address_Type 1, top bits 01
 * resolvable or 00 non-resolvable): the kind resolution may make a row
 * of. Anonymous reports and the reserved sub-type never are. */
static int ble_private(uint8_t addr_type, const uint8_t addr[6]) {
    return addr_type == 1 && ((addr[0] & 0xC0) == 0x40 || (addr[0] & 0xC0) == 0x00);
}

const char *sweep_status_name(int st) {
    switch (st) {
    case SW_ST_NEW:     return "new";
    case SW_ST_KNOWN:   return "known";
    case SW_ST_MISSING: return "missing";
    default:            return "";
    }
}

int sweep_ble_kept_type(uint8_t addr_type, const uint8_t addr[6]) {
    switch (addr_type) {
    case 0: case 2:
        return SW_BLE_PUBLIC;
    case 1: case 3:
        /* Address_Type 3 is a resolved random (static) identity; 1 is
         * the address as received, whose top two bits say which random
         * kind it is (Core v5.4 Vol 6 Part B §1.3.2): 11 static, 01
         * resolvable private, 00 non-resolvable private, 10 reserved. */
        if (addr_type == 3) return SW_BLE_STATIC;
        return (addr[0] & 0xC0) == 0xC0 ? SW_BLE_STATIC : -1;
    default:
        return -1;          /* 0xFF anonymous: no address at all */
    }
}

/* ── counts-only sets ── */

static uint64_t set_key(const uint8_t a[6], unsigned tag) {
    uint64_t k = (uint64_t)tag << 48;
    for (int i = 0; i < 6; i++) k |= (uint64_t)a[i] << (8 * (5 - i));
    return k | ((uint64_t)1 << 56);       /* never 0, the empty slot */
}

static void set_add(sw_set_t *set, uint64_t k) {
    /* Open addressing at a load of at most 3/4, so a probe ends. */
    uint64_t h = k * 0x9E3779B97F4A7C15ull;
    unsigned i = (unsigned)(h >> 52) % SW_SET_CAP;
    for (int p = 0; p < SW_SET_CAP; p++) {
        unsigned j = (i + (unsigned)p) % SW_SET_CAP;
        if (set->key[j] == k) return;
        if (set->key[j] == 0) {
            if (set->n >= SW_SET_CAP * 3 / 4) { set->full = 1; return; }
            set->key[j] = k;
            set->n++;
            return;
        }
    }
    set->full = 1;
}

int sweep_set_count(const sw_set_t *set) { return set ? set->n : 0; }

static int set_has(const sw_set_t *set, uint64_t k) {
    uint64_t h = k * 0x9E3779B97F4A7C15ull;
    unsigned i = (unsigned)(h >> 52) % SW_SET_CAP;
    for (int p = 0; p < SW_SET_CAP; p++) {
        unsigned j = (i + (unsigned)p) % SW_SET_CAP;
        if (set->key[j] == k) return 1;
        if (set->key[j] == 0) return 0;
    }
    return 0;
}

static void key_addr(uint64_t k, uint8_t a[6], unsigned *tag) {
    for (int i = 0; i < 6; i++) a[i] = (uint8_t)(k >> (8 * (5 - i)));
    *tag = (unsigned)((k >> 48) & 0xFF);
}

/* ── rows ── */

static sw_emitter_t *find_rw(sw_inv_t *inv, int kind, const uint8_t addr[6],
                             int ble_type) {
    for (int i = 0; i < inv->n; i++) {
        sw_emitter_t *e = &inv->e[i];
        if (e->kind == kind && memcmp(e->addr, addr, 6) == 0 &&
            (kind != SW_K_BLE || e->ble_type == ble_type))
            return e;
    }
    return NULL;
}

const sw_emitter_t *sweep_inv_find(const sw_inv_t *inv, int kind,
                                   const uint8_t addr[6], int ble_type) {
    if (!inv || !addr) return NULL;
    return find_rw((sw_inv_t *)inv, kind, addr, ble_type);
}

static int kind_cap(int kind) {
    return kind == SW_K_AP ? SW_MAX_AP : kind == SW_K_CLIENT ? SW_MAX_CLIENT
                                                             : SW_MAX_BLE;
}

/* The row for (kind, addr), created when new; NULL when the kind is
 * full (counted in dropped[]). */
static sw_emitter_t *row(sw_inv_t *inv, int kind, const uint8_t addr[6],
                         int ble_type, time_t seen) {
    sw_emitter_t *e = find_rw(inv, kind, addr, ble_type);
    if (e) return e;
    if (inv->per_kind[kind] >= kind_cap(kind) || inv->n >= SW_MAX_EMIT) {
        inv->dropped[kind]++;
        return NULL;
    }
    e = &inv->e[inv->n++];
    memset(e, 0, sizeof(*e));
    e->kind = (uint8_t)kind;
    memcpy(e->addr, addr, 6);
    e->ble_type = (uint8_t)ble_type;
    e->channel = kind == SW_K_BLE ? -1 : 0;
    e->first_seen = seen;
    inv->per_kind[kind]++;
    inv->has_kind[kind] = 1;
    return e;
}

static void note_dbm(sw_emitter_t *e, int has, int8_t dbm) {
    if (!has || dbm >= 0) return;       /* 0 is "unseen" in every table read */
    if (!e->has_dbm || dbm > e->best_dbm) e->best_dbm = dbm;
    e->has_dbm = 1;
}

static void note_seen(sw_emitter_t *e, time_t first, time_t last) {
    if (first && (!e->first_seen || first < e->first_seen)) e->first_seen = first;
    if (last > e->last_seen) e->last_seen = last;
}

int sweep_inv_add(sw_inv_t *inv, const sw_emitter_t *src) {
    if (!inv || !src || src->kind >= SW_K_N) return -1;
    sw_emitter_t *e = row(inv, src->kind, src->addr, src->ble_type,
                          src->first_seen);
    if (!e) return -1;
    *e = *src;
    return 0;
}

/* A camera vendor's own block (a mixed-vendor block is a prior only,
 * camera_vendor.h, and never a camera by itself). */
static void camera_by_oui(sw_emitter_t *e) {
    const char *v = NULL;
    int mixed = 0;
    if (cam_vendor_oui(e->addr, &v, NULL, NULL, &mixed) && !mixed && v) {
        e->flags |= SW_F_CAMERA;
        if (!e->camera[0]) snprintf(e->camera, sizeof(e->camera), "%s", v);
    }
}

static int open_setup_alert(const sloth_state_t *s, const uint8_t bssid[6]) {
    char b[20];
    snprintf(b, sizeof(b), "%02x:%02x:%02x:%02x:%02x:%02x",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    for (int i = 0; i < s->alert_count && i < MAX_ALERTS; i++) {
        const alert_t *a = &s->alerts[i];
        if (a->type == ALERT_TYPE_OPEN_SETUP_AP && !a->resolved &&
            strstr(a->key, b))
            return 1;
    }
    return 0;
}

static void observe_aps(sw_inv_t *inv, const sloth_state_t *s) {
    for (int i = 0; i < s->beacon_count && i < MAX_BEACON_APS; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        sw_emitter_t *e = row(inv, SW_K_AP, a->bssid, 0, a->first_seen);
        if (!e) continue;
        /* A revealed SSID replaces the empty one; a later empty beacon
         * never blanks a name already learnt. */
        if (a->ssid[0]) snprintf(e->ssid, sizeof(e->ssid), "%s", a->ssid);
        if (!a->ssid[0] || a->revealed) e->flags |= SW_F_HIDDEN;
        if (a->enc[0])    snprintf(e->enc, sizeof(e->enc), "%s", a->enc);
        if (a->akm[0])    snprintf(e->akm, sizeof(e->akm), "%s", a->akm);
        if (a->vendor[0]) snprintf(e->vendor, sizeof(e->vendor), "%s", a->vendor);
        e->mfp = a->mfp;
        if (a->channel > 0) e->channel = a->channel;
        note_dbm(e, 1, a->signal_dbm);
        note_dbm(e, 1, a->rssi_max_60s);
        note_seen(e, a->first_seen, a->last_seen);
        camera_by_oui(e);
        const char *label = NULL;
        if (a->ssid[0] && cam_setup_ssid(a->ssid, &label, NULL)) {
            e->flags |= SW_F_CAMERA | SW_F_SETUP;
            if (label) snprintf(e->camera, sizeof(e->camera), "%s", label);
        }
        if (open_setup_alert(s, a->bssid)) e->flags |= SW_F_SETUP;
    }
}

/* ── resolution of randomised addresses (sweep.h) ── */

static sw_cand_t *cand_find(sw_inv_t *inv, int kind, const uint8_t a[6]) {
    for (int i = 0; i < inv->ncand; i++)
        if (inv->cand[i].kind == kind && !memcmp(inv->cand[i].addr, a, 6))
            return &inv->cand[i];
    return NULL;
}

/* Follow a randomised address; the row once it is resolved, else NULL.
 * A full table follows nothing new: that address stays counted. */
static sw_emitter_t *cand_note(sw_inv_t *inv, int kind, const uint8_t a[6],
                               time_t first, time_t last, int assoc) {
    sw_cand_t *c = cand_find(inv, kind, a);
    if (!c) {
        if (inv->ncand >= SW_MAX_CAND) { inv->cand_dropped++; return NULL; }
        c = &inv->cand[inv->ncand++];
        memset(c, 0, sizeof(*c));
        c->kind = (uint8_t)kind;
        memcpy(c->addr, a, 6);
        c->first_seen = first;
    }
    if (first && (!c->first_seen || first < c->first_seen)) c->first_seen = first;
    if (last > c->last_seen) c->last_seen = last;
    if (assoc && kind == SW_K_CLIENT) c->assoc = 1;
    int bt = kind == SW_K_BLE ? SW_BLE_PRIVATE : 0;
    if (c->resolved) return find_rw(inv, kind, a, bt);
    int res = c->assoc ? SW_RES_ASSOC
            : c->first_seen && c->last_seen - c->first_seen >= SW_STABLE_SPAN_S
              ? SW_RES_PERSIST : SW_RES_NONE;
    if (res == SW_RES_NONE) return NULL;
    sw_emitter_t *e = row(inv, kind, a, bt, c->first_seen);
    if (!e) return NULL;                /* the kind is full: stays counted */
    c->resolved = 1;
    e->res = (uint8_t)res;
    e->res_conf = res == SW_RES_ASSOC ? SW_CONF_ASSOC : SW_CONF_PERSIST;
    note_seen(e, c->first_seen, c->last_seen);
    return e;
}

/* A client address: kept, or counted when locally administered and
 * kept as well once resolved. */
static sw_emitter_t *client_row(sw_inv_t *inv, const uint8_t mac[6],
                                time_t first, time_t last, int assoc) {
    if (mac[0] & 0x01) return NULL;               /* group: never a transmitter */
    if (mac[0] & 0x02) {
        set_add(&inv->client_random, set_key(mac, 0));
        sw_emitter_t *e = cand_note(inv, SW_K_CLIENT, mac, first, last, assoc);
        /* An assoc row's method can only be stronger than persistence. */
        if (e && assoc && e->res == SW_RES_PERSIST) {
            e->res = SW_RES_ASSOC;
            e->res_conf = SW_CONF_ASSOC;
        }
        return e;
    }
    sw_emitter_t *e = row(inv, SW_K_CLIENT, mac, 0, first);
    if (e && !e->vendor[0]) {
        const char *v = oui_lookup(mac);
        if (v) snprintf(e->vendor, sizeof(e->vendor), "%s", v);
        camera_by_oui(e);
    }
    return e;
}

static void observe_clients(sw_inv_t *inv, const sloth_state_t *s) {
    for (int i = 0; i < s->probe_count && i < MAX_PROBE_CLIENTS; i++) {
        const probe_client_t *p = &s->probe_clients[i];
        sw_emitter_t *e = client_row(inv, p->mac, p->first_seen, p->last_seen, 0);
        if (!e) continue;
        if (p->channel > 0) e->channel = p->channel;
        note_dbm(e, 1, p->signal_dbm);
        note_seen(e, p->first_seen, p->last_seen);
    }
    /* (Re)association responses: the AP sent the frame, so its signal is
     * the AP's and is not the client's (sloth.h, assoc_t). */
    for (int i = 0; i < s->assoc_count && i < MAX_ASSOC_ENTRIES; i++) {
        const assoc_t *a = &s->assocs[i];
        sw_emitter_t *e = client_row(inv, a->sta_mac, a->first_seen, a->last_seen, 1);
        if (!e) continue;
        if (a->channel > 0 && !e->channel) e->channel = a->channel;
        note_seen(e, a->first_seen, a->last_seen);
    }
    for (int i = 0; i < s->assoc_req_count && i < MAX_ASSOC_ENTRIES; i++) {
        const assoc_req_t *r = &s->assoc_reqs[i];
        sw_emitter_t *e = client_row(inv, r->sta, r->ts, r->ts, 1);
        if (e) note_seen(e, r->ts, r->ts);
    }
    /* A randomised probe address whose counter continues, strongly,
     * into a universal one is linked to that device: a count, never a
     * row (sweep.h). */
    for (int i = 0; i < s->seqnum_correlation_count &&
                    i < MAX_SEQNUM_CORRELATIONS; i++) {
        const seqnum_correlation_t *c = &s->seqnum_correlations[i];
        if (!seqnum_corr_is_strong(c)) continue;
        const uint8_t *rnd = c->mac_a_random ? c->mac_a : c->mac_b;
        if ((rnd[0] & 0x03) != 0x02) continue;
        set_add(&inv->client_random, set_key(rnd, 0));
        set_add(&inv->client_linked, set_key(rnd, 0));
    }
}

static void observe_ble(sw_inv_t *inv, const sloth_state_t *s) {
    for (int i = 0; i < s->ble_device_count && i < MAX_BLE_DEVICES; i++) {
        const ble_device_t *d = &s->ble_devices[i];
        int t = sweep_ble_kept_type(d->addr_type, d->addr);
        sw_emitter_t *e;
        if (t < 0) {
            set_add(&inv->ble_private, set_key(d->addr, d->addr_type));
            if (!ble_private(d->addr_type, d->addr)) continue;
            e = cand_note(inv, SW_K_BLE, d->addr, d->first_seen, d->last_seen, 0);
        } else {
            e = row(inv, SW_K_BLE, d->addr, t, d->first_seen);
        }
        if (!e) continue;
        if (d->has_name && d->name[0])
            snprintf(e->name, sizeof(e->name), "%s", d->name);
        if (d->watch_cat[0])
            snprintf(e->cat, sizeof(e->cat), "%s", d->watch_cat);
        if (d->channel >= 0) e->channel = d->channel;
        note_dbm(e, d->has_rssi, d->rssi_best);
        note_seen(e, d->first_seen, d->last_seen);
        if (t == SW_BLE_PUBLIC) camera_by_oui(e);
    }
}

void sweep_inv_observe(sw_inv_t *inv, const sloth_state_t *s) {
    if (!inv || !s) return;
    observe_aps(inv, s);
    observe_clients(inv, s);
    observe_ble(inv, s);
}

/* ── compare ── */

static int cmp_rows(const void *pa, const void *pb) {
    const sw_emitter_t *a = pa, *b = pb;
    if (a->status != b->status) return (int)a->status - (int)b->status;
    if (a->status != SW_ST_MISSING) {
        if (a->has_dbm != b->has_dbm) return a->has_dbm ? -1 : 1;
        if (a->has_dbm && a->best_dbm != b->best_dbm)
            return a->best_dbm > b->best_dbm ? -1 : 1;
    }
    if (a->kind != b->kind) return (int)a->kind - (int)b->kind;
    int c = memcmp(a->addr, b->addr, 6);
    if (c) return c;
    return (int)a->ble_type - (int)b->ble_type;
}

int sweep_compare(const sw_inv_t *cur, const sw_inv_t *base, sw_cmp_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!cur) return -1;
    int cap = cur->n + (base ? base->n : 0);
    out->row = calloc(cap > 0 ? (size_t)cap : 1, sizeof(sw_emitter_t));
    if (!out->row) return -1;
    out->have_base = base != NULL;
    for (int k = 0; k < SW_K_N; k++)
        out->compared[k] = base && base->has_kind[k];
    out->compared_resolved = base && base->has_resolved;
    for (int i = 0; i < cur->n; i++) {
        sw_emitter_t r = cur->e[i];
        int cmp = out->compared[r.kind] && (!r.res || out->compared_resolved);
        const sw_emitter_t *b = cmp
            ? sweep_inv_find(base, r.kind, r.addr, r.ble_type) : NULL;
        r.status = b ? SW_ST_KNOWN : SW_ST_NEW;
        r.base_channel = 0;
        r.base_enc[0] = '\0';
        if (b && r.kind == SW_K_AP) {
            r.base_channel = b->channel;
            snprintf(r.base_enc, sizeof(r.base_enc), "%s", b->enc);
        }
        out->row[out->n++] = r;
        out->count[r.kind][r.status]++;
    }
    for (int i = 0; base && i < base->n; i++) {
        const sw_emitter_t *b = &base->e[i];
        if (!out->compared[b->kind]) continue;
        const sw_emitter_t *h = sweep_inv_find(cur, b->kind, b->addr, b->ble_type);
        if (h) continue;
        /* A resolved row heard this sweep only as a count (not followed
         * long enough to resolve again) was heard: not missing. */
        if (b->res && b->kind == SW_K_CLIENT &&
            set_has(&cur->client_random, set_key(b->addr, 0)))
            continue;
        if (b->res && b->kind == SW_K_BLE &&
            set_has(&cur->ble_private, set_key(b->addr, 1)))
            continue;
        sw_emitter_t r = *b;
        r.status = SW_ST_MISSING;
        r.has_dbm = 0;
        out->row[out->n++] = r;
        out->count[r.kind][SW_ST_MISSING]++;
    }
    qsort(out->row, (size_t)out->n, sizeof(sw_emitter_t), cmp_rows);
    return 0;
}

void sweep_rand_counts(const sw_inv_t *inv, sw_rand_t *o) {
    memset(o, 0, sizeof(*o));
    if (!inv) return;
    o->client_random = sweep_set_count(&inv->client_random);
    o->ble_private = sweep_set_count(&inv->ble_private);
    o->floor = inv->client_random.full || inv->ble_private.full ||
               inv->client_linked.full;
    for (int i = 0; i < inv->n; i++) {
        if (!inv->e[i].res) continue;
        if (inv->e[i].kind == SW_K_CLIENT) o->client_resolved++;
        else if (inv->e[i].kind == SW_K_BLE) o->ble_resolved++;
    }
    for (int j = 0; j < SW_SET_CAP; j++) {
        uint64_t k = inv->client_linked.key[j];
        if (!k) continue;
        uint8_t a[6];
        unsigned tag;
        key_addr(k, a, &tag);
        if (!sweep_inv_find(inv, SW_K_CLIENT, a, 0)) o->client_linked++;
    }
    o->client_unresolved = o->client_random - o->client_resolved - o->client_linked;
    o->ble_unresolved = o->ble_private - o->ble_resolved;
    if (o->client_unresolved < 0) o->client_unresolved = 0;
    if (o->ble_unresolved < 0) o->ble_unresolved = 0;
}

void sweep_cmp_free(sw_cmp_t *c) {
    if (!c) return;
    free(c->row);
    memset(c, 0, sizeof(*c));
}
