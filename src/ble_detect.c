#include <stdio.h>
#include <string.h>
#include "ble_detect.h"
#include "ble_flood.h"
#include "ble_rotation.h"
#include "alert_key.h"
#include "sloth_alert.h"
#include "tune.h"
#include "wifi_oui_attacker.h"

/* Contract, gates and their bases in ble_detect.h. */

int ble_appearance_is_hid(uint16_t a) {
    /* Bluetooth SIG Assigned Numbers, appearance_values.yaml: category
     * 0x00F "Human Interface Device", subcategories 0x01 Keyboard ..
     * 0x0A Presentation Remote; 0x00 is the generic HID value. An
     * appearance is (category << 6) | subcategory. */
    return a >= 0x03C0 && a <= 0x03CA;
}

/* HCI Event_Type, Core Spec v5.4 Vol 4 Part E §7.7.65.2. */
const char *ble_adv_type_name(uint8_t t) {
    switch (t) {
    case 0x00: return "ADV_IND";
    case 0x01: return "ADV_DIRECT_IND";
    case 0x02: return "ADV_SCAN_IND";
    case 0x03: return "ADV_NONCONN_IND";
    case 0x04: return "SCAN_RSP";
    case BLE_EVT_EXT_ADV:      return "EXT_ADV";
    case BLE_EVT_EXT_SCAN_RSP: return "EXT_SCAN_RSP";
    default:   return "adv";
    }
}

/* Bounded copy that always terminates; snprintf("%s") here draws
 * -Wformat-truncation from GCC on every field-to-field copy. */
static void cpy(char *dst, size_t n, const char *src) {
    size_t l = strnlen(src, n - 1);
    memcpy(dst, src, l);
    dst[l] = '\0';
}

static int addr_is_public(uint8_t t)  { return t == 0 || t == 2; }
static int addr_is_random(uint8_t t)  { return t == 1 || t == 3; }

/* Room left in `out`, or count the drop. Every lane goes on calling
 * after a refusal, so *dropped is the whole overflow, not 1. */
static ble_finding_t *slot(ble_finding_t *out, int max, int *n, int *dropped) {
    if (*n >= max) { (*dropped)++; return NULL; }
    ble_finding_t *f = &out[(*n)++];
    memset(f, 0, sizeof(*f));
    return f;
}

static int win_passes(const ble_flood_win_t *w, uint32_t window_ms) {
    if (window_ms == 0) return 0;
    long need_addrs = tune_val(TUNE_BLE_FLOOD_DISTINCT_ADDRS);
    long rate       = tune_val(TUNE_BLE_FLOOD_RATE);
    /* Rate over the whole window length, so a window in progress is
     * judged on what it holds so far: never an extrapolation upward. */
    uint64_t need_total = (uint64_t)rate * window_ms / 1000u;
    if (need_total < 1) need_total = 1;
    return w->baseline && (long)w->fresh >= need_addrs &&
           (uint64_t)w->total >= need_total;
}

static void flood_findings(const sloth_state_t *s, ble_finding_t *out,
                           int max, int *n, int *dropped) {
    for (int i = 0; i < s->ble_flood_count && i < MAX_BLE_FLOOD; i++) {
        const ble_flood_row_t *r = &s->ble_flood[i];
        if (!r->spam_known) continue;                       /* gate 3 */
        const ble_flood_win_t *w = NULL;
        int which = 0;
        if (win_passes(&r->cur, r->window_ms))       { w = &r->cur;  which = 0; }
        else if (win_passes(&r->prev, r->window_ms)) { w = &r->prev; which = 1; }
        if (!w) continue;                                   /* gates 1, 2 */

        ble_finding_t *f = slot(out, max, n, dropped);
        if (!f) continue;               /* counted in *dropped; keep counting */
        f->kind        = BLE_FIND_FLOOD;
        f->alert_type  = ALERT_TYPE_BLE_ADV_FLOOD;
        f->sensor_kind = r->sensor_kind;
        memcpy(f->sensor_iface, r->sensor_iface, sizeof(f->sensor_iface));
        f->sensor_iface[sizeof(f->sensor_iface) - 1] = '\0';
        f->sampled     = r->sampled;
        f->adv_type    = r->adv_type;
        f->family      = r->family;
        f->id          = r->id;
        f->subtype     = r->subtype;
        f->window      = (uint8_t)which;
        f->window_s    = r->window_ms / 1000u;
        f->total       = w->total;
        f->distinct    = w->distinct;
        f->distinct_capped = w->distinct_capped;
        f->fresh       = w->fresh;
        f->prev_total  = r->prev.total;
        f->prev_fresh  = r->prev.fresh;
        f->prev_has_rssi    = r->prev.has_rssi;
        f->prev_rssi_median = r->prev.rssi_median;
        f->rate_x10    = (uint32_t)((uint64_t)w->total * 10000u / r->window_ms);
        f->has_rssi    = w->has_rssi;
        f->rssi_median = w->rssi_median;
        ble_spam_family_known(r->family, r->id, r->subtype, &f->spam_source);

        akey_t ak;
        akey_begin(&ak, f->key, sizeof(f->key), "bleflood");
        akey_tok(&ak, f->sensor_iface);
        akey_u(&ak, r->adv_type);
        akey_tok(&ak, ble_family_name(r->family));
        akey_u(&ak, r->id);
        if (r->subtype >= 0) akey_u(&ak, (unsigned)r->subtype);
        else                 akey_tok(&ak, "none");
        if (!akey_end(&ak)[0]) (*n)--;
    }
}

static void hid_oui_findings(const sloth_state_t *s, ble_finding_t *out,
                             int max, int *n, int *dropped) {
    for (int i = 0; i < s->ble_device_count && i < MAX_BLE_DEVICES; i++) {
        const ble_device_t *d = &s->ble_devices[i];
        if (!d->hid || !addr_is_public(d->addr_type)) continue;
        const char *table = NULL;
        if (oui_is_hak5(d->addr))           table = "Hak5";
        else if (oui_is_espressif(d->addr)) table = "Espressif";
        if (!table) continue;

        ble_finding_t *f = slot(out, max, n, dropped);
        if (!f) continue;               /* counted in *dropped; keep counting */
        f->kind        = BLE_FIND_HID_OUI;
        f->alert_type  = ALERT_TYPE_BLE_HID_UNEXPECTED;
        f->sensor_kind = d->sensor_kind;
        memcpy(f->sensor_iface, d->sensor_iface, sizeof(f->sensor_iface));
        f->sensor_iface[sizeof(f->sensor_iface) - 1] = '\0';
        f->sampled     = d->sampled;
        memcpy(f->addr, d->addr, 6);
        f->addr_type   = d->addr_type;
        f->hid         = d->hid;
        f->appearance  = d->has_appearance ? d->appearance : 0;
        f->oui_table   = table;
        f->addrs       = 1;

        akey_t ak;
        akey_begin(&ak, f->key, sizeof(f->key), "blehid");
        akey_tok(&ak, "oui");
        akey_tok(&ak, f->sensor_iface);
        akey_mac(&ak, d->addr);
        if (!akey_end(&ak)[0]) (*n)--;
    }
}

/* Distinct sensor ifaces among the rows, in first-seen order. */
static int ifaces_of(const sloth_state_t *s, char out[][24], int max) {
    int n = 0;
    for (int i = 0; i < s->ble_device_count && i < MAX_BLE_DEVICES; i++) {
        const char *ifc = s->ble_devices[i].sensor_iface;
        int k = 0;
        while (k < n && strcmp(out[k], ifc) != 0) k++;
        if (k < n || n >= max) continue;
        cpy(out[n++], 24, ifc);
    }
    return n;
}

static time_t sensor_first_ts(const ble_host_t *h, const char *ifc) {
    for (int i = 0; i < BLE_SENSOR_IFACES_MAX; i++)
        if (h->adv_first_by[i].first_ts &&
            strncmp(h->adv_first_by[i].iface, ifc,
                    sizeof(h->adv_first_by[i].iface)) == 0)
            return h->adv_first_by[i].first_ts;
    return 0;
}

typedef struct { const char *ifc; time_t since; } hid_rot_ctx_t;

static int hid_rot_keep(const ble_device_t *d, void *vctx) {
    const hid_rot_ctx_t *c = vctx;
    return strcmp(d->sensor_iface, c->ifc) == 0 &&
           addr_is_random(d->addr_type) &&
           (d->hid & BLE_HID_APPEARANCE) && d->first_seen > c->since;
}

static void hid_rotate_findings(const sloth_state_t *s, time_t now,
                                ble_finding_t *out, int max, int *n,
                                int *dropped) {
    const time_t win = (time_t)tune_val(TUNE_BLE_HID_ROTATE_WINDOW_S);
    const long   need = tune_val(TUNE_BLE_HID_ROTATE_ADDRS);
    const time_t since = now - win;

    char ifs[BLE_SENSOR_IFACES_MAX][24];
    int nif = ifaces_of(s, ifs, BLE_SENSOR_IFACES_MAX);
    for (int k = 0; k < nif; k++) {
        /* This sensor's first window: every address is new to it, so no
         * rotation can be told from a room full of keyboards. Per
         * sensor, because a --bt-capture started an hour after
         * --bt-monitor has a first window of its own. */
        time_t first = sensor_first_ts(&s->ble_host, ifs[k]);
        if (first == 0 || first > since) continue;
        hid_rot_ctx_t c = { ifs[k], since };
        int count = 0;
        const ble_device_t *last = NULL;
        for (int i = 0; i < s->ble_device_count && i < MAX_BLE_DEVICES; i++) {
            const ble_device_t *d = &s->ble_devices[i];
            if (!hid_rot_keep(d, &c)) continue;
            count++;
            last = d;
        }
        /* #156: with --ble-rotation-hints, addresses a committed
         * PAYLOAD hint chains together count once, so an advertiser
         * carrying a documented token across its rotations is one, not
         * N new ones. Timing-only chains do not count here: the
         * research grades them a corroborator, never a finding, and a
         * lone fast rotator - the case this form exists for - is never
         * ambiguous, so timing would suppress it. Without the flag
         * every row is its own chain and this is `count`. */
        int advertisers = ble_rot_distinct(s, hid_rot_keep, &c, 1);
        if (advertisers < need || !last) continue;

        ble_finding_t *f = slot(out, max, n, dropped);
        if (!f) continue;               /* counted in *dropped; keep counting */
        f->kind        = BLE_FIND_HID_ROTATE;
        f->alert_type  = ALERT_TYPE_BLE_HID_UNEXPECTED;
        f->sensor_kind = last->sensor_kind;
        cpy(f->sensor_iface, sizeof(f->sensor_iface), ifs[k]);
        f->sampled     = last->sampled;
        f->hid         = BLE_HID_APPEARANCE;
        f->appearance  = last->appearance;
        f->addrs       = count;
        f->window_s    = (uint32_t)win;

        akey_t ak;
        akey_begin(&ak, f->key, sizeof(f->key), "blehid");
        akey_tok(&ak, "rotate");
        akey_tok(&ak, f->sensor_iface);
        if (!akey_end(&ak)[0]) (*n)--;
    }
}

static void watch_findings(const sloth_state_t *s, time_t now,
                           ble_finding_t *out, int max, int *n,
                           int *dropped) {
    /* (iface, category) pairs, in first-seen order. */
    struct { char ifc[24]; char cat[16]; int addrs; const ble_device_t *d; }
        g[BLE_FINDINGS_MAX];
    int ng = 0;
    for (int i = 0; i < s->ble_device_count && i < MAX_BLE_DEVICES; i++) {
        const ble_device_t *d = &s->ble_devices[i];
        if (!d->watch_cat[0]) continue;
        if (d->last_seen < now - BLE_WATCH_RECENT_SECS) continue;
        int k = 0;
        while (k < ng && (strcmp(g[k].ifc, d->sensor_iface) != 0 ||
                          strcmp(g[k].cat, d->watch_cat) != 0)) k++;
        if (k == ng) {
            if (ng >= BLE_FINDINGS_MAX) {
                /* One drop per (iface, category) group, not per row:
                 * an earlier qualifying row of the same group has
                 * already been counted. */
                int seen = 0;
                for (int j = 0; j < i && !seen; j++) {
                    const ble_device_t *e = &s->ble_devices[j];
                    seen = e->watch_cat[0] &&
                           e->last_seen >= now - BLE_WATCH_RECENT_SECS &&
                           strcmp(e->watch_cat, d->watch_cat) == 0 &&
                           strcmp(e->sensor_iface, d->sensor_iface) == 0;
                }
                if (!seen) (*dropped)++;
                continue;
            }
            cpy(g[ng].ifc, sizeof(g[ng].ifc), d->sensor_iface);
            cpy(g[ng].cat, sizeof(g[ng].cat), d->watch_cat);
            g[ng].addrs = 0;
            g[ng].d = d;
            ng++;
        }
        g[k].addrs++;
    }
    for (int k = 0; k < ng; k++) {
        ble_finding_t *f = slot(out, max, n, dropped);
        if (!f) continue;               /* counted in *dropped; keep counting */
        f->kind        = BLE_FIND_WATCH;
        f->alert_type  = ALERT_TYPE_BLE_WATCHLIST;
        f->sensor_kind = g[k].d->sensor_kind;
        cpy(f->sensor_iface, sizeof(f->sensor_iface), g[k].ifc);
        f->sampled     = g[k].d->sampled;
        f->addrs       = g[k].addrs;
        f->window_s    = BLE_WATCH_RECENT_SECS;
        cpy(f->category, sizeof(f->category), g[k].cat);

        akey_t ak;
        akey_begin(&ak, f->key, sizeof(f->key), "blewl");
        akey_tok(&ak, f->category);
        akey_tok(&ak, f->sensor_iface);
        if (!akey_end(&ak)[0]) (*n)--;
    }
}

int ble_findings_build(const sloth_state_t *s, time_t now,
                       ble_finding_t *out, int max, int *dropped) {
    int n = 0, drop = 0;
    if (s && out && max > 0) {
        flood_findings(s, out, max, &n, &drop);
        hid_oui_findings(s, out, max, &n, &drop);
        hid_rotate_findings(s, now, out, max, &n, &drop);
        watch_findings(s, now, out, max, &n, &drop);
    }
    if (dropped) *dropped = drop;
    return n;
}
