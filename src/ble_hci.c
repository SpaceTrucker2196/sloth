#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "ble_hci.h"
#include "ble_snoop.h"
#include "ble_detect.h"
#include "ble_flood.h"
#include "ble_watchlist.h"
#include "sloth_clock.h"
#include "stab.h"

/* Contract, allow-list and sources in ble_hci.h. Opcodes are
 * OGF << 10 | OCF, Core Specification v5.4 Vol 4 Part E §5.4.1; the
 * command parameters below are read per the §7 clause named on each. */

#define HCI_EV_LE_META              0x3E
#define HCI_SUBEV_ADV_REPORT        0x02
#define HCI_SUBEV_EXT_ADV_REPORT    0x0D

#define OP_INQUIRY                  0x0401  /* §7.1.1 */
#define OP_PERIODIC_INQUIRY         0x0403  /* §7.1.3 */
#define OP_EXIT_PERIODIC_INQUIRY    0x0404  /* §7.1.4 */
#define OP_CREATE_CONN              0x0405  /* §7.1.5 */
#define OP_REMOTE_NAME_REQ          0x0419  /* §7.1.19 */
#define OP_RESET                    0x0C03  /* §7.3.2 */
#define OP_WRITE_SCAN_ENABLE        0x0C1A  /* §7.3.18 */
#define OP_LE_SET_ADV_ENABLE        0x200A  /* §7.8.9 */
#define OP_LE_SET_SCAN_PARAMS       0x200B  /* §7.8.10 */
#define OP_LE_SET_SCAN_ENABLE       0x200C  /* §7.8.11 */
#define OP_LE_CREATE_CONN           0x200D  /* §7.8.12 */
#define OP_LE_SET_EXT_ADV_ENABLE    0x2039  /* §7.8.56 */
#define OP_LE_SET_PER_ADV_ENABLE    0x2040  /* §7.8.63 */
#define OP_LE_SET_EXT_SCAN_PARAMS   0x2041  /* §7.8.64 */
#define OP_LE_SET_EXT_SCAN_ENABLE   0x2042  /* §7.8.65 */
#define OP_LE_EXT_CREATE_CONN       0x2043  /* §7.8.66 */

int bt_dev_is_bluetooth(const char *name) {
    return name && strncmp(name, "bluetooth", 9) == 0;
}

int bt_dev_is_raw_hci(const char *name) {
    return bt_dev_is_bluetooth(name) && name[9] >= '0' && name[9] <= '9';
}

/* ── State ─────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t     addr[6];   /* display order */
    uint8_t     type;
    uint8_t     kind;      /* sensor_kind_t */
    char        iface[sizeof(((ble_device_t *)0)->sensor_iface)];
} ble_key_t;

/* Keyed on the sensor as well as the address (#144 slice 3): the host
 * controller hears every advertisement it is scanning for, an Ubertooth
 * samples one channel, and one row summing both would mean neither. */
static int dev_key_eq(const void *row, const void *key) {
    const ble_device_t *d = row;
    const ble_key_t    *k = key;
    return d->addr_type == k->type && memcmp(d->addr, k->addr, 6) == 0 &&
           d->sensor_kind == k->kind &&
           strcmp(d->sensor_iface, k->iface) == 0;
}

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
/* STAB_OLDEST: an advertiser picks its own address and a random one
 * rotates by design, so a spray of fresh addresses must churn the table
 * rather than make it refuse. Every loss lands in evict_ble_device. */
STAB_DECL(g_devs, ble_device_t, MAX_BLE_DEVICES, last_seen, STAB_OLDEST,
          SH_EVICT_BLE_DEVICE, NULL, dev_key_eq);
static ble_host_t g_host;
static int        g_host_init;

/* Open fragment trains (ble_hci.h, "Fragmented extended reports"). */
typedef struct {
    uint64_t seq;          /* 0 = free; otherwise last touched, for eviction */
    uint16_t adapter;
    uint8_t  addr_type;
    uint8_t  addr[6];      /* HCI order */
    uint8_t  sid;
    uint8_t  scan_rsp;
} ext_train_t;
static ext_train_t g_trains[BLE_EXT_TRAINS];
static uint64_t    g_train_seq;

static void trains_clear_adapter(int adapter) {
    for (int i = 0; i < BLE_EXT_TRAINS; i++)
        if (adapter < 0 || g_trains[i].adapter == (uint16_t)adapter)
            memset(&g_trains[i], 0, sizeof(g_trains[i]));
}

static void ctrl_init(ble_ctrl_t *c, int index) {
    memset(c, 0, sizeof(*c));
    c->index        = index;
    c->scan_enabled = -1;
    c->scan_mode    = BLE_SCAN_UNKNOWN;
}

static void host_init_locked(void) {
    if (g_host_init) return;
    memset(&g_host, 0, sizeof(g_host));
    g_host.ctrl_index      = -1;
    g_host.scan_mode       = BLE_SCAN_UNKNOWN;
    g_host.filter_policy   = -1;
    g_host.scan_enabled    = -1;
    g_host.last_tx_kind    = BT_TX_NONE;
    g_host.last_tx_adapter = -1;
    for (int k = 0; k < BT_TX_KIND_COUNT; k++) g_host.tx_adapter[k] = -1;
    for (int i = 0; i < BT_MAX_CTRL; i++) ctrl_init(&g_host.ctrl[i], -1);
    ctrl_init(&g_host.ctrl_overflow, -1);
    trains_clear_adapter(-1);
    g_host_init = 1;
}

/* ── Per-controller on/off state ──────────────────────────────────── */

static int handles_any(const uint32_t *set) {
    for (int i = 0; i < BT_ADV_HANDLE_WORDS; i++) if (set[i]) return 1;
    return 0;
}

static void handle_put(uint32_t *set, uint8_t h, int on) {
    uint32_t bit = 1u << (h & 31);
    if (on) set[h >> 5] |= bit;
    else    set[h >> 5] &= ~bit;
}

static int is_overflow(const ble_ctrl_t *c) { return c == &g_host.ctrl_overflow; }

/* The slot for HCI index `adapter`: its own, else a free one, else one
 * holding nothing worth keeping (no NEW_INDEX, nothing on), else the
 * shared overflow slot. */
static ble_ctrl_t *ctrl_for(uint16_t adapter) {
    ble_ctrl_t *spare = NULL;
    for (int i = 0; i < BT_MAX_CTRL; i++) {
        ble_ctrl_t *c = &g_host.ctrl[i];
        if (c->index == (int)adapter) return c;
        if (!spare && c->index < 0) spare = c;
    }
    for (int i = 0; !spare && i < BT_MAX_CTRL; i++) {
        ble_ctrl_t *c = &g_host.ctrl[i];
        if (!c->live && c->on_mask == 0) spare = c;
    }
    if (!spare) {
        g_host.ctrl_untracked++;
        return &g_host.ctrl_overflow;
    }
    ctrl_init(spare, adapter);
    return spare;
}

static ble_ctrl_t *ctrl_find(uint16_t adapter) {
    for (int i = 0; i < BT_MAX_CTRL; i++)
        if (g_host.ctrl[i].index == (int)adapter) return &g_host.ctrl[i];
    return NULL;
}

/* Rederive one controller's on_mask from its fields, then the host's
 * view across all of them. The overflow slot only ever gains bits: it
 * stands for several controllers, so a disable seen on one of them is
 * not evidence the others stopped. */
static void ctrl_recompute(ble_ctrl_t *c) {
    uint32_t m = 0;
    if (c->adv_on)                                   m |= 1u << BT_TX_ADV;
    if (c->ext_adv_unknown || handles_any(c->ext_adv_sets))
                                                     m |= 1u << BT_TX_EXT_ADV;
    if (handles_any(c->per_adv_sets))                m |= 1u << BT_TX_PERIODIC_ADV;
    if (c->page_inq_scan_on)                         m |= 1u << BT_TX_SCAN_ENABLE;
    if (c->per_inquiry_on)                           m |= 1u << BT_TX_PERIODIC_INQUIRY;
    if (c->scan_enabled == 1 && c->scan_mode == BLE_SCAN_ACTIVE)
                                                     m |= 1u << BT_TX_ACTIVE_SCAN;
    c->on_mask = is_overflow(c) ? (c->on_mask | m) : m;

    uint32_t on = g_host.ctrl_overflow.on_mask;
    int live = 0, used = 0, reset_all = 1;
    for (int i = 0; i < BT_MAX_CTRL; i++) {
        const ble_ctrl_t *k = &g_host.ctrl[i];
        if (k->index < 0) continue;
        used++;
        on |= k->on_mask;
        if (k->live && k->primary) live++;
        if (!k->reset_seen) reset_all = 0;
    }
    g_host.tx_on_mask  = on;
    g_host.controllers = live;
    g_host.tx_baseline = used > 0 && reset_all && g_host.ctrl_untracked == 0;
}

/* ── Names ─────────────────────────────────────────────────────────── */

const char *bt_tx_kind_name(int kind) {
    switch (kind) {
    case BT_TX_NONE:             return "none";
    case BT_TX_ACTIVE_SCAN:      return "active_scan";
    case BT_TX_INQUIRY:          return "inquiry";
    case BT_TX_PERIODIC_INQUIRY: return "periodic_inquiry";
    case BT_TX_ADV:              return "advertising";
    case BT_TX_EXT_ADV:          return "ext_advertising";
    case BT_TX_PERIODIC_ADV:     return "periodic_advertising";
    case BT_TX_LE_CONNECT:       return "le_connect";
    case BT_TX_BREDR_CONNECT:    return "bredr_connect";
    case BT_TX_REMOTE_NAME:      return "remote_name_request";
    case BT_TX_SCAN_ENABLE:      return "inquiry_page_scan";
    default:                     return "";
    }
}

const char *bt_tx_recency_name(int recency) {
    switch (recency) {
    case BT_TX_NEVER:   return "never";
    case BT_TX_RECENT:  return "recent";
    case BT_TX_EARLIER: return "earlier";
    default:            return "";
    }
}

const char *ble_scan_mode_name(int mode) {
    switch (mode) {
    case BLE_SCAN_PASSIVE: return "passive";
    case BLE_SCAN_ACTIVE:  return "active";
    default:               return "unknown";
    }
}

const char *ble_filter_policy_name(int policy) {
    switch (policy) {
    case 0:  return "basic";
    case 1:  return "accept_list";
    case 2:  return "extended";
    case 3:  return "extended_accept_list";
    default: return "unknown";
    }
}

int ble_filter_policy_is_accept_list(int policy) {
    return policy == 1 || policy == 3;
}

int bt_tx_recency(time_t last_tx_wall, time_t now) {
    if (last_tx_wall <= 0) return BT_TX_NEVER;
    /* A clock that stepped backwards reads as recent: the safe side for
     * a finding about sloth's own host transmitting. */
    if (now - last_tx_wall <= BT_TX_RECENT_SECS) return BT_TX_RECENT;
    return BT_TX_EARLIER;
}

uint32_t bt_tx_asserted_mask(const ble_host_t *h, time_t now) {
    uint32_t m = 0;
    if (!h) return 0;
    for (int k = BT_TX_NONE + 1; k < BT_TX_KIND_COUNT; k++)
        if (((h->tx_on_mask >> k) & 1u) ||
            bt_tx_recency(h->tx_wall[k], now) == BT_TX_RECENT)
            m |= 1u << k;
    return m;
}

void bt_tx_kinds_format(uint32_t mask, char *buf, size_t sz) {
    if (!buf || sz == 0) return;
    size_t off = 0;
    buf[0] = '\0';
    for (int k = BT_TX_NONE + 1; k < BT_TX_KIND_COUNT; k++) {
        if (!((mask >> k) & 1u)) continue;
        const char *n = bt_tx_kind_name(k);
        size_t need = strlen(n) + (off ? 1 : 0);
        if (off + need + 1 > sz) break;
        if (off) buf[off++] = ',';
        memcpy(buf + off, n, strlen(n));
        off += strlen(n);
        buf[off] = '\0';
    }
}

/* ── Advertising reports ───────────────────────────────────────────── */

typedef struct {
    uint16_t adapter;
    time_t   ts;
} adv_ctx_t;

/* Caller holds g_mu. */
static void observe_locked(const ble_obs_t *o) {
    const ble_adv_report_t *r = o->r;
    ble_key_t key;
    for (int i = 0; i < 6; i++) key.addr[i] = r->addr[5 - i];
    key.type  = r->addr_type;
    key.kind  = o->sensor_kind;
    /* Truncated to the row's field before comparing, so a name longer
     * than the field still finds the row it made. */
    snprintf(key.iface, sizeof(key.iface), "%s", o->iface ? o->iface : "");

    int created = 0;
    ble_device_t *d = stab_get(&g_devs, &key, o->ts, &created);
    if (!d) return;   /* STAB_OLDEST never refuses; defensive only */
    if (created) {
        memcpy(d->addr, key.addr, 6);
        d->addr_type   = key.type;
        d->sensor_kind = key.kind;
        memcpy(d->sensor_iface, key.iface, sizeof(d->sensor_iface));
        d->first_seen  = o->ts;
        d->rssi_best   = -128;
    }
    d->last_seen       = o->ts;
    d->adapter         = o->adapter;
    d->sampled         = o->sampled ? 1 : 0;
    d->channel         = (int8_t)(o->channel >= 0 && o->channel <= 39 ? o->channel : -1);
    d->last_event_type = r->event_type;
    if (r->event_type <= 7) d->pdu_mask |= (uint8_t)(1u << r->event_type);
    if (created) d->adv_sid = 0xFF;
    if (r->ext) {
        if (!(r->ext_event_type & 0x0010)) d->ext_adv = 1;
        d->primary_phy   = r->primary_phy;
        d->secondary_phy = r->secondary_phy;
        d->adv_sid       = r->sid;
    }
    d->adv_count++;
    /* Fields are kept once seen: an ADV_IND and its SCAN_RSP carry
     * different AD structures, and the absence of one in the next report
     * is not evidence the device stopped advertising it. */
    if (r->has_local_name) {
        d->has_name      = 1;
        d->name_complete = r->local_name_complete ? 1 : 0;
        size_t n = strnlen(r->local_name, BLE_LOCAL_NAME_MAX);
        if (n > BLE_DEV_NAME_MAX) n = BLE_DEV_NAME_MAX;
        memcpy(d->name, r->local_name, n);
        d->name[n] = '\0';
    }
    if (r->has_service_uuid16) { d->has_uuid16 = 1; d->uuid16 = r->service_uuid16; }
    /* Manufacturer company and first octet: the FIRST pair heard, kept
     * (sloth.h), so a device rotating Continuity types is one row state. */
    if (r->has_mfr_data && !d->has_mfr) {
        d->has_mfr = 1;
        d->mfr_id  = r->mfr_id;
        if (r->mfr_data_len >= 1) {
            d->has_mfr_sub = 1;
            d->mfr_sub     = r->mfr_data[0];
        }
    }
    if (r->has_appearance)     { d->has_appearance = 1; d->appearance = r->appearance; }
    if (r->has_tx_power)       { d->has_tx_power = 1; d->tx_power = r->tx_power; }
    if (r->has_flags)          { d->has_flags = 1; d->flags = r->flags; }
    if (r->has_rssi) {
        d->has_rssi = 1;
        d->rssi     = r->rssi;
        if (r->rssi > d->rssi_best) d->rssi_best = r->rssi;
    }
    /* #144 slice 4: what the three BLE rules key on. */
    if (r->has_svc_data16) {
        d->has_svc_data    = 1;
        d->svc_data_uuid16 = r->svc_data_uuid16;
    }
    if (r->has_appearance && ble_appearance_is_hid(r->appearance))
        d->hid |= BLE_HID_APPEARANCE;
    for (int i = 0; i < r->uuid16_count && i < BLE_UUID16_LIST_MAX; i++)
        if (r->uuid16_list[i] == 0x1812) d->hid |= BLE_HID_SERVICE;
    const char *cat = ble_watchlist_match(r);
    if (cat) snprintf(d->watch_cat, sizeof(d->watch_cat), "%s", cat);

    if (g_host.adv_first_ts == 0 || o->ts < g_host.adv_first_ts)
        g_host.adv_first_ts = o->ts;
    if (o->ts > g_host.adv_last_ts) g_host.adv_last_ts = o->ts;
    /* Per sensor iface: the rotation form's first-window gate. A table
     * full of ifaces leaves a new one untracked, and an untracked iface
     * is never judged (ble_detect.c), so overflow is quiet, not noisy. */
    for (int i = 0; i < BLE_SENSOR_IFACES_MAX; i++) {
        if (g_host.adv_first_by[i].first_ts == 0) {
            memcpy(g_host.adv_first_by[i].iface, key.iface,
                   sizeof(g_host.adv_first_by[i].iface));
            g_host.adv_first_by[i].first_ts = o->ts;
            break;
        }
        if (strcmp(g_host.adv_first_by[i].iface, key.iface) == 0) {
            if (o->ts < g_host.adv_first_by[i].first_ts)
                g_host.adv_first_by[i].first_ts = o->ts;
            break;
        }
    }

    ble_flood_note(o, key.addr, sloth_mono_ms());
}

void ble_dev_observe(const ble_obs_t *o) {
    if (!o || !o->r) return;
    pthread_mutex_lock(&g_mu);
    host_init_locked();
    observe_locked(o);
    pthread_mutex_unlock(&g_mu);
}

static void on_report(const ble_adv_report_t *r, void *vctx) {
    const adv_ctx_t *c = vctx;
    ble_obs_t o = { r, SENSOR_BLE, BT_MONITOR_DEVICE, c->adapter, -1, 0, c->ts };
    observe_locked(&o);
}

static int train_find(const ext_train_t *k) {
    for (int i = 0; i < BLE_EXT_TRAINS; i++) {
        const ext_train_t *t = &g_trains[i];
        if (t->seq && t->adapter == k->adapter && t->addr_type == k->addr_type &&
            t->sid == k->sid && t->scan_rsp == k->scan_rsp &&
            memcmp(t->addr, k->addr, 6) == 0)
            return i;
    }
    return -1;
}

static void train_open(const ext_train_t *k) {
    int slot = 0;
    for (int i = 0; i < BLE_EXT_TRAINS; i++) {
        if (!g_trains[i].seq) { slot = i; break; }
        if (g_trains[i].seq < g_trains[slot].seq) slot = i;
    }
    if (g_trains[slot].seq) g_host.ext_trains_evicted++;
    g_trains[slot] = *k;
    g_trains[slot].seq = ++g_train_seq;
}

/* One decoded 0x0D report: into the table, or counted as the tail of a
 * fragment train (ble_hci.h). */
static ble_rec_verdict_t ext_report(const ble_adv_report_t *r,
                                    uint16_t adapter, time_t ts) {
    /* A Legacy-bit report is a whole legacy PDU, never fragmented, and
     * the parser has refused one that says otherwise. */
    if (!(r->ext_event_type & 0x0010)) {
        ext_train_t k;
        memset(&k, 0, sizeof(k));
        k.adapter   = adapter;
        k.addr_type = r->addr_type;
        memcpy(k.addr, r->addr, 6);
        k.sid       = r->sid;
        k.scan_rsp  = r->event_type == BLE_EVT_EXT_SCAN_RSP;
        int t = train_find(&k);
        if (t >= 0) {
            /* Middle or last fragment: its data starts wherever the one
             * before stopped, so it is not walked. */
            if (r->data_status == BLE_EXT_DATA_INCOMPLETE)
                g_trains[t].seq = ++g_train_seq;
            else
                memset(&g_trains[t], 0, sizeof(g_trains[t]));
            g_host.ext_fragments++;
            return BLE_REC_EXT_FRAGMENT;
        }
        if (r->data_status == BLE_EXT_DATA_INCOMPLETE) train_open(&k);
        if (r->data_status != BLE_EXT_DATA_COMPLETE) g_host.ext_adv_partial++;
    }
    adv_ctx_t c = { adapter, ts };
    on_report(r, &c);
    return BLE_REC_EXT_ADV;
}

typedef struct {
    uint16_t adapter;
    time_t   ts;
    int      rows;     /* reports of this event that reached the table */
} ext_ctx_t;

static void on_ext_report(const ble_adv_report_t *r, void *vctx) {
    ext_ctx_t *c = vctx;
    if (ext_report(r, c->adapter, c->ts) == BLE_REC_EXT_ADV) c->rows++;
}

static ble_rec_verdict_t ingest_event(const uint8_t *p, size_t len,
                                      uint16_t adapter, time_t ts) {
    if (len < 2) return BLE_REC_MALFORMED;
    /* Only the LE Meta event is on the list; every other event — Link
     * Key Notification among them — is refused on its code alone. */
    if (p[0] != HCI_EV_LE_META) return BLE_REC_IGNORED;
    size_t plen = p[1];
    if (plen < 1 || 2 + plen > len) return BLE_REC_MALFORMED;
    uint8_t sub = p[2];
    /* Every report of a multi-report event, as consecutive records
     * (ble_snoop.h): the walkers refuse the whole event unless its
     * reports fill the parameters exactly, so nothing reaches the table
     * from an event whose Num_Reports disagrees with its bytes. */
    if (sub == HCI_SUBEV_EXT_ADV_REPORT) {
        ext_ctx_t c = { adapter, ts, 0 };
        if (ble_hci_ext_adv_walk(p, 2 + plen, on_ext_report, &c) == 0)
            return BLE_REC_MALFORMED;
        return c.rows ? BLE_REC_EXT_ADV : BLE_REC_EXT_FRAGMENT;
    }
    if (sub != HCI_SUBEV_ADV_REPORT) return BLE_REC_IGNORED;
    adv_ctx_t c = { adapter, ts };
    return ble_hci_adv_walk(p, 2 + plen, on_report, &c) > 0
        ? BLE_REC_ADV : BLE_REC_MALFORMED;
}

static int popcount_phys(uint8_t phys) {
    /* Scanning_PHYs bit 0 = LE 1M, bit 2 = LE Coded; bit 1 is reserved
     * because LE 2M carries no primary advertising channel. */
    return ((phys & 0x01) ? 1 : 0) + ((phys & 0x04) ? 1 : 0);
}

static void note_tx(int kind, uint16_t adapter, time_t wall) {
    g_host.last_tx_kind     = kind;
    g_host.last_tx_adapter  = adapter;
    g_host.last_tx_wall     = wall;
    g_host.tx_wall[kind]    = wall;
    g_host.tx_adapter[kind] = adapter;
    g_host.tx_kind_mask    |= 1u << kind;
    g_host.tx_count++;
}

/* Returns MALFORMED for an allow-listed command whose parameters do not
 * have the length its clause gives, IGNORED for anything else. */
static ble_rec_verdict_t ingest_command(const uint8_t *p, size_t len,
                                        uint16_t adapter, time_t wall) {
    if (len < 2) return BLE_REC_MALFORMED;
    uint16_t op = (uint16_t)(p[0] | (p[1] << 8));
    int tx = BT_TX_NONE;
    switch (op) {
    case OP_INQUIRY:            tx = BT_TX_INQUIRY;          break;
    case OP_CREATE_CONN:        tx = BT_TX_BREDR_CONNECT;    break;
    case OP_REMOTE_NAME_REQ:    tx = BT_TX_REMOTE_NAME;      break;
    case OP_LE_CREATE_CONN:
    case OP_LE_EXT_CREATE_CONN: tx = BT_TX_LE_CONNECT;       break;
    case OP_PERIODIC_INQUIRY:
    case OP_EXIT_PERIODIC_INQUIRY:
    case OP_RESET:
    case OP_WRITE_SCAN_ENABLE:
    case OP_LE_SET_ADV_ENABLE:
    case OP_LE_SET_EXT_ADV_ENABLE:
    case OP_LE_SET_PER_ADV_ENABLE:
    case OP_LE_SET_SCAN_PARAMS:
    case OP_LE_SET_EXT_SCAN_PARAMS:
    case OP_LE_SET_SCAN_ENABLE:
    case OP_LE_SET_EXT_SCAN_ENABLE:
        break;                     /* parameters decide; read below */
    default:
        return BLE_REC_IGNORED;    /* parameters never read */
    }
    if (len < 3) return BLE_REC_MALFORMED;
    size_t plen = p[2];
    if (3 + plen > len) return BLE_REC_MALFORMED;
    const uint8_t *a = p + 3;

    /* The one-shot commands whose mere issue puts the controller on the
     * air: inquiry and paging transmit ID packets, and an LE initiator
     * sends CONNECT_IND. Each ends on its own (Inquiry_Length is at most
     * 61.44 s, inside the recency window), so recency alone covers them
     * and their parameters are not needed. */
    if (tx != BT_TX_NONE) {
        note_tx(tx, adapter, wall);
        return BLE_REC_COMMAND;
    }

    /* Every length is checked before the controller's state is touched,
     * so a malformed command changes nothing. */
    switch (op) {
    case OP_PERIODIC_INQUIRY:      if (plen != 9) return BLE_REC_MALFORMED; break;
    case OP_EXIT_PERIODIC_INQUIRY:
    case OP_RESET:                 if (plen != 0) return BLE_REC_MALFORMED; break;
    case OP_WRITE_SCAN_ENABLE:
    case OP_LE_SET_ADV_ENABLE:     if (plen != 1) return BLE_REC_MALFORMED; break;
    case OP_LE_SET_EXT_ADV_ENABLE:
        /* Enable, Num_Sets, then Advertising_Handle, Duration(2),
         * Max_Extended_Advertising_Events for each set (§7.8.56). */
        if (plen < 2 || plen != (size_t)(2 + 4 * a[1])) return BLE_REC_MALFORMED;
        break;
    case OP_LE_SET_PER_ADV_ENABLE:
    case OP_LE_SET_SCAN_ENABLE:    if (plen != 2) return BLE_REC_MALFORMED; break;
    case OP_LE_SET_SCAN_PARAMS:    if (plen != 7) return BLE_REC_MALFORMED; break;
    case OP_LE_SET_EXT_SCAN_PARAMS: {
        if (plen < 3) return BLE_REC_MALFORMED;
        int nphy = popcount_phys(a[2]);
        if (nphy == 0 || plen != (size_t)(3 + 5 * nphy)) return BLE_REC_MALFORMED;
        break;
    }
    case OP_LE_SET_EXT_SCAN_ENABLE: if (plen != 6) return BLE_REC_MALFORMED; break;
    default: break;
    }

    ble_ctrl_t *c = ctrl_for(adapter);
    switch (op) {
    case OP_PERIODIC_INQUIRY:
        /* Inquires every period until Exit Periodic Inquiry Mode. */
        c->per_inquiry_on = 1;
        note_tx(BT_TX_PERIODIC_INQUIRY, adapter, wall);
        break;
    case OP_EXIT_PERIODIC_INQUIRY:
        c->per_inquiry_on = 0;
        break;
    case OP_RESET:
        /* §7.3.2: the controller returns to its power-on state — no
         * advertising, no scan, no inquiry or page scan, no periodic
         * inquiry. From here every change crosses the channel, so this
         * controller's on-state is complete (tx_baseline). The scan type
         * is not assumed from the default; it waits for parameters. */
        if (!is_overflow(c)) {
            int idx = c->index;
            uint8_t live = c->live, primary = c->primary;
            ctrl_init(c, idx);
            /* The controller drops whatever reports it was assembling. */
            trains_clear_adapter(idx);
            c->live = live;
            c->primary = primary;
            c->scan_enabled = 0;
            c->reset_seen = 1;
        }
        break;
    case OP_WRITE_SCAN_ENABLE:
        /* Scan_Enable: bit 0 inquiry scan, bit 1 page scan — either
         * makes the controller answer another device's inquiry or page,
         * until a Write_Scan_Enable that clears both. */
        c->page_inq_scan_on = (a[0] & 0x03) != 0;
        if (c->page_inq_scan_on) note_tx(BT_TX_SCAN_ENABLE, adapter, wall);
        break;
    case OP_LE_SET_ADV_ENABLE:
        /* 0x00 off, 0x01 on; other values are reserved and change nothing. */
        if (a[0] == 0x01) { c->adv_on = 1; note_tx(BT_TX_ADV, adapter, wall); }
        else if (a[0] == 0x00) c->adv_on = 0;
        break;
    case OP_LE_SET_EXT_ADV_ENABLE: {
        /* Sets are tracked by handle only when Num_Sets is 1. For more,
         * the handles are not read yet: Vol 4 Part E §5.2 makes the sets
         * consecutive records, as the kernel's struct hci_cp_ext_adv_set
         * does, so they could be. Until then an enable of several sets
         * is "on, handles unknown", which only a disable of all sets
         * (Num_Sets 0) clears; a partial disable of several sets changes
         * nothing, the safe side. */
        uint8_t n = a[1];
        if (a[0] == 0x01) {
            if (n == 1) handle_put(c->ext_adv_sets, a[2], 1);
            else        c->ext_adv_unknown = 1;
            note_tx(BT_TX_EXT_ADV, adapter, wall);
        } else if (a[0] == 0x00) {
            if (n == 0) {
                memset(c->ext_adv_sets, 0, sizeof(c->ext_adv_sets));
                c->ext_adv_unknown = 0;
            } else if (n == 1) {
                handle_put(c->ext_adv_sets, a[2], 0);
            }
        }
        break;
    }
    case OP_LE_SET_PER_ADV_ENABLE:
        /* Enable bit 0 = periodic advertising on (bit 1 is ADI only),
         * then the Advertising_Handle it applies to (§7.8.63). */
        handle_put(c->per_adv_sets, a[1], a[0] & 0x01);
        if (a[0] & 0x01) note_tx(BT_TX_PERIODIC_ADV, adapter, wall);
        break;
    case OP_LE_SET_SCAN_PARAMS:
        /* LE_Scan_Type, Interval(2), Window(2), Own_Address_Type,
         * Scanning_Filter_Policy. */
        g_host.scan_mode     = a[0] == 0x01 ? BLE_SCAN_ACTIVE : BLE_SCAN_PASSIVE;
        g_host.filter_policy = a[6] <= 3 ? a[6] : -1;
        c->scan_mode         = (int8_t)g_host.scan_mode;
        if (g_host.scan_mode == BLE_SCAN_ACTIVE)
            note_tx(BT_TX_ACTIVE_SCAN, adapter, wall);
        break;
    case OP_LE_SET_EXT_SCAN_PARAMS: {
        /* Own_Address_Type, Scanning_Filter_Policy, Scanning_PHYs, then
         * Scan_Type, Interval(2), Window(2) per PHY bit set. Active if
         * any PHY scans actively. */
        int nphy = popcount_phys(a[2]);
        int active = 0;
        for (int i = 0; i < nphy; i++)
            if (a[3 + 5 * i] == 0x01) active = 1;
        g_host.scan_mode     = active ? BLE_SCAN_ACTIVE : BLE_SCAN_PASSIVE;
        g_host.filter_policy = a[1] <= 3 ? a[1] : -1;
        c->scan_mode         = (int8_t)g_host.scan_mode;
        if (active) note_tx(BT_TX_ACTIVE_SCAN, adapter, wall);
        break;
    }
    case OP_LE_SET_SCAN_ENABLE:
    case OP_LE_SET_EXT_SCAN_ENABLE:
        /* LE_Scan_Enable first in both (§7.8.11, §7.8.65). Enabling under
         * active parameters is itself a transmission: the kernel restarts
         * a scan by toggling enable alone, parameters untouched, and the
         * scan sends SCAN_REQ again from that moment. */
        g_host.scan_enabled = a[0] == 0x01;
        c->scan_enabled     = (int8_t)(a[0] == 0x01);
        if (a[0] == 0x01 && c->scan_mode == BLE_SCAN_ACTIVE)
            note_tx(BT_TX_ACTIVE_SCAN, adapter, wall);
        break;
    default:
        break;
    }
    ctrl_recompute(c);
    return BLE_REC_COMMAND;
}

static ble_rec_verdict_t ingest_new_index(const uint8_t *p, size_t len,
                                          uint16_t adapter) {
    /* struct hci_mon_new_index: type, bus, bdaddr (6, LE), name[8]. */
    if (len != 16) return BLE_REC_MALFORMED;
    /* A newly registered controller has been told nothing yet; the
     * replay a new monitor socket gets for controllers already up is
     * the same record, and there too nothing is known before it. */
    ble_ctrl_t *c = ctrl_for(adapter);
    if (!is_overflow(c)) {
        ctrl_init(c, adapter);
        c->live    = 1;
        c->primary = p[0] == 0x00;   /* HCI_PRIMARY; 0x01 is AMP */
    }
    ctrl_recompute(c);
    g_host.ctrl_index = adapter;
    g_host.ctrl_bus   = p[1];
    for (int i = 0; i < 6; i++) g_host.ctrl_addr[i] = p[2 + 5 - i];
    /* The kernel's own "hciN", but still bytes off a socket: printable
     * ASCII only, stopping at the first NUL. */
    int n = 0;
    for (int i = 0; i < 8 && p[8 + i]; i++) {
        uint8_t ch = p[8 + i];
        g_host.ctrl_name[n++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
    }
    g_host.ctrl_name[n] = '\0';
    return BLE_REC_NEW_INDEX;
}

static ble_rec_verdict_t ingest_del_index(size_t len, uint16_t adapter) {
    /* DEL_INDEX carries no payload. The controller is gone, so it is
     * transmitting nothing and no longer counts as present. */
    if (len != 0) return BLE_REC_MALFORMED;
    ble_ctrl_t *c = ctrl_find(adapter);
    if (c) {
        ctrl_init(c, -1);
        ctrl_recompute(c);
    }
    trains_clear_adapter(adapter);
    return BLE_REC_DEL_INDEX;
}

ble_rec_verdict_t ble_mon_ingest(const uint8_t *rec, size_t caplen,
                                 size_t origlen, time_t frame_ts,
                                 time_t wall) {
    pthread_mutex_lock(&g_mu);
    host_init_locked();
    g_host.records++;
    ble_rec_verdict_t v = BLE_REC_MALFORMED;
    if (rec && caplen >= BT_MON_HDR_LEN) {
        uint16_t adapter = (uint16_t)((rec[0] << 8) | rec[1]);
        uint16_t opcode  = (uint16_t)((rec[2] << 8) | rec[3]);
        const uint8_t *p = rec + BT_MON_HDR_LEN;
        size_t len = caplen - BT_MON_HDR_LEN;
        int listed = opcode == BT_MON_NEW_INDEX ||
                     opcode == BT_MON_DEL_INDEX ||
                     opcode == BT_MON_COMMAND_PKT ||
                     opcode == BT_MON_EVENT_PKT;
        if (!listed)
            v = BLE_REC_IGNORED;
        else if (caplen < origlen)
            v = BLE_REC_MALFORMED;   /* never decode from a snapped prefix */
        else if (opcode == BT_MON_NEW_INDEX)
            v = ingest_new_index(p, len, adapter);
        else if (opcode == BT_MON_DEL_INDEX)
            v = ingest_del_index(len, adapter);
        else if (opcode == BT_MON_EVENT_PKT)
            v = ingest_event(p, len, adapter, frame_ts);
        else
            v = ingest_command(p, len, adapter, wall);
    }
    switch (v) {
    case BLE_REC_MALFORMED:         g_host.malformed++;         break;
    case BLE_REC_IGNORED:           g_host.ignored++;           break;
    case BLE_REC_NEW_INDEX:
    case BLE_REC_DEL_INDEX:         g_host.index_records++;     break;
    case BLE_REC_ADV:               g_host.adv_reports++;       break;
    case BLE_REC_EXT_ADV:           g_host.ext_adv_reports++;   break;
    case BLE_REC_EXT_FRAGMENT:      g_host.ext_adv_undecoded++; break;
    case BLE_REC_COMMAND:           g_host.commands++;          break;
    }
    pthread_mutex_unlock(&g_mu);
    return v;
}

void ble_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    host_init_locked();
    s->ble_host = g_host;
    s->ble_device_count = stab_snapshot(&g_devs, s->ble_devices, MAX_BLE_DEVICES);
    ble_flood_snapshot(s, sloth_mono_ms());
    pthread_mutex_unlock(&g_mu);
}

void ble_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_devs);
    ble_flood_clear();
    g_host_init = 0;
    host_init_locked();
    pthread_mutex_unlock(&g_mu);
}
