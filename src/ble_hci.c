#include <pthread.h>
#include <stddef.h>
#include <string.h>
#include "ble_hci.h"
#include "ble_snoop.h"
#include "stab.h"

/* Contract, allow-list and sources in ble_hci.h. Opcodes are
 * OGF << 10 | OCF, Core Specification v5.4 Vol 4 Part E §5.4.1; the
 * command parameters below are read per the §7 clause named on each. */

#define HCI_EV_LE_META              0x3E
#define HCI_SUBEV_ADV_REPORT        0x02
#define HCI_SUBEV_EXT_ADV_REPORT    0x0D

#define OP_INQUIRY                  0x0401  /* §7.1.1 */
#define OP_PERIODIC_INQUIRY         0x0403  /* §7.1.3 */
#define OP_CREATE_CONN              0x0405  /* §7.1.5 */
#define OP_REMOTE_NAME_REQ          0x0419  /* §7.1.19 */
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

/* The struct-of-arrays fixed fields of one report, for the single-report
 * check before the walker runs. */
#define ADV_REPORT_MIN_PARAMS       (1 + 1 + 1 + 1 + 6 + 1 + 1)

int bt_dev_is_bluetooth(const char *name) {
    return name && strncmp(name, "bluetooth", 9) == 0;
}

int bt_dev_is_raw_hci(const char *name) {
    return bt_dev_is_bluetooth(name) && name[9] >= '0' && name[9] <= '9';
}

/* ── State ─────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t addr[6];   /* display order */
    uint8_t type;
} ble_key_t;

static int dev_key_eq(const void *row, const void *key) {
    const ble_device_t *d = row;
    const ble_key_t    *k = key;
    return d->addr_type == k->type && memcmp(d->addr, k->addr, 6) == 0;
}

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
/* STAB_OLDEST: an advertiser picks its own address and a random one
 * rotates by design, so a spray of fresh addresses must churn the table
 * rather than make it refuse. Every loss lands in evict_ble_device. */
STAB_DECL(g_devs, ble_device_t, MAX_BLE_DEVICES, last_seen, STAB_OLDEST,
          SH_EVICT_BLE_DEVICE, NULL, dev_key_eq);
static ble_host_t g_host;
static int        g_host_init;

static void host_init_locked(void) {
    if (g_host_init) return;
    memset(&g_host, 0, sizeof(g_host));
    g_host.ctrl_index      = -1;
    g_host.scan_mode       = BLE_SCAN_UNKNOWN;
    g_host.filter_policy   = -1;
    g_host.scan_enabled    = -1;
    g_host.last_tx_kind    = BT_TX_NONE;
    g_host.last_tx_adapter = -1;
    g_host_init = 1;
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

/* ── Advertising reports ───────────────────────────────────────────── */

typedef struct {
    uint16_t adapter;
    time_t   ts;
} adv_ctx_t;

static void on_report(const ble_adv_report_t *r, void *vctx) {
    const adv_ctx_t *c = vctx;
    ble_key_t key;
    for (int i = 0; i < 6; i++) key.addr[i] = r->addr[5 - i];
    key.type = r->addr_type;

    int created = 0;
    ble_device_t *d = stab_get(&g_devs, &key, c->ts, &created);
    if (!d) return;   /* STAB_OLDEST never refuses; defensive only */
    if (created) {
        memcpy(d->addr, key.addr, 6);
        d->addr_type  = key.type;
        d->first_seen = c->ts;
        d->rssi_best  = -128;
    }
    d->last_seen       = c->ts;
    d->adapter         = c->adapter;
    d->last_event_type = r->event_type;
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
    if (r->has_mfr_data)       { d->has_mfr = 1;    d->mfr_id = r->mfr_id; }
    if (r->has_appearance)     { d->has_appearance = 1; d->appearance = r->appearance; }
    if (r->has_tx_power)       { d->has_tx_power = 1; d->tx_power = r->tx_power; }
    if (r->has_flags)          { d->has_flags = 1; d->flags = r->flags; }
    if (r->has_rssi) {
        d->has_rssi = 1;
        d->rssi     = r->rssi;
        if (r->rssi > d->rssi_best) d->rssi_best = r->rssi;
    }
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
    if (sub == HCI_SUBEV_EXT_ADV_REPORT) return BLE_REC_EXT_ADV_UNDECODED;
    if (sub != HCI_SUBEV_ADV_REPORT)     return BLE_REC_IGNORED;
    if (plen < 2) return BLE_REC_MALFORMED;
    uint8_t num = p[3];
    if (num == 0) return BLE_REC_MALFORMED;
    if (num > 1)  return BLE_REC_MULTI_REJECTED;
    if (plen < ADV_REPORT_MIN_PARAMS) return BLE_REC_MALFORMED;
    /* One report: Data_Length is at a fixed offset, and the event must
     * hold exactly the report — trailing bytes would mean the layout is
     * not what this decoder thinks it is. */
    if ((size_t)p[2 + 1 + 1 + 1 + 1 + 6] + ADV_REPORT_MIN_PARAMS != plen)
        return BLE_REC_MALFORMED;
    adv_ctx_t c = { adapter, ts };
    return ble_hci_adv_walk(p, 2 + plen, on_report, &c) == 1
        ? BLE_REC_ADV : BLE_REC_MALFORMED;
}

static int popcount_phys(uint8_t phys) {
    /* Scanning_PHYs bit 0 = LE 1M, bit 2 = LE Coded; bit 1 is reserved
     * because LE 2M carries no primary advertising channel. */
    return ((phys & 0x01) ? 1 : 0) + ((phys & 0x04) ? 1 : 0);
}

static void note_tx(int kind, uint16_t adapter, time_t wall) {
    g_host.last_tx_kind    = kind;
    g_host.last_tx_adapter = adapter;
    g_host.last_tx_wall    = wall;
    g_host.tx_kind_mask   |= 1u << kind;
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
    case OP_PERIODIC_INQUIRY:   tx = BT_TX_PERIODIC_INQUIRY; break;
    case OP_CREATE_CONN:        tx = BT_TX_BREDR_CONNECT;    break;
    case OP_REMOTE_NAME_REQ:    tx = BT_TX_REMOTE_NAME;      break;
    case OP_LE_CREATE_CONN:
    case OP_LE_EXT_CREATE_CONN: tx = BT_TX_LE_CONNECT;       break;
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

    /* The five commands whose mere issue puts the controller on the air:
     * inquiry and paging transmit ID packets, and an LE initiator sends
     * CONNECT_IND. Their parameters are not needed to say so. */
    if (tx != BT_TX_NONE) {
        note_tx(tx, adapter, wall);
        return BLE_REC_COMMAND;
    }

    switch (op) {
    case OP_WRITE_SCAN_ENABLE:
        /* Scan_Enable: bit 0 inquiry scan, bit 1 page scan — either
         * makes the controller answer another device's inquiry or page. */
        if (plen != 1) return BLE_REC_MALFORMED;
        if (a[0] & 0x03) note_tx(BT_TX_SCAN_ENABLE, adapter, wall);
        break;
    case OP_LE_SET_ADV_ENABLE:
        if (plen != 1) return BLE_REC_MALFORMED;
        if (a[0] == 0x01) note_tx(BT_TX_ADV, adapter, wall);
        break;
    case OP_LE_SET_EXT_ADV_ENABLE:
        /* Enable, Num_Sets, then per-set arrays; only Enable matters. */
        if (plen < 2) return BLE_REC_MALFORMED;
        if (a[0] == 0x01) note_tx(BT_TX_EXT_ADV, adapter, wall);
        break;
    case OP_LE_SET_PER_ADV_ENABLE:
        /* Enable bit 0 = periodic advertising on (bit 1 is ADI only). */
        if (plen != 2) return BLE_REC_MALFORMED;
        if (a[0] & 0x01) note_tx(BT_TX_PERIODIC_ADV, adapter, wall);
        break;
    case OP_LE_SET_SCAN_PARAMS:
        /* LE_Scan_Type, Interval(2), Window(2), Own_Address_Type,
         * Scanning_Filter_Policy. */
        if (plen != 7) return BLE_REC_MALFORMED;
        g_host.scan_mode     = a[0] == 0x01 ? BLE_SCAN_ACTIVE : BLE_SCAN_PASSIVE;
        g_host.filter_policy = a[6] <= 3 ? a[6] : -1;
        if (g_host.scan_mode == BLE_SCAN_ACTIVE)
            note_tx(BT_TX_ACTIVE_SCAN, adapter, wall);
        break;
    case OP_LE_SET_EXT_SCAN_PARAMS: {
        /* Own_Address_Type, Scanning_Filter_Policy, Scanning_PHYs, then
         * Scan_Type, Interval(2), Window(2) per PHY bit set. Active if
         * any PHY scans actively. */
        if (plen < 3) return BLE_REC_MALFORMED;
        int nphy = popcount_phys(a[2]);
        if (nphy == 0 || plen != (size_t)(3 + 5 * nphy))
            return BLE_REC_MALFORMED;
        int active = 0;
        for (int i = 0; i < nphy; i++)
            if (a[3 + 5 * i] == 0x01) active = 1;
        g_host.scan_mode     = active ? BLE_SCAN_ACTIVE : BLE_SCAN_PASSIVE;
        g_host.filter_policy = a[1] <= 3 ? a[1] : -1;
        if (active) note_tx(BT_TX_ACTIVE_SCAN, adapter, wall);
        break;
    }
    case OP_LE_SET_SCAN_ENABLE:
        if (plen != 2) return BLE_REC_MALFORMED;
        g_host.scan_enabled = a[0] == 0x01;
        break;
    case OP_LE_SET_EXT_SCAN_ENABLE:
        if (plen != 6) return BLE_REC_MALFORMED;
        g_host.scan_enabled = a[0] == 0x01;
        break;
    default:
        break;
    }
    return BLE_REC_COMMAND;
}

static ble_rec_verdict_t ingest_new_index(const uint8_t *p, size_t len,
                                          uint16_t adapter) {
    /* struct hci_mon_new_index: type, bus, bdaddr (6, LE), name[8]. */
    if (len != 16) return BLE_REC_MALFORMED;
    g_host.controllers++;
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
                     opcode == BT_MON_COMMAND_PKT ||
                     opcode == BT_MON_EVENT_PKT;
        if (!listed)
            v = BLE_REC_IGNORED;
        else if (caplen < origlen)
            v = BLE_REC_MALFORMED;   /* never decode from a snapped prefix */
        else if (opcode == BT_MON_NEW_INDEX)
            v = ingest_new_index(p, len, adapter);
        else if (opcode == BT_MON_EVENT_PKT)
            v = ingest_event(p, len, adapter, frame_ts);
        else
            v = ingest_command(p, len, adapter, wall);
    }
    switch (v) {
    case BLE_REC_MALFORMED:         g_host.malformed++;         break;
    case BLE_REC_IGNORED:           g_host.ignored++;           break;
    case BLE_REC_NEW_INDEX:         g_host.new_index++;         break;
    case BLE_REC_ADV:               g_host.adv_reports++;       break;
    case BLE_REC_MULTI_REJECTED:    g_host.multi_rejected++;    break;
    case BLE_REC_EXT_ADV_UNDECODED: g_host.ext_adv_undecoded++; break;
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
    pthread_mutex_unlock(&g_mu);
}

void ble_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_devs);
    g_host_init = 0;
    host_init_locked();
    pthread_mutex_unlock(&g_mu);
}
