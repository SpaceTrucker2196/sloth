#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "ble_hci.h"
#include "alerts.h"
#include "jsonl.h"
#include "sensor_health.h"
#include "sloth_clock.h"
#include "capture/capture.h"
#include "capture/replay.h"
#ifdef WITH_PCAP
#include "capture/bt_monitor.h"
#include "capture/probe.h"
#endif

/*
 * The Bluetooth host source — #144 slice 2.
 *
 * Every record is built by hand from the layouts it is read by, never
 * captured (agents/AGENTS.md, "No pcap fixtures"):
 *
 *   libpcap DLT 254 header (pcap-bt-monitor-linux.c,
 *   pcap/bluetooth.h `pcap_bluetooth_linux_monitor_header`):
 *     adapter_id  BE16
 *     opcode      BE16    Linux include/net/bluetooth/hci_mon.h:
 *                         0 NEW_INDEX, 2 COMMAND_PKT, 3 EVENT_PKT,
 *                         4 ACL_TX_PKT, 16 CTRL_COMMAND ...
 *   payload by opcode:
 *     NEW_INDEX   struct hci_mon_new_index: type, bus, bdaddr[6] (LE),
 *                 name[8]
 *     COMMAND     HCI command packet, Core Spec v5.4 Vol 4 Part E §5.4.1:
 *                 opcode LE16 (OGF << 10 | OCF), param len, params
 *     EVENT       HCI event packet, §5.4.4: event code, param len, params
 *
 *   LE Advertising Report (§7.7.65.2), ONE report — the only shape
 *   decoded; for one report the spec's per-field arrays and the kernel's
 *   per-report records are the same bytes:
 *     0x3E plen 0x02 01 Event_Type Address_Type Address[6] Data_Length
 *     Data[Data_Length] RSSI
 */

#define TS 1700000000   /* frame clock for device evidence */

static uint8_t g_rec[512];
static sloth_state_t g_s;

static int put_hdr(uint8_t *b, uint16_t adapter, uint16_t opcode) {
    b[0] = (uint8_t)(adapter >> 8); b[1] = (uint8_t)adapter;
    b[2] = (uint8_t)(opcode >> 8);  b[3] = (uint8_t)opcode;
    return 4;
}

static int rec_cmd_at(uint8_t *b, uint16_t adapter, uint16_t op,
                      const uint8_t *p, uint8_t plen) {
    int n = put_hdr(b, adapter, BT_MON_COMMAND_PKT);
    b[n++] = (uint8_t)op; b[n++] = (uint8_t)(op >> 8);
    b[n++] = plen;
    if (plen) memcpy(b + n, p, plen);
    return n + plen;
}

static int rec_cmd(uint8_t *b, uint16_t op, const uint8_t *p, uint8_t plen) {
    return rec_cmd_at(b, 0, op, p, plen);
}

static int rec_evt(uint8_t *b, uint8_t code, const uint8_t *p, uint8_t plen) {
    int n = put_hdr(b, 0, BT_MON_EVENT_PKT);
    b[n++] = code;
    b[n++] = plen;
    if (plen) memcpy(b + n, p, plen);
    return n + plen;
}

/* One LE Advertising Report. `addr_le` is the address in HCI order
 * (least significant octet first), as it travels. */
static int rec_adv(uint8_t *b, uint16_t adapter, uint8_t evt_type,
                   uint8_t addr_type, const uint8_t addr_le[6],
                   const uint8_t *data, uint8_t dlen, int8_t rssi) {
    int n = put_hdr(b, adapter, BT_MON_EVENT_PKT);
    b[n++] = 0x3E;
    b[n++] = (uint8_t)(12 + dlen);   /* sub, num, evt, atype, addr6, dlen, rssi */
    b[n++] = 0x02;
    b[n++] = 1;
    b[n++] = evt_type;
    b[n++] = addr_type;
    memcpy(b + n, addr_le, 6); n += 6;
    b[n++] = dlen;
    if (dlen) memcpy(b + n, data, dlen);
    n += dlen;
    b[n++] = (uint8_t)rssi;
    return n;
}

/* struct hci_mon_new_index; `type` 0x00 HCI_PRIMARY, 0x01 HCI_AMP
 * (Linux include/net/bluetooth/hci.h). */
static int rec_new_index_type(uint8_t *b, uint16_t adapter, uint8_t type,
                              uint8_t bus, const uint8_t addr_le[6],
                              const char *name) {
    int n = put_hdr(b, adapter, BT_MON_NEW_INDEX);
    b[n++] = type;
    b[n++] = bus;
    memcpy(b + n, addr_le, 6); n += 6;
    memset(b + n, 0, 8);
    memcpy(b + n, name, strlen(name) < 8 ? strlen(name) : 8);
    return n + 8;
}

static int rec_new_index(uint8_t *b, uint16_t adapter, uint8_t bus,
                         const uint8_t addr_le[6], const char *name) {
    return rec_new_index_type(b, adapter, 0x00, bus, addr_le, name);
}

/* DEL_INDEX: the monitor header alone, no payload. */
static int rec_del_index(uint8_t *b, uint16_t adapter) {
    return put_hdr(b, adapter, BT_MON_DEL_INDEX);
}

static ble_rec_verdict_t ing(const uint8_t *b, int n, time_t wall) {
    return ble_mon_ingest(b, (size_t)n, (size_t)n, TS, wall);
}

static int contains_bytes(const void *hay, size_t hn, const void *needle,
                          size_t nn) {
    const uint8_t *h = hay;
    for (size_t i = 0; i + nn <= hn; i++)
        if (memcmp(h + i, needle, nn) == 0) return 1;
    return 0;
}

static const uint8_t ADDR_LE[6] = { 0x66, 0x55, 0x44, 0x33, 0x22, 0xC1 };

/* AD: Flags 0x06; Complete Local Name "sloth-tag"; 16-bit UUID 0xFEAA. */
static int build_ad(uint8_t *d) {
    int n = 0;
    d[n++] = 2;  d[n++] = 0x01; d[n++] = 0x06;
    d[n++] = 10; d[n++] = 0x09; memcpy(d + n, "sloth-tag", 9); n += 9;
    d[n++] = 3;  d[n++] = 0x03; d[n++] = 0xAA; d[n++] = 0xFE;
    return n;
}

/* ── Device refusal ─────────────────────────────────────────────── */

static void test_raw_hci_device_names_are_refused(void) {
    ASSERT_EQ(bt_dev_is_raw_hci("bluetooth0"), 1);
    ASSERT_EQ(bt_dev_is_raw_hci("bluetooth12"), 1);
    ASSERT_EQ(bt_dev_is_raw_hci("bluetooth-monitor"), 0);
    ASSERT_EQ(bt_dev_is_raw_hci("bluetooth"), 0);
    ASSERT_EQ(bt_dev_is_raw_hci("wlan0"), 0);
    ASSERT_EQ(bt_dev_is_raw_hci(NULL), 0);
    ASSERT_EQ(bt_dev_is_bluetooth("bluetooth-monitor"), 1);
    ASSERT_EQ(bt_dev_is_bluetooth("eth0"), 0);
    /* The device the worker opens is not a raw one. */
    ASSERT_EQ(bt_dev_is_raw_hci(BT_MONITOR_DEVICE), 0);
}

/* The IP capture's findalldevs fallback used to take the head of the
 * list. Seen to fail: with the bt_dev_is_bluetooth() skip removed from
 * capture_fallback_device(), the first two cases pick "bluetooth0". */
static void test_ip_fallback_never_picks_a_bluetooth_device(void) {
    const char *a[] = { "bluetooth0", "bluetooth-monitor", "eth0" };
    const char *pick = capture_fallback_device(a, 3);
    ASSERT(pick != NULL);
    if (pick) ASSERT_STR(pick, "eth0");
    const char *b[] = { "bluetooth0", "bluetooth1" };
    ASSERT(capture_fallback_device(b, 2) == NULL);
    const char *c[] = { "enp3s0", "bluetooth0" };
    pick = capture_fallback_device(c, 2);
    ASSERT(pick != NULL);
    if (pick) ASSERT_STR(pick, "enp3s0");
    ASSERT(capture_fallback_device(NULL, 3) == NULL);
}

#ifdef WITH_PCAP
/* Seen to fail: without the refusal in probe_set_iface() the call goes
 * on to pcap_open_live("bluetooth0") and probe_err carries libpcap's
 * error instead. */
static void test_monitor_retarget_refuses_raw_hci(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_set_iface(&g_s, "bluetooth0");
    ASSERT(strstr(g_s.probe_err, "refused: raw HCI device") != NULL);
    ASSERT_EQ(g_s.probe_iface[0], '\0');
}
#endif

/* ── NEW_INDEX ──────────────────────────────────────────────────── */

static void test_new_index_records_the_controller(void) {
    const uint8_t a[6] = { 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
    int n = rec_new_index(g_rec, 3, 0x01 /* USB */, a, "hci3");
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_NEW_INDEX);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.controllers, 1);
    ASSERT_EQ(g_s.ble_host.ctrl_index, 3);
    ASSERT_EQ(g_s.ble_host.ctrl_bus, 1);
    ASSERT_EQ(g_s.ble_host.ctrl_addr[0], 0x11);
    ASSERT_EQ(g_s.ble_host.ctrl_addr[5], 0x66);
    ASSERT_STR(g_s.ble_host.ctrl_name, "hci3");
    /* A NEW_INDEX of the wrong size is refused, not half-read. */
    ASSERT_EQ((int)ing(g_rec, n - 1, 0), (int)BLE_REC_MALFORMED);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.controllers, 1);
}

/* ── Advertising reports ────────────────────────────────────────── */

static void test_single_report_creates_a_device(void) {
    uint8_t ad[32];
    int dl = build_ad(ad);
    int n = rec_adv(g_rec, 0, 0x00 /* ADV_IND */, 0x01, ADDR_LE, ad,
                    (uint8_t)dl, -60);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_ADV);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_device_count, 1);
    const ble_device_t *d = &g_s.ble_devices[0];
    /* Display order: the most significant octet first. */
    ASSERT_EQ(d->addr[0], 0xC1);
    ASSERT_EQ(d->addr[5], 0x66);
    ASSERT_EQ(d->addr_type, 1);
    ASSERT_EQ(d->has_name, 1);
    ASSERT_EQ(d->name_complete, 1);
    ASSERT_STR(d->name, "sloth-tag");
    ASSERT_EQ(d->has_uuid16, 1);
    ASSERT_EQ(d->uuid16, 0xFEAA);
    ASSERT_EQ(d->has_flags, 1);
    ASSERT_EQ(d->flags, 0x06);
    ASSERT_EQ(d->rssi, -60);
    ASSERT_EQ(d->first_seen, (time_t)TS);
    ASSERT_EQ((int)d->adv_count, 1);
    ASSERT_EQ((int)g_s.ble_host.adv_reports, 1);

    /* The SCAN_RSP for the same address carries only TX Power; the name
     * seen in the ADV_IND is kept, the strongest RSSI follows. */
    const uint8_t tx[3] = { 2, 0x0A, 0xF8 };   /* TX Power -8 dBm */
    n = rec_adv(g_rec, 0, 0x04 /* SCAN_RSP */, 0x01, ADDR_LE, tx, 3, -41);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_ADV);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_device_count, 1);
    d = &g_s.ble_devices[0];
    ASSERT_STR(d->name, "sloth-tag");
    ASSERT_EQ(d->has_tx_power, 1);
    ASSERT_EQ(d->tx_power, -8);
    ASSERT_EQ(d->rssi_best, -41);
    ASSERT_EQ(d->last_event_type, 0x04);
    ASSERT_EQ((int)d->adv_count, 2);

    /* Same address, other address type: a different advertiser. */
    n = rec_adv(g_rec, 0, 0x00, 0x00, ADDR_LE, tx, 3, -70);
    ing(g_rec, n, 0);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_device_count, 2);
}

/* Seen to fail: with the Num_Reports > 1 refusal relaxed to > 2, the
 * walker decodes this event and two device rows appear. */
static void test_multi_report_event_is_rejected_and_counted(void) {
    /* Two reports, each with an empty Data field. Under the spec's
     * per-field arrays this is: evt[2] atype[2] addr[2][6] dlen[2] rssi[2]. */
    uint8_t p[2 + 2 + 2 + 12 + 2 + 2];
    int k = 0;
    p[k++] = 0x02; p[k++] = 2;
    p[k++] = 0x00; p[k++] = 0x00;                         /* Event_Type[2] */
    p[k++] = 0x01; p[k++] = 0x01;                         /* Address_Type[2] */
    memcpy(p + k, ADDR_LE, 6); k += 6;
    memcpy(p + k, ADDR_LE, 6); p[k] ^= 0x01; k += 6;      /* Address[2] */
    p[k++] = 0; p[k++] = 0;                               /* Data_Length[2] */
    p[k++] = (uint8_t)-50; p[k++] = (uint8_t)-51;         /* RSSI[2] */
    int n = rec_evt(g_rec, 0x3E, p, (uint8_t)k);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_MULTI_REJECTED);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_device_count, 0);
    ASSERT_EQ((int)g_s.ble_host.multi_rejected, 1);
    ASSERT_EQ((int)g_s.ble_host.adv_reports, 0);
}

static void test_extended_report_is_counted_not_decoded(void) {
    const uint8_t p[4] = { 0x0D, 1, 0x13, 0x00 };
    int n = rec_evt(g_rec, 0x3E, p, 4);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_EXT_ADV_UNDECODED);
    ble_snapshot(&g_s);
    ASSERT_EQ((int)g_s.ble_host.ext_adv_undecoded, 1);
    ASSERT_EQ(g_s.ble_device_count, 0);
}

static void test_bad_lengths_are_malformed_not_decoded(void) {
    uint8_t ad[32];
    int dl = build_ad(ad);
    int n = rec_adv(g_rec, 0, 0x00, 0x01, ADDR_LE, ad, (uint8_t)dl, -60);
    /* Snapped: captured shorter than the record was. */
    ASSERT_EQ((int)ble_mon_ingest(g_rec, (size_t)n - 3, (size_t)n, TS, 0),
              (int)BLE_REC_MALFORMED);
    /* Captured whole, but the event says more than the record holds. */
    ASSERT_EQ((int)ing(g_rec, n - 1, 0), (int)BLE_REC_MALFORMED);
    /* Data_Length disagrees with the event length (a trailing octet). */
    g_rec[5] = (uint8_t)(g_rec[5] + 1);
    g_rec[n] = 0;
    ASSERT_EQ((int)ing(g_rec, n + 1, 0), (int)BLE_REC_MALFORMED);
    g_rec[5] = (uint8_t)(g_rec[5] - 1);
    /* Shorter than the monitor header. */
    ASSERT_EQ((int)ing(g_rec, 3, 0), (int)BLE_REC_MALFORMED);
    ASSERT_EQ((int)ble_mon_ingest(NULL, 0, 0, TS, 0), (int)BLE_REC_MALFORMED);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_device_count, 0);
    ASSERT_EQ((int)g_s.ble_host.malformed, 5);
}

/* ── The allow-list ─────────────────────────────────────────────── */

/* Link keys, LTKs and ACL data cross the same channel. Each record here
 * carries the same 16-octet key; none may be decoded, and none of its
 * bytes may be anywhere in the state afterwards.
 *
 * Seen to fail: with the LE-Meta-only check in ingest_event() removed,
 * the Link Key Notification below (whose first two octets are shaped
 * like a subevent and a report count) is no longer IGNORED. */
static void test_records_outside_the_allow_list_are_never_read(void) {
    static const uint8_t KEY[16] = {
        0x5e, 0xc2, 0x37, 0xa1, 0x90, 0x44, 0x1b, 0xd8,
        0x72, 0x0f, 0xe3, 0x66, 0x29, 0xb5, 0x81, 0xcc };
    uint8_t p[32];
    /* Link Key Notification (event 0x18, §7.7.24): BD_ADDR, Link_Key,
     * Key_Type. BD_ADDR begins 02 01 on purpose. */
    p[0] = 0x02; p[1] = 0x01; p[2] = 0x33; p[3] = 0x44; p[4] = 0x55; p[5] = 0x66;
    memcpy(p + 6, KEY, 16); p[22] = 0x04;
    int n = rec_evt(g_rec, 0x18, p, 23);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_IGNORED);
    /* Link_Key_Request_Reply (0x040B, §7.1.10): BD_ADDR, Link_Key. */
    memcpy(p, ADDR_LE, 6); memcpy(p + 6, KEY, 16);
    n = rec_cmd(g_rec, 0x040B, p, 22);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_IGNORED);
    /* LE Long Term Key Request Reply (0x201A, §7.8.25): handle, LTK. */
    p[0] = 0x40; p[1] = 0x00; memcpy(p + 2, KEY, 16);
    n = rec_cmd(g_rec, 0x201A, p, 18);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_IGNORED);
    /* ACL data, and a MGMT command (Load Link Keys rides CTRL_COMMAND). */
    int m = put_hdr(g_rec, 0, BT_MON_ACL_RX_PKT);
    memcpy(g_rec + m, KEY, 16);
    ASSERT_EQ((int)ing(g_rec, m + 16, 0), (int)BLE_REC_IGNORED);
    m = put_hdr(g_rec, 0, BT_MON_CTRL_COMMAND);
    memcpy(g_rec + m, KEY, 16);
    ASSERT_EQ((int)ing(g_rec, m + 16, 0), (int)BLE_REC_IGNORED);
    /* Not on the list even though it is an LE Meta event: a Connection
     * Complete is not an advertising report. */
    p[0] = 0x01; memset(p + 1, 0, 18);
    n = rec_evt(g_rec, 0x3E, p, 19);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_IGNORED);

    ble_snapshot(&g_s);
    ASSERT_EQ((int)g_s.ble_host.ignored, 6);
    ASSERT_EQ((int)g_s.ble_host.records, 6);
    ASSERT_EQ(g_s.ble_device_count, 0);
    ASSERT_EQ((int)g_s.ble_host.tx_count, 0);
    ASSERT(!contains_bytes(&g_s.ble_host, sizeof(g_s.ble_host), KEY, 6));
    ASSERT(!contains_bytes(g_s.ble_devices, sizeof(g_s.ble_devices), KEY, 6));
}

/* ── Scan configuration ─────────────────────────────────────────── */

/* Seen to fail: with LE Set Scan Enable also setting scan_mode to
 * PASSIVE, the mode reads passive here although no parameters were
 * ever set. */
static void test_scan_mode_unknown_until_parameters_are_seen(void) {
    const uint8_t en[2] = { 0x01, 0x00 };
    int n = rec_cmd(g_rec, 0x200C, en, 2);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_COMMAND);
    uint8_t ad[32];
    int dl = build_ad(ad);
    n = rec_adv(g_rec, 0, 0x00, 0x01, ADDR_LE, ad, (uint8_t)dl, -60);
    ing(g_rec, n, 0);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.scan_mode, (int)BLE_SCAN_UNKNOWN);
    ASSERT_EQ(g_s.ble_host.filter_policy, -1);
    ASSERT_EQ(g_s.ble_host.scan_enabled, 1);
    ASSERT_EQ(g_s.ble_device_count, 1);
    ASSERT_STR(ble_scan_mode_name(g_s.ble_host.scan_mode), "unknown");
    ASSERT_EQ(bt_tx_recency(g_s.ble_host.last_tx_wall, 1000), (int)BT_TX_NEVER);
}

static void test_legacy_scan_parameters_set_mode_and_filter(void) {
    /* LE_Scan_Type, Interval 0x0010, Window 0x0010, Own_Address_Type,
     * Scanning_Filter_Policy (§7.8.10). */
    uint8_t p[7] = { 0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00 };
    int n = rec_cmd(g_rec, 0x200B, p, 7);
    ASSERT_EQ((int)ing(g_rec, n, 500), (int)BLE_REC_COMMAND);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.scan_mode, (int)BLE_SCAN_PASSIVE);
    ASSERT_EQ(g_s.ble_host.filter_policy, 0);
    ASSERT_EQ(ble_filter_policy_is_accept_list(g_s.ble_host.filter_policy), 0);
    ASSERT_EQ((int)g_s.ble_host.tx_count, 0);

    p[0] = 0x01; p[6] = 0x01;     /* active, Filter Accept List only */
    n = rec_cmd(g_rec, 0x200B, p, 7);
    ing(g_rec, n, 500);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.scan_mode, (int)BLE_SCAN_ACTIVE);
    ASSERT_STR(ble_filter_policy_name(g_s.ble_host.filter_policy), "accept_list");
    ASSERT_EQ(ble_filter_policy_is_accept_list(g_s.ble_host.filter_policy), 1);
    ASSERT_EQ(g_s.ble_host.last_tx_kind, (int)BT_TX_ACTIVE_SCAN);
    ASSERT_EQ(g_s.ble_host.last_tx_wall, (time_t)500);

    /* Wrong parameter length: refused, state unchanged. */
    n = rec_cmd(g_rec, 0x200B, p, 6);
    ASSERT_EQ((int)ing(g_rec, n, 600), (int)BLE_REC_MALFORMED);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.last_tx_wall, (time_t)500);
}

static void test_extended_scan_parameters_per_phy(void) {
    /* Own_Address_Type, Filter policy 2, Scanning_PHYs 0x05 (1M + Coded),
     * then Scan_Type/Interval/Window for 1M (passive) and Coded (active). */
    uint8_t p[13] = { 0x00, 0x02, 0x05,
                      0x00, 0x10, 0x00, 0x10, 0x00,
                      0x01, 0x10, 0x00, 0x10, 0x00 };
    int n = rec_cmd(g_rec, 0x2041, p, 13);
    ASSERT_EQ((int)ing(g_rec, n, 700), (int)BLE_REC_COMMAND);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.scan_mode, (int)BLE_SCAN_ACTIVE);
    ASSERT_STR(ble_filter_policy_name(g_s.ble_host.filter_policy), "extended");
    ASSERT_EQ(g_s.ble_host.last_tx_kind, (int)BT_TX_ACTIVE_SCAN);

    /* 1M only, passive. */
    uint8_t q[8] = { 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x10, 0x00 };
    n = rec_cmd(g_rec, 0x2041, q, 8);
    ing(g_rec, n, 700);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.scan_mode, (int)BLE_SCAN_PASSIVE);
    ASSERT_EQ((int)g_s.ble_host.tx_count, 1);

    /* PHY bits that promise two PHY blocks over one block of bytes. */
    q[2] = 0x05;
    n = rec_cmd(g_rec, 0x2041, q, 8);
    ASSERT_EQ((int)ing(g_rec, n, 700), (int)BLE_REC_MALFORMED);
}

/* ── Own transmissions ──────────────────────────────────────────── */

typedef struct {
    uint16_t op;
    uint8_t  plen;
    uint8_t  p[26];
    int      kind;
} tx_case_t;

static void test_each_transmit_command_is_recorded(void) {
    static const tx_case_t cases[] = {
        /* Inquiry: LAP 0x9E8B33 (GIAC), Inquiry_Length, Num_Responses */
        { 0x0401, 5, { 0x33, 0x8B, 0x9E, 0x08, 0x00 }, BT_TX_INQUIRY },
        { 0x0403, 9, { 0x05, 0x00, 0x04, 0x00, 0x33, 0x8B, 0x9E, 0x02, 0x00 },
          BT_TX_PERIODIC_INQUIRY },
        { 0x0405, 13, { 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x18, 0xCC,
                        0x01, 0x00, 0x00, 0x00, 0x01 }, BT_TX_BREDR_CONNECT },
        { 0x0419, 10, { 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x01, 0x00,
                        0x00, 0x00 }, BT_TX_REMOTE_NAME },
        { 0x200D, 25, { 0x60, 0x00, 0x30, 0x00, 0x00, 0x01, 0x66, 0x55,
                        0x44, 0x33, 0x22, 0xC1, 0x00, 0x18, 0x00, 0x28,
                        0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00,
                        0x00 }, BT_TX_LE_CONNECT },
        { 0x2043, 10, { 0x00, 0x00, 0x01, 0x66, 0x55, 0x44, 0x33, 0x22,
                        0xC1, 0x00 }, BT_TX_LE_CONNECT },
        { 0x200A, 1, { 0x01 }, BT_TX_ADV },
        /* Enable, Num_Sets 1, Handle 0, Duration 0, Max_Events 0 */
        { 0x2039, 6, { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00 }, BT_TX_EXT_ADV },
        { 0x2040, 2, { 0x01, 0x00 }, BT_TX_PERIODIC_ADV },
        /* Scan_Enable 0x02: page scan only */
        { 0x0C1A, 1, { 0x02 }, BT_TX_SCAN_ENABLE },
    };
    uint32_t want_mask = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const tx_case_t *c = &cases[i];
        int n = rec_cmd(g_rec, c->op, c->p, c->plen);
        ASSERT_EQ((int)ing(g_rec, n, (time_t)(1000 + i)), (int)BLE_REC_COMMAND);
        ble_snapshot(&g_s);
        if (g_s.ble_host.last_tx_kind != c->kind)
            printf("    opcode 0x%04x: kind %d, want %d\n",
                   c->op, g_s.ble_host.last_tx_kind, c->kind);
        ASSERT_EQ(g_s.ble_host.last_tx_kind, c->kind);
        ASSERT_EQ(g_s.ble_host.last_tx_wall, (time_t)(1000 + i));
        ASSERT(bt_tx_kind_name(c->kind)[0] != '\0');
        want_mask |= 1u << c->kind;
    }
    ASSERT_EQ(g_s.ble_host.tx_kind_mask, want_mask);
    ASSERT_EQ((int)g_s.ble_host.tx_count, 10);
}

/* Seen to fail: with LE Set Advertising Enable's test loosened from
 * `== 0x01` to `<= 0x01`, the disable below records BT_TX_ADV. */
static void test_disabling_commands_are_not_transmissions(void) {
    static const tx_case_t cases[] = {
        { 0x0C1A, 1, { 0x00 }, 0 },                       /* scans off */
        { 0x200A, 1, { 0x00 }, 0 },                       /* advertising off */
        { 0x2039, 2, { 0x00, 0x00 }, 0 },                 /* all sets off */
        { 0x2040, 2, { 0x00, 0x00 }, 0 },                 /* periodic off */
        { 0x200C, 2, { 0x00, 0x00 }, 0 },                 /* scan off */
        { 0x2042, 6, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int n = rec_cmd(g_rec, cases[i].op, cases[i].p, cases[i].plen);
        ASSERT_EQ((int)ing(g_rec, n, 1000), (int)BLE_REC_COMMAND);
    }
    ble_snapshot(&g_s);
    ASSERT_EQ((int)g_s.ble_host.tx_count, 0);
    ASSERT_EQ(g_s.ble_host.last_tx_wall, (time_t)0);
    ASSERT_EQ(g_s.ble_host.scan_enabled, 0);
    ASSERT_EQ((int)g_s.ble_host.commands, 6);
}

static void test_recency_is_bucketed_not_latched(void) {
    ASSERT_EQ(bt_tx_recency(0, 5000), (int)BT_TX_NEVER);
    ASSERT_EQ(bt_tx_recency(5000, 5000), (int)BT_TX_RECENT);
    ASSERT_EQ(bt_tx_recency(5000, 5000 + BT_TX_RECENT_SECS), (int)BT_TX_RECENT);
    ASSERT_EQ(bt_tx_recency(5000, 5000 + BT_TX_RECENT_SECS + 1), (int)BT_TX_EARLIER);
    /* A clock that stepped back reads recent, the safe side. */
    ASSERT_EQ(bt_tx_recency(5000, 4000), (int)BT_TX_RECENT);
    ASSERT_STR(bt_tx_recency_name(BT_TX_EARLIER), "earlier");
    ASSERT_STR(bt_tx_recency_name(BT_TX_NEVER), "never");
}

/* ── BT_OWN_TRANSMIT ────────────────────────────────────────────── */

static time_t g_wall;
static time_t pinned_wall(void) { return g_wall; }

static int find_alert(const sloth_state_t *s, alert_type_t type) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == type) return i;
    return -1;
}

static void active_scan_at(time_t wall) {
    uint8_t p[7] = { 0x01, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00 };
    int n = rec_cmd(g_rec, 0x200B, p, 7);
    ing(g_rec, n, wall);
}

static void test_own_transmit_fires_while_recent(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(NULL, pinned_wall);
    memset(&g_s, 0, sizeof(g_s));
    active_scan_at(g_wall - 30);
    ble_snapshot(&g_s);
    alerts_update(&g_s);
    int i = find_alert(&g_s, ALERT_TYPE_BT_OWN_TRANSMIT);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT_STR(g_s.alerts[i].title, "BT_OWN_TRANSMIT");
        ASSERT(strstr(g_s.alerts[i].detail, "active_scan") != NULL);
        ASSERT(strstr(g_s.alerts[i].key, "bttx:active_scan") != NULL);
    }
    /* Own operational state: the NO_MONITOR_MODE form, no technique. */
    ASSERT_STR(alert_technique(ALERT_TYPE_BT_OWN_TRANSMIT), "");
    ASSERT_STR(alert_type_name(ALERT_TYPE_BT_OWN_TRANSMIT),
               "ALERT_TYPE_BT_OWN_TRANSMIT");
    sloth_clock_test_set(NULL, NULL);
}

/* Seen to fail: with the recency gate removed from
 * rule_bt_own_transmit(), the transmission 200 s ago still fires. */
static void test_own_transmit_silent_when_never_or_earlier(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(NULL, pinned_wall);
    memset(&g_s, 0, sizeof(g_s));
    ble_snapshot(&g_s);
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_BT_OWN_TRANSMIT), -1);

    active_scan_at(g_wall - 200);
    ble_snapshot(&g_s);
    ASSERT_EQ(bt_tx_recency(g_s.ble_host.last_tx_wall, g_wall), (int)BT_TX_EARLIER);
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_BT_OWN_TRANSMIT), -1);
    sloth_clock_test_set(NULL, NULL);
}

/* ── Persistent transmissions: on until disabled ────────────────── */

#define W0 1800000000

static void cmd_at(uint16_t adapter, uint16_t op, const uint8_t *p,
                   uint8_t plen, time_t wall) {
    int n = rec_cmd_at(g_rec, adapter, op, p, plen);
    ASSERT_EQ((int)ing(g_rec, n, wall), (int)BLE_REC_COMMAND);
}

static int key_fired(const sloth_state_t *s, const char *key) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == ALERT_TYPE_BT_OWN_TRANSMIT &&
            strstr(s->alerts[i].key, key))
            return i;
    return -1;
}

/* The review case: advertising enabled at t and never disabled is still
 * on the air at t+300, long past the recency window, and the finding
 * must still be asserted. The disable is what ends it.
 *
 * Seen to fail, two ways: with bt_tx_asserted_mask() reading recency
 * only (the on-mask term removed) the t+300 assertions go red; with the
 * `a[0] == 0x00` branch removed from LE Set Advertising Enable the
 * post-disable assertions go red. */
static void test_advertising_held_on_until_disabled(void) {
    g_wall = W0 + 300;
    sloth_clock_test_set(NULL, pinned_wall);
    memset(&g_s, 0, sizeof(g_s));
    const uint8_t on = 0x01, off = 0x00;
    cmd_at(0, 0x200A, &on, 1, W0);
    ble_snapshot(&g_s);
    ASSERT_EQ(bt_tx_recency(g_s.ble_host.tx_wall[BT_TX_ADV], g_wall),
              (int)BT_TX_EARLIER);
    ASSERT_EQ((int)((g_s.ble_host.tx_on_mask >> BT_TX_ADV) & 1u), 1);
    ASSERT_EQ(bt_tx_asserted_mask(&g_s.ble_host, g_wall), 1u << BT_TX_ADV);
    alerts_update(&g_s);
    int i = key_fired(&g_s, "bttx:advertising");
    ASSERT(i >= 0);
    if (i >= 0) ASSERT(strstr(g_s.alerts[i].detail, "still on") != NULL);

    cmd_at(0, 0x200A, &off, 1, W0 + 300);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 0u);
    g_wall = W0 + 300 + BT_TX_RECENT_SECS + 1;
    ASSERT_EQ(bt_tx_asserted_mask(&g_s.ble_host, g_wall), 0u);
    alerts_clear();
    memset(&g_s.alerts, 0, sizeof(g_s.alerts));
    g_s.alert_count = 0;
    alerts_update(&g_s);
    ASSERT_EQ(find_alert(&g_s, ALERT_TYPE_BT_OWN_TRANSMIT), -1);
    sloth_clock_test_set(NULL, NULL);
}

typedef struct {
    const char *what;
    uint16_t on_op;  uint8_t on_len;  uint8_t on_p[13];
    uint16_t off_op; uint8_t off_len; uint8_t off_p[6];
    int      kind;
} hold_case_t;

/* Every persistent kind, each with its own disable (Core Spec v5.4
 * Vol 4 Part E clause on each row). Enabled at W0, judged at W0+300
 * (EARLIER by recency, so only the on-state can assert it), then
 * disabled and judged again.
 *
 * Seen to fail: with `c->page_inq_scan_on = ...` changed to set only
 * on a non-zero Scan_Enable (never cleared), the inquiry_page_scan row
 * stays asserted after its disable; with Exit Periodic Inquiry Mode's
 * clear removed, the periodic_inquiry row does. */
static void test_each_persistent_kind_holds_until_its_disable(void) {
    static const hold_case_t cases[] = {
        { "page scan (§7.3.18)", 0x0C1A, 1, { 0x02 }, 0x0C1A, 1, { 0x00 },
          BT_TX_SCAN_ENABLE },
        { "inquiry scan (§7.3.18)", 0x0C1A, 1, { 0x01 }, 0x0C1A, 1, { 0x00 },
          BT_TX_SCAN_ENABLE },
        /* Enable, Num_Sets 1, Handle 3, Duration 0, Max_Events 0; then
         * disable that one set by handle (§7.8.56). */
        { "one ext set by handle", 0x2039, 6, { 0x01, 0x01, 0x03, 0, 0, 0 },
          0x2039, 6, { 0x00, 0x01, 0x03, 0, 0, 0 }, BT_TX_EXT_ADV },
        { "ext sets, disable all", 0x2039, 6, { 0x01, 0x01, 0x00, 0, 0, 0 },
          0x2039, 2, { 0x00, 0x00 }, BT_TX_EXT_ADV },
        /* Enable, Advertising_Handle (§7.8.63). */
        { "periodic adv (§7.8.63)", 0x2040, 2, { 0x01, 0x05 },
          0x2040, 2, { 0x00, 0x05 }, BT_TX_PERIODIC_ADV },
        /* Max 5, Min 4, GIAC, Inquiry_Length 2, Num_Responses 0; Exit
         * Periodic Inquiry Mode has no parameters (§7.1.3, §7.1.4). */
        { "periodic inquiry (§7.1.3/4)", 0x0403, 9,
          { 0x05, 0x00, 0x04, 0x00, 0x33, 0x8B, 0x9E, 0x02, 0x00 },
          0x0404, 0, { 0 }, BT_TX_PERIODIC_INQUIRY },
    };
    g_wall = W0 + 300;
    sloth_clock_test_set(NULL, pinned_wall);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const hold_case_t *c = &cases[i];
        ble_clear();
        cmd_at(0, c->on_op, c->on_p, c->on_len, W0);
        ble_snapshot(&g_s);
        uint32_t bit = 1u << c->kind;
        if (bt_tx_asserted_mask(&g_s.ble_host, g_wall) != bit)
            printf("    %s: asserted 0x%x after enable\n", c->what,
                   bt_tx_asserted_mask(&g_s.ble_host, g_wall));
        ASSERT_EQ(bt_tx_asserted_mask(&g_s.ble_host, g_wall), bit);
        cmd_at(0, c->off_op, c->off_p, c->off_len, W0 + 300);
        ble_snapshot(&g_s);
        if (g_s.ble_host.tx_on_mask != 0)
            printf("    %s: on 0x%x after disable\n", c->what,
                   g_s.ble_host.tx_on_mask);
        ASSERT_EQ(g_s.ble_host.tx_on_mask, 0u);
    }
    sloth_clock_test_set(NULL, NULL);
}

/* Several extended sets in one command: their handles are not read
 * (spec arrays and kernel per-set records disagree on where they sit),
 * so a partial disable leaves the state on — the safe side — and only
 * Num_Sets 0 clears it.
 *
 * Seen to fail: with the n == 1 guard dropped from the partial-disable
 * branch (any partial disable clearing everything), the middle
 * assertion goes red. */
static void test_multi_set_ext_adv_clears_only_on_disable_all(void) {
    /* Enable, Num_Sets 2, then two 4-octet set entries. */
    const uint8_t en2[10] = { 0x01, 0x02, 0x00, 0, 0, 0, 0x01, 0, 0, 0 };
    const uint8_t dis1[6] = { 0x00, 0x01, 0x00, 0, 0, 0 };
    const uint8_t all[2]  = { 0x00, 0x00 };
    cmd_at(0, 0x2039, en2, 10, W0);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 1u << BT_TX_EXT_ADV);
    cmd_at(0, 0x2039, dis1, 6, W0);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 1u << BT_TX_EXT_ADV);
    cmd_at(0, 0x2039, all, 2, W0);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 0u);
    /* Num_Sets that promises more set entries than the bytes hold. */
    const uint8_t bad[6] = { 0x01, 0x02, 0x00, 0, 0, 0 };
    int n = rec_cmd(g_rec, 0x2039, bad, 6);
    ASSERT_EQ((int)ing(g_rec, n, W0), (int)BLE_REC_MALFORMED);
}

/* The kernel restarts a scan by toggling LE Set Scan Enable alone, the
 * parameters set active long before. Each enable is a fresh SCAN_REQ
 * source, so it refreshes the kind's clock; and while enabled under
 * active parameters the scan is on regardless of age.
 *
 * Seen to fail: without the note_tx() in the LE Set Scan Enable case,
 * tx_wall[ACTIVE_SCAN] stays at the parameter command's W0 - 500. */
static void test_scan_enable_under_active_parameters_transmits(void) {
    const uint8_t act[7] = { 0x01, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const uint8_t pas[7] = { 0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const uint8_t en[2] = { 0x01, 0x00 }, dis[2] = { 0x00, 0x00 };
    cmd_at(0, 0x200B, act, 7, W0 - 500);
    cmd_at(0, 0x200C, en, 2, W0);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_wall[BT_TX_ACTIVE_SCAN], (time_t)W0);
    ASSERT_EQ((int)g_s.ble_host.tx_count, 2);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 1u << BT_TX_ACTIVE_SCAN);
    ASSERT_EQ(bt_tx_asserted_mask(&g_s.ble_host, W0 + 1000),
              1u << BT_TX_ACTIVE_SCAN);
    cmd_at(0, 0x200C, dis, 2, W0 + 1);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 0u);
    ASSERT_EQ(bt_tx_asserted_mask(&g_s.ble_host, W0 + 1000), 0u);
    /* The extended enable (§7.8.65) is read the same way. */
    const uint8_t xen[6] = { 0x01, 0x00, 0, 0, 0, 0 };
    cmd_at(0, 0x2042, xen, 6, W0 + 2);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_wall[BT_TX_ACTIVE_SCAN], (time_t)(W0 + 2));
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 1u << BT_TX_ACTIVE_SCAN);
    /* Under passive parameters an enable sends nothing. */
    cmd_at(0, 0x200C, dis, 2, W0 + 3);
    cmd_at(0, 0x200B, pas, 7, W0 + 3);
    cmd_at(0, 0x200C, en, 2, W0 + 4);
    ble_snapshot(&g_s);
    ASSERT_EQ((int)g_s.ble_host.tx_count, 3);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 0u);
}

/* The other review case: two kinds inside the window are two
 * incidents. An active scan at t-30 and an inquiry at t-5; the newer
 * one must not hide the older.
 *
 * Seen to fail: with the rule firing only last_tx_kind (the pre-review
 * shape), bttx:active_scan is missing. */
static void test_two_kinds_in_the_window_are_two_incidents(void) {
    g_wall = W0;
    sloth_clock_test_set(NULL, pinned_wall);
    memset(&g_s, 0, sizeof(g_s));
    active_scan_at(W0 - 30);
    const uint8_t inq[5] = { 0x33, 0x8B, 0x9E, 0x08, 0x00 };
    cmd_at(0, 0x0401, inq, 5, W0 - 5);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.last_tx_kind, (int)BT_TX_INQUIRY);
    alerts_update(&g_s);
    ASSERT(key_fired(&g_s, "bttx:active_scan") >= 0);
    ASSERT(key_fired(&g_s, "bttx:inquiry") >= 0);
    sloth_clock_test_set(NULL, NULL);
}

/* HCI_Reset (§7.3.2) returns the controller to its power-on state, so
 * it clears every on-kind and, from then on, the view of that
 * controller is complete (tx_baseline). DEL_INDEX removes it outright.
 *
 * Seen to fail: with the OP_RESET case emptied, adv stays on after the
 * Reset and tx_baseline stays 0. */
static void test_reset_and_del_index_end_the_on_state(void) {
    const uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
    int n = rec_new_index(g_rec, 0, 0x01, a, "hci0");
    ing(g_rec, n, W0);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_baseline, 0);
    const uint8_t on = 0x01;
    cmd_at(0, 0x200A, &on, 1, W0);
    cmd_at(0, 0x0C1A, (const uint8_t *)"\x02", 1, W0);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_on_mask,
              (1u << BT_TX_ADV) | (1u << BT_TX_SCAN_ENABLE));
    cmd_at(0, 0x0C03, NULL, 0, W0 + 1);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 0u);
    ASSERT_EQ(g_s.ble_host.tx_baseline, 1);
    ASSERT_EQ(g_s.ble_host.controllers, 1);
    /* A Reset with parameters is not one. */
    n = rec_cmd(g_rec, 0x0C03, &on, 1);
    ASSERT_EQ((int)ing(g_rec, n, W0), (int)BLE_REC_MALFORMED);

    cmd_at(0, 0x200A, &on, 1, W0 + 2);
    n = rec_del_index(g_rec, 0);
    ASSERT_EQ((int)ing(g_rec, n, W0 + 3), (int)BLE_REC_DEL_INDEX);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 0u);
    ASSERT_EQ(g_s.ble_host.controllers, 0);
    ASSERT_EQ(g_s.ble_host.tx_baseline, 0);
    /* Recency still holds both enables (W0 and W0 + 2) at W0 + 10, and
     * neither once the window has passed. */
    ASSERT_EQ(bt_tx_asserted_mask(&g_s.ble_host, W0 + 10),
              (1u << BT_TX_ADV) | (1u << BT_TX_SCAN_ENABLE));
    ASSERT_EQ(bt_tx_asserted_mask(&g_s.ble_host, W0 + 2 + BT_TX_RECENT_SECS + 1),
              0u);
}

/* `controllers` is how many primary controllers are present, not how
 * many announcements arrived: an AMP controller is not counted, and a
 * controller that resets (DEL_INDEX, NEW_INDEX) counts once.
 *
 * Seen to fail: with the `p[0] == 0x00` primary check dropped, the AMP
 * index makes it 2; with DEL_INDEX left IGNORED, the re-announce does. */
static void test_controllers_counts_live_primary_only(void) {
    const uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
    int n = rec_new_index(g_rec, 0, 0x01, a, "hci0");
    ing(g_rec, n, 0);
    n = rec_new_index_type(g_rec, 1, 0x01 /* HCI_AMP */, 0x01, a, "hci1");
    ing(g_rec, n, 0);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.controllers, 1);
    n = rec_del_index(g_rec, 0);
    ASSERT_EQ((int)ing(g_rec, n, 0), (int)BLE_REC_DEL_INDEX);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.controllers, 0);
    n = rec_new_index(g_rec, 0, 0x01, a, "hci0");
    ing(g_rec, n, 0);
    ing(g_rec, n, 0);    /* announced twice with no removal between */
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.controllers, 1);
    ASSERT_EQ((int)g_s.ble_host.index_records, 5);
    /* DEL_INDEX has no payload; one with bytes is not a DEL_INDEX. */
    n = rec_del_index(g_rec, 0);
    g_rec[n] = 0xAA;
    ASSERT_EQ((int)ing(g_rec, n + 1, 0), (int)BLE_REC_MALFORMED);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.controllers, 1);
    ASSERT_EQ((int)g_s.ble_host.records,
              (int)(g_s.ble_host.index_records + g_s.ble_host.malformed));
}

/* Past BT_MAX_CTRL present controllers, the rest share one slot whose
 * on-state only grows: a disable on one of them says nothing about the
 * others.
 *
 * Seen to fail: with ctrl_recompute() assigning the overflow slot's
 * mask instead of OR-ing it, the disable on hci<BT_MAX_CTRL> clears it. */
static void test_untracked_controllers_never_clear(void) {
    const uint8_t on = 0x01, off = 0x00;
    const uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
    /* Fill every slot with a present controller, so none is reusable. */
    for (int i = 0; i < BT_MAX_CTRL; i++) {
        int n = rec_new_index(g_rec, (uint16_t)i, 0x01, a, "hci");
        ing(g_rec, n, W0);
        cmd_at((uint16_t)i, 0x0C03, NULL, 0, W0);
    }
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.tx_baseline, 1);
    cmd_at(BT_MAX_CTRL, 0x200A, &on, 1, W0);
    cmd_at(BT_MAX_CTRL, 0x200A, &off, 1, W0);
    ble_snapshot(&g_s);
    ASSERT_EQ((int)g_s.ble_host.ctrl_untracked, 2);
    ASSERT_EQ(g_s.ble_host.tx_on_mask, 1u << BT_TX_ADV);
    ASSERT_EQ(g_s.ble_host.tx_baseline, 0);
}

static void test_kinds_format(void) {
    char b[192];
    bt_tx_kinds_format(0, b, sizeof(b));
    ASSERT_STR(b, "");
    bt_tx_kinds_format((1u << BT_TX_ADV) | (1u << BT_TX_ACTIVE_SCAN), b, sizeof(b));
    ASSERT_STR(b, "active_scan,advertising");
    char small[8];
    bt_tx_kinds_format(1u << BT_TX_ADV, small, sizeof(small));
    ASSERT_STR(small, "");     /* does not fit: nothing half-written */
}

/* ── Eviction ───────────────────────────────────────────────────── */

static void test_advertiser_table_evicts_and_tallies(void) {
    sh_evict_reset();
    uint8_t a[6] = { 0, 0, 0, 0, 0, 0xC0 };
    for (int i = 0; i < MAX_BLE_DEVICES + 5; i++) {
        a[0] = (uint8_t)i; a[1] = (uint8_t)(i >> 8);
        int n = rec_adv(g_rec, 0, 0x03, 0x01, a, NULL, 0, -80);
        /* Distinct, increasing frame times so the oldest is well-defined. */
        ble_mon_ingest(g_rec, (size_t)n, (size_t)n, TS + i, 0);
    }
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_device_count, MAX_BLE_DEVICES);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_BLE_DEVICE), 5);
    ASSERT_STR(sh_evict_name(SH_EVICT_BLE_DEVICE), "ble_device");
    ASSERT_EQ(sh_evict_is_flow_ring(SH_EVICT_BLE_DEVICE), 0);
}

/* ── sensor_health ──────────────────────────────────────────────── */

static char g_tmp[] = "/tmp/sloth_ble_XXXXXX";

static int open_tmp_jsonl(void) {
    int fd = mkstemp(g_tmp);
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_tmp);
    return jsonl_open(g_tmp);
}

static char *slurp_tmp(void) {
    FILE *fp = fopen(g_tmp, "r");
    if (!fp) return NULL;
    static char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static int count_lines(const char *b) {
    int n = 0;
    for (; b && *b; b++) if (*b == '\n') n++;
    return n;
}

static void test_sensor_health_carries_the_bluetooth_block(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(NULL, pinned_wall);
    ASSERT(open_tmp_jsonl());
    memset(&g_s, 0, sizeof(g_s));
    snprintf(g_s.bt_iface, sizeof(g_s.bt_iface), "%s", BT_MONITOR_DEVICE);
    uint8_t p[7] = { 0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00 };
    int n = rec_cmd(g_rec, 0x200B, p, 7);
    ing(g_rec, n, g_wall);
    uint8_t q[4] = { 0x02, 2, 0, 0 };
    n = rec_evt(g_rec, 0x3E, q, 4);
    ing(g_rec, n, g_wall);
    ble_snapshot(&g_s);
    jsonl_emit_sensor_health(&g_s);
    jsonl_close();
    char *b = slurp_tmp();
    ASSERT(b != NULL);
    if (b) {
        ASSERT(strstr(b, "\"btmon_iface\":\"bluetooth-monitor\"") != NULL);
        ASSERT(strstr(b, "\"btmon_open\":0") != NULL);
        ASSERT(strstr(b, "\"ble_scan_mode\":\"passive\"") != NULL);
        ASSERT(strstr(b, "\"ble_scan_filter\":\"basic\"") != NULL);
        ASSERT(strstr(b, "\"ble_scan_accept_list\":0") != NULL);
        ASSERT(strstr(b, "\"ble_own_tx\":\"never\"") != NULL);
        ASSERT(strstr(b, "\"ble_own_tx_kind\":\"none\"") != NULL);
        ASSERT(strstr(b, "\"ble_own_tx_secs\":-1") != NULL);
        ASSERT(strstr(b, "\"ble_own_tx_on\":\"\"") != NULL);
        ASSERT(strstr(b, "\"ble_own_tx_asserted\":\"\"") != NULL);
        ASSERT(strstr(b, "\"ble_own_tx_baseline\":0") != NULL);
        ASSERT(strstr(b, "\"ble_index_records\":0") != NULL);
        ASSERT(strstr(b, "\"ble_multi_report_rejected\":1") != NULL);
        ASSERT(strstr(b, "\"ble_records\":2") != NULL);
        ASSERT(strstr(b, "\"ble_host_commands\":1") != NULL);
        ASSERT(strstr(b, "\"evict_ble_device\":") != NULL);
        ASSERT_EQ(count_lines(b), 1);
    }
    unlink(g_tmp);
    sloth_clock_test_set(NULL, NULL);
}

/* The own-transmission state enters the change-only signature as its
 * bucket: a new transmission kind or a bucket crossing is a line, a
 * second command of a kind already seen is not.
 *
 * Seen to fail: with `tx_count` signed instead of the kind mask, the
 * third emit below writes a line. */
static void test_own_transmit_signature_is_bucketed(void) {
    g_wall = 1800000000;
    sloth_clock_test_set(NULL, pinned_wall);
    ASSERT(open_tmp_jsonl());
    memset(&g_s, 0, sizeof(g_s));
    ble_snapshot(&g_s);
    jsonl_emit_sensor_health(&g_s);          /* 1: first line */
    active_scan_at(g_wall);
    ble_snapshot(&g_s);
    g_wall += 1;
    jsonl_emit_sensor_health(&g_s);          /* 2: never -> recent, new kind */
    active_scan_at(g_wall);
    ble_snapshot(&g_s);
    g_wall += 1;
    jsonl_emit_sensor_health(&g_s);          /* suppressed: same bucket, kind */
    g_wall += BT_TX_RECENT_SECS + 1;
    jsonl_emit_sensor_health(&g_s);          /* 3: recent -> earlier */
    jsonl_close();
    char *b = slurp_tmp();
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_lines(b), 3);
        ASSERT(strstr(b, "\"ble_own_tx\":\"recent\"") != NULL);
        ASSERT(strstr(b, "\"ble_own_tx\":\"earlier\"") != NULL);
    }
    unlink(g_tmp);
    sloth_clock_test_set(NULL, NULL);
}

/* What is on the air now reaches sensor_health, and stays there past
 * the recency window: at +300 s `ble_own_tx` reads `earlier` while
 * `ble_own_tx_on` still says advertising. And a scan the kernel toggles
 * on and off under active parameters is one line, not one per toggle:
 * the signature carries the asserted kinds (on or recent), which do not
 * move while the scan keeps re-enabling.
 *
 * Seen to fail: with `sig.ble_tx_asserted` set from tx_on_mask instead
 * of bt_tx_asserted_mask(), the toggles below write extra lines. */
static void test_sensor_health_reports_what_is_on(void) {
    g_wall = W0;
    sloth_clock_test_set(NULL, pinned_wall);
    ASSERT(open_tmp_jsonl());
    memset(&g_s, 0, sizeof(g_s));
    const uint8_t act[7] = { 0x01, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const uint8_t en[2] = { 0x01, 0x00 }, dis[2] = { 0x00, 0x00 };
    cmd_at(0, 0x200B, act, 7, W0);
    cmd_at(0, 0x200C, en, 2, W0);
    ble_snapshot(&g_s);
    jsonl_emit_sensor_health(&g_s);                 /* 1 */
    for (int i = 1; i <= 4; i++) {
        g_wall = W0 + i;
        cmd_at(0, 0x200C, (i & 1) ? dis : en, 2, g_wall);
        ble_snapshot(&g_s);
        jsonl_emit_sensor_health(&g_s);             /* suppressed */
    }
    const uint8_t on = 0x01;
    cmd_at(0, 0x200A, &on, 1, g_wall);
    ble_snapshot(&g_s);
    jsonl_emit_sensor_health(&g_s);                 /* 2: new kind */
    g_wall += 300;
    jsonl_emit_sensor_health(&g_s);                 /* 3: recent -> earlier */
    jsonl_close();
    char *b = slurp_tmp();
    ASSERT(b != NULL);
    if (b) {
        ASSERT_EQ(count_lines(b), 3);
        const char *last = b;
        for (const char *q = b; (q = strstr(q, "\"type\":\"sensor_health\"")); q++)
            last = q;
        ASSERT(strstr(last, "\"ble_own_tx\":\"earlier\"") != NULL);
        ASSERT(strstr(last, "\"ble_own_tx_on\":\"active_scan,advertising\"") != NULL);
        ASSERT(strstr(last, "\"ble_own_tx_asserted\":\"active_scan,advertising\"") != NULL);
        ASSERT(strstr(last, "\"ble_own_tx_baseline\":0") != NULL);
    }
    unlink(g_tmp);
    sloth_clock_test_set(NULL, NULL);
}

/* ── Routing and the worker callback ────────────────────────────── */

static void test_replay_routes_dlt_254_to_the_bluetooth_source(void) {
    ASSERT_EQ((int)replay_route(254), (int)REPLAY_ROUTE_BT);
    ASSERT_EQ((int)replay_route(127), (int)REPLAY_ROUTE_MONITOR);
    ASSERT_EQ((int)replay_route(1),   (int)REPLAY_ROUTE_WIRED);
    ASSERT_EQ((int)replay_route(201), (int)REPLAY_ROUTE_NONE);  /* raw H4 HCI */
}

#ifdef WITH_PCAP
static void test_worker_callback_decodes_a_dlt_254_savefile(void) {
    static uint8_t f0[64], f1[64], f2[64];
    const uint8_t ca[6] = { 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
    int l0 = rec_new_index(f0, 0, 0x01, ca, "hci0");
    uint8_t ad[32];
    int dl = build_ad(ad);
    int l1 = rec_adv(f1, 0, 0x00, 0x01, ADDR_LE, ad, (uint8_t)dl, -55);
    int l2 = put_hdr(f2, 0, BT_MON_ACL_TX_PKT);
    memset(f2 + l2, 0xAB, 20); l2 += 20;
    const uint8_t *const frames[3] = { f0, f1, f2 };
    const int lens[3] = { l0, l1, l2 };
    ASSERT_EQ(bt_monitor_dispatch_frames(frames, lens, NULL, NULL, 3), 3);
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_host.controllers, 1);
    ASSERT_EQ(g_s.ble_device_count, 1);
    ASSERT_EQ((int)g_s.ble_host.ignored, 1);
    ASSERT_EQ((int)g_s.ble_host.records, 3);
    /* The frame clock reached the device row. */
    ASSERT(g_s.ble_devices[0].first_seen >= (time_t)1700000000);

    /* The pcap-edge gate runs first: a record one octet past the
     * 65535 the gate admits never reaches the decoder. (The seam's
     * savefile writer clamps origlen up to caplen, so the caplen >
     * origlen refusal cannot be expressed here; tests/test_capture_path.c
     * says the same for the other two streams.) */
    sh_parse_fault_reset();
    uint8_t *big = calloc(1, 65536);
    ASSERT(big != NULL);
    if (!big) return;
    memcpy(big, f1, (size_t)l1);
    const uint8_t *const one[1] = { big };
    const int len1[1] = { 65536 };
    ASSERT_EQ(bt_monitor_dispatch_frames(one, len1, NULL, NULL, 1), 1);
    free(big);
    ble_snapshot(&g_s);
    ASSERT_EQ((int)g_s.ble_host.records, 3);
    ASSERT_EQ((int)sh_parse_fault_count(SH_PF_FRAME_EDGE), 1);
}
#endif

/* ── Never sends ────────────────────────────────────────────────── */

static char *slurp_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (buf) { buf[fread(buf, 1, (size_t)n, fp)] = '\0'; }
    fclose(fp);
    return buf;
}

/* MISSION §2: the Bluetooth source has no transmit path, so neither of
 * its files may reach for one. A source scan, not a behaviour test —
 * the handle cannot be exercised without a controller — and named as
 * such. Seen to fail: a call to the libpcap send function added to
 * bt_monitor.c turns it red. */
static void test_bluetooth_source_files_never_send(void) {
    static const char *const files[] = {
        "src/capture/bt_monitor.c", "src/ble_hci.c", "src/alerts/rules_ble.c"
    };
    static const char *const banned[] = {
        "pcap_inject", "pcap_sendpacket", "AF_BLUETOOTH", "socket("
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char *src = slurp_file(files[i]);
        ASSERT(src != NULL);
        if (!src) continue;
        for (size_t j = 0; j < sizeof(banned) / sizeof(banned[0]); j++) {
            if (strstr(src, banned[j]))
                printf("    %s contains %s\n", files[i], banned[j]);
            ASSERT(strstr(src, banned[j]) == NULL);
        }
        free(src);
    }
}

void run_ble_hci_tests(void) {
    TEST_SUITE("Bluetooth host source: HCI monitor channel (#144 slice 2)");
    RUN_TEST(test_raw_hci_device_names_are_refused);
    RUN_TEST(test_ip_fallback_never_picks_a_bluetooth_device);
#ifdef WITH_PCAP
    RUN_TEST(test_monitor_retarget_refuses_raw_hci);
#endif
    RUN_TEST(test_new_index_records_the_controller);
    RUN_TEST(test_single_report_creates_a_device);
    RUN_TEST(test_multi_report_event_is_rejected_and_counted);
    RUN_TEST(test_extended_report_is_counted_not_decoded);
    RUN_TEST(test_bad_lengths_are_malformed_not_decoded);
    RUN_TEST(test_records_outside_the_allow_list_are_never_read);
    RUN_TEST(test_scan_mode_unknown_until_parameters_are_seen);
    RUN_TEST(test_legacy_scan_parameters_set_mode_and_filter);
    RUN_TEST(test_extended_scan_parameters_per_phy);
    RUN_TEST(test_each_transmit_command_is_recorded);
    RUN_TEST(test_disabling_commands_are_not_transmissions);
    RUN_TEST(test_recency_is_bucketed_not_latched);
    RUN_TEST(test_own_transmit_fires_while_recent);
    RUN_TEST(test_own_transmit_silent_when_never_or_earlier);
    RUN_TEST(test_advertising_held_on_until_disabled);
    RUN_TEST(test_each_persistent_kind_holds_until_its_disable);
    RUN_TEST(test_multi_set_ext_adv_clears_only_on_disable_all);
    RUN_TEST(test_scan_enable_under_active_parameters_transmits);
    RUN_TEST(test_two_kinds_in_the_window_are_two_incidents);
    RUN_TEST(test_reset_and_del_index_end_the_on_state);
    RUN_TEST(test_controllers_counts_live_primary_only);
    RUN_TEST(test_untracked_controllers_never_clear);
    RUN_TEST(test_kinds_format);
    RUN_TEST(test_advertiser_table_evicts_and_tallies);
    RUN_TEST(test_sensor_health_carries_the_bluetooth_block);
    RUN_TEST(test_own_transmit_signature_is_bucketed);
    RUN_TEST(test_sensor_health_reports_what_is_on);
    RUN_TEST(test_replay_routes_dlt_254_to_the_bluetooth_source);
#ifdef WITH_PCAP
    RUN_TEST(test_worker_callback_decodes_a_dlt_254_savefile);
#endif
    RUN_TEST(test_bluetooth_source_files_never_send);
}
