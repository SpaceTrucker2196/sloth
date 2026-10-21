#ifndef BLE_HCI_H
#define BLE_HCI_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"
#include "ble_snoop.h"

/* The Bluetooth host source (#144 slice 2): records read off the Linux
 * HCI monitor channel, as libpcap delivers them from its
 * `bluetooth-monitor` device (LINKTYPE_BLUETOOTH_LINUX_MONITOR, 254).
 *
 * Pure decode and state, no libpcap: the capture worker in
 * src/capture/bt_monitor.c and the DLT 254 replay route both hand
 * records here, and so do the tests and the fuzz target.
 *
 * ── What the channel is ──
 *
 * The kernel copies every HCI packet that crosses any controller, in
 * both directions, to every socket bound to HCI_CHANNEL_MONITOR, plus
 * index lifecycle notes and the MGMT traffic of bluetoothd. Sending on
 * that socket is refused by the kernel (hci_sock_sendmsg() returns
 * EOPNOTSUPP for the monitor channel), which is why it is the source
 * MISSION §2 allows. The raw per-controller devices libpcap also lists,
 * `bluetooth0`, `bluetooth1`, ..., are HCI_CHANNEL_RAW and accept
 * injected packets; bt_dev_is_raw_hci() is the check every open path
 * applies to refuse them.
 *
 * ── Allow-list ──
 *
 * The same channel carries link keys, LTKs and IRKs (Link Key
 * Notification, LE Long Term Key Request Reply, MGMT Load Link Keys) and
 * every ACL payload. So nothing is decoded by default. A record is read
 * only when its monitor opcode and, for HCI packets, its HCI opcode or
 * event code are on this list:
 *
 *   NEW_INDEX (monitor opcode 0)       controller announced
 *   DEL_INDEX (monitor opcode 1)       controller removed (no payload)
 *   EVENT 0x3E / subevent 0x02         LE Advertising Report (single report)
 *   EVENT 0x3E / subevent 0x0D         counted, not decoded yet
 *   COMMAND, host's own scan, advertise and connect commands:
 *     0x200B LE Set Scan Parameters        0x2041 LE Set Extended Scan Parameters
 *     0x200C LE Set Scan Enable            0x2042 LE Set Extended Scan Enable
 *     0x200A LE Set Advertising Enable     0x2039 LE Set Extended Advertising Enable
 *     0x2040 LE Set Periodic Advertising Enable
 *     0x200D LE Create Connection          0x2043 LE Extended Create Connection
 *     0x0401 Inquiry                       0x0403 Periodic Inquiry Mode
 *     0x0404 Exit Periodic Inquiry Mode    0x0C03 Reset
 *     0x0405 Create Connection             0x0419 Remote Name Request
 *     0x0C1A Write Scan Enable
 *
 * The enable and disable halves are both read: advertising, inquiry or
 * page scan, periodic inquiry and an enabled active scan stay on the air
 * until the matching disable, a Reset or DEL_INDEX, so each controller
 * holds them as on/off (ble_ctrl_t) and BT_OWN_TRANSMIT fires while one
 * is on, not only while its command is recent.
 *
 * Anything else is counted under `ignored` after reading at most its
 * monitor opcode and HCI opcode/event code, and its bytes are never
 * copied. Nothing a record carries is written anywhere verbatim — not
 * to JSONL, the database, a pcap, or a log line — only the decoded
 * fields in ble_device_t and ble_host_t exist after the call returns.
 *
 * ── Multi-report events ──
 *
 * An LE Advertising Report with Num_Reports > 1 is refused whole and
 * counted (`multi_rejected`). The Core Specification draws the
 * parameters as per-field arrays; the Linux kernel parses them as
 * consecutive per-report records. The two agree for one report and
 * disagree for more, so until the layout is confirmed against a
 * controller sloth decodes none of them rather than half of them wrong.
 *
 * Thread model: ble_mon_ingest() runs on the capture worker (or the
 * replay/test thread), ble_snapshot() on the poll thread. One module
 * mutex covers both. */

#define BT_MONITOR_DEVICE   "bluetooth-monitor"
#define BT_DLT_LINUX_MONITOR 254
#define BT_MON_HDR_LEN      4     /* adapter_id (BE16) + opcode (BE16), libpcap's header */
/* Largest record any allow-listed type can be: the 4-byte header plus a
 * full HCI command (3 + 255) or event (2 + 255). The worker's snaplen,
 * so a longer record — ACL data, which is never decoded — is not even
 * copied whole out of the kernel. */
#define BT_MONITOR_SNAPLEN  (BT_MON_HDR_LEN + 3 + 255)

/* A transmit command counts as RECENT for this long after it arrived. */
#define BT_TX_RECENT_SECS   120

/* Monitor opcodes, Linux include/net/bluetooth/hci_mon.h. */
#define BT_MON_NEW_INDEX    0
#define BT_MON_DEL_INDEX    1
#define BT_MON_COMMAND_PKT  2
#define BT_MON_EVENT_PKT    3
#define BT_MON_ACL_TX_PKT   4
#define BT_MON_ACL_RX_PKT   5
#define BT_MON_CTRL_COMMAND 16
#define BT_MON_CTRL_EVENT   17

typedef enum {
    BLE_REC_MALFORMED = 0,     /* allow-listed type, bad length or snapped */
    BLE_REC_IGNORED,           /* outside the allow-list */
    BLE_REC_NEW_INDEX,
    BLE_REC_ADV,               /* one advertising report decoded */
    BLE_REC_MULTI_REJECTED,    /* Num_Reports > 1 */
    BLE_REC_EXT_ADV_UNDECODED, /* subevent 0x0D */
    BLE_REC_COMMAND,           /* allow-listed host command read */
    BLE_REC_DEL_INDEX          /* controller removed */
} ble_rec_verdict_t;

/* 1 for a libpcap raw-HCI device name ("bluetooth" followed by a
 * digit): an injectable HCI_CHANNEL_RAW socket, refused everywhere. */
int bt_dev_is_raw_hci(const char *name);

/* 1 for any libpcap Bluetooth device ("bluetooth0", "bluetooth-monitor",
 * ...). None of them is an IP interface, so the IP capture's
 * first-device fallback skips them all. */
int bt_dev_is_bluetooth(const char *name);

/* Decode one monitor record (libpcap's 4-byte header + payload).
 * `caplen` is what was captured, `origlen` the record's real length;
 * an allow-listed record that was snapped is MALFORMED, never decoded
 * from a prefix. `frame_ts` stamps device evidence; `wall` is the
 * arrival clock that own-transmission recency is measured on. */
ble_rec_verdict_t ble_mon_ingest(const uint8_t *rec, size_t caplen,
                                 size_t origlen, time_t frame_ts,
                                 time_t wall);

/* One advertising observation from any BLE sensor (#144 slice 3: the
 * Ubertooth stream feeds the same table the host source does). `r` is
 * the HCI-shaped report, address in transmission order (LSO first). The
 * row is keyed by (sensor_kind, iface, address, address type). */
typedef struct {
    const ble_adv_report_t *r;
    uint8_t     sensor_kind;   /* sensor_kind_t */
    const char *iface;         /* BT_MONITOR_DEVICE, BT_CAPTURE_IFACE */
    uint16_t    adapter;       /* HCI index; 0 for a capture stream */
    int         channel;       /* LL channel index 0..39, -1 unknown */
    int         sampled;       /* 1: one-channel sample (Ubertooth) */
    time_t      ts;            /* frame clock */
} ble_obs_t;

void ble_dev_observe(const ble_obs_t *o);

/* Copy the device table and host state into `s`. */
void ble_snapshot(sloth_state_t *s);

/* Empty the table and the host state. The eviction tally is untouched,
 * as for every stab_t table. */
void ble_clear(void);

/* bt_tx_recency_t for an own transmission that arrived at `last_tx_wall`
 * (0 = never), judged at `now`. */
int bt_tx_recency(time_t last_tx_wall, time_t now);

/* Bit per bt_tx_kind_t that BT_OWN_TRANSMIT asserts at `now`: on, on
 * any controller, or its own newest command RECENT. */
uint32_t bt_tx_asserted_mask(const ble_host_t *h, time_t now);

/* `mask`'s kinds as comma-separated bt_tx_kind_name()s in enum order,
 * "" for none. Always terminates `buf` when sz > 0. */
void bt_tx_kinds_format(uint32_t mask, char *buf, size_t sz);

/* Stable names, part of the sensor_health JSONL contract. */
const char *bt_tx_kind_name(int kind);        /* "none", "active_scan", ... */
const char *bt_tx_recency_name(int recency);  /* "never", "recent", "earlier" */
const char *ble_scan_mode_name(int mode);     /* "unknown", "passive", "active" */
/* Scanning_Filter_Policy (Vol 4 Part E §7.8.10): "unknown" (-1),
 * "basic", "accept_list", "extended", "extended_accept_list". */
const char *ble_filter_policy_name(int policy);
/* 1 when the policy restricts reports to the controller's Filter Accept
 * List (policy 1 or 3): a scan that hears only devices the host already
 * knows, which must be labelled as such. */
int ble_filter_policy_is_accept_list(int policy);

#endif /* BLE_HCI_H */
