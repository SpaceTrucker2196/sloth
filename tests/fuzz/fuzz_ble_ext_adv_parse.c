#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ble_snoop.h"

/* libFuzzer target for the LE Extended Advertising Report parser
 * (subevent 0x0D, Core Specification v5.x Vol 4 Part E §7.7.65.13).
 *
 * The input is one HCI event as framed (event code, parameter length,
 * parameters), in the fuzzer's own redzoned buffer, so any read past
 * `size` faults here. The input is offered as is, and again with the
 * event and subevent codes and the parameter length forced to agree
 * with it, so the fuzzer spends its time past the framing checks.
 * fuzz_ble_mon_ingest reaches the same parser through the monitor
 * decoder; this target holds the parser's own contract:
 *
 *   a non-zero return only for Num_Reports consecutive records that
 *   fill the parameters exactly (2 + sum of BLE_EXT_REPORT_FIXED +
 *   Data_Length), with one callback per report, in order, each with a
 *   known PDU code, a data status that is not reserved, a terminated
 *   name, an all-zero address for an anonymous one, and a Legacy-bit
 *   report that is complete, at most 31 octets, on LE 1M with no
 *   secondary PHY, and SID 0xFF;
 *   0 with no callback otherwise. */
typedef struct {
    const uint8_t *e;
    size_t         off;     /* next record's offset in e */
    int            calls;
} walk_t;

static void on_rep(const ble_adv_report_t *r, void *vctx) {
    walk_t *w = vctx;
    const uint8_t *rec = w->e + w->off;
    if (!r->ext || r->data_len != rec[23]) abort();
    if (r->ext_event_type != (uint16_t)(rec[0] | (rec[1] << 8))) abort();
    if (r->event_type > BLE_EVT_EXT_SCAN_RSP) abort();
    if (r->data_status > BLE_EXT_DATA_TRUNCATED) abort();
    if (r->ext_event_type & 0x0010) {
        if (r->event_type > 4 || r->data_status != BLE_EXT_DATA_COMPLETE ||
            r->data_len > 31 || r->primary_phy != 0x01 ||
            r->secondary_phy != 0x00 || r->sid != 0xFF)
            abort();
    } else if (r->event_type < BLE_EVT_EXT_ADV) {
        abort();
    }
    if (strnlen(r->local_name, sizeof(r->local_name)) >= sizeof(r->local_name))
        abort();
    if (r->addr_type == BLE_ADDR_ANONYMOUS) {
        static const uint8_t Z[6] = { 0 };
        if (memcmp(r->addr, Z, 6) != 0) abort();
    }
    if (r->has_rssi && r->rssi == 127) abort();
    if (r->has_adv_tx_power && r->adv_tx_power == 127) abort();
    w->off += BLE_EXT_REPORT_FIXED + rec[23];
    w->calls++;
}

static void check(const uint8_t *e, size_t n) {
    walk_t w = { e, 4, 0 };
    int v = ble_hci_ext_adv_walk(e, n, on_rep, &w);
    if (v == 0) {
        if (w.calls != 0) abort();
        return;
    }
    if (n < 4 || e[0] != 0x3E || e[2] != 0x0D || (size_t)e[1] + 2 != n) abort();
    if (v != e[3] || w.calls != v || v > BLE_EXT_REPORTS_MAX) abort();
    if (w.off != n) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 300) return 0;
    check(data, size);
    if (size >= 4 && size <= 257) {
        uint8_t *e = malloc(size);
        if (!e) return 0;
        memcpy(e, data, size);
        e[0] = 0x3E;
        e[1] = (uint8_t)(size - 2);
        e[2] = 0x0D;
        check(e, size);
        free(e);
    }
    return 0;
}
