#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "btle_ll.h"
#include "ble_snoop.h"

/* libFuzzer target for the BLE Link Layer decoder (#144 slice 3).
 *
 * The input is one record, offered three ways: as a DLT 256 record
 * (pseudo-header first), as a DLT 192 PPI record, and as a bare LE
 * packet. The buffer is the fuzzer's own, tightly redzoned, so a read
 * past `size` faults here. After each parse the trusted-length contract
 * is checked: never more than claimed, never past the Ubertooth limit,
 * AdvData inside the record, and the report built from it terminates
 * its name. */
static void check(const uint8_t *buf, size_t size, const btle_pkt_t *p,
                  btle_verdict_t v) {
    if (v == BTLE_V_MALFORMED) return;
    if (p->len_trusted > p->len_claimed) abort();
    if (p->len_trusted > BTLE_PAYLOAD_TRUST_MAX) abort();
    if (p->truncated != (p->len_trusted < p->len_claimed) &&
        v != BTLE_V_DATA) abort();
    if (p->data) {
        if (p->data < buf || p->data + p->data_len > buf + size) abort();
        if (p->data_len + 6 > p->len_trusted) abort();
    }
    if (p->channel_index < -1 || p->channel_index > 39) abort();
    ble_adv_report_t r;
    if (btle_adv_report(p, &r)) {
        if (strnlen(r.local_name, sizeof(r.local_name)) >= sizeof(r.local_name))
            abort();
        if (r.event_type > 4) abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    btle_pkt_t p;
    btle_verdict_t v = btle_phdr_record_parse(data, size, &p);
    check(data, size, &p, v);
    v = btle_ppi_record_parse(data, size, &p);
    check(data, size, &p, v);
    v = btle_ll_parse(data, size, &p);
    check(data, size, &p, v);
    return 0;
}
