#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sloth.h"
#include "bt_stream.h"
#include "ble_hci.h"

/* libFuzzer target for the Ubertooth stream framer (#144 slice 3).
 *
 * The input is a byte stream as a FIFO would deliver it, fed in chunks
 * whose sizes come from the input itself, so header and record
 * boundaries land at every offset. The first octet picks one of the
 * three accepted link types and a valid file header is put in front
 * half the time, so the record path is reached without the fuzzer
 * having to discover the magic; the other half the raw input is the
 * header. Afterwards the accounting must hold: every record in exactly
 * one bucket, nothing more truncated than received, every device name
 * terminated. */
static bt_stream_t g_st;
static sloth_state_t g_s;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 1 << 16) return 0;
    /* Both tables emptied per input, so a crash reproduces from its
     * input alone. */
    bt_stream_clear();
    ble_clear();
    bt_stream_configure();
    bt_stream_init(&g_st);
    uint8_t sel = data[0];
    data++; size--;
    if (sel & 1) {
        static const uint32_t DLT[3] = { 256, 192, 255 };
        uint8_t h[24];
        memset(h, 0, sizeof(h));
        h[0] = 0xD4; h[1] = 0xC3; h[2] = 0xB2; h[3] = 0xA1;
        h[4] = 2; h[6] = 4;
        h[16] = 0xFF; h[17] = 0xFF;
        uint32_t d = DLT[(sel >> 1) % 3];
        h[20] = (uint8_t)d; h[21] = (uint8_t)(d >> 8);
        (void)bt_stream_feed(&g_st, h, sizeof(h), 1);
    }
    size_t off = 0;
    while (off < size) {
        size_t chunk = (size_t)(data[off] % 37) + 1;
        if (chunk > size - off) chunk = size - off;
        if (!bt_stream_feed(&g_st, data + off, chunk, 1)) break;
        off += chunk;
    }
    bt_stream_snapshot(&g_s);
    ble_snapshot(&g_s);
    const bt_capture_health_t *c = &g_s.btcap;
    if (c->drop + c->adv + c->scan_req + c->connect_ind + c->ext_adv +
        c->data_pdus + c->other + c->bredr != c->recv) abort();
    if (c->truncated > c->recv) abort();
    if (c->bredr_iac > c->bredr) abort();
    if (strnlen(c->err, sizeof(c->err)) >= sizeof(c->err)) abort();
    if (g_s.bredr_lap_count < 0 || g_s.bredr_lap_count > MAX_BREDR_LAPS) abort();
    for (int i = 0; i < g_s.ble_device_count; i++)
        if (strnlen(g_s.ble_devices[i].name, sizeof(g_s.ble_devices[i].name)) >=
            sizeof(g_s.ble_devices[i].name))
            abort();
    return 0;
}
