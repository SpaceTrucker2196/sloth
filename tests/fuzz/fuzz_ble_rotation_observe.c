#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sloth.h"
#include "ble_hci.h"
#include "ble_rotation.h"
#include "ble_snoop.h"
#include "sensors.h"

/* libFuzzer target for the BLE address-rotation hints (#156 item 2).
 *
 * The input is a sequence of observations, each a control octet, a
 * 6-octet address (display order) and a length-prefixed AD blob that
 * ble_ad_parse() walks into a report, so the token extractors read
 * whatever the walker kept and the seam logic sees adversarial
 * interleavings, rotations and replays. The control octet picks the
 * time step (0..7 s), the Address_Type (random or resolved identity),
 * the adapter (0 or 1), the sensor iface and the PDU type. State
 * persists across inputs on purpose: eviction, retention and the chain
 * caps are reached only after many observations.
 *
 * After each input: every hint is within its documented bounds, a row
 * with a basis is in a chain, and the de-duplicated count is between 1
 * and the row count. */
static sloth_state_t g_s;
static time_t        g_ts = 1700000000;
static int           g_init;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_init) {
        if (ble_hci_rotation_enable(1) != 0) abort();
        g_init = 1;
    }
    size_t off = 0;
    while (off + 8 <= size) {
        uint8_t ctl = data[off];
        uint8_t addr[6];
        memcpy(addr, data + off + 1, 6);
        size_t len = data[off + 7];
        off += 8;
        if (len > size - off) len = size - off;

        ble_adv_report_t r;
        memset(&r, 0, sizeof(r));
        static const uint8_t evts[4] = { 0x00, 0x03, 0x04, BLE_EVT_EXT_ADV };
        r.event_type = evts[(ctl >> 5) & 3];
        r.addr_type  = (ctl & 0x08) ? 3 : 1;
        for (int i = 0; i < 6; i++) r.addr[i] = addr[5 - i];
        ble_ad_parse(data + off, len, &r);
        off += len;

        g_ts += ctl & 0x07;
        ble_obs_t o = { &r, SENSOR_BLE,
                        (ctl & 0x80) ? "ubertooth" : BT_MONITOR_DEVICE,
                        (uint16_t)((ctl >> 4) & 1), -1, 0, g_ts };
        ble_dev_observe(&o);
    }

    ble_snapshot(&g_s);
    if (!g_s.ble_rot.enabled) abort();
    int rows = g_s.ble_device_count;
    if (rows < 0 || rows > MAX_BLE_DEVICES) abort();
    for (int i = 0; i < rows; i++) {
        const ble_identity_hint_t *h = &g_s.ble_devices[i].hint;
        if (h->basis > BLE_HINT_TIMING) abort();
        if (h->basis == BLE_HINT_PAYLOAD && h->confidence > BLE_ROT_CONF_PAYLOAD_MAX) abort();
        if (h->basis == BLE_HINT_TIMING && h->confidence > BLE_ROT_CONF_TIMING_MAX) abort();
        if (h->basis && !h->chain) abort();
        if (h->hops > BLE_ROT_MAX_HOPS) abort();
        if (g_s.ble_devices[i].addr_type != 1 && h->chain) abort();
    }
    int d = ble_rot_distinct(&g_s, NULL, NULL);
    if (d > rows || (rows > 0 && d < 1)) abort();
    return 0;
}
