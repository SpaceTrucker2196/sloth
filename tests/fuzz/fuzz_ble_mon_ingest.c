#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sloth.h"
#include "ble_hci.h"
#include "ble_detect.h"

/* libFuzzer target for the Bluetooth HCI monitor decoder (#144 slice 2).
 *
 * ble_mon_ingest() takes a DLT 254 record — libpcap's 4-byte header and
 * a payload every byte of which crossed a monitor socket — and walks the
 * allow-list: NEW_INDEX, the LE advertising report into the AD walker
 * (src/ble_snoop.c), and the host's own scan/advertise/connect commands.
 * The record is the fuzzer's own redzoned buffer, so an over-read past
 * `size` faults here.
 *
 * Two calls per input: the whole buffer as captured, then a prefix of
 * it (length chosen by the first byte) reported as snapped from the
 * full size, so the whole-record and the snapped branches are both
 * reached. Table state persists across
 * runs on purpose: eviction is reached only once the table has filled.
 * Afterwards every decoded string must still be terminated inside its
 * field. Since #144 slice 4 the advertisements also feed the flood
 * windows, and the three BLE detector lanes are run over each snapshot:
 * every finding's key must be terminated and the count in bounds. */
static sloth_state_t g_s;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535) return 0;
    (void)ble_mon_ingest(data, size, size, 1700000000, 1700000000);
    if (size > 1) {
        size_t cut = (size_t)data[0] % size;
        (void)ble_mon_ingest(data, cut, size, 1700000000, 1700000000);
    }
    ble_snapshot(&g_s);
    if (g_s.ble_device_count < 0 || g_s.ble_device_count > MAX_BLE_DEVICES)
        abort();
    for (int i = 0; i < g_s.ble_device_count; i++) {
        const ble_device_t *d = &g_s.ble_devices[i];
        if (strnlen(d->name, sizeof(d->name)) >= sizeof(d->name)) abort();
    }
    if (strnlen(g_s.ble_host.ctrl_name, sizeof(g_s.ble_host.ctrl_name)) >=
        sizeof(g_s.ble_host.ctrl_name))
        abort();
    if (g_s.ble_host.last_tx_kind < 0 ||
        g_s.ble_host.last_tx_kind >= BT_TX_KIND_COUNT)
        abort();
    /* On-state is a set of kinds; nothing outside the enum, and no
     * more live controllers than slots. */
    if (g_s.ble_host.tx_on_mask >> BT_TX_KIND_COUNT) abort();
    if (g_s.ble_host.tx_on_mask & 1u) abort();
    if (g_s.ble_host.controllers < 0 || g_s.ble_host.controllers > BT_MAX_CTRL)
        abort();
    {
        char kinds[192];
        bt_tx_kinds_format(~0u, kinds, sizeof(kinds));
        if (strnlen(kinds, sizeof(kinds)) >= sizeof(kinds)) abort();
    }
    if (g_s.ble_flood_count < 0 || g_s.ble_flood_count > MAX_BLE_FLOOD)
        abort();
    for (int i = 0; i < g_s.ble_device_count; i++) {
        const ble_device_t *d = &g_s.ble_devices[i];
        if (strnlen(d->watch_cat, sizeof(d->watch_cat)) >= sizeof(d->watch_cat))
            abort();
    }
    {
        static ble_finding_t f[BLE_FINDINGS_MAX];
        int dropped = 0;
        int n = ble_findings_build(&g_s, 1700000000, f, BLE_FINDINGS_MAX,
                                   &dropped);
        if (n < 0 || n > BLE_FINDINGS_MAX || dropped < 0) abort();
        for (int i = 0; i < n; i++)
            if (strnlen(f[i].key, sizeof(f[i].key)) >= sizeof(f[i].key) ||
                !f[i].key[0])
                abort();
    }
    return 0;
}
