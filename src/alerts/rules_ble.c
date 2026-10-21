/* Bluetooth host-source rules (#144 slice 2). One so far, and it is
 * about sloth's own host, not about anything it overheard.
 *
 * BT_OWN_TRANSMIT: MISSION §2 holds Bluetooth to the passive absolute —
 * no inquiry, no active scan (no SCAN_REQ), no connection, no
 * advertising. sloth itself sends no HCI or MGMT command, but the
 * controller it listens through is driven by the operator's stack
 * (bluetoothd, the kernel, a desktop settings panel), and any of them
 * can make it transmit. The monitor channel shows those commands, so
 * the sensor can say when its own host is not passive.
 *
 * Empty technique on the NO_MONITOR_MODE form: own operational state,
 * no adversary. The commands it keys on are listed with their Core
 * Specification clauses in src/ble_hci.h and src/ble_hci.c. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ble_hci.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"

/* One incident per transmission kind, fired while that kind is ON on
 * any controller (advertising, inquiry / page scan, periodic inquiry, an
 * enabled active scan: they stay on the air until disabled) or its own
 * newest command is RECENT (BT_TX_RECENT_SECS; the one-shot kinds).
 * Once neither holds it stops being re-asserted and the engine's quiet
 * period resolves it: bucketed, never latched. Each kind keeps its own
 * clock, so an active scan followed by advertising is two findings, not
 * one whose newer kind hides the older. */
void rule_bt_own_transmit(const sloth_state_t *s, time_t now) {
    const ble_host_t *h = &s->ble_host;
    const uint32_t asserted = bt_tx_asserted_mask(h, now);
    for (int k = BT_TX_NONE + 1; k < BT_TX_KIND_COUNT; k++) {
        if (!((asserted >> k) & 1u)) continue;
        int on = (h->tx_on_mask >> k) & 1u;
        const char *kind = bt_tx_kind_name(k);

        char key[64];
        akey_t ak;
        akey_begin(&ak, key, sizeof(key), "bttx");
        akey_tok(&ak, kind);
        if (!akey_end(&ak)[0]) continue;

        char when[48];
        if (h->tx_wall[k] > 0)
            snprintf(when, sizeof(when), "last command %ld s ago",
                     (long)(now - h->tx_wall[k]));
        else
            snprintf(when, sizeof(when), "no command seen");
        char detail[240];
        snprintf(detail, sizeof(detail),
                 "host controller hci%d told to transmit (%s, %s, %s); "
                 "scan mode %s, filter %s - sloth sent nothing, the host "
                 "stack did: this sensor's host is not passive",
                 h->tx_adapter[k], kind, on ? "still on" : "recent", when,
                 ble_scan_mode_name(h->scan_mode),
                 ble_filter_policy_name(h->filter_policy));
        fire(ALERT_TYPE_BT_OWN_TRANSMIT, ALERT_SEV_WARN, "BT_OWN_TRANSMIT",
             detail, key, NULL, 0, now);
    }
}
