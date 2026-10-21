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

/* Fires while the last own transmission is RECENT (BT_TX_RECENT_SECS)
 * and stops being re-asserted once it is not, so the engine's quiet
 * period resolves it: bucketed by recency, never latched. One incident
 * per transmission kind, so an advertising stack and an active scan are
 * two findings rather than one whose detail flips between them. */
void rule_bt_own_transmit(const sloth_state_t *s, time_t now) {
    const ble_host_t *h = &s->ble_host;
    if (bt_tx_recency(h->last_tx_wall, now) != BT_TX_RECENT) return;
    const char *kind = bt_tx_kind_name(h->last_tx_kind);
    if (!kind[0] || h->last_tx_kind == BT_TX_NONE) return;

    char key[64];
    akey_t k;
    akey_begin(&k, key, sizeof(key), "bttx");
    akey_tok(&k, kind);
    if (!akey_end(&k)[0]) return;

    char detail[200];
    snprintf(detail, sizeof(detail),
             "host controller hci%d told to transmit (%s, %ld s ago); "
             "scan mode %s, filter %s - sloth sent nothing, the host "
             "stack did: this sensor's host is not passive",
             h->last_tx_adapter, kind, (long)(now - h->last_tx_wall),
             ble_scan_mode_name(h->scan_mode),
             ble_filter_policy_name(h->filter_policy));
    fire(ALERT_TYPE_BT_OWN_TRANSMIT, ALERT_SEV_WARN, "BT_OWN_TRANSMIT",
         detail, key, NULL, 0, now);
}
