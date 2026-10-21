/* Bluetooth rules. BT_OWN_TRANSMIT (#144 slice 2) is about sloth's own
 * host, not about anything it overheard; the three BLE_* lanes after it
 * (#144 slice 4) are about advertisements other devices broadcast.
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
#include "ble_detect.h"
#include "ble_flood.h"
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

/* ── The three BLE detector lanes (#144 slice 4) ─────────────────────
 *
 * Gates, bases and the "corroborate, never confirm" wording live in
 * src/ble_detect.h; ble_findings_build() is shared with the ble_alert
 * JSONL record so the alert and the record cannot disagree. All WARN:
 * the CRIT the issue sketches is deferred (ble_detect.h). */

static void fire_finding(const ble_finding_t *f, time_t now) {
    char detail[ALERT_DETAIL_LEN];
    char mac[18];
    switch (f->kind) {
    case BLE_FIND_FLOOD: {
        char sub[8], rssi[24];
        if (f->subtype >= 0) snprintf(sub, sizeof(sub), "0x%02x", (unsigned)f->subtype);
        else                 snprintf(sub, sizeof(sub), "-");
        if (f->has_rssi) snprintf(rssi, sizeof(rssi), ", median %d dBm", (int)f->rssi_median);
        else             rssi[0] = '\0';
        snprintf(detail, sizeof(detail),
                 "%s %s 0x%04x/%s: %s%u addresses, %u adv in %us (%u.%u/s)%s "
                 "via %s%s - a documented BLE-spam payload key at flood "
                 "volume; genuine devices send this key too, so the count "
                 "and rate are the evidence, not the payload",
                 ble_adv_type_name(f->adv_type), ble_family_name(f->family),
                 (unsigned)f->id, sub, f->distinct_capped ? ">=" : "",
                 (unsigned)f->distinct, (unsigned)f->total,
                 (unsigned)f->window_s, (unsigned)(f->rate_x10 / 10),
                 (unsigned)(f->rate_x10 % 10), rssi, f->sensor_iface,
                 f->sampled ? " (one-channel sample: a lower bound)" : "");
        fire(ALERT_TYPE_BLE_ADV_FLOOD, ALERT_SEV_WARN, "BLE_ADV_FLOOD",
             detail, f->key, NULL, 0, now);
        break;
    }
    case BLE_FIND_HID_OUI:
        mac_to_str(f->addr, mac, sizeof(mac));
        snprintf(detail, sizeof(detail),
                 "public address %s (%s OUI table) advertises %s%s%s via %s "
                 "- a keyboard-class advertiser on attacker-helper silicon; "
                 "precursor shape of CVE-2023-45866, no pairing observed",
                 mac, f->oui_table,
                 (f->hid & BLE_HID_APPEARANCE) ? "a HID appearance" : "",
                 (f->hid & BLE_HID_APPEARANCE) && (f->hid & BLE_HID_SERVICE)
                     ? " and " : "",
                 (f->hid & BLE_HID_SERVICE) ? "the HID service 0x1812" : "",
                 f->sensor_iface);
        fire(ALERT_TYPE_BLE_HID_UNEXPECTED, ALERT_SEV_WARN,
             "BLE_HID_UNEXPECTED", detail, f->key, NULL, 0, now);
        break;
    case BLE_FIND_HID_ROTATE:
        snprintf(detail, sizeof(detail),
                 "%d new random addresses advertised a HID appearance "
                 "(last 0x%04x) via %s in %us - one keyboard-class advertiser "
                 "rotating its address, or several new ones; precursor "
                 "shape of CVE-2023-45866, no pairing observed",
                 f->addrs, (unsigned)f->appearance, f->sensor_iface,
                 (unsigned)f->window_s);
        fire(ALERT_TYPE_BLE_HID_UNEXPECTED, ALERT_SEV_WARN,
             "BLE_HID_UNEXPECTED", detail, f->key, NULL, 0, now);
        break;
    case BLE_FIND_WATCH:
        snprintf(detail, sizeof(detail),
                 "%d address%s matching watched category %s heard via %s in "
                 "the last %us - addresses rotate, so this is not a count of "
                 "devices; a category, never an identity",
                 f->addrs, f->addrs == 1 ? "" : "es", f->category,
                 f->sensor_iface, (unsigned)f->window_s);
        fire(ALERT_TYPE_BLE_WATCHLIST, ALERT_SEV_WARN, "BLE_WATCHLIST",
             detail, f->key, NULL, 0, now);
        break;
    default:
        break;
    }
}

static void fire_kinds(const sloth_state_t *s, time_t now, int a, int b) {
    ble_finding_t f[BLE_FINDINGS_MAX];
    int n = ble_findings_build(s, now, f, BLE_FINDINGS_MAX, NULL);
    for (int i = 0; i < n; i++)
        if (f[i].kind == a || f[i].kind == b) fire_finding(&f[i], now);
}

void rule_ble_adv_flood(const sloth_state_t *s, time_t now) {
    fire_kinds(s, now, BLE_FIND_FLOOD, BLE_FIND_FLOOD);
}

void rule_ble_hid_unexpected(const sloth_state_t *s, time_t now) {
    fire_kinds(s, now, BLE_FIND_HID_OUI, BLE_FIND_HID_ROTATE);
}

void rule_ble_watchlist(const sloth_state_t *s, time_t now) {
    fire_kinds(s, now, BLE_FIND_WATCH, BLE_FIND_WATCH);
}
