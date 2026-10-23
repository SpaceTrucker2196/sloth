#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "sensors.h"
#include "ble_detect.h"
#include "ble_flood.h"
#include "ble_rotation.h"
#include "views/ble.h"

/* [*] BLE — #144 slice 4.
 *
 * One row per ble_device_t: an advertiser as one sensor heard it, so
 * the host controller and an Ubertooth hearing the same address are two
 * rows (their counts mean different things; see sloth.h). Enter opens
 * every decoded field of the selected row. Read-only: sloth never
 * scans actively, connects, or reads GATT, so there is nothing here to
 * act on. The key is '*' because every letter and digit already
 * selects a view or does something global; 'b' is Beacons. */

static int ble_cols(void) {
#ifdef WITH_NCURSES
    return COLS > 0 ? COLS : 100;
#else
    return 100;
#endif
}

static int page_rows(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int p = LINES - 8;
#else
    int p = 30;
#endif
    if (s->ble_rot.enabled)           /* the rotation-hints estimate */
        p -= s->ble_rot.hints_timing ? 4 : 3;
    return p < 3 ? 3 : p;
}

/* Address type, one letter: P public, R random, p / r the resolved
 * identity forms (Core Spec v5.4 Vol 4 Part E §7.7.65.2). */
static char type_ch(uint8_t t) {
    switch (t) {
    case 0:  return 'P';
    case 1:  return 'R';
    case 2:  return 'p';
    case 3:  return 'r';
    default: return '?';
    }
}

static void age_cell(time_t last, time_t now, char *out, size_t n) {
    long a = (long)(now - last);
    if (last == 0) { snprintf(out, n, "-"); return; }
    if (a < 0) a = 0;
    if      (a < 60)    snprintf(out, n, "%lds", a);
    else if (a < 3600)  snprintf(out, n, "%ldm", a / 60);
    else if (a < 86400) snprintf(out, n, "%ldh", a / 3600);
    else                snprintf(out, n, "%ldd", a / 86400);
}

static void count_cell(uint64_t c, char *out, size_t n) {
    if (c < 100000ULL)          snprintf(out, n, "%llu", (unsigned long long)c);
    else if (c < 100000000ULL)  snprintf(out, n, "%lluk", (unsigned long long)(c / 1000));
    else                        snprintf(out, n, "%lluM", (unsigned long long)(c / 1000000));
}

/* What the advertiser says about itself, most specific first. */
static void summary_cell(const ble_device_t *d, char *out, size_t n) {
    int off = 0;
    out[0] = '\0';
#define ADD(...) do { if (off < (int)n) { int w = snprintf(out + off, n - (size_t)off, __VA_ARGS__); if (w > 0) off += w; } } while (0)
    if (d->has_name)       ADD("\"%s\" ", d->name);
    if (d->has_mfr) {
        if (d->has_mfr_sub) ADD("mfr %04x/%02x ", d->mfr_id, d->mfr_sub);
        else                ADD("mfr %04x ", d->mfr_id);
    }
    if (d->has_uuid16)     ADD("svc %04x ", d->uuid16);
    if (d->has_svc_data)   ADD("sd %04x ", d->svc_data_uuid16);
    if (d->has_appearance) ADD("app %04x ", d->appearance);
#undef ADD
    if (off > 0 && off <= (int)n && out[off - 1] == ' ') out[off - 1] = '\0';
    if (!out[0]) snprintf(out, n, "-");
}

static void flags_cell(const ble_device_t *d, char out[4]) {
    out[0] = d->hid ? 'H' : '-';
    out[1] = d->watch_cat[0] ? 'W' : '-';
    out[2] = d->sampled ? '~' : '-';
    out[3] = '\0';
}

/* ── column plan ───────────────────────────────────────────
 *
 * Fixed: marker, address, type, RSSI, adv count, age, flags. Flexing:
 * the sensor iface and the summary share what is left, so 100 columns
 * gets a row that does not wrap and a wide terminal gets whole names. */
#define BLE_FIXED (1 + 17 + 2 + 1 + 2 + 4 + 2 + 6 + 2 + 4 + 2 + 3 + 2)

typedef struct { int iface, summary; } ble_plan_t;

static ble_plan_t plan_cols(int cols) {
    ble_plan_t p;
    int avail = cols - 1 - BLE_FIXED;     /* never the last column */
    if (avail < 20) avail = 20;
    /* The iface takes its whole name (17 for "bluetooth-monitor") while
     * the summary keeps at least 24; past that the summary has it all. */
    p.iface = avail - 2 - 24;
    if (p.iface < 9)  p.iface = 9;
    if (p.iface > 17) p.iface = 17;
    p.summary = avail - p.iface - 2;
    return p;
}

static const ble_device_t *detail_row(const sloth_state_t *s) {
    for (int i = 0; i < s->ble_device_count; i++) {
        const ble_device_t *d = &s->ble_devices[i];
        if (memcmp(d->addr, s->ble_detail_addr, 6) == 0 &&
            d->addr_type == s->ble_detail_type &&
            strcmp(d->sensor_iface, s->ble_detail_iface) == 0)
            return d;
    }
    return NULL;
}

static void kv(const char *k, const char *fmt_v) {
    tui_dim();    TPRINT("  %-16s ", k);
    tui_normal(); TPRINT("%s\n", fmt_v);
}

static void draw_detail(const sloth_state_t *s) {
    const ble_device_t *d = detail_row(s);
    tui_dim(); TPRINT(" ── BLE advertiser ── "); tui_normal();
    tui_dim(); TPRINT("[Enter/Esc] back\n"); tui_normal();
    if (!d) {
        tui_dim();
        TPRINT("  (the row has left the table: the advertiser stopped, or a\n"
               "   newer one took its slot)\n");
        tui_normal();
        return;
    }
    char v[96];
    time_t now = sloth_wall();
    snprintf(v, sizeof(v), "%02x:%02x:%02x:%02x:%02x:%02x (%c)",
             d->addr[0], d->addr[1], d->addr[2], d->addr[3], d->addr[4],
             d->addr[5], type_ch(d->addr_type));
    kv("address", v);
    snprintf(v, sizeof(v), "%s on %s, adapter %u%s",
             sensor_kind_name(d->sensor_kind), d->sensor_iface,
             (unsigned)d->adapter,
             d->sampled ? " - one-channel sample, counts are a fraction" : "");
    kv("sensor", v);
    if (d->channel >= 0) { snprintf(v, sizeof(v), "%d", d->channel); kv("LL channel", v); }
    kv("last PDU", ble_adv_type_name(d->last_event_type));
    snprintf(v, sizeof(v), "%s%s", d->has_name ? d->name : "-",
             d->has_name && !d->name_complete ? " (shortened)" : "");
    kv("local name", v);
    if (d->has_mfr) {
        if (d->has_mfr_sub)
            snprintf(v, sizeof(v), "company 0x%04x, first octet 0x%02x",
                     d->mfr_id, d->mfr_sub);
        else
            snprintf(v, sizeof(v), "company 0x%04x", d->mfr_id);
        kv("manufacturer", v);
    }
    if (d->has_uuid16) { snprintf(v, sizeof(v), "0x%04x (first listed)", d->uuid16); kv("service", v); }
    if (d->has_svc_data) { snprintf(v, sizeof(v), "0x%04x", d->svc_data_uuid16); kv("service data", v); }
    if (d->has_appearance) {
        snprintf(v, sizeof(v), "0x%04x%s", d->appearance,
                 ble_appearance_is_hid(d->appearance) ? " (HID)" : "");
        kv("appearance", v);
    }
    if (d->hid) {
        snprintf(v, sizeof(v), "%s%s%s",
                 (d->hid & BLE_HID_APPEARANCE) ? "appearance" : "",
                 (d->hid & BLE_HID_APPEARANCE) && (d->hid & BLE_HID_SERVICE) ? ", " : "",
                 (d->hid & BLE_HID_SERVICE) ? "service 0x1812" : "");
        kv("HID", v);
    }
    if (d->has_tx_power) { snprintf(v, sizeof(v), "%d dBm", (int)d->tx_power); kv("TX power", v); }
    if (d->has_flags)    { snprintf(v, sizeof(v), "0x%02x", d->flags); kv("AD flags", v); }
    if (d->has_rssi) {
        snprintf(v, sizeof(v), "%d dBm (best %d)", (int)d->rssi, (int)d->rssi_best);
        kv("RSSI", v);
    }
    snprintf(v, sizeof(v), "%llu", (unsigned long long)d->adv_count);
    kv("advertisements", v);
    char a1[24], a2[24];
    age_cell(d->first_seen, now, a1, sizeof(a1));
    age_cell(d->last_seen, now, a2, sizeof(a2));
    snprintf(v, sizeof(v), "%s ago, last %s ago", a1, a2);
    kv("first heard", v);
    if (d->watch_cat[0]) {
        snprintf(v, sizeof(v), "%s - a category, never an identity", d->watch_cat);
        kv("watchlist", v);
    }
}

void view_ble_draw(const sloth_state_t *s) {
    if (s->ble_detail) { draw_detail(s); return; }

    int hid = 0, wl = 0;
    for (int i = 0; i < s->ble_device_count; i++) {
        if (s->ble_devices[i].hid) hid++;
        if (s->ble_devices[i].watch_cat[0]) wl++;
    }
    tui_normal(); TPRINT(" BLE advertisers: ");
    tui_bright(); TPRINT("%d", s->ble_device_count);
    tui_normal(); TPRINT("  HID: ");
    if (hid) tui_heat(0.5); else tui_dim();
    TPRINT("%d", hid);
    tui_normal(); TPRINT("  watchlist: ");
    if (wl) tui_heat(0.5); else tui_dim();
    TPRINT("%d", wl);
    tui_dim(); TPRINT("  flood keys: %d  [up/dn] [Enter] detail\n",
                      s->ble_flood_count);
    tui_normal();

    if (s->ble_device_count == 0) {
        tui_dim();
        TPRINT("  (no advertisements decoded - start with --bt-monitor or\n"
               "   --bt-capture PATH; see docs/wiki/ble.md. sloth never scans,\n"
               "   connects or reads GATT: the operator's stack runs the scan.)\n");
        tui_normal();
        return;
    }

    /* #156, --ble-rotation-hints only: the de-duplicated total, stated
     * as an estimate. No row says which addresses it joined. */
    if (s->ble_rot.enabled) {
        int est = ble_rot_distinct(s, NULL, NULL, 0);
        tui_dim();
        TPRINT(" rotation hints (internal): est. %d advertiser%s for %d "
               "address%s - possible address rotation;\n",
               est, est == 1 ? "" : "s", s->ble_device_count,
               s->ble_device_count == 1 ? "" : "es");
        TPRINT("   corroborates, does not confirm, and identifies no device "
               "or person.\n"
               "   These records alone are not grounds for personnel action "
               "or physical identification.\n");
        /* The research's timing-only wording, whenever the estimate may
         * rest on one. */
        if (s->ble_rot.hints_timing)
            TPRINT("   Includes timing-only hints. Weak: another advertiser "
                   "leaving and arriving reads the same.\n");
        tui_normal();
    }

    ble_plan_t w = plan_cols(ble_cols());
    tui_dim();
    TPRINT(" %-17s  %c  %-*s  %4s  %6s  %4s  %-3s  %s\n",
           "ADDRESS", 'T', w.iface, "SENSOR", "RSSI", "ADV", "AGE", "HWS",
           "ADVERTISES");
    tui_normal();

    int page = page_rows(s);
    int sel = s->ble_sel;
    if (sel >= s->ble_device_count) sel = s->ble_device_count - 1;
    if (sel < 0) sel = 0;
    int top = sel - page / 2;
    if (top + page > s->ble_device_count) top = s->ble_device_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->ble_device_count) end = s->ble_device_count;

    time_t now = sloth_wall();
    for (int i = top; i < end; i++) {
        const ble_device_t *d = &s->ble_devices[i];
        char addr[18], rssi[6], adv[24], age[24], fl[4], sum[256], ifc[32];
        snprintf(addr, sizeof(addr), "%02x:%02x:%02x:%02x:%02x:%02x",
                 d->addr[0], d->addr[1], d->addr[2], d->addr[3],
                 d->addr[4], d->addr[5]);
        if (d->has_rssi) snprintf(rssi, sizeof(rssi), "%d", (int)d->rssi);
        else             snprintf(rssi, sizeof(rssi), "-");
        count_cell(d->adv_count, adv, sizeof(adv));
        age_cell(d->last_seen, now, age, sizeof(age));
        flags_cell(d, fl);
        summary_cell(d, sum, sizeof(sum));
        snprintf(ifc, sizeof(ifc), "%s", d->sensor_iface[0] ? d->sensor_iface : "-");
        if ((int)strlen(ifc) > w.iface) ifc[w.iface] = '\0';
        if ((int)strlen(sum) > w.summary) {
            sum[w.summary > 1 ? w.summary - 1 : 0] = '~';
            sum[w.summary > 1 ? w.summary : 1] = '\0';
        }
        if (i == sel) tui_sel(); else if (d->hid || d->watch_cat[0]) tui_bright(); else tui_normal();
        TPRINT("%c%-17s  %c  %-*s  %4s  %6s  %4s  %-3s  %s\n",
               i == sel ? '>' : ' ', addr, type_ch(d->addr_type), w.iface,
               ifc, rssi, adv, age, fl, sum);
        tui_normal();
    }
    tui_dim();
    TPRINT(" T: P public R random p/r resolved   H HID  W watchlist  ~ one-channel sample\n");
    tui_normal();
}

void view_ble_key(sloth_state_t *s, int key) {
    if (s->ble_detail) {
        if (key == '\r' || key == '\n' || key == 27) s->ble_detail = 0;
        return;
    }
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->ble_sel > 0) s->ble_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->ble_device_count > 0 && s->ble_sel < s->ble_device_count - 1)
            s->ble_sel++;
        break;
    case '\r': case '\n':
        if (s->ble_sel >= 0 && s->ble_sel < s->ble_device_count) {
            const ble_device_t *d = &s->ble_devices[s->ble_sel];
            memcpy(s->ble_detail_addr, d->addr, 6);
            s->ble_detail_type = d->addr_type;
            memcpy(s->ble_detail_iface, d->sensor_iface,
                   sizeof(s->ble_detail_iface));
            s->ble_detail = 1;
        }
        break;
    default:
        break;
    }
}
