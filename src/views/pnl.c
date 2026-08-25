#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "oui.h"
#include "filter.h"
#include "views/pnl.h"

/* PNL view: per-MAC Preferred Network List.
 *
 * Each row is one client (identified by MAC) with the list of SSIDs
 * that device has probed for since launch. The PNL fingerprints the
 * device's owner — it's the list of every prior workplace / hotel /
 * home WiFi network the device has connected to.
 *
 * Randomized MACs (locally-administered bit) get a dim "(random)"
 * vendor stamp; real (burned-in) MACs get their OUI vendor. The
 * count badge shows how many unique SSIDs we've seen this device
 * probe for; the SSID list itself is rendered in the same hash-
 * palette colours used elsewhere so the same SSID lights up the
 * same colour across panels. */

static void fmt_mac(const uint8_t *mac, char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void fmt_age(time_t last_seen, char *buf, int sz) {
    long age = (long)(time(NULL) - last_seen);
    if (age < 0)     age = 0;
    if (age > 99999) age = 99999;   /* clamp so the buffer (8 bytes) suffices */
    if      (age <   60) snprintf(buf, sz, "%lds", age);
    else if (age < 3600) snprintf(buf, sz, "%ldm", age / 60);
    else                 snprintf(buf, sz, "%ldh", age / 3600);
}

void view_pnl_draw(const sloth_state_t *s) {
    int rand_n = 0, real_n = 0;
    for (int i = 0; i < s->pnl_count; i++) {
        if (s->pnl_clients[i].mac_random) rand_n++; else real_n++;
    }

    tui_normal(); TPRINT(" PNL clients: ");
    tui_bright(); TPRINT("%d", s->pnl_count);
    tui_dim();    TPRINT(" (");
    tui_normal(); TPRINT("%d real", real_n);
    tui_dim();    TPRINT(" / ");
    tui_normal(); TPRINT("%d randomized", rand_n);
    tui_dim();    TPRINT(")  [up/dn] navigate  [c] clear");
    tui_filter_status(s);
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-17s  %-14s  %-8s  %-8s  %-3s  %-4s  %-4s  %s\n",
           "MAC", "vendor", "OS", "PHY", "#", "age", "hits",
           "preferred networks");
    TPRINT(" %-17s  %-14s  %-8s  %-8s  %-3s  %-4s  %-4s  %s\n",
           "-----------------", "--------------", "--------",
           "--------", "---", "----", "----",
           "----------------------------------------");
    tui_normal();

    if (s->pnl_count == 0) {
        tui_dim();
        TPRINT("  (no directed probes observed yet — wildcard probes "
               "don't count toward the PNL)\n");
        if (s->probe_iface[0]) {
            TPRINT("  Monitoring on ");
            tui_bright(); TPRINT("%s", s->probe_iface); tui_dim();
            TPRINT(" — PNLs build as clients re-scan for known networks.\n");
        } else {
            TPRINT("  No monitor-mode iface available. Set one up first.\n");
        }
        tui_normal();
        return;
    }

    for (int i = 0; i < s->pnl_count; i++) {
        const pnl_client_t *c = &s->pnl_clients[i];
        if (s->filter[0]) {
            /* Match against any SSID in the client's list + the MAC. */
            char mac_buf[20]; fmt_mac(c->mac, mac_buf, sizeof(mac_buf));
            int matched = filter_match_any(s->filter, mac_buf, NULL,
                                           NULL, NULL, NULL);
            for (int j = 0; !matched && j < c->ssid_count; j++)
                matched = filter_match_any(s->filter, c->ssids[j],
                                            NULL, NULL, NULL, NULL);
            if (!matched) continue;
        }

        char mac_buf[20]; fmt_mac(c->mac, mac_buf, sizeof(mac_buf));
        char age_buf[8];  fmt_age(c->last_seen, age_buf, sizeof(age_buf));

        if (i == s->pnl_sel) tui_sel(); else tui_normal();
        TPRINT(" %-17s  ", mac_buf);

        /* Vendor column — dim "(random)" for randomized MACs, bright
         * OUI lookup for real ones. */
        if (c->mac_random) {
            tui_dim();    TPRINT("%-14s", "(random)");
        } else {
            const char *v = oui_lookup(c->mac);
            if (!v || !v[0]) { tui_dim(); v = "?"; }
            else             { tui_bright(); }
            TPRINT("%-14.14s", v);
        }

        /* OS fingerprint — bright if we have one, dim "?" if not. */
        if (c->os_fp[0]) { tui_bright(); TPRINT("  %-8.8s", c->os_fp); }
        else             { tui_dim();    TPRINT("  %-8s",  "?"); }

        /* PHY tier — Wi-Fi 6+ bright, Wi-Fi 5 normal, older dim.
         *
         * A trailing '*' marks a tier confirmed by an association
         * request rather than inferred from a probe (#60). Probes are
         * the weaker evidence: clients send stripped-down variants that
         * omit VHT/HE while scanning, so an unmarked tier is a floor,
         * not a measurement. */
        if (c->phy[0]) {
            if (strncmp(c->phy, "Wi-Fi 6", 7) == 0 ||
                strncmp(c->phy, "Wi-Fi 7", 7) == 0) tui_bright();
            else if (strncmp(c->phy, "Wi-Fi 5", 7) == 0) tui_normal();
            else                                          tui_dim();
            char phy_buf[12];
            snprintf(phy_buf, sizeof(phy_buf), "%s%s", c->phy,
                     c->phy_confirmed ? "*" : "");
            TPRINT("  %-8.8s", phy_buf);
        } else {
            tui_dim(); TPRINT("  %-8s", "?");
        }

        if (i == s->pnl_sel) tui_sel(); else tui_normal();
        TPRINT("  %-3d", c->ssid_count);
        tui_dim();    TPRINT("  %-4s", age_buf);
        tui_bright(); TPRINT("  %-4d", c->probe_count);

        /* SSID list — render each in the same hash palette used by
         * the WiFi panel so the SSID lights up the same colour
         * everywhere. Comma-separated, on the same line. */
        TPRINT("  ");
        for (int j = 0; j < c->ssid_count; j++) {
            if (j > 0) { tui_dim(); TPRINT(", "); }
#ifdef WITH_NCURSES
            tui_ssid_addstr(c->ssids[j], 0 /* PKT_CAT_OTHER */);
#else
            if (i == s->pnl_sel) tui_sel(); else tui_normal();
            TPRINT("%s", c->ssids[j]);
#endif
        }
        tui_reset();
        TPRINT("\n");
    }
    tui_normal();
}

void view_pnl_key(sloth_state_t *s, int key) {
    extern void probe_pnl_clear(void);
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->pnl_sel > 0) s->pnl_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->pnl_count > 0 && s->pnl_sel < s->pnl_count - 1)
            s->pnl_sel++;
        break;
    case 'c': case 'C':
        probe_pnl_clear();
        s->pnl_count = 0;
        s->pnl_sel   = 0;
        break;
    default:
        break;
    }
}
