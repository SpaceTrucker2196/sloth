#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "oui.h"
#include "assoc_track.h"
#include "views/assoc.h"

/* VIEW_ASSOC — STA <-> AP association tracker.
 *
 * One row per (BSSID, STA) pair we've observed evidence for: completed
 * EAPOL handshake, assoc-response status=0, or reassoc-response
 * status=0. Disassoc / deauth removes the row. Answers "who is on
 * which WiFi network right now?" — useful for tracking who's roamed
 * onto a target AP or evaluating which clients are exposed to the
 * same network's auth crypto. */

static void fmt_mac(const uint8_t *m, char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void fmt_age(time_t ts, char *buf, int sz) {
    long age = (long)(time(NULL) - ts);
    if (age < 0)     age = 0;
    if (age > 99999) age = 99999;
    if      (age <   60) snprintf(buf, sz, "%lds", age);
    else if (age < 3600) snprintf(buf, sz, "%ldm", age / 60);
    else                 snprintf(buf, sz, "%ldh", age / 3600);
}

static const char *src_label(int s) {
    switch (s) {
    case ASSOC_SRC_EAPOL:   return "EAPOL";
    case ASSOC_SRC_ASSOC:   return "AssocResp";
    case ASSOC_SRC_REASSOC: return "ReassocResp";
    default:                return "?";
    }
}

void view_assoc_draw(const sloth_state_t *s) {
    tui_normal(); TPRINT(" Associated clients: ");
    tui_bright(); TPRINT("%d", s->assoc_count);
    tui_dim();    TPRINT("  [up/dn] navigate  [c] clear\n");

    tui_dim();
    TPRINT(" %-17s  %-20s  %-17s  %-14s  %3s  %3s  %4s  %-11s  %4s\n",
           "BSSID", "SSID", "STA", "vendor", "ch", "rnd", "sig", "via", "age");
    TPRINT(" %-17s  %-20s  %-17s  %-14s  %3s  %3s  %4s  %-11s  %4s\n",
           "-----------------", "--------------------",
           "-----------------", "--------------",
           "---", "---", "----", "-----------", "----");
    tui_normal();

    if (s->assoc_count == 0) {
        tui_dim();
        if (s->probe_iface[0]) {
            TPRINT("  Monitoring on ");
            tui_bright(); TPRINT("%s", s->probe_iface); tui_dim();
            TPRINT(" — associations appear on EAPOL completion / assoc-response.\n");
        } else {
            TPRINT("  (no monitor-mode iface available)\n");
        }
        tui_normal();
        return;
    }

    for (int i = 0; i < s->assoc_count; i++) {
        const assoc_t *a = &s->assocs[i];
        char bssid_buf[20], sta_buf[20], age_buf[8];
        fmt_mac(a->bssid,   bssid_buf, sizeof(bssid_buf));
        fmt_mac(a->sta_mac, sta_buf,   sizeof(sta_buf));
        fmt_age(a->last_seen, age_buf, sizeof(age_buf));

        if (i == s->assoc_sel) tui_sel(); else tui_normal();
        TPRINT(" %-17s  ", bssid_buf);

#ifdef WITH_NCURSES
        if (a->ssid[0]) {
            char b[24];
            snprintf(b, sizeof(b), "%-20.20s", a->ssid);
            tui_ssid_addstr(b, 0);
        } else {
            tui_dim(); TPRINT("%-20s", "(?)");
        }
#else
        if (a->ssid[0]) TPRINT("%-20.20s", a->ssid);
        else            TPRINT("%-20s",    "(?)");
#endif

        if (i == s->assoc_sel) tui_sel(); else tui_normal();
        TPRINT("  %-17s  ", sta_buf);

        /* Vendor — dim for random/unknown, bright for known OUI. */
        if (a->sta_random) {
            tui_dim();    TPRINT("%-14s", "(random)");
        } else {
            const char *v = oui_lookup(a->sta_mac);
            if (!v || !v[0]) { tui_dim(); v = "?"; } else { tui_bright(); }
            TPRINT("%-14.14s", v);
        }

        tui_dim();
        TPRINT("  %3d  %-3s  %4d  ", a->channel,
               a->sta_random ? "Y" : "-", a->signal_dbm);

        /* via — EAPOL is the strongest signal, brighten it. */
        if (a->source == ASSOC_SRC_EAPOL) tui_bright();
        else                              tui_normal();
        TPRINT("%-11s", src_label(a->source));

        tui_dim();
        TPRINT("  %-4s\n", age_buf);
        tui_reset();
    }
    tui_normal();
}

void view_assoc_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->assoc_sel > 0) s->assoc_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->assoc_count > 0 && s->assoc_sel < s->assoc_count - 1)
            s->assoc_sel++;
        break;
    case 'c': case 'C':
        assoc_clear();
        s->assoc_count = 0;
        s->assoc_sel   = 0;
        break;
    default:
        break;
    }
}
