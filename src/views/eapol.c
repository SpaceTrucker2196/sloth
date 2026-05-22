#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "eapol_log.h"
#include "views/eapol.h"

/* VIEW_EAPOL — surfaces captured EAPOL-Key frames and the
 * 4-way handshake state machine. Each row is one frame; rows with
 * has_pmkid=1 or handshake_complete=1 are the SIGINT prizes (offline
 * crackable). The view is newest-first. */

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

void view_eapol_draw(const sloth_state_t *s) {
    int pmkid_n = 0, hs_complete = 0;
    for (int i = 0; i < s->eapol_count; i++) {
        if (s->eapol_events[i].has_pmkid)          pmkid_n++;
        if (s->eapol_events[i].handshake_complete) hs_complete++;
    }

    tui_normal(); TPRINT(" EAPOL events: ");
    tui_bright(); TPRINT("%d", s->eapol_count);
    tui_dim();    TPRINT(" (");
    if (pmkid_n > 0)     { tui_heat(1.0); TPRINT("%d PMKID", pmkid_n); }
    else                 { tui_dim();      TPRINT("0 PMKID"); }
    tui_dim();    TPRINT(" / ");
    if (hs_complete > 0) { tui_heat(1.0); TPRINT("%d full handshake", hs_complete); }
    else                 { tui_dim();      TPRINT("0 full handshake"); }
    tui_dim();    TPRINT(")  [up/dn] navigate  [c] clear\n");

    tui_dim();
    TPRINT(" %-8s  %-3s  %-17s  %-20s  %-17s  %3s  %4s  %s\n",
           "age", "msg", "BSSID", "SSID", "STA", "ch", "sig", "notes");
    TPRINT(" %-8s  %-3s  %-17s  %-20s  %-17s  %3s  %4s  %s\n",
           "--------", "---", "-----------------", "--------------------",
           "-----------------", "---", "----", "----------------------");
    tui_normal();

    if (s->eapol_count == 0) {
        tui_dim();
        if (s->probe_iface[0]) {
            TPRINT("  Monitoring on ");
            tui_bright(); TPRINT("%s", s->probe_iface); tui_dim();
            TPRINT(" — waiting for a WPA2/WPA3 (re)association.\n");
            TPRINT("  Pass --eapol-dir DIR on the CLI to stream captures "
                   "to hashcat 22000 format.\n");
        } else {
            TPRINT("  (no monitor-mode iface available)\n");
            if (s->probe_err[0])
                TPRINT("  Detail: %s\n", s->probe_err);
            TPRINT("  Set one up first:  sudo iw dev <iface> set type monitor "
                   "&& sudo ip link set <iface> up\n");
        }
        tui_normal();
        return;
    }

    for (int i = 0; i < s->eapol_count; i++) {
        const eapol_event_t *e = &s->eapol_events[i];
        char bssid_buf[20], sta_buf[20], age_buf[8];
        fmt_mac(e->bssid,   bssid_buf, sizeof(bssid_buf));
        fmt_mac(e->sta_mac, sta_buf,   sizeof(sta_buf));
        fmt_age(e->ts,      age_buf,   sizeof(age_buf));

        int prize = e->has_pmkid || e->handshake_complete;

        if (i == s->eapol_sel)   tui_sel();
        else if (prize)          tui_heat(1.0);
        else                     tui_normal();
        TPRINT(" %-8s", age_buf);

        tui_dim();    TPRINT("  M%d ", e->msg_num);
        if (i == s->eapol_sel) tui_sel();
        else if (prize)        tui_heat(1.0);
        else                   tui_normal();
        TPRINT(" %-17s  ", bssid_buf);
#ifdef WITH_NCURSES
        /* SSID coloured by hash like elsewhere; dim "(?)" when we
         * haven't seen its beacon yet. */
        if (e->ssid[0]) {
            char buf[24];
            snprintf(buf, sizeof(buf), "%-20.20s", e->ssid);
            tui_ssid_addstr(buf, 0 /* PKT_CAT_OTHER */);
        } else {
            tui_dim(); TPRINT("%-20s", "(?)");
        }
#else
        if (e->ssid[0]) TPRINT("%-20.20s", e->ssid);
        else            TPRINT("%-20s",    "(?)");
#endif
        if (i == s->eapol_sel) tui_sel();
        else if (prize)        tui_heat(1.0);
        else                   tui_normal();
        TPRINT("  %-17s", sta_buf);
        tui_dim();    TPRINT("  %3d  %4d  ", e->channel, e->signal_dbm);

        if (e->has_pmkid && e->handshake_complete) {
            tui_heat(1.0); TPRINT("PMKID + full handshake");
        } else if (e->has_pmkid) {
            tui_heat(1.0); TPRINT("PMKID (offline-crackable M1)");
        } else if (e->handshake_complete) {
            tui_heat(1.0); TPRINT("4-way handshake captured");
        } else {
            switch (e->msg_num) {
            case 1: tui_normal(); TPRINT("M1: AP advertised ANonce"); break;
            case 2: tui_normal(); TPRINT("M2: STA replied (need M1 for cracking)"); break;
            case 3: tui_dim();    TPRINT("M3: post-association"); break;
            case 4: tui_dim();    TPRINT("M4: confirmation"); break;
            default: tui_dim();   TPRINT("?"); break;
            }
        }
        tui_reset();
        TPRINT("\n");
    }
    tui_normal();
}

void view_eapol_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->eapol_sel > 0) s->eapol_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->eapol_count > 0 && s->eapol_sel < s->eapol_count - 1)
            s->eapol_sel++;
        break;
    case 'c': case 'C':
        eapol_clear();
        s->eapol_count = 0;
        s->eapol_sel   = 0;
        break;
    default:
        break;
    }
}
