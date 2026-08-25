#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "oui.h"
#include "views/beacon.h"
#include "wifi_assess.h"
#include "beacon_snoop.h"

#define BEACON_PAGE 30

static char fmt_bssid[18];

static const char *bssid_str(const uint8_t *b) {
    snprintf(fmt_bssid, sizeof(fmt_bssid),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
    return fmt_bssid;
}

static const char *band_for(int ch) {
    if (ch >= 1   && ch <= 14)  return "2.4 GHz";
    if (ch >= 32  && ch <= 177) return "5 GHz";
    if (ch >= 181 && ch <= 233) return "6 GHz";
    return "?";
}

/* Full-screen detail panel for the selected AP. Triggered by Enter
 * in the beacons list; Enter/Esc returns. Renders every field we've
 * already collected for this BSSID, plus cross-references against
 * the assoc tracker and EAPOL log. Each section is annotated with
 * attacker / defender notes so the operator gets the SIGINT context
 * inline instead of cross-referencing four other views. */
static void draw_beacon_detail(const sloth_state_t *s) {
    if (s->beacon_sel < 0 || s->beacon_sel >= s->beacon_count) {
        tui_dim();
        TPRINT(" (no AP selected — press Enter to return)\n");
        return;
    }
    const beacon_ap_t *ap = &s->beacon_aps[s->beacon_sel];

    tui_dim(); TPRINT(" \xe2\x94\x80\xe2\x94\x80 AP DETAIL \xe2\x94\x80\xe2\x94\x80\n");

    /* Header: SSID + BSSID */
    if (ap->ssid[0]) tui_bright();
    else             tui_dim();
    TPRINT("  %-12s", ap->ssid[0] ? ap->ssid : "(hidden)");
    if (ap->revealed) { tui_dim(); TPRINT(" * (revealed via probe response)"); }
    TPRINT("\n");

    tui_dim();    TPRINT("  BSSID:       ");
    tui_bright(); TPRINT("%s", bssid_str(ap->bssid));
    {
        const char *oui_v = oui_lookup(ap->bssid);
        if (oui_v && oui_v[0]) {
            tui_dim();    TPRINT("   (OUI: ");
            tui_normal(); TPRINT("%s", oui_v);
            tui_dim();    TPRINT(")");
        }
    }
    TPRINT("\n");

    /* Radio */
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 RADIO \xe2\x94\x80\xe2\x94\x80\n");
    TPRINT("  Channel:     "); tui_bright();
    TPRINT("%d", ap->channel);
    tui_dim(); TPRINT("  (%s)\n", band_for(ap->channel));
    TPRINT("  Signal:      "); {
        double frac = (ap->signal_dbm + 90.0) / 60.0;
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1;
        tui_heat(frac);
    }
    TPRINT("%d dBm\n", ap->signal_dbm);
    tui_dim(); TPRINT("  Beacon intv: "); tui_normal();
    TPRINT("%u ms\n", (unsigned)ap->beacon_ms);
    tui_dim(); TPRINT("  PHY tier:    ");
    if (ap->phy[0]) tui_bright(); else tui_dim();
    TPRINT("%s\n", ap->phy[0] ? ap->phy : "?");
    tui_dim(); TPRINT("  Vendor:      ");
    if (ap->vendor[0]) tui_bright(); else tui_dim();
    TPRINT("%s\n", ap->vendor[0] ? ap->vendor : "?");

    /* Security */
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 SECURITY \xe2\x94\x80\xe2\x94\x80\n");
    TPRINT("  Encryption:  ");
    if (strcmp(ap->enc, "OPEN") == 0 || strcmp(ap->enc, "WEP") == 0)
        tui_heat(0.9);
    else if (strcmp(ap->enc, "WPA3") == 0)
        tui_bright();
    else
        tui_normal();
    TPRINT("%s\n", ap->enc);
    tui_dim(); TPRINT("  Pairwise:    "); tui_normal();
    TPRINT("%s", ap->pairwise[0] ? ap->pairwise : "-");
    if (strcmp(ap->pairwise, "TKIP") == 0) {
        tui_heat(0.7); TPRINT("   (TKIP on WPA2 — downgrade smell)");
    }
    TPRINT("\n");
    tui_dim(); TPRINT("  Group:       "); tui_normal();
    TPRINT("%s\n", ap->group[0]    ? ap->group    : "-");
    tui_dim(); TPRINT("  AKM:         "); tui_normal();
    TPRINT("%s\n", ap->akm[0]      ? ap->akm      : "-");
    tui_dim(); TPRINT("  MFP:         ");
    if (ap->mfp == 2)       { tui_bright(); TPRINT("REQUIRED"); }
    else if (ap->mfp == 1)  { tui_normal(); TPRINT("capable"); }
    else                    { tui_heat(0.7); TPRINT("off (deauth-attackable)"); }
    TPRINT("\n");
    tui_dim(); TPRINT("  WPS:         ");
    if (ap->has_wps) {
        /* AP Setup Locked overrides — locked means PIN attacks won't
         * work, so render the "interesting" coloring only when both
         * unlocked AND not configured. */
        int unlocked_unconfigured =
            (ap->wps_locked == 1 && ap->wps_state == 1);
        if (unlocked_unconfigured) tui_heat(1.0);
        else                       tui_heat(0.7);
        TPRINT("ON");
        tui_dim();
        if (ap->wps_state == 1)      TPRINT("  (NotConfigured)");
        else if (ap->wps_state == 2) TPRINT("  (Configured)");
        if (ap->wps_locked == 2)     TPRINT("  [LOCKED]");
        else if (ap->wps_locked == 1) {
            tui_heat(1.0);
            TPRINT("  [UNLOCKED — PixieDust / WPS-PIN candidate]");
        }
    } else {
        tui_normal(); TPRINT("-");
    }
    TPRINT("\n");

    /* Associated clients we've observed. */
    int my_assocs[MAX_ASSOC_ENTRIES];
    int my_assoc_n = 0;
    for (int i = 0; i < s->assoc_count; i++) {
        if (memcmp(s->assocs[i].bssid, ap->bssid, 6) == 0)
            my_assocs[my_assoc_n++] = i;
    }
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 ASSOCIATED CLIENTS (%d) \xe2\x94\x80\xe2\x94\x80\n",
           my_assoc_n);
    if (my_assoc_n == 0) {
        tui_dim();
        TPRINT("  (none observed)\n");
    } else {
        for (int j = 0; j < my_assoc_n && j < 10; j++) {
            const assoc_t *as = &s->assocs[my_assocs[j]];
            char m[20];
            snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
                     as->sta_mac[0], as->sta_mac[1], as->sta_mac[2],
                     as->sta_mac[3], as->sta_mac[4], as->sta_mac[5]);
            tui_normal(); TPRINT("  %s", m);
            tui_dim();
            if (as->sta_random)         TPRINT("  (random)");
            else {
                const char *v = oui_lookup(as->sta_mac);
                if (v && v[0]) TPRINT("  %.14s", v);
            }
            tui_dim();    TPRINT("  via ");
            if (as->source == ASSOC_SRC_EAPOL) tui_bright(); else tui_normal();
            TPRINT("%s",
                   as->source == ASSOC_SRC_EAPOL   ? "EAPOL" :
                   as->source == ASSOC_SRC_ASSOC   ? "AssocResp" :
                   as->source == ASSOC_SRC_REASSOC ? "ReassocResp" : "?");
            TPRINT("\n");
        }
        if (my_assoc_n > 10) {
            tui_dim();
            TPRINT("  ... and %d more (see [w] Assoc view)\n",
                   my_assoc_n - 10);
        }
    }

    /* 802.11k Neighbor Reports — APs this AP advertises as neighbors.
     * Useful for ESS topology mapping and for discovering BSSIDs we
     * haven't tuned to yet (off-channel). */
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 NEIGHBORS (802.11k, %d) \xe2\x94\x80\xe2\x94\x80\n",
           ap->neighbor_count);
    if (ap->neighbor_count == 0) {
        tui_dim();
        TPRINT("  (none advertised — AP doesn't emit Neighbor Report IEs)\n");
    } else {
        for (int j = 0; j < ap->neighbor_count; j++) {
            const ap_neighbor_t *n = &ap->neighbors[j];
            char m[20];
            snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
                     n->bssid[0], n->bssid[1], n->bssid[2],
                     n->bssid[3], n->bssid[4], n->bssid[5]);
            /* Is this neighbor a BSSID we've also seen directly? */
            int direct = 0;
            for (int k = 0; k < s->beacon_count; k++) {
                if (memcmp(s->beacon_aps[k].bssid, n->bssid, 6) == 0) {
                    direct = 1;
                    break;
                }
            }
            tui_normal(); TPRINT("  %s", m);
            tui_dim();    TPRINT("  ch ");
            tui_bright(); TPRINT("%d", n->channel);
            tui_dim();    TPRINT("  %s\n",
                                  direct ? "(observed directly)"
                                         : "(NOT directly seen \xe2\x80\x94 hop here)");
        }
    }

    /* Captured handshakes against this BSSID. */
    int crit = 0, pmkid = 0;
    for (int i = 0; i < s->eapol_count; i++) {
        if (memcmp(s->eapol_events[i].bssid, ap->bssid, 6) != 0) continue;
        if (s->eapol_events[i].handshake_complete) crit++;
        if (s->eapol_events[i].has_pmkid)          pmkid++;
    }
    tui_dim();
    TPRINT("\n \xe2\x94\x80\xe2\x94\x80 CAPTURED HANDSHAKES \xe2\x94\x80\xe2\x94\x80\n");
    if (crit > 0 || pmkid > 0) {
        if (pmkid > 0) { tui_heat(1.0); TPRINT("  %d PMKID capture(s)", pmkid); TPRINT("\n"); }
        if (crit > 0)  { tui_heat(1.0); TPRINT("  %d full 4-way handshake(s)", crit); TPRINT("\n"); }
        tui_dim();
        TPRINT("  See [e] EAPOL for details. --eapol-dir DIR writes "
               "hashcat 22000.\n");
    } else {
        tui_dim();
        TPRINT("  (none yet — wait for a client (re)association)\n");
    }

    tui_dim(); TPRINT("\n [Enter / Esc] back to beacons list\n");
    tui_normal();
}

void view_beacon_draw(const sloth_state_t *s) {
    if (s->beacon_detail) { draw_beacon_detail(s); return; }

#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = BEACON_PAGE;
#endif

    tui_normal(); TPRINT(" Passive beacons: ");
    tui_bright();  TPRINT("%d", s->beacon_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear");
    if (s->twin_episode_count > 0) {
        tui_dim();    TPRINT("  twin episodes: ");
        tui_bright(); TPRINT("%d", s->twin_episode_count);
        tui_dim();    TPRINT(" [x]");
    }
    if (s->probe_iface[0]) {
        tui_dim(); TPRINT("  iface: %s", s->probe_iface);
    }
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-22s  %-17s  %4s  %-7s  %-5s  %-9s  %-8s  %-10s  %-3s  %-9s  %-8s  %4s\n",
           "SSID", "BSSID", "Sig", "Ch", "Enc",
           "Pairwise", "posture", "AKM", "WPS", "Vendor", "PHY", "Last");
    TPRINT(" %-22s  %-17s  %4s  %-7s  %-5s  %-9s  %-8s  %-10s  %-3s  %-9s  %-8s  %4s\n",
           "----------------------", "-----------------",
           "----", "-------", "-----", "---------", "--------",
           "----------", "---", "---------", "--------", "----");
    tui_normal();

    if (s->beacon_count == 0) {
        tui_dim();
        TPRINT("  (no beacons seen -- waiting for 802.11 beacon frames on monitor iface)\n");
        tui_normal();
        return;
    }

    int page_top = s->beacon_sel - page / 2;
    if (page_top + page > s->beacon_count) page_top = s->beacon_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->beacon_count) page_end = s->beacon_count;

    time_t now = time(NULL);
    for (int row = page_top; row < page_end; row++) {
        const beacon_ap_t *ap = &s->beacon_aps[row];

        char ssid_display[40];
        /* Look up twin-cluster membership: '!' = chain-tainted twin
         * (attack-in-progress), '#' = vendor-IE hash mismatch detected,
         * '@' = OUI on the Hak5/Espressif attacker list, '~' = appears
         * in a twin pair as the legit "real" side. Glyphs are ASCII
         * to match the Twins view legend. */
        char twin_glyph[4] = "";
        for (int t = 0; t < s->twin_episode_count; t++) {
            const twin_episode_t *e = &s->twin_episodes[t];
            if (memcmp(e->twin_bssid, ap->bssid, 6) == 0) {
                if      (e->attack_in_progress) twin_glyph[0] = '!';
                else if (e->attacker_oui)       twin_glyph[0] = '@';
                else if (e->hash_mismatch)      twin_glyph[0] = '#';
                else                            twin_glyph[0] = '*';
                break;
            }
            if (memcmp(e->real_bssid, ap->bssid, 6) == 0) {
                twin_glyph[0] = '~';
                break;
            }
        }
        const char *gsuffix = twin_glyph[0] ? twin_glyph : "";

        if (ap->ssid[0]) {
            if (ap->revealed)
                snprintf(ssid_display, sizeof(ssid_display), "%s *%s",
                         ap->ssid, gsuffix);
            else
                snprintf(ssid_display, sizeof(ssid_display), "%s%s",
                         ap->ssid, gsuffix);
        } else {
            snprintf(ssid_display, sizeof(ssid_display), "(hidden)%s",
                     gsuffix);
        }
        const char *ssid = ssid_display;

        char sig_buf[8];
        snprintf(sig_buf, sizeof(sig_buf), "%d", ap->signal_dbm);

        int age = (int)(now - ap->last_seen);
        char age_buf[16];
        if      (age < 60)   snprintf(age_buf, sizeof(age_buf), "%ds",  age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%dm",  age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%dh",  age / 3600);

        /* Posture, not just MFP (#62). When the AP advertises a
         * downgrade lane the column names it — that is the finding, and
         * "cap" alone never conveyed it. With no downgrade the column
         * falls back to the MFP state it always showed. */
        /* Channel with its operating width (#66): "36/80" is a very
         * different amount of spectrum from "36", and sloth treated
         * every AP as 20 MHz until the operation IEs were decoded. */
        char ch_buf[10];
        if (ap->operating_width == CH_WIDTH_80P80)
            snprintf(ch_buf, sizeof(ch_buf), "%d/80+", ap->channel);
        else if (ap->operating_width)
            snprintf(ch_buf, sizeof(ch_buf), "%d/%u", ap->channel,
                     (unsigned)ap->operating_width);
        else
            snprintf(ch_buf, sizeof(ch_buf), "%d", ap->channel);

        const char *dg_s  = wifi_downgrade_column(ap->downgrade_flags);
        const char *mfp_s = dg_s ? dg_s
                          : (ap->mfp == 2) ? "REQ"
                          : (ap->mfp == 1) ? "cap" : "-";
        const char *pw    = ap->pairwise[0] ? ap->pairwise : "-";
        const char *akm   = ap->akm[0]      ? ap->akm      : "-";
        const char *wps_s = ap->has_wps ? "ON" : "-";
        const char *vend  = ap->vendor[0] ? ap->vendor : "-";
        const char *phy_s = ap->phy[0]    ? ap->phy    : "-";

        /* A pending channel switch replaces the PHY cell while it is in
         * flight (#63). It is transient and it is the more urgent fact:
         * the PHY tier will still be there after the AP has moved. */
        char phy_or_csa[12];
        if (ap->pending_csa_channel) {
            snprintf(phy_or_csa, sizeof(phy_or_csa), "CSA>%u",
                     ap->pending_csa_channel);
            phy_s = phy_or_csa;
        }

        if (row == s->beacon_sel) {
            tui_sel();
            TPRINT(" %-22.22s  %-17.17s  %4s  %-7s  %-5.5s  %-9.9s  %-8s  %-10.10s  %-3s  %-9.9s  %-8.8s  %s\n",
                   ssid, bssid_str(ap->bssid), sig_buf, ch_buf,
                   ap->enc, pw, mfp_s, akm, wps_s, vend, phy_s, age_buf);
            tui_reset();
        } else {
            /* dim hidden SSIDs */
            if (!ap->ssid[0]) tui_dim(); else tui_normal();
            TPRINT(" %-22.22s", ssid);

            tui_dim();
            TPRINT("  %-17.17s", bssid_str(ap->bssid));

            /* signal heat */
            double frac = (ap->signal_dbm + 90.0) / 60.0;  /* -90=0.0, -30=1.0 */
            tui_heat(frac);
            TPRINT("  %4s", sig_buf);

            tui_normal();
            TPRINT("  %-7s", ch_buf);

            /* enc color: OPEN/WEP dim, WPA/WPA2/WPA3 normal/bright */
            if (strcmp(ap->enc, "OPEN") == 0 || strcmp(ap->enc, "WEP") == 0)
                tui_dim();
            else if (strcmp(ap->enc, "WPA3") == 0)
                tui_bright();
            else
                tui_normal();
            TPRINT("  %-5.5s", ap->enc);

            /* pairwise cipher — TKIP is a smell on a WPA2 net */
            if (strcmp(pw, "TKIP") == 0) tui_heat(0.7);
            else                          tui_normal();
            TPRINT("  %-9.9s", pw);

            /* Posture — a named downgrade lane is heat-coloured
             * because it is the finding; otherwise the old MFP shading
             * (REQ bright, cap normal, off dim). */
            if (dg_s)                    tui_heat(0.85);
            else if (ap->mfp == 2)       tui_bright();
            else if (ap->mfp == 1)       tui_normal();
            else                         tui_dim();
            TPRINT("  %-8s", mfp_s);

            tui_normal();
            TPRINT("  %-10.10s", akm);

            /* WPS — on = heat-coloured smell (PixieDust / PIN-attack
             * vector). off = dim. */
            if (ap->has_wps) tui_heat(0.7);
            else             tui_dim();
            TPRINT("  %-3s", wps_s);

            /* Vendor — bright for known, dim "-" for unknown. */
            if (ap->vendor[0]) tui_bright();
            else                tui_dim();
            TPRINT("  %-9.9s", vend);

            /* PHY — Wi-Fi 6/7 bright, Wi-Fi 5 normal, older dim. */
            if (ap->phy[0]) {
                if (strncmp(ap->phy, "Wi-Fi 6", 7) == 0 ||
                    strncmp(ap->phy, "Wi-Fi 7", 7) == 0) tui_bright();
                else if (strncmp(ap->phy, "Wi-Fi 5", 7) == 0) tui_normal();
                else                                          tui_dim();
            } else { tui_dim(); }
            /* A pending switch overrides the PHY shading — it is the
             * transient fact and the more urgent one. */
            if (ap->pending_csa_channel) tui_heat(0.8);
            TPRINT("  %-8.8s", phy_s);

            tui_dim();
            TPRINT("  %s\n", age_buf);
            tui_normal();
        }
    }
    tui_normal();
}

void view_beacon_key(sloth_state_t *s, int key) {
    /* Detail mode swallows nav keys; Enter or Esc returns. */
    if (s->beacon_detail) {
        if (key == '\r' || key == '\n' || key == 27)
            s->beacon_detail = 0;
        else if (key == 'c' || key == 'C') {
            beacon_clear();
            s->beacon_count   = 0;
            s->beacon_sel     = 0;
            s->beacon_detail  = 0;
        }
        return;
    }

    switch (key) {
    case SLOTH_KEY_UP:
        if (s->beacon_sel > 0) s->beacon_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->beacon_count > 0 && s->beacon_sel < s->beacon_count - 1)
            s->beacon_sel++;
        break;
    case '\r': case '\n':
        if (s->beacon_count > 0) s->beacon_detail = 1;
        break;
    case 'c': case 'C':
        beacon_clear();
        s->beacon_count = 0;
        s->beacon_sel   = 0;
        break;
    default:
        break;
    }
}
