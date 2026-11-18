#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "eapol_log.h"
#include "harvest_track.h"
#include "views/eapol.h"

/* VIEW_EAPOL — surfaces captured EAPOL-Key frames and the
 * 4-way handshake state machine. Each row is one frame; rows with
 * has_pmkid=1 or handshake_complete=1 are the SIGINT prizes (offline
 * crackable). The view is newest-first.
 *
 * The `clust` column is the harvest tracker's cluster the frame was
 * counted in (#172, eapol_event_t.harvest_cluster_id), heat-coloured
 * while that cluster is a finding: a station row with an M1 left
 * unanswered, or a deauth-then-reconnect chain. [g] on a row with a
 * cluster shows that cluster's rows alone under a one-line summary;
 * [g] again shows every row. The group is view-local display state, so
 * it lives here and not in sloth_state_t. */

static uint32_t g_group;     /* 0 = every row */

uint32_t view_eapol_group(void) { return g_group; }
void     view_eapol_group_reset(void) { g_group = 0; }

/* Is cluster `id` a finding in this poll's harvest tables? */
static int cluster_is_finding(const sloth_state_t *s, uint32_t id) {
    const harvest_sta_t *h = harvest_find_sta_cluster(s, id);
    if (h && h->unanswered > 0) return 1;
    return harvest_find_chain_cluster(s, id) != NULL;
}

static int row_shown(const eapol_event_t *e) {
    return g_group == 0 || e->harvest_cluster_id == g_group;
}

static uint32_t beacon_akm(const sloth_state_t *s, const uint8_t bssid[6]) {
    for (int i = 0; i < s->beacon_count; i++)
        if (memcmp(s->beacon_aps[i].bssid, bssid, 6) == 0)
            return s->beacon_aps[i].akm_bits;
    return 0;
}

static void fmt_span(long secs, char *buf, int sz) {
    if (secs < 0) secs = 0;
    if      (secs <   60) snprintf(buf, sz, "%lds", secs);
    else if (secs < 3600) snprintf(buf, sz, "%ldm%02lds", secs / 60, secs % 60);
    else                  snprintf(buf, sz, "%ldh%02ldm", secs / 3600,
                                   (secs % 3600) / 60);
}

static void fmt_mac(const uint8_t *m, char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void fmt_age(time_t ts, char *buf, int sz) {
    long age = (long)(sloth_wall() - ts);
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
    tui_dim();    TPRINT(")  [up/dn] navigate  [g] group cluster  [c] clear\n");
    if (s->eapol_export_failures > 0) {
        tui_heat(1.0);
        TPRINT(" --eapol-dir export failing (%d): %s\n",
               s->eapol_export_failures, s->eapol_export_err);
        tui_normal();
    }

    /* The selected frame's AP posture (#172): an AP heard handing the
     * PMKID KDE to a station in M1 hands it to a harvester too. */
    if (s->eapol_count > 0 && s->eapol_sel >= 0 &&
        s->eapol_sel < s->eapol_count) {
        const eapol_event_t *e = &s->eapol_events[s->eapol_sel];
        int hp = harvest_posture_psk(e->bssid, beacon_akm(s, e->bssid));
        if (hp >= 0) {
            char b[20];
            fmt_mac(e->bssid, b, sizeof(b));
            if (hp == 1) {
                tui_heat(0.7);
                TPRINT(" AP %s: harvest-friendly - sends the PMKID KDE in "
                       "M1 to any station that associates, PSK AKM\n", b);
            } else {
                tui_dim();
                TPRINT(" AP %s: sends the PMKID KDE in M1; no PSK AKM on "
                       "its beacon, so not a passphrase target\n", b);
            }
            tui_normal();
        }
    }

    /* [g]: the cluster's one-line summary, from its rows in the ring. */
    if (g_group) {
        uint8_t stas[MAX_EAPOL_EVENTS][6], bss[MAX_EAPOL_EVENTS][6];
        int n_sta = 0, n_bss = 0, pmk = 0, rows = 0;
        time_t t0 = 0, t1 = 0;
        for (int i = 0; i < s->eapol_count; i++) {
            const eapol_event_t *e = &s->eapol_events[i];
            if (e->harvest_cluster_id != g_group) continue;
            rows++;
            if (e->has_pmkid && e->msg_num == 1) pmk++;
            if (!t0 || e->ts < t0) t0 = e->ts;
            if (e->ts > t1) t1 = e->ts;
            int k;
            for (k = 0; k < n_sta; k++)
                if (!memcmp(stas[k], e->sta_mac, 6)) break;
            if (k == n_sta) memcpy(stas[n_sta++], e->sta_mac, 6);
            for (k = 0; k < n_bss; k++)
                if (!memcmp(bss[k], e->bssid, 6)) break;
            if (k == n_bss) memcpy(bss[n_bss++], e->bssid, 6);
        }
        tui_bright();
        TPRINT(" cluster #%u", (unsigned)g_group);
        tui_normal();
        if (rows == 0) {
            TPRINT(": no rows left in the ring  [g] all rows\n");
        } else {
            char who[20], span[48];
            fmt_span((long)(t1 - t0), span, sizeof(span));
            if (n_sta == 1) {
                fmt_mac(stas[0], who, sizeof(who));
                TPRINT(": STA %s, %d BSSID%s", who, n_bss,
                       n_bss == 1 ? "" : "s");
            } else {
                fmt_mac(bss[0], who, sizeof(who));
                TPRINT(": %d stations, %d BSSID%s%s%s", n_sta, n_bss,
                       n_bss == 1 ? "" : "s", n_bss == 1 ? " " : "",
                       n_bss == 1 ? who : "");
            }
            TPRINT(", %d PMKID, %s, %d rows", pmk, span, rows);
            const harvest_sta_t   *h = harvest_find_sta_cluster(s, g_group);
            const harvest_chain_t *c = harvest_find_chain_cluster(s, g_group);
            if (h && h->unanswered > 0) {
                tui_heat(1.0);
                TPRINT(" - %d of %d M1s unanswered", h->unanswered,
                       h->m1_bssids);
            } else if (c) {
                tui_heat(1.0);
                TPRINT(" - %d victims after %d deauths", c->victims,
                       c->deauth_frames);
            }
            if ((h && h->qevict > 0) || (c && c->qevict > 0)) {
                tui_heat(1.0);
                TPRINT(" - QUEUE_EVICT on the same pair");
            }
            tui_dim();
            TPRINT("  [g] all rows\n");
        }
        tui_normal();
    }

    tui_dim();
    TPRINT(" %-8s  %-3s  %-17s  %-20s  %-17s  %3s  %4s  %-6s  %s\n",
           "age", "msg", "BSSID", "SSID", "STA", "ch", "sig", "clust", "notes");
    TPRINT(" %-8s  %-3s  %-17s  %-20s  %-17s  %3s  %4s  %-6s  %s\n",
           "--------", "---", "-----------------", "--------------------",
           "-----------------", "---", "----", "------",
           "----------------------");
    tui_normal();

    if (s->eapol_count == 0) {
        tui_dim();
        if (s->probe_iface[0]) {
            TPRINT("  Monitoring on ");
            tui_bright(); TPRINT("%s", s->probe_iface); tui_dim();
            TPRINT(" — waiting for a WPA2/WPA3 (re)association.\n");
            TPRINT("  --eapol-dir DIR streams captures to "
                   "DIR/eapol.22000 (hashcat -m 22000)\n");
            TPRINT("    plus a per-handshake DIR/<bssid>_<sta>.pcap "
                   "for aircrack-ng / Wireshark.\n");
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
        if (!row_shown(e)) continue;
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
        if (e->harvest_cluster_id) {
            char cl[12];
            snprintf(cl, sizeof(cl), "#%u", (unsigned)e->harvest_cluster_id);
            if (cluster_is_finding(s, e->harvest_cluster_id)) tui_heat(1.0);
            TPRINT("%-6s  ", cl);
            tui_dim();
        } else {
            TPRINT("%-6s  ", "-");
        }

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
        /* Grouped, the cursor moves between the cluster's rows only. */
        for (int i = s->eapol_sel - 1; i >= 0; i--)
            if (row_shown(&s->eapol_events[i])) { s->eapol_sel = i; break; }
        break;
    case SLOTH_KEY_DOWN:
        for (int i = s->eapol_sel + 1; i < s->eapol_count; i++)
            if (row_shown(&s->eapol_events[i])) { s->eapol_sel = i; break; }
        break;
    case 'g': case 'G':
        if (g_group) {
            g_group = 0;
        } else if (s->eapol_sel >= 0 && s->eapol_sel < s->eapol_count) {
            /* A row the tracker counted nowhere has no cluster to show. */
            g_group = s->eapol_events[s->eapol_sel].harvest_cluster_id;
        }
        break;
    case 'c': case 'C':
        eapol_clear();
        s->eapol_count = 0;
        s->eapol_sel   = 0;
        g_group        = 0;
        break;
    default:
        break;
    }
}
