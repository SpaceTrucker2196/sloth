#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/twins.h"
/* ../ is required: src/views/alerts.h is the view header and would
 * shadow the rules header on a bare "alerts.h" from this directory.
 * Same form src/views/alerts.c already uses. */
#include "../alerts.h"
#include "../wired_attach.h"

#define TWINS_PAGE 30

static void fmt_mac(const uint8_t mac[6], char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void view_twins_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = TWINS_PAGE;
#endif

    /* Status bar */
    tui_normal(); TPRINT(" Evil-twin episodes: ");
    tui_bright(); TPRINT("%d", s->twin_episode_count);
    tui_dim();    TPRINT(" / max %d", MAX_TWIN_EPISODES);
    int in_progress = 0;
    for (int i = 0; i < s->twin_episode_count; i++) {
        if (s->twin_episodes[i].attack_in_progress) in_progress++;
    }
    if (in_progress > 0) {
        tui_dim();    TPRINT("  attack-in-progress: ");
        tui_bright(); TPRINT("%d", in_progress);
    }
    /* Whether anything is even looking at the wire (#89 slice 3). A
     * Wired column full of `?` reads very differently depending on the
     * answer: "nobody asked" is not "nothing found", and an operator
     * who cannot tell those apart will eventually read the first as the
     * second. */
    tui_dim();    TPRINT("  wired correlation: ");
    tui_bright(); TPRINT("%s", wired_attach_have_correlator()
                               ? "active" : "none");
    TPRINT("\n");

    /* Column headers — fixed widths: SSID 18 | A 17 | B 17 |
     * enc 6 | conf 4 | class 8 | wired 5 | swing 5 | flags 6 | last
     *
     * "BSSID A / B" rather than "Real / Twin" (#89). On a `?`-flagged
     * row nothing has established which half is the impostor and the
     * two columns are only the pair in canonical order — heading them
     * "Real" and "Twin" made the table state a verdict sloth does not
     * have. An attributed row says so by *not* carrying the `?`.
     *
     * Class and Wired are two columns rather than one (#89 slice 3)
     * because they answer questions with different evidence
     * requirements. Class is decidable from RF plus the approved
     * inventory. Wired attachment is not decidable from RF at all, so
     * it can never be filled in by anything in this view's data path —
     * separating them is what keeps "impostor" from being read as
     * "rogue on our LAN". */
    tui_dim();
    TPRINT(" %-18s  %-17s  %-17s  %-6s  %-4s  %-8s  %-5s  %-5s  %-6s  %s\n",
           "SSID", "BSSID A", "BSSID B", "Cipher", "Conf", "Class",
           "Wired", "Swing", "Flags", "Last");
    TPRINT(" %-18s  %-17s  %-17s  %-6s  %-4s  %-8s  %-5s  %-5s  %-6s  %s\n",
           "------------------",
           "-----------------",
           "-----------------",
           "------", "----", "--------", "-----", "-----", "------", "----");
    tui_normal();

    if (s->twin_episode_count == 0) {
        tui_dim();
        TPRINT("  (no twin pairs observed — sloth needs at least two same-SSID,\n"
               "   same-cipher beacons plus some positive impersonation\n"
               "   evidence to record one.)\n");
        tui_normal();
        return;
    }

    int top = s->twin_episode_sel - page / 2;
    if (top + page > s->twin_episode_count) top = s->twin_episode_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->twin_episode_count) end = s->twin_episode_count;

    for (int row = top; row < end; row++) {
        const twin_episode_t *e = &s->twin_episodes[row];
        char real_mac[20], twin_mac[20], swing[8], flags[8], conf[8];
        fmt_mac(e->real_bssid, real_mac, sizeof(real_mac));
        fmt_mac(e->twin_bssid, twin_mac, sizeof(twin_mac));
        if (e->rssi_swing_dbm) snprintf(swing, sizeof(swing), "%udB", e->rssi_swing_dbm);
        else                   snprintf(swing, sizeof(swing), "-");
        /* Confidence, not severity (#89) — how likely the pair is an
         * impersonation, which the alert row's colour does not tell you. */
        if (e->confidence) snprintf(conf, sizeof(conf), "%u%%", e->confidence);
        else               snprintf(conf, sizeof(conf), "-");
        /* The two pair axes (#89 slice 3). Both render their unknown as
         * a literal `?` rather than a blank: an empty cell invites the
         * reader to supply their own answer, and on the Wired column
         * the answer they supply is usually the alarming one. */
        const char *cls_s   = twin_class_label((twin_class_t)e->ap_class);
        const char *wired_s =
            wired_attach_label((wired_attach_t)e->wired_attach);
        /* Flag glyphs (ASCII for portability):
         *   ! = attack-in-progress (deauth-fed chain CRIT)
         *   * = attacker-tool OUI (Hak5 / Espressif)
         *   # = vendor-IE hash mismatch
         *   ? = unattributed — candidate pair, neither half accused */
        int  fi = 0;
        if (e->attack_in_progress) flags[fi++] = '!';
        if (e->attacker_oui)       flags[fi++] = '*';
        if (e->hash_mismatch)      flags[fi++] = '#';
        if (!e->attributed)        flags[fi++] = '?';
        flags[fi] = '\0';
        if (!flags[0]) snprintf(flags, sizeof(flags), "-");

        char age[12];
        time_t now = time(NULL);
        if (e->last_seen == 0) snprintf(age, sizeof(age), "?");
        else snprintf(age, sizeof(age), "%lds", (long)(now - e->last_seen));

#ifdef WITH_NCURSES
        if (row == s->twin_episode_sel) {
            tui_sel();
            printw(" %-18.18s  %-17s  %-17s  %-6.6s  %-4s  %-8.8s  %-5.5s"
                   "  %-5s  %-6s  %s\n",
                   e->ssid, real_mac, twin_mac, e->enc, conf, cls_s, wired_s,
                   swing, flags, age);
            tui_reset();
        } else {
            tui_bright(); printw(" %-18.18s", e->ssid);
            tui_dim();    printw("  %-17s", real_mac);
            /* Bright on the B column only when the pair is attributed —
             * there it really is the suspected rogue. On an
             * unattributed pair the two halves are peers and colouring
             * one of them would accuse whichever BSSID sorted higher. */
            if (e->attributed) tui_bright(); else tui_dim();
            printw("  %-17s", twin_mac);
            tui_dim();    printw("  %-6.6s", e->enc);
            tui_normal(); printw("  %-4s", conf);
            /* Bright only on a class that names an impersonator. A
             * `neighbor` or `declared` row is the detector saying "not
             * your problem" and should not compete for attention. */
            if (e->ap_class == (uint8_t)TWIN_CLASS_IMPERSONATOR) tui_bright();
            else                                                 tui_dim();
            printw("  %-8.8s", cls_s);
            /* Never bright on `?`, which is every row until a
             * correlator exists: highlighting a column sloth has no
             * answer for would advertise the absence as a finding. */
            if (e->wired_attach == (uint8_t)WIRED_ATTACH_ATTACHED) tui_bright();
            else                                                   tui_dim();
            printw("  %-5.5s", wired_s);
            tui_normal(); printw("  %-5s", swing);
            if (e->attack_in_progress) tui_bright(); else tui_dim();
            printw("  %-6s", flags);
            tui_dim();    printw("  %s\n", age);
            tui_normal();
        }
#else
        if (row == s->twin_episode_sel) {
            tui_sel();
            printf(" %-18.18s  %-17s  %-17s  %-6.6s  %-4s  %-8.8s  %-5.5s"
                   "  %-5s  %-6s  %s",
                   e->ssid, real_mac, twin_mac, e->enc, conf, cls_s, wired_s,
                   swing, flags, age);
            tui_reset(); printf("\n");
        } else {
            tui_bright(); printf(" %-18.18s", e->ssid);
            tui_dim();    printf("  %-17s", real_mac);
            if (e->attributed) tui_bright(); else tui_dim();
            printf("  %-17s", twin_mac);
            tui_dim();    printf("  %-6.6s", e->enc);
            tui_normal(); printf("  %-4s", conf);
            if (e->ap_class == (uint8_t)TWIN_CLASS_IMPERSONATOR) tui_bright();
            else                                                 tui_dim();
            printf("  %-8.8s", cls_s);
            if (e->wired_attach == (uint8_t)WIRED_ATTACH_ATTACHED) tui_bright();
            else                                                   tui_dim();
            printf("  %-5.5s", wired_s);
            tui_normal(); printf("  %-5s", swing);
            if (e->attack_in_progress) tui_bright(); else tui_dim();
            printf("  %-6s", flags);
            tui_dim();    printf("  %s\n", age);
            tui_normal();
        }
#endif
    }
    tui_normal();

    /* Legend */
    tui_dim();
    TPRINT(" flags: ! attack-in-progress  * attacker OUI  # vendor-IE hash mismatch\n");
    TPRINT("        ? sides unattributed - candidate pair, neither half accused\n");
    /* The three categories #89 asked the UI to separate, and the one it
     * asked the UI not to assert. */
    TPRINT(" class: impostor over-the-air impersonation  neighbor outside the declared\n");
    TPRINT("        estate  declared both halves in the approved inventory  ? no inventory\n");
    TPRINT(" wired: ? not established - RF cannot show what a radio is plugged into;\n");
    TPRINT("        needs controller/switch/DHCP correlation%s\n",
           wired_attach_have_correlator() ? "" : " (none registered)");
    tui_normal();
}

void view_twins_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->twin_episode_sel > 0) s->twin_episode_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->twin_episode_count > 0 &&
            s->twin_episode_sel < s->twin_episode_count - 1)
            s->twin_episode_sel++;
        break;
    default:
        break;
    }
}
