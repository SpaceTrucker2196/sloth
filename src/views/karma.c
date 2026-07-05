#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/karma.h"

#define KARMA_PAGE 30

static void fmt_mac(const uint8_t mac[6], char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void view_karma_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = KARMA_PAGE;
#endif

    /* Status bar */
    tui_normal(); TPRINT(" KARMA/PineAP candidates: ");
    tui_bright(); TPRINT("%d", s->karma_count);
    tui_dim();    TPRINT(" / max %d", MAX_KARMA_APS);
    int chained = 0;
    for (int i = 0; i < s->karma_count; i++)
        if (s->karma_aps[i].deauth_chain) chained++;
    if (chained > 0) {
        tui_dim();    TPRINT("  deauth-then-lure: ");
        tui_bright(); TPRINT("%d", chained);
    }
    TPRINT("\n");

    /* Columns — BSSID 17 | SSIDs 5 | PNL 4 | J% 4 | chain 5 | score 5 | SSID */
    tui_dim();
    TPRINT(" %-17s  %-5s  %-4s  %-4s  %-5s  %-5s  %s\n",
           "BSSID", "SSIDs", "PNL", "J%", "chain", "score", "Top SSID / last");
    TPRINT(" %-17s  %-5s  %-4s  %-4s  %-5s  %-5s  %s\n",
           "-----------------", "-----", "----", "----", "-----", "-----",
           "---------------");
    tui_normal();

    if (s->karma_count == 0) {
        tui_dim();
        TPRINT("  (no KARMA candidates — sloth needs one BSSID beaconing >=%d\n"
               "   distinct SSIDs. Start monitor capture and give it time.)\n",
               3);
        tui_normal();
        return;
    }

    int top = s->karma_sel - page / 2;
    if (top + page > s->karma_count) top = s->karma_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->karma_count) end = s->karma_count;

    time_t now = time(NULL);
    for (int row = top; row < end; row++) {
        const karma_ap_t *k = &s->karma_aps[row];
        char bssid[20], chain[6], age[12], last[48], jac[6];
        fmt_mac(k->bssid, bssid, sizeof(bssid));
        snprintf(chain, sizeof(chain), "%s", k->deauth_chain ? "YES" : "-");
        snprintf(jac, sizeof(jac), "%d%%", (k->pnl_jaccard_ppm + 5000) / 10000);
        if (k->last_seen == 0) snprintf(age, sizeof(age), "?");
        else snprintf(age, sizeof(age), "%lds", (long)(now - k->last_seen));
        snprintf(last, sizeof(last), "%.24s (%s)", k->top_ssid, age);

#ifdef WITH_NCURSES
        if (row == s->karma_sel) {
            tui_sel();
            printw(" %-17s  %5d  %4d  %-4s  %-5s  %5d  %s\n",
                   bssid, k->ssid_count, k->pnl_overlap, jac, chain, k->score, last);
            tui_reset();
        } else {
            tui_bright(); printw(" %-17s", bssid);
            tui_normal(); printw("  %5d", k->ssid_count);
            if (k->pnl_overlap > 0) tui_bright(); else tui_dim();
            printw("  %4d", k->pnl_overlap);
            if (k->pnl_jaccard_ppm >= 700000) tui_bright(); else tui_dim();
            printw("  %-4s", jac);
            if (k->deauth_chain) tui_bright(); else tui_dim();
            printw("  %-5s", chain);
            tui_bright(); printw("  %5d", k->score);
            tui_dim();    printw("  %s\n", last);
            tui_normal();
        }
#else
        if (row == s->karma_sel) {
            tui_sel();
            printf(" %-17s  %5d  %4d  %-4s  %-5s  %5d  %s",
                   bssid, k->ssid_count, k->pnl_overlap, jac, chain, k->score, last);
            tui_reset(); printf("\n");
        } else {
            printf(" %-17s  %5d  %4d  %-4s  %-5s  %5d  %s\n",
                   bssid, k->ssid_count, k->pnl_overlap, jac, chain, k->score, last);
        }
#endif
    }
    tui_normal();

    /* Legend */
    tui_dim();
    TPRINT(" PNL = advertised SSIDs matching nearby client probe lists;"
           " chain = concurrent deauth flood\n");
    tui_normal();
}

void view_karma_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->karma_sel > 0) s->karma_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->karma_count > 0 && s->karma_sel < s->karma_count - 1)
            s->karma_sel++;
        break;
    default:
        break;
    }
}
