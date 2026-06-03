#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/twins.h"

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
    TPRINT("\n");

    /* Column headers — fixed widths: SSID 18 | real 17 | twin 17 |
     * enc 6 | swing 5 | flags 6 | last */
    tui_dim();
    TPRINT(" %-18s  %-17s  %-17s  %-6s  %-5s  %-6s  %s\n",
           "SSID", "Real BSSID", "Twin BSSID", "Cipher", "Swing", "Flags", "Last");
    TPRINT(" %-18s  %-17s  %-17s  %-6s  %-5s  %-6s  %s\n",
           "------------------",
           "-----------------",
           "-----------------",
           "------", "-----", "------", "----");
    tui_normal();

    if (s->twin_episode_count == 0) {
        tui_dim();
        TPRINT("  (no twin pairs observed — sloth needs at least two same-SSID,\n"
               "   same-cipher beacons with different vendor OUIs to detect one.)\n");
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
        char real_mac[20], twin_mac[20], swing[8], flags[8];
        fmt_mac(e->real_bssid, real_mac, sizeof(real_mac));
        fmt_mac(e->twin_bssid, twin_mac, sizeof(twin_mac));
        if (e->rssi_swing_dbm) snprintf(swing, sizeof(swing), "%udB", e->rssi_swing_dbm);
        else                   snprintf(swing, sizeof(swing), "-");
        /* Flag glyphs (ASCII for portability):
         *   ! = attack-in-progress (deauth-fed chain CRIT)
         *   * = attacker-tool OUI (Hak5 / Espressif)
         *   # = vendor-IE hash mismatch */
        int  fi = 0;
        if (e->attack_in_progress) flags[fi++] = '!';
        if (e->attacker_oui)       flags[fi++] = '*';
        if (e->hash_mismatch)      flags[fi++] = '#';
        flags[fi] = '\0';
        if (!flags[0]) snprintf(flags, sizeof(flags), "-");

        char age[12];
        time_t now = time(NULL);
        if (e->last_seen == 0) snprintf(age, sizeof(age), "?");
        else snprintf(age, sizeof(age), "%lds", (long)(now - e->last_seen));

#ifdef WITH_NCURSES
        if (row == s->twin_episode_sel) {
            tui_sel();
            printw(" %-18.18s  %-17s  %-17s  %-6.6s  %-5s  %-6s  %s\n",
                   e->ssid, real_mac, twin_mac, e->enc, swing, flags, age);
            tui_reset();
        } else {
            tui_bright(); printw(" %-18.18s", e->ssid);
            tui_dim();    printw("  %-17s", real_mac);
            /* Twin BSSID is the suspected rogue — render bright to draw
             * the operator's eye. */
            tui_bright(); printw("  %-17s", twin_mac);
            tui_dim();    printw("  %-6.6s", e->enc);
            tui_normal(); printw("  %-5s", swing);
            if (e->attack_in_progress) tui_bright(); else tui_dim();
            printw("  %-6s", flags);
            tui_dim();    printw("  %s\n", age);
            tui_normal();
        }
#else
        if (row == s->twin_episode_sel) {
            tui_sel();
            printf(" %-18.18s  %-17s  %-17s  %-6.6s  %-5s  %-6s  %s",
                   e->ssid, real_mac, twin_mac, e->enc, swing, flags, age);
            tui_reset(); printf("\n");
        } else {
            tui_bright(); printf(" %-18.18s", e->ssid);
            tui_dim();    printf("  %-17s", real_mac);
            tui_bright(); printf("  %-17s", twin_mac);
            tui_dim();    printf("  %-6.6s", e->enc);
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
