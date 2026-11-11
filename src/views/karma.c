#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/view_page.h"
#include "views/karma.h"
/* KARMA_PNL_CORROB_MIN — the legend and the PNL highlight must quote
 * the same number the score and the alert gate use. */
#include "karma_detect.h"

#define KARMA_PAGE 30
/* Lines the view draws under the candidate rows: the two-line legend.
 * It used to be left out of the page budget, so a full page pushed it
 * off the bottom of the screen - the half of the view that says a tool
 * name is a hypothesis. The status and header lines above the rows are
 * measured rather than counted: the page is taken after they are
 * drawn (#150). */
#define KARMA_LEGEND_ROWS 2
/* Shortest top-SSID prefix a row keeps before the tool attribution
 * starts giving up its label (the SSID is the observation; the tool is
 * a hypothesis about it). */
#define KARMA_SSID_MIN 8
/* Fewest label characters worth printing in front of the "~" that marks
 * a clipped tool label; a shorter stub could pass for a whole name. */
#define KARMA_LABEL_MIN 3

static void fmt_mac(const uint8_t mac[6], char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Fit a row's tail - "<top SSID> (<age>)" and the optional
 * "  [<tool attribution>]" - into `room` cells, so the row never reaches
 * the last column and wraps. At the 100-column minimum a full-length
 * SSID, its age and the longest attribution need ~30 cells more than
 * the row has.
 *
 * What gives way, in order: the SSID down to KARMA_SSID_MIN, then the
 * tool label. The "/conf? provisional" tail of the attribution is kept
 * whole for as long as anything of the label fits, because that word is
 * what tells the operator the name is unverified (#90); a clipped label
 * ends in "~" so a stub is never read as a name. Only below that is the
 * bracket clipped outright. Bytes are counted, not cells: the
 * sanitiser never lengthens a string and no glyph is wider than the
 * octets that encode it, so the byte count bounds the width. */
static void karma_fit_tail(const karma_ap_t *k, const char *age, int room,
                           char *last, size_t last_sz,
                           char *tool, size_t tool_sz) {
    char full[64] = "";
    if (k->tool[0]) snprintf(full, sizeof(full), "  [%s]", k->tool);
    int t_len    = (int)strlen(full);
    int age_len  = (int)strlen(age) + 3;              /* " (" age ")" */
    int ssid_len = 0;
    while (ssid_len < 24 && k->top_ssid[ssid_len]) ssid_len++;
    int ssid_w   = ssid_len;
    if (ssid_w + age_len + t_len > room) {
        ssid_w = room - age_len - t_len;
        if (ssid_w < KARMA_SSID_MIN) ssid_w = KARMA_SSID_MIN;
        if (ssid_w > ssid_len) ssid_w = ssid_len;
    }
    snprintf(last, last_sz, "%.*s (%s)", ssid_w, k->top_ssid, age);
    int l_len = (int)strlen(last);
    if (l_len > room) {                  /* narrower than any sane row */
        l_len = room > 0 ? room : 0;
        /* l_len < strlen(last) < last_sz here, but say so: under ASan
         * gcc loses that bound and -Warray-bounds fires (#95). */
        if ((size_t)l_len < last_sz) last[l_len] = '\0';
    }
    int rem = room - l_len;
    tool[0] = '\0';
    if (!full[0] || rem <= 0) return;
    if (t_len <= rem) { snprintf(tool, tool_sz, "%s", full); return; }
    const char *slash = strrchr(k->tool, '/');
    int tail_len = slash ? (int)strlen(slash) : 0;
    int label_w  = rem - 4 - tail_len;               /* "  [" + "]" */
    if (slash && label_w >= 1) {
        /* A clipped label is marked: "[ES/med? ...]" reads as the whole
         * name of some tool, not a cut "ESP32 Marauder". Below
         * KARMA_LABEL_MIN kept characters the stub says nothing, so
         * only the marker is left. */
        if (label_w > KARMA_LABEL_MIN)
            snprintf(tool, tool_sz, "  [%.*s~%s]", label_w - 1, k->tool, slash);
        else    /* k->tool is 48 bytes; the bound only satisfies -Wformat-truncation */
            snprintf(tool, tool_sz, "  [~%.*s]",
                     tail_len < 59 ? tail_len : 59, slash);
        return;
    }
    snprintf(tool, tool_sz, "%.*s", rem, full);
}

void view_karma_draw(const sloth_state_t *s) {
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

    /* Columns — BSSID 17 | SSIDs 5 | PNL 4 | J% 4 | IE 2 | chain 5 |
     * FR 2 | score 5. FR is #187 S2's forged-answer count: names this
     * BSSID answered directed probes for and never beaconed. */
    tui_dim();
    TPRINT(" %-17s  %-5s  %-4s  %-4s  %-2s  %-5s  %-2s  %-5s  %s\n",
           "BSSID", "SSIDs", "PNL", "J%", "IE", "chain", "FR", "score",
           "Top SSID / last");
    TPRINT(" %-17s  %-5s  %-4s  %-4s  %-2s  %-5s  %-2s  %-5s  %s\n",
           "-----------------", "-----", "----", "----", "--", "-----", "--",
           "-----", "---------------");
    tui_normal();

    if (s->karma_count == 0) {
        tui_dim();
        TPRINT("  (no KARMA candidates — sloth needs one BSSID beaconing >=%d\n"
               "   distinct SSIDs, or answering directed probes for >=%d it\n"
               "   never beaconed. Start monitor capture and give it time.)\n",
               KARMA_SSID_THRESH, KARMA_FORGE_SSID_MIN);
        tui_normal();
        return;
    }

    int page = view_page_budget(KARMA_LEGEND_ROWS, KARMA_PAGE);
    int top = s->karma_sel - page / 2;
    if (top + page > s->karma_count) top = s->karma_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->karma_count) end = s->karma_count;

    time_t now = sloth_wall();
    for (int row = top; row < end; row++) {
        const karma_ap_t *k = &s->karma_aps[row];
        char bssid[20], chain[6], age[24], last[64], jac[16], tool[64];
        /* Forged answers, clamped to the row's SSID set for the same
         * reason the IE cell is: a wider cell shoves the row. "-" is
         * none, not "unknown": no forge row and no countable answer
         * read the same to the operator. */
        char frg[4];
        int forged = k->forged;
        if (forged > KARMA_FORGE_MAX_SSIDS) forged = KARMA_FORGE_MAX_SSIDS;
        if (forged > 0) snprintf(frg, sizeof(frg), "%d", forged);
        else            snprintf(frg, sizeof(frg), "-");
        /* The distinct-fingerprint count, not a yes/no (#187 S4). "1"
         * against an SSIDs column of 4 is the collapse; "4" is the AP
         * showing four different security postures, which is the
         * reading that argues against one spoofing radio — and the old
         * "-" said that and "nothing observed" with the same glyph.
         * Still "-" when a fingerprint is missing, which is the only
         * case that is genuinely an absent observation.
         *
         * Clamped to MAX_AP_SSID_HISTORY here rather than trusting the
         * producer: the count cannot exceed it by construction, but the
         * invariant lives in another file, and the cost of being wrong
         * is a cell wider than the 2-column field, which shoves every
         * column after it out of line for that row. */
        char ie[4];
        int ie_fps = k->ie_fp_distinct;
        if (ie_fps > MAX_AP_SSID_HISTORY) ie_fps = MAX_AP_SSID_HISTORY;
        if (ie_fps > 0) snprintf(ie, sizeof(ie), "%d", ie_fps);
        else            snprintf(ie, sizeof(ie), "-");
        fmt_mac(k->bssid, bssid, sizeof(bssid));
        snprintf(chain, sizeof(chain), "%s", k->deauth_chain ? "YES" : "-");
        snprintf(jac, sizeof(jac), "%d%%", (k->pnl_jaccard_ppm + 5000) / 10000);
        if (k->last_seen == 0) snprintf(age, sizeof(age), "?");
        else {
            /* Whole days past a day (#187 S2): the FR column took four
             * cells from the tail, and "(1234567s)" spent ten of what
             * was left on a figure nobody reads in seconds. */
            long secs = (long)(now - k->last_seen);
            if (secs >= 86400) snprintf(age, sizeof(age), "%ldd", secs / 86400);
            else               snprintf(age, sizeof(age), "%lds", secs);
        }
        /* Same bracketed attribution the KARMA_AP alert detail carries
         * (#90), including its "? provisional" suffix for a signature
         * with no capture behind it - fitted to the terminal width,
         * since a row that wraps shoves every row below it down and the
         * legend off the screen. */
#ifdef WITH_NCURSES
        int prefix = snprintf(NULL, 0,
                              " %-17s  %5d  %4d  %-4s  %-2s  %-5s  %-2s  %5d  ",
                              bssid, k->ssid_count, k->pnl_overlap, jac, ie,
                              chain, frg, k->score);
        int room = COLS - 1 - prefix;
#else
        int room = (int)sizeof(last) + (int)sizeof(tool);
#endif
        karma_fit_tail(k, age, room, last, sizeof(last), tool, sizeof(tool));

#ifdef WITH_NCURSES
        if (row == s->karma_sel) {
            tui_sel();
            tui_printf(" %-17s  %5d  %4d  %-4s  %-2s  %-5s  %-2s  %5d  %s%s\n",
                   bssid, k->ssid_count, k->pnl_overlap, jac, ie, chain, frg,
                   k->score, last, tool);
            tui_reset();
        } else {
            tui_bright(); tui_printf(" %-17s", bssid);
            tui_normal(); tui_printf("  %5d", k->ssid_count);
            /* Bright on the count that actually corroborates (#90), not
             * on a union hit — drawing the operator's eye to a
             * coincidence is what this column used to do. The column
             * still prints the union, so narrowing the gate does not
             * hide the reading.
             *
             * Pinned by tests/test_karma.c ::
             * test_view_pnl_column_still_shows_the_union, which reads the
             * cell's colour pair off the offscreen screen (#116). */
            if (k->pnl_best >= KARMA_PNL_CORROB_MIN) tui_bright();
            else tui_dim();
            tui_printf("  %4d", k->pnl_overlap);
            if (k->pnl_jaccard_ppm >= 700000) tui_bright(); else tui_dim();
            tui_printf("  %-4s", jac);
            if (k->ie_uniform) tui_bright(); else tui_dim();
            tui_printf("  %-2s", ie);
            if (k->deauth_chain) tui_bright(); else tui_dim();
            tui_printf("  %-5s", chain);
            if (k->forged >= KARMA_FORGE_SSID_MIN) tui_bright(); else tui_dim();
            tui_printf("  %-2s", frg);
            tui_bright(); tui_printf("  %5d", k->score);
            tui_dim();    tui_printf("  %s", last);
            if (tool[0]) { tui_bright(); tui_printf("%s", tool); }
            tui_printf("\n");
            tui_normal();
        }
#else
        if (row == s->karma_sel) {
            tui_sel();
            tui_printf(" %-17s  %5d  %4d  %-4s  %-2s  %-5s  %-2s  %5d  %s%s",
                   bssid, k->ssid_count, k->pnl_overlap, jac, ie, chain, frg,
                   k->score, last, tool);
            tui_reset(); tui_printf("\n");
        } else {
            tui_printf(" %-17s  %5d  %4d  %-4s  %-2s  %-5s  %-2s  %5d  %s%s\n",
                   bssid, k->ssid_count, k->pnl_overlap, jac, ie, chain, frg,
                   k->score, last, tool);
        }
#endif
    }
    tui_normal();

    /* Legend */
    tui_dim();
    /* 95 cells: the legend has to fit the 100-column minimum, which is
     * why "in client probe lists" became "probed" when FR joined it. */
    TPRINT(" PNL = SSIDs probed, >=%d on one station;"
           " chain = deauth-then-lure on shared victim; FR = forged\n",
           KARMA_PNL_CORROB_MIN);
    TPRINT(" [tool/conf? provisional] = UNVERIFIED signature, no capture:"
           " a hypothesis, not an identification\n");
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
