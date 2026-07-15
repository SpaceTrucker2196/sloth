#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "eap_parse.h"
#include "views/rogue_radius.h"

#define ROGUE_RADIUS_PAGE 30

static void fmt_mac(const uint8_t mac[6], char *buf, int sz) {
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void rogue_radius_fmt_methods(uint32_t types, char *buf, int sz) {
    /* Types 1-3 (Identity / Notification / Nak) are RFC 3748 "special"
     * frames, not authentication methods — Identity already has its own
     * leak column, so listing them here would be noise. */
    int off = 0;
    buf[0] = '\0';
    for (int t = EAP_TYPE_MD5; t < 32 && off < sz - 1; t++) {
        if (!(types & (1u << t))) continue;
        const char *name = eap_type_name(t);
        if (strcmp(name, "?") == 0)
            off += snprintf(buf + off, sz - off, "%sT%d",
                            off ? "," : "", t);
        else
            off += snprintf(buf + off, sz - off, "%s%s",
                            off ? "," : "", name);
    }
    if (!buf[0]) snprintf(buf, sz, "-");
}

/* Display order: weak-method APs first, then most recently active —
 * the row most likely to be hostile floats to the top. Sorted as an
 * index permutation per draw; the snapshot itself stays untouched. */
static int order_rows(const sloth_state_t *s, int idx[MAX_ROGUE_RADIUS]) {
    int n = s->rogue_radius_count;
    if (n > MAX_ROGUE_RADIUS) n = MAX_ROGUE_RADIUS;
    for (int i = 0; i < n; i++) idx[i] = i;
    for (int i = 1; i < n; i++) {
        int v = idx[i], j = i;
        const rogue_radius_ap_t *a = &s->rogue_radius[v];
        while (j > 0) {
            const rogue_radius_ap_t *b = &s->rogue_radius[idx[j - 1]];
            if (b->weak_method > a->weak_method) break;
            if (b->weak_method == a->weak_method &&
                b->last_seen >= a->last_seen) break;
            idx[j] = idx[j - 1];
            j--;
        }
        idx[j] = v;
    }
    return n;
}

void view_rogue_radius_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = ROGUE_RADIUS_PAGE;
#endif

    int idx[MAX_ROGUE_RADIUS];
    int n = order_rows(s, idx);

    /* Status bar */
    tui_normal(); TPRINT(" 802.1X EAP conversations: ");
    tui_bright(); TPRINT("%d", n);
    tui_dim();    TPRINT(" AP%s / max %d", n == 1 ? "" : "s", MAX_ROGUE_RADIUS);
    int weak = 0, leaks = 0;
    for (int i = 0; i < n; i++) {
        if (s->rogue_radius[i].weak_method) weak++;
        leaks += s->rogue_radius[i].identity_leaks;
    }
    if (weak > 0) {
        tui_dim();    TPRINT("  weak-method APs: ");
        tui_bright(); TPRINT("%d", weak);
    }
    if (leaks > 0) {
        tui_dim();    TPRINT("  identity leaks: ");
        tui_bright(); TPRINT("%d", leaks);
    }
    TPRINT("\n");

    /* Columns — BSSID 17 | methods 20 | weak 4 | leaks 5 | identity/age */
    tui_dim();
    TPRINT(" %-17s  %-20s  %-4s  %-5s  %s\n",
           "BSSID", "EAP methods", "weak", "leaks", "Last identity / seen");
    TPRINT(" %-17s  %-20s  %-4s  %-5s  %s\n",
           "-----------------", "--------------------", "----", "-----",
           "--------------------");
    tui_normal();

    if (n == 0) {
        tui_dim();
        TPRINT("  (no 802.1X EAP conversations observed — needs a WPA-Enterprise\n"
               "   network in monitor range. See docs/views/rogue-radius.md.)\n");
        tui_normal();
        return;
    }

    int sel = s->rogue_radius_sel;
    if (sel >= n) sel = n - 1;
    int top = sel - page / 2;
    if (top + page > n) top = n - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > n) end = n;

    time_t now = time(NULL);
    for (int row = top; row < end; row++) {
        const rogue_radius_ap_t *r = &s->rogue_radius[idx[row]];
        char bssid[20], methods[32], age[12], last[64];
        const char *wk = r->weak_method ? "YES" : "-";
        fmt_mac(r->bssid, bssid, sizeof(bssid));
        rogue_radius_fmt_methods(r->eap_types_seen, methods, sizeof(methods));
        if (r->last_seen == 0) snprintf(age, sizeof(age), "?");
        else snprintf(age, sizeof(age), "%lds", (long)(now - r->last_seen));
        snprintf(last, sizeof(last), "%.40s (%s)",
                 r->last_identity[0] ? r->last_identity : "-", age);

#ifdef WITH_NCURSES
        if (row == sel) {
            tui_sel();
            printw(" %-17s  %-20.20s  %-4s  %5d  %s\n",
                   bssid, methods, wk, r->identity_leaks, last);
            tui_reset();
        } else {
            tui_bright(); printw(" %-17s", bssid);
            tui_normal(); printw("  %-20.20s", methods);
            if (r->weak_method) tui_bright(); else tui_dim();
            printw("  %-4s", wk);
            if (r->identity_leaks > 0) tui_bright(); else tui_dim();
            printw("  %5d", r->identity_leaks);
            tui_dim();    printw("  %s\n", last);
            tui_normal();
        }
#else
        if (row == sel) {
            tui_sel();
            printf(" %-17s  %-20.20s  %-4s  %5d  %s",
                   bssid, methods, wk, r->identity_leaks, last);
            tui_reset(); printf("\n");
        } else {
            printf(" %-17s  %-20.20s  %-4s  %5d  %s\n",
                   bssid, methods, wk, r->identity_leaks, last);
        }
#endif
    }
    tui_normal();

    /* Legend */
    tui_dim();
    TPRINT(" weak = MD5/GTC offered (eaphammer / hostapd-wpe lure);"
           " leaks = non-anonymous Response/Identity\n");
    tui_normal();
}

void view_rogue_radius_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->rogue_radius_sel > 0) s->rogue_radius_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->rogue_radius_count > 0 &&
            s->rogue_radius_sel < s->rogue_radius_count - 1)
            s->rogue_radius_sel++;
        break;
    default:
        break;
    }
}
