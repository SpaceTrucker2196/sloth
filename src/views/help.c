#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "views/help.h"

static void section(const char *title) {
    int len = (int)strlen(title);
    tui_dim();    TPRINT("\n  ");
    tui_bright(); TPRINT("%s\n", title);
    tui_dim();    TPRINT("  ");
    for (int i = 0; i < len && i < 40; i++) TPRINT("-");
    TPRINT("\n");
    tui_normal();
}

static void key_row(const char *k1, const char *l1,
                    const char *k2, const char *l2,
                    const char *k3, const char *l3) {
    tui_normal();  TPRINT("    ");
    tui_bright();  TPRINT("[%-3s]", k1);
    tui_normal();  TPRINT(" %-18s", l1);
    if (k2 && k2[0]) {
        tui_bright(); TPRINT(" [%-3s]", k2);
        tui_normal(); TPRINT(" %-18s", l2);
    } else {
        TPRINT("%-26s", "");
    }
    if (k3 && k3[0]) {
        tui_bright(); TPRINT(" [%-3s]", k3);
        tui_normal(); TPRINT(" %s", l3);
    }
    TPRINT("\n");
}

void view_help_draw(const sloth_state_t *s) {
    tui_normal(); TPRINT(" sloth help");
    tui_dim();    TPRINT("       press [?] or any view key to return");
    TPRINT("\n");

    /* Rendered straight from view_label() — the same table the tab bar
     * uses — so every view that exists appears here without a second
     * list to keep in sync. Three columns, enum order. */
    section("View selection");
    for (int v = 0; v < VIEW_COUNT; v += 3) {
        tui_normal(); TPRINT("    ");
        for (int c = 0; c < 3 && v + c < VIEW_COUNT; c++) {
            tui_bright(); TPRINT("%-14s", view_label((view_t)(v + c)));
            if (c < 2 && v + c + 1 < VIEW_COUNT) { tui_normal(); TPRINT("  "); }
        }
        TPRINT("\n");
    }
    tui_normal();

    section("Global");
    key_row("tab", "cycle views forward",
            "n",   "toggle DNS-name resolve",
            "?",   "this screen");
    key_row("q",   "quit",
            "/",   "filter current view",
            "\\",  "clear filter");

    section("Per-view (when shown in a list view)");
    key_row("up/dn", "navigate rows",
            "c",     "clear log",
            "",      "");
    key_row("t",     "iface: toggle visible",
            "",      "",
            "",      "");

    section("Command line");
    tui_normal(); TPRINT("    ");
    tui_bright(); TPRINT("sloth -o FILE");
    tui_normal(); TPRINT("   append a JSONL forensic log of every observed event\n");
    TPRINT("\n");

    section("Version");
    tui_normal(); TPRINT("    running: ");
    tui_bright(); TPRINT("%s\n", s->updater.current[0] ? s->updater.current
                                                       : "(unknown)");
    if (s->updater.enabled) {
        tui_normal(); TPRINT("    latest:  ");
        if (s->updater.err) {
            tui_dim(); TPRINT("(%s)\n", s->updater.err_msg);
        } else if (s->updater.latest[0]) {
            /* Colour the label per state — bright green-ish phosphor
             * for "up to date," heat for "update available." Uses
             * tui_heat instead of hardcoded ANSI so the theme wins. */
            if (s->updater.has_update) {
                tui_heat(0.75); TPRINT("%s  -- update available\n",
                                        s->updater.latest);
                if (s->updater.url[0]) {
                    tui_dim(); TPRINT("             %s\n", s->updater.url);
                }
            } else {
                tui_bright(); TPRINT("%s  ", s->updater.latest);
                tui_dim();    TPRINT("(up to date)\n");
            }
        } else {
            tui_dim(); TPRINT("(pending first check)\n");
        }
    } else {
        tui_dim();
        TPRINT("    latest:  (no --check-manifest; see docs/wiki/version-checkin.md)\n");
    }

    section("About");
    tui_dim();
    TPRINT("    sloth is a passive network monitor for Linux. Run it on the\n");
    TPRINT("    host whose traffic you want to observe -- it never injects\n");
    TPRINT("    packets, scans, or alters routes.\n");
    tui_normal();
}

void view_help_key(sloth_state_t *s, int key) {
    (void)s; (void)key;
}
