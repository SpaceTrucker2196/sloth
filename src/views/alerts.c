#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/alerts.h"
#include "../alerts.h"
#include "filter.h"
#include "geo.h"
#include "ip_owner.h"

#define ALERTS_PAGE 30

static const char *sev_label(alert_sev_t sev) {
    switch (sev) {
        case ALERT_SEV_CRIT: return "CRIT";
        case ALERT_SEV_WARN: return "WARN";
        default:             return "INFO";
    }
}

static int sev_is_crit(alert_sev_t sev) { return sev == ALERT_SEV_CRIT; }
static int sev_is_warn(alert_sev_t sev) { return sev == ALERT_SEV_WARN; }

/* Render a one-line enrichment panel for the selected alert when it has a
 * concrete match_ip. Shows region (RIR-level geo) and owner (well-known
 * orgs only — NULL means we don't know it). */
static void draw_enrichment(const alert_t *a) {
    if (!a || !a->match_ip[0]) {
        tui_dim();
        TPRINT("\n  (select an alert with a known flow to see IP context)\n");
        tui_normal();
        return;
    }

    const char *region_code = geo_lookup_str(a->match_ip);
    const char *region_name = geo_region_name(region_code);
    const char *owner       = ip_owner_lookup_str(a->match_ip);

    tui_dim();    TPRINT("\n  context  ");
    tui_normal(); TPRINT("ip=");
    tui_bright(); TPRINT("%-15s", a->match_ip);
    if (a->match_port != 0) {
        tui_normal(); TPRINT("  port=");
        tui_bright(); TPRINT("%-5u", (unsigned)a->match_port);
    } else {
        TPRINT("        ");
    }

    tui_normal(); TPRINT("  region=");
    if (region_name) {
        tui_bright(); TPRINT("%-20s", region_name);
    } else {
        tui_dim();    TPRINT("%-20s", "unknown");
    }

    tui_normal(); TPRINT("  owner=");
    if (owner) {
        tui_bright(); TPRINT("%s", owner);
    } else {
        tui_dim();    TPRINT("(unknown / not in embedded list)");
    }
    tui_normal();
    TPRINT("\n");
}

void view_alerts_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = ALERTS_PAGE;
#endif

    /* count crits for the banner */
    int crits = 0, warns = 0;
    for (int i = 0; i < s->alert_count; i++) {
        if (s->alerts[i].sev == ALERT_SEV_CRIT) crits++;
        else if (s->alerts[i].sev == ALERT_SEV_WARN) warns++;
    }

    tui_normal(); TPRINT(" Alerts: ");
    if (crits > 0) { tui_heat(1.0);  TPRINT("%d crit ", crits); }
    if (warns > 0) { tui_heat(0.7);  TPRINT("%d warn ", warns); }
    tui_bright();  TPRINT("%d total", s->alert_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear  (newest first)");
    tui_filter_status(s);
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-8s  %-4s  %-15s  %-3s  %s\n",
           "Time", "Sev", "Title", "n", "Detail");
    TPRINT(" %-8s  %-4s  %-15s  %-3s  %s\n",
           "--------", "----", "---------------", "---",
           "------------------------------------------------");
    tui_normal();

    if (s->alert_count == 0) {
        tui_dim();
        TPRINT("  (no alerts -- everything looks normal)\n");
        tui_normal();
        return;
    }

    /* Reserve one line at the bottom for the enrichment footer. */
    if (page > 2) page -= 2;

    int page_top = s->alert_sel - page / 2;
    if (page_top + page > s->alert_count) page_top = s->alert_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->alert_count) page_end = s->alert_count;

    for (int row = page_top; row < page_end; row++) {
        const alert_t *a = &s->alerts[row];
        if (s->filter[0] &&
            !filter_match_any(s->filter, a->title, a->detail,
                              a->key, NULL, NULL))
            continue;

        char ts_buf[10];
        struct tm *tm = localtime(&a->last_seen);
        if (tm) strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        else    snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

        if (row == s->alert_sel) {
            tui_sel();
            TPRINT(" %-8s  %-4s  %-15.15s  %-3d  %s\n",
                   ts_buf, sev_label(a->sev), a->title, a->count, a->detail);
            tui_reset();
        } else {
            tui_dim();   TPRINT(" %-8s", ts_buf);

            if      (sev_is_crit(a->sev)) tui_heat(1.0);
            else if (sev_is_warn(a->sev)) tui_heat(0.7);
            else                          tui_normal();
            TPRINT("  %-4s", sev_label(a->sev));

            tui_bright(); TPRINT("  %-15.15s", a->title);

            if (a->count > 1) tui_heat(0.6); else tui_dim();
            TPRINT("  %-3d", a->count);

            tui_normal(); TPRINT("  %s\n", a->detail);
            tui_normal();
        }
    }

    /* Footer: enrichment for the selected alert. */
    if (s->alert_sel >= 0 && s->alert_sel < s->alert_count)
        draw_enrichment(&s->alerts[s->alert_sel]);

    tui_normal();
}

void view_alerts_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->alert_sel > 0) s->alert_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->alert_count > 0 && s->alert_sel < s->alert_count - 1)
            s->alert_sel++;
        break;
    case 'c': case 'C':
        alerts_clear();
        s->alert_count = 0;
        s->alert_sel   = 0;
        break;
    default:
        break;
    }
}
