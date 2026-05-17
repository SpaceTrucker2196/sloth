#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "views/mdns.h"
#include "mdns_snoop.h"

#define MDNS_PAGE 30

/* Strip "._service._proto.local" suffix → just the instance label. */
static void fmt_instance(const char *full, char *buf, int sz) {
    strncpy(buf, full, sz - 1);
    buf[sz - 1] = '\0';
    char *p = buf;
    while ((p = strchr(p, '.')) != NULL) {
        if (*(p + 1) == '_') { *p = '\0'; return; }
        p++;
    }
    /* fallback: strip .local */
    char *dot = strstr(buf, ".local");
    if (dot) *dot = '\0';
}

/* Strip .local suffix from a hostname for compact display. */
static void fmt_host(const char *host, char *buf, int sz) {
    strncpy(buf, host, sz - 1);
    buf[sz - 1] = '\0';
    char *dot = strstr(buf, ".local");
    if (dot) *dot = '\0';
}

void view_mdns_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = MDNS_PAGE;
#endif

    tui_normal(); TPRINT(" mDNS services: ");
    tui_bright();  TPRINT("%d", s->mdns_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear");
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-15s  %-22s  %-16s  %-15s  %5s\n",
           "Service", "Instance", "Host", "IP", "Port");
    TPRINT(" %-15s  %-22s  %-16s  %-15s  %5s\n",
           "---------------", "----------------------",
           "----------------", "---------------", "-----");
    tui_normal();

    if (s->mdns_count == 0) {
        tui_dim();
        TPRINT("  (no mDNS services seen — waiting for UDP/5353 traffic)\n");
        tui_normal();
        return;
    }

    int page_top = s->mdns_sel - page / 2;
    if (page_top + page > s->mdns_count) page_top = s->mdns_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->mdns_count) page_end = s->mdns_count;

    for (int row = page_top; row < page_end; row++) {
        const mdns_service_t *m = &s->mdns_services[row];
        char inst[32], host[20];
        fmt_instance(m->instance, inst, sizeof(inst));
        fmt_host(m->host, host, sizeof(host));

        const char *svc  = m->service[0] ? m->service : "?";
        const char *istr = inst[0] ? inst : (m->instance[0] ? m->instance : "?");
        const char *hstr = host[0] ? host : (m->host[0] ? m->host : "?");

        if (row == s->mdns_sel) {
            tui_sel();
            TPRINT(" %-15.15s  %-22.22s  %-16.16s  %-15.15s  %5u\n",
                   svc, istr, hstr,
                   m->ip[0] ? m->ip : "?", (unsigned)m->port);
            tui_reset();
        } else {
            tui_bright(); TPRINT(" %-15.15s", svc);
            tui_normal(); TPRINT("  %-22.22s", istr);
            tui_dim();    TPRINT("  %-16.16s", hstr);
            if (m->ip[0]) { tui_normal(); } else { tui_dim(); }
            TPRINT("  %-15.15s", m->ip[0] ? m->ip : "?");
            if (m->port)  { tui_bright(); } else { tui_dim(); }
            TPRINT("  %5u\n", (unsigned)m->port);
            tui_normal();
        }
    }
    tui_normal();
}

void view_mdns_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->mdns_sel > 0) s->mdns_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->mdns_count > 0 && s->mdns_sel < s->mdns_count - 1)
            s->mdns_sel++;
        break;
    case 'c': case 'C':
        mdns_clear();
        s->mdns_count = 0;
        s->mdns_sel   = 0;
        break;
    default:
        break;
    }
}
