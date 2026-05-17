#include <stdio.h>
#include <string.h>
#include <locale.h>

#ifdef WITH_NCURSES
#  include <curses.h>
#else
#  include <termios.h>
#  include <unistd.h>
#  include <sys/select.h>
#endif

#include "sloth.h"
#include "tui.h"
#include "views/iface.h"
#include "views/conns.h"
#include "views/wifi.h"
#include "views/packets.h"
#include "views/procs.h"
#include "views/stats.h"
#include "views/probe.h"
#include "views/arp.h"
#include "views/mdns.h"
#include "views/nbns.h"
#include "views/dhcp_snoop.h"
#include "views/ssdp.h"
#include "views/beacon.h"
#include "views/deauth.h"
#include "views/http.h"
#include "views/tls.h"
#include "views/quic.h"
#include "views/dns_log.h"
#include "views/ntp.h"
#include "views/icmp.h"
#include "views/alerts.h"
#include "views/devices.h"
#include "views/help.h"

static const char *view_labels[VIEW_COUNT] = {
    "[1] Interfaces",
    "[2] Connections",
    "[3] WiFi",
    "[4] Packets",
    "[5] Processes",
    "[6] Stats",
    "[7] Probe",
    "[8] ARP",
    "[9] mDNS",
    "[0] NBNS",
    "[d] DHCP",
    "[s] SSDP",
    "[b] Beacons",
    "[a] Deauth",
    "[h] HTTP",
    "[t] TLS",
    "[u] QUIC",
    "[r] DNS",
    "[p] NTP",
    "[i] ICMP",
    "[v] Alerts",
    "[g] Devices",
    "[?] Help",
};

void tui_filter_status(const sloth_state_t *s) {
    if (!s) return;
    if (s->filter_editing) {
        tui_heat(0.9); TPRINT("  /%s_", s->filter);
        tui_normal();
    } else if (s->filter[0]) {
        tui_heat(0.5); TPRINT("  /%s/", s->filter);
        tui_normal();
    }
}

/* out must hold width*3+1 bytes (each glyph is 3 UTF-8 bytes). */
void tui_bar(double val, double max, int width, char *out) {
    int filled = (max > 0.0) ? (int)((val / max) * width) : 0;
    if (filled > width) filled = width;
    int pos = 0;
    for (int i = 0; i < width; i++) {
        const char *g = (i < filled) ? "\xe2\x96\x88" : "\xe2\x96\x91";  /* █ : ░ */
        out[pos++] = g[0]; out[pos++] = g[1]; out[pos++] = g[2];
    }
    out[pos] = '\0';
}

static void dispatch_view(const sloth_state_t *s) {
    switch (s->active_view) {
    case VIEW_IFACE:   view_iface_draw(s);   break;
    case VIEW_CONNS:   view_conns_draw(s);   break;
    case VIEW_WIFI:    view_wifi_draw(s);    break;
    case VIEW_PACKETS: view_packets_draw(s); break;
    case VIEW_PROCS:   view_procs_draw(s);   break;
    case VIEW_STATS:   view_stats_draw(s);   break;
    case VIEW_PROBE:   view_probe_draw(s);   break;
    case VIEW_ARP:     view_arp_draw(s);     break;
    case VIEW_MDNS:    view_mdns_draw(s);    break;
    case VIEW_NBNS:    view_nbns_draw(s);         break;
    case VIEW_DHCP:    view_dhcp_snoop_draw(s);   break;
    case VIEW_SSDP:    view_ssdp_draw(s);         break;
    case VIEW_BEACON:  view_beacon_draw(s);        break;
    case VIEW_DEAUTH:  view_deauth_draw(s);        break;
    case VIEW_HTTP:    view_http_draw(s);          break;
    case VIEW_TLS:     view_tls_draw(s);           break;
    case VIEW_QUIC:    view_quic_draw(s);          break;
    case VIEW_DNS:     view_dns_draw(s);           break;
    case VIEW_NTP:     view_ntp_draw(s);           break;
    case VIEW_ICMP:    view_icmp_draw(s);          break;
    case VIEW_ALERTS:  view_alerts_draw(s);        break;
    case VIEW_DEVICES: view_devices_draw(s);       break;
    case VIEW_HELP:    view_help_draw(s);          break;
    default: break;
    }
}

/* ═══════════════════════════════════════════════════════════
   ncurses implementation
   ═══════════════════════════════════════════════════════════ */
#ifdef WITH_NCURSES

void tui_bright(void) { attrset(COLOR_PAIR(CP_BRIGHT)); }
void tui_normal(void) { attrset(COLOR_PAIR(CP_NORMAL)); }
void tui_dim(void)    { attrset(COLOR_PAIR(CP_DIM));    }
void tui_sel(void)    { attrset(COLOR_PAIR(CP_NORMAL) | A_REVERSE); }
void tui_reset(void)  { attrset(COLOR_PAIR(CP_NORMAL)); }

void tui_init(void) {
    setlocale(LC_ALL, "");  /* must precede initscr() for UTF-8 to work */
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    if (has_colors()) {
        start_color();
        if (COLORS >= 256) {
            /* nuclear teal-green pairs */
            init_pair(CP_BRIGHT, 49, 0);        /* #00ffaf rgb(0,255,175) */
            init_pair(CP_NORMAL, 43, 0);        /* #00d7af rgb(0,215,175) */
            init_pair(CP_DIM,    29, 0);        /* #00875f rgb(0,135,95)  */
            /* heat gradient pairs: grey → amber → orange → red */
            init_pair(CP_HEAT_LO,   241, 0);   /* rgb(98,98,98)   */
            init_pair(CP_HEAT_MID,  178, 0);   /* rgb(215,175,0)  */
            init_pair(CP_HEAT_HI,   208, 0);   /* rgb(255,135,0)  */
            init_pair(CP_HEAT_PEAK, 196, 0);   /* rgb(255,0,0)    */
        } else {
            init_pair(CP_BRIGHT,    COLOR_GREEN, COLOR_BLACK);
            init_pair(CP_NORMAL,    COLOR_GREEN, COLOR_BLACK);
            init_pair(CP_DIM,       COLOR_GREEN, COLOR_BLACK);
            init_pair(CP_HEAT_LO,   COLOR_WHITE, COLOR_BLACK);
            init_pair(CP_HEAT_MID,  COLOR_YELLOW, COLOR_BLACK);
            init_pair(CP_HEAT_HI,   COLOR_YELLOW, COLOR_BLACK);
            init_pair(CP_HEAT_PEAK, COLOR_RED,   COLOR_BLACK);
        }
    }
}

void tui_heat(double frac) {
    if      (frac < 0.15) attrset(COLOR_PAIR(CP_HEAT_LO));
    else if (frac < 0.40) attrset(COLOR_PAIR(CP_HEAT_MID));
    else if (frac < 0.70) attrset(COLOR_PAIR(CP_HEAT_HI));
    else                  attrset(COLOR_PAIR(CP_HEAT_PEAK));
}

void tui_cleanup(void) {
    endwin();
}

static void draw_tabbar(const sloth_state_t *s) {
    tui_bright();
    printw(" sloth v" SLOTH_VERSION);
    for (int i = 0; i < VIEW_COUNT; i++) {
        tui_dim(); printw("  ");
        if (i == (int)s->active_view) tui_sel(); else tui_dim();
        printw(" %s ", view_labels[i]);
    }
    tui_dim();
    printw("  [Tab] cycle  [q]uit");
    tui_normal();
}

void tui_draw(const sloth_state_t *s) {
    erase();
    bkgd(COLOR_PAIR(CP_NORMAL));
    move(0, 0);
    draw_tabbar(s);
    move(1, 0);
    tui_dim(); hline(ACS_HLINE, getmaxx(stdscr));
    move(2, 0);
    tui_normal();
    dispatch_view(s);
    refresh();
}

int tui_poll_key(int timeout_ms) {
    timeout(timeout_ms);
    int ch = getch();
    if (ch == ERR)            return 0;
    if (ch == KEY_UP)         return SLOTH_KEY_UP;
    if (ch == KEY_DOWN)       return SLOTH_KEY_DOWN;
    if (ch == KEY_BACKSPACE ||
        ch == 127 || ch == 8) return SLOTH_KEY_BACKSPACE;
    return ch;
}

/* ═══════════════════════════════════════════════════════════
   ANSI fallback (embedded / no-ncurses)
   ═══════════════════════════════════════════════════════════ */
#else

/* nuclear teal-green: rgb(0, 215, 130) bright / rgb(0, 175, 105) normal / rgb(0, 100, 58) dim */
void tui_bright(void) { printf("\033[38;2;0;215;130m\033[1m"); }
void tui_normal(void) { printf("\033[0m\033[38;2;0;175;105m"); }
void tui_dim(void)    { printf("\033[0m\033[38;2;0;100;58m");  }
void tui_sel(void)    { printf("\033[0m\033[38;2;0;175;105m\033[7m"); }
void tui_reset(void)  { printf("\033[0m\033[38;2;0;175;105m"); }

/* heat gradient: grey → amber → orange → red */
void tui_heat(double frac) {
    if      (frac < 0.15) printf("\033[38;2;98;98;98m");
    else if (frac < 0.40) printf("\033[38;2;215;175;0m");
    else if (frac < 0.70) printf("\033[38;2;255;135;0m");
    else                  printf("\033[38;2;220;20;0m");
}

static struct termios g_saved_term;

void tui_init(void) {
    struct termios raw;
    tcgetattr(STDIN_FILENO, &g_saved_term);
    raw = g_saved_term;
    raw.c_lflag &= (tcflag_t)~(ECHO | ICANON);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

void tui_cleanup(void) {
    tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_term);
    printf("\033[0m\n");
}

static void draw_tabbar(const sloth_state_t *s) {
    tui_bright(); printf(" sloth v" SLOTH_VERSION);
    for (int i = 0; i < VIEW_COUNT; i++) {
        tui_dim(); printf("  ");
        if (i == (int)s->active_view) tui_sel(); else tui_dim();
        printf(" %s ", view_labels[i]);
    }
    tui_dim(); printf("  [Tab] cycle  [q]uit\n");
    printf("------------------------------------------------------------\n");
    tui_normal();
}

void tui_draw(const sloth_state_t *s) {
    printf("\033[2J\033[H");
    tui_normal();
    draw_tabbar(s);
    dispatch_view(s);
    tui_reset();
    fflush(stdout);
}

static int read_char_timeout(int us) {
    fd_set fds;
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = us;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
        unsigned char c = 0;
        if (read(STDIN_FILENO, &c, 1) == 1)
            return (int)c;
    }
    return -1;
}

int tui_poll_key(int timeout_ms) {
    fd_set fds;
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) <= 0)
        return 0;

    unsigned char c = 0;
    if (read(STDIN_FILENO, &c, 1) != 1)
        return 0;

    if (c == 127 || c == 8)
        return SLOTH_KEY_BACKSPACE;
    if (c != '\033')
        return (int)c;

    int b = read_char_timeout(10000);
    if (b != '[')
        return '\033';

    int d = read_char_timeout(10000);
    if (d == 'A') return SLOTH_KEY_UP;
    if (d == 'B') return SLOTH_KEY_DOWN;
    return '\033';
}

#endif /* WITH_NCURSES */
