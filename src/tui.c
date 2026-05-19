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
#include "views/dashboard.h"

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
    "[o] Dash",
};

/* Row-bg lookup: backgrounds were retired, so every category collapses
 * to the project's default phosphor pair. The IP / brand / SSID
 * helpers still take a `cat` for API stability — currently a no-op. */
static int cp_for_bg_cat(int cat) {
    (void)cat;
    return CP_NORMAL;
}

static int cp_for_ip_on_cat(int cat, int ip_idx) {
    int base;
    switch (cat) {
    case 1: base = CP_IP_BASE_TCP;   break;
    case 2: base = CP_IP_BASE_UDP;   break;
    case 3: base = CP_IP_BASE_DNS;   break;
    case 4: base = CP_IP_BASE_ICMP;  break;
    case 5: base = CP_IP_BASE_HTTP;  break;
    case 6: base = CP_IP_BASE_TLS;   break;
    default: base = CP_IP_BASE_OTHER; break;
    }
    return base + (ip_idx & 7);
}

void tui_pkt_bg_cat(int cat) {
    attrset(COLOR_PAIR(cp_for_bg_cat(cat)));
}

void tui_ip_addstr(const char *ip, int cat) {
    extern int ip_color_index(const char *);              /* ip_color.h */
    extern int ip_index_is_cross_panel(const char *);
    if (!ip || !ip[0]) return;
    int idx = ip_color_index(ip);
    attr_t a  = COLOR_PAIR(cp_for_ip_on_cat(cat, idx));
    if (ip_index_is_cross_panel(ip)) a |= A_BOLD;
    attrset(a);
    addstr(ip);
}

void tui_ssid_addstr(const char *ssid, int cat) {
    extern int ip_color_index(const char *);
    if (!ssid || !ssid[0]) return;
    int idx = ip_color_index(ssid);
    attrset(COLOR_PAIR(cp_for_ip_on_cat(cat, idx)));
    addstr(ssid);
}

/* ── Brand colourisation ─────────────────────────────────── */

static int cp_for_brand_on_cat(int cat, int brand_idx) {
    int base;
    switch (cat) {
    case 1: base = CP_BR_BASE_TCP;   break;
    case 2: base = CP_BR_BASE_UDP;   break;
    case 3: base = CP_BR_BASE_DNS;   break;
    case 4: base = CP_BR_BASE_ICMP;  break;
    case 5: base = CP_BR_BASE_HTTP;  break;
    case 6: base = CP_BR_BASE_TLS;   break;
    default: base = CP_BR_BASE_OTHER; break;
    }
    return base + (brand_idx & 7);
}

static int ci_strncmp(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return ca - cb;
        if (ca == 0)  return 0;
    }
    return 0;
}

/* Find the earliest brand match at or after `s`. Returns the start offset,
 * or -1 if none. *brand and *match_len receive the brand id and the
 * matched substring's length. */
static int find_brand(const char *s, int *brand_out, int *len_out) {
    static const struct { int brand; const char *sub; } tbl[] = {
        { BR_GOOGLE_BLUE, "google"      },
        { BR_FIREFOX,     "firefox"     },
        { BR_CLOUDFLARE,  "cloudflare"  },
        { BR_EXAMPLE,     "example.org" },
    };
    int best = -1, best_brand = 0, best_len = 0;
    for (int i = 0; i < (int)(sizeof(tbl) / sizeof(tbl[0])); i++) {
        int sublen = (int)strlen(tbl[i].sub);
        for (int j = 0; s[j]; j++) {
            if (ci_strncmp(s + j, tbl[i].sub, sublen) == 0) {
                if (best < 0 || j < best) {
                    best = j;
                    best_brand = tbl[i].brand;
                    best_len = sublen;
                }
                break;  /* first match for this brand is enough */
            }
        }
    }
    if (best < 0) return -1;
    *brand_out = best_brand;
    *len_out   = best_len;
    return best;
}

void tui_brand_addstr(const char *text, int cat) {
    if (!text || !*text) return;

    int brand, mlen;
    int start = find_brand(text, &brand, &mlen);
    if (start < 0) {
        /* No brand match — render in the row's plain pair. */
        attrset(COLOR_PAIR(cp_for_bg_cat(cat)));
        addstr(text);
        return;
    }

    /* Prefix in default colour */
    if (start > 0) {
        attrset(COLOR_PAIR(cp_for_bg_cat(cat)));
        addnstr(text, start);
    }

    if (brand == BR_GOOGLE_BLUE) {
        /* G-o-o-g-l-e: blue / red / yellow / blue / green / red */
        static const int gseq[] = {
            BR_GOOGLE_BLUE, BR_GOOGLE_RED, BR_GOOGLE_YELLOW,
            BR_GOOGLE_BLUE, BR_GOOGLE_GREEN, BR_GOOGLE_RED,
        };
        for (int i = 0; i < mlen; i++) {
            int slot = gseq[i % 6];
            attrset(COLOR_PAIR(cp_for_brand_on_cat(cat, slot)));
            addch((chtype)(unsigned char)text[start + i]);
        }
    } else {
        attrset(COLOR_PAIR(cp_for_brand_on_cat(cat, brand)));
        addnstr(text + start, mlen);
    }

    /* Recurse for any further brand matches in the rest of the string. */
    tui_brand_addstr(text + start + mlen, cat);
}

void tui_pkt_bg(int proto, uint16_t sport, uint16_t dport) {
    /* Mirror pkt_categorize() — kept local so tui.c doesn't depend on
     * ip_color.h. The two implementations must agree. */
    int cat;
    if      (proto == 1 || proto == 58)          cat = 4;  /* ICMP */
    else if (sport == 53  || dport == 53)        cat = 3;  /* DNS  */
    else if (sport == 443 || dport == 443)       cat = 6;  /* TLS  */
    else if (sport == 80  || dport == 80  ||
             sport == 8080 || dport == 8080 ||
             sport == 8000 || dport == 8000)     cat = 5;  /* HTTP */
    else if (proto == 6)                         cat = 1;  /* TCP  */
    else if (proto == 17)                        cat = 2;  /* UDP  */
    else                                          cat = 0;  /* OTHER */
    tui_pkt_bg_cat(cat);
}

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

/* Earth-tone colour for a packet info string. Same string -> same slot
 * so repeating values keep visual identity across the packets band. */
void tui_info_color(const char *info) {
    extern int ip_color_index(const char *);   /* reuse djb2 hash */
    if (!info || !info[0]) {
        attrset(COLOR_PAIR(CP_NORMAL));
        return;
    }
    int idx = ip_color_index(info);
    attrset(COLOR_PAIR(CP_INFO_BASE + (idx & 7)));
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
    case VIEW_DASH:    view_dashboard_draw(s);     break;
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
            /* Backgrounds disabled: every row sits on the terminal's
             * default bg. Hue and category cues are carried entirely by
             * the IP / brand / SSID foreground palettes. */
            short grey_bg[7] = { 0, 0, 0, 0, 0, 0, 0 };
            /* 8 IP fg colours × 5 row bgs.
             * Fallout-inspired phosphor palette — teal phosphor (already
             * the project's base CP_NORMAL = 43) is the anchor; these eight
             * orbit it with related hues a CRT might glow at: */
            static const short ip_fg[8] = {
                50,    /* #00ffd7  bright phosphor teal      */
                80,    /* #5fd7d7  aged dim phosphor cyan    */
                121,   /* #87ffaf  rad-green                  */
                156,   /* #afff87  mutated lime               */
                178,   /* #d7af00  amber CRT dial             */
                215,   /* #ffaf5f  hazmat orange              */
                174,   /* #d78787  faded crimson (Nuka)       */
                110,   /* #87afd7  Vault-Tec blue             */
            };
            for (int i = 0; i < 8; i++) {
                init_pair(CP_IP_BASE_OTHER + i, ip_fg[i], grey_bg[0]);
                init_pair(CP_IP_BASE_TCP   + i, ip_fg[i], grey_bg[1]);
                init_pair(CP_IP_BASE_UDP   + i, ip_fg[i], grey_bg[2]);
                init_pair(CP_IP_BASE_DNS   + i, ip_fg[i], grey_bg[3]);
                init_pair(CP_IP_BASE_ICMP  + i, ip_fg[i], grey_bg[4]);
                init_pair(CP_IP_BASE_HTTP  + i, ip_fg[i], grey_bg[5]);
                init_pair(CP_IP_BASE_TLS   + i, ip_fg[i], grey_bg[6]);
            }
            /* Brand colour palette: slot indices match BR_* in tui.h */
            static const short brand_fg[8] = {
                33,    /* Google blue     #0087ff */
                167,   /* Google red      #d75f5f */
                220,   /* Google yellow   #ffd700 */
                35,    /* Google green    #00af5f */
                208,   /* Firefox orange  #ff8700 */
                196,   /* Cloudflare red  #ff0000 */
                244,   /* example grey    #808080 */
                253,   /* reserved        #dadada */
            };
            for (int i = 0; i < 8; i++) {
                init_pair(CP_BR_BASE_OTHER + i, brand_fg[i], grey_bg[0]);
                init_pair(CP_BR_BASE_TCP   + i, brand_fg[i], grey_bg[1]);
                init_pair(CP_BR_BASE_UDP   + i, brand_fg[i], grey_bg[2]);
                init_pair(CP_BR_BASE_DNS   + i, brand_fg[i], grey_bg[3]);
                init_pair(CP_BR_BASE_ICMP  + i, brand_fg[i], grey_bg[4]);
                init_pair(CP_BR_BASE_HTTP  + i, brand_fg[i], grey_bg[5]);
                init_pair(CP_BR_BASE_TLS   + i, brand_fg[i], grey_bg[6]);
            }
        } else {
            init_pair(CP_BRIGHT,    COLOR_GREEN, COLOR_BLACK);
            init_pair(CP_NORMAL,    COLOR_GREEN, COLOR_BLACK);
            init_pair(CP_DIM,       COLOR_GREEN, COLOR_BLACK);
            init_pair(CP_HEAT_LO,   COLOR_WHITE, COLOR_BLACK);
            init_pair(CP_HEAT_MID,  COLOR_YELLOW, COLOR_BLACK);
            init_pair(CP_HEAT_HI,   COLOR_YELLOW, COLOR_BLACK);
            init_pair(CP_HEAT_PEAK, COLOR_RED,   COLOR_BLACK);
            /* CP_PKT_* pairs are no longer needed since the row-bg
             * lookup goes through cp_for_bg_cat()->CP_NORMAL. */
            static const short ip_fg_8[8] = {
                COLOR_CYAN,    COLOR_BLUE,    COLOR_YELLOW,  3,
                COLOR_MAGENTA, COLOR_RED,     COLOR_GREEN,   COLOR_WHITE,
            };
            for (int b = 0; b < 7; b++) {
                int base = (b == 0) ? CP_IP_BASE_OTHER :
                           (b == 1) ? CP_IP_BASE_TCP   :
                           (b == 2) ? CP_IP_BASE_UDP   :
                           (b == 3) ? CP_IP_BASE_DNS   :
                           (b == 4) ? CP_IP_BASE_ICMP  :
                           (b == 5) ? CP_IP_BASE_HTTP  : CP_IP_BASE_TLS;
                for (int i = 0; i < 8; i++)
                    init_pair(base + i, ip_fg_8[i], COLOR_BLACK);
            }
            /* 8-colour fallback for brand pairs */
            static const short brand_fg_8[8] = {
                COLOR_BLUE,    COLOR_RED,    COLOR_YELLOW, COLOR_GREEN,
                COLOR_YELLOW,  COLOR_RED,    COLOR_WHITE,  COLOR_WHITE,
            };
            for (int b = 0; b < 7; b++) {
                int base = (b == 0) ? CP_BR_BASE_OTHER :
                           (b == 1) ? CP_BR_BASE_TCP   :
                           (b == 2) ? CP_BR_BASE_UDP   :
                           (b == 3) ? CP_BR_BASE_DNS   :
                           (b == 4) ? CP_BR_BASE_ICMP  :
                           (b == 5) ? CP_BR_BASE_HTTP  : CP_BR_BASE_TLS;
                for (int i = 0; i < 8; i++)
                    init_pair(base + i, brand_fg_8[i], COLOR_BLACK);
            }
            /* 8-colour fallback for info palette + border */
            static const short info_fg_8[8] = {
                COLOR_RED,    COLOR_YELLOW, COLOR_YELLOW, COLOR_GREEN,
                COLOR_RED,    COLOR_YELLOW, COLOR_MAGENTA, COLOR_WHITE,
            };
            for (int i = 0; i < 8; i++)
                init_pair(CP_INFO_BASE + i, info_fg_8[i], COLOR_BLACK);
            init_pair(CP_BORDER, COLOR_GREEN, COLOR_BLACK);
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

/* Draw the tab bar, wrapping onto extra rows as needed. Returns the
 * number of rows consumed by the bar (>= 1). */
static int draw_tabbar(const sloth_state_t *s) {
    int max_x = getmaxx(stdscr);
    int y     = 0;
    int x     = 0;

    move(y, x);
    tui_bright();
    static const char *banner = " sloth v" SLOTH_VERSION;
    int banner_w = (int)strlen(banner);
    printw("%s", banner);
    x = banner_w;

    for (int i = 0; i < VIEW_COUNT; i++) {
        /* "  [n] Label "  ≈ 2 sep + 2 label-padding + label width */
        int lbl_w = (int)strlen(view_labels[i]) + 4;
        if (x + lbl_w >= max_x) {
            y++; x = 0;
            move(y, x);
        }
        tui_dim();   printw("  ");
        if (i == (int)s->active_view) tui_sel(); else tui_dim();
        printw(" %s ", view_labels[i]);
        x += lbl_w;
    }
    tui_normal();
    return y + 1;
}

void tui_draw(const sloth_state_t *s) {
    erase();
    bkgd(COLOR_PAIR(CP_NORMAL));

    /* The dashboard owns the whole screen — no tab bar above it.
     * Switch into a detail view (Enter on a focused panel, or any
     * direct view key) to bring the bar back. */
    if (s->active_view == VIEW_DASH) {
        move(0, 0);
        tui_normal();
        dispatch_view(s);
        refresh();
        return;
    }

    int tabbar_h = draw_tabbar(s);
    move(tabbar_h, 0);
    tui_dim(); hline(ACS_HLINE, getmaxx(stdscr));
    move(tabbar_h + 1, 0);
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
