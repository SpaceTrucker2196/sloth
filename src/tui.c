/* Before any header: the offscreen read-back (#116) uses ncursesw's
 * wide-char API, which curses.h declares only when asked. */
#define NCURSES_WIDECHAR 1

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <wchar.h>
#include <locale.h>
#include <time.h>

#include <unistd.h>
#include <sys/select.h>

#ifdef WITH_NCURSES
#  include <curses.h>
#else
#  include <termios.h>
#endif

#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "persist_health.h"
#include "tui_palette.h"
#include "netstr.h"
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
#include "views/pnl.h"
#include "views/eapol.h"
#include "views/seqnum.h"
#include "views/assoc.h"
#include "views/channel.h"
#include "views/osi.h"
#include "views/twins.h"
#include "views/karma.h"
#include "views/rogue_radius.h"
#include "views/research.h"
#include "views/fragattack.h"


/* ── Sanitised emission (#138) ───────────────────────────── *
 *
 * The one place a view's text reaches the terminal. Each string is
 * copied into a bounded buffer and run through display_sanitize()
 * before addstr / fputs see it: ncurses renders most C0 as ^X but acts
 * on \r \b \t, and the ANSI backend acted on all of it. A string longer
 * than the stack buffer goes to the heap rather than being cut, since a
 * truncated row would be a rendering change of its own. */
#define T_EMIT_STACK 1024

/* Sanitised copy of s[0..n) (n < 0: to the NUL). Returns buf, a heap
 * block the caller frees (*heap set), or NULL when that allocation fails. */
static char *t_sanitized_copy(const char *s, int n, char *buf, size_t bufsz,
                              int *heap) {
    /* Bounded scan when n is given: addnstr() reads at most n octets,
     * so the replacement must not walk past them looking for a NUL. */
    size_t len = 0;
    if (n < 0) len = strlen(s);
    else while (len < (size_t)n && s[len]) len++;
    char *p = buf;
    *heap = 0;
    if (len + 1 > bufsz) {
        p = malloc(len + 1);
        if (!p) return NULL;
        *heap = 1;
    }
    memcpy(p, s, len);
    p[len] = '\0';
    display_sanitize(p);
    return p;
}

void tui_fputs_sanitized(FILE *fp, const char *s, int n) {
    if (!fp || !s) return;
    char buf[T_EMIT_STACK];
    int heap;
    char *p = t_sanitized_copy(s, n, buf, sizeof buf, &heap);
    if (!p) return;
    fputs(p, fp);
    if (heap) free(p);
}

#ifdef WITH_NCURSES
static void t_emit(const char *s, int n) {
    if (!s) return;
    char buf[T_EMIT_STACK];
    int heap;
    char *p = t_sanitized_copy(s, n, buf, sizeof buf, &heap);
    if (!p) return;
    addstr(p);
    if (heap) free(p);
}
#else
static void t_emit(const char *s, int n) { tui_fputs_sanitized(stdout, s, n); }
#endif

void tui_addstr(const char *s)         { t_emit(s, -1); }
void tui_addnstr(const char *s, int n) { t_emit(s, n); }

void tui_printf(const char *fmt, ...) {
    char buf[T_EMIT_STACK];
    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (need < 0) return;
    if ((size_t)need < sizeof buf) { t_emit(buf, -1); return; }
    char *big = malloc((size_t)need + 1);
    if (!big) { t_emit(buf, -1); return; }   /* the truncated form, still sanitised */
    va_start(ap, fmt);
    vsnprintf(big, (size_t)need + 1, fmt, ap);
    va_end(ap);
    t_emit(big, -1);
    free(big);
}

/* ── Backend-neutral output primitives ───────────────────── *
 *
 * The colour helpers below (IP / SSID / brand / alert-hot) are shared by
 * both backends, so they are written against these four operations
 * rather than against ncurses directly. Under WITH_NCURSES they are the
 * curses calls; otherwise they emit SGR sequences resolved through
 * tui_pair_colors(). Before #48 the helpers called attrset/addstr
 * unconditionally and the no-ncurses build simply did not compile. */
#ifdef WITH_NCURSES

static void t_pair(int pair)      { attrset(COLOR_PAIR(pair)); }
static void t_pair_bold(int pair) { attrset(COLOR_PAIR(pair) | A_BOLD); }
static void t_puts(const char *s) { t_emit(s, -1); }
static void t_putn(const char *s, int n) { t_emit(s, n); }
static void t_putc(char c)        { addch((chtype)(unsigned char)c); }

#else

/* SGR: reset, then 256-colour fg (and bg only where a pair defines one
 * — every pair but CP_HIGHLIGHT renders on the terminal default). An
 * unmapped pair falls back to the phosphor normal so text is never
 * emitted with whatever attribute happened to be live. */
static void t_pair_attr(int pair, int bold) {
    if (!tui_color_enabled()) return;
    short fg = TUI_C_NORMAL, bg = -1;
    tui_pair_colors(pair, &fg, &bg);
    printf("\033[0m");
    if (bold) printf("\033[1m");
    printf("\033[38;5;%dm", (int)fg);
    if (bg >= 0) printf("\033[48;5;%dm", (int)bg);
}

static void t_pair(int pair)      { t_pair_attr(pair, 0); }
static void t_pair_bold(int pair) { t_pair_attr(pair, 1); }
static void t_puts(const char *s) { tui_fputs_sanitized(stdout, s, -1); }
static void t_putn(const char *s, int n) { tui_fputs_sanitized(stdout, s, n); }
static void t_putc(char c)        { fputc(c, stdout); }

#endif /* WITH_NCURSES */

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
    t_pair(cp_for_bg_cat(cat));
}

/* Monitor-sourced rows: same phosphor levels, dark grey bg. Backend-
 * neutral — the ANSI path resolves the bg via tui_pair_colors(). */
void tui_mon_bright(void) { t_pair(CP_MON_ROW_BRIGHT); }
void tui_mon_normal(void) { t_pair(CP_MON_ROW); }
void tui_mon_dim(void)    { t_pair(CP_MON_ROW_DIM); }

void tui_ip_addstr(const char *ip, int cat) {
    extern int ip_color_index(const char *);              /* ip_color.h */
    extern int ip_index_is_cross_panel(const char *);
    if (!ip || !ip[0]) return;
    /* Alert-hot override: any IP that has appeared in a CRIT alert
     * within the last ALERT_HOT_TTL_S seconds renders in deep red,
     * regardless of hash colour, brand colour, or cross-panel
     * highlight. Checked before everything else so it always wins. */
    int hot_sev = tui_alert_hot_check(ip);
    if (hot_sev >= 0) {
        tui_alert_hot_attr(hot_sev);
        t_puts(ip);
        return;
    }
    /* Cross-panel highlight: when the dashboard's conn panel has focus
     * its selected row's IPs go through tui_set_highlight_ips() — every
     * other panel that renders one of them swaps to CP_HIGHLIGHT so the
     * same flow lights up across the dashboard. */
    extern int tui_ip_is_highlighted_(const char *);
    if (tui_ip_is_highlighted_(ip)) {
        t_pair(CP_HIGHLIGHT);
        t_puts(ip);
        return;
    }
    int idx  = ip_color_index(ip);
    int pair = cp_for_ip_on_cat(cat, idx);
    if (ip_index_is_cross_panel(ip)) t_pair_bold(pair);
    else                             t_pair(pair);
    t_puts(ip);
}

/* Static state + matcher — exposed via tui_set_highlight_ips(). The
 * underscore-suffixed checker is referenced by tui_ip_addstr above. */
static char g_hl_a[46];
static char g_hl_b[46];

void tui_set_highlight_ips(const char *a, const char *b) {
    if (a && a[0]) snprintf(g_hl_a, sizeof(g_hl_a), "%s", a); else g_hl_a[0] = '\0';
    if (b && b[0]) snprintf(g_hl_b, sizeof(g_hl_b), "%s", b); else g_hl_b[0] = '\0';
}

int tui_ip_is_highlighted_(const char *ip) {
    if (!ip || !ip[0]) return 0;
    if (g_hl_a[0] && strcmp(g_hl_a, ip) == 0) return 1;
    if (g_hl_b[0] && strcmp(g_hl_b, ip) == 0) return 1;
    return 0;
}

/* ── Alert-hot IP override ───────────────────────────────── *
 * Small flat table. ALERT_HOT_CAP is generous (256) — even a
 * very alerty session won't fill it within a TTL window, and
 * lookup is linear which is fine at draw rates. */
#define ALERT_HOT_CAP 256

struct alert_hot_slot {
    char ip[46];   /* INET6_ADDRSTRLEN */
    long t;        /* epoch seconds — when this alert was last seen */
    int  sev;      /* alert_sev_t: 0=LOW, 1=WARN, 2=CRIT */
};

static struct alert_hot_slot g_alert_hot[ALERT_HOT_CAP];
static int                   g_alert_hot_n = 0;

void tui_alert_hot_set(const char *ip, long t, int sev) {
    if (!ip || !ip[0]) return;
    if (sev < ALERT_SEV_LOW)  sev = ALERT_SEV_LOW;
    if (sev > ALERT_SEV_CRIT) sev = ALERT_SEV_CRIT;
    for (int i = 0; i < g_alert_hot_n; i++) {
        if (strcmp(g_alert_hot[i].ip, ip) == 0) {
            if (t   > g_alert_hot[i].t)   g_alert_hot[i].t   = t;
            /* Promotion only — a later LOW alert must not override an
             * earlier CRIT on the same IP within the TTL window. */
            if (sev > g_alert_hot[i].sev) g_alert_hot[i].sev = sev;
            return;
        }
    }
    if (g_alert_hot_n < ALERT_HOT_CAP) {
        snprintf(g_alert_hot[g_alert_hot_n].ip,
                 sizeof(g_alert_hot[g_alert_hot_n].ip), "%s", ip);
        g_alert_hot[g_alert_hot_n].t   = t;
        g_alert_hot[g_alert_hot_n].sev = sev;
        g_alert_hot_n++;
        return;
    }
    /* Table full — replace the oldest entry (lowest t). Bounded scan
     * since the table is small. */
    int oldest = 0;
    for (int i = 1; i < g_alert_hot_n; i++)
        if (g_alert_hot[i].t < g_alert_hot[oldest].t) oldest = i;
    snprintf(g_alert_hot[oldest].ip,
             sizeof(g_alert_hot[oldest].ip), "%s", ip);
    g_alert_hot[oldest].t   = t;
    g_alert_hot[oldest].sev = sev;
}

int tui_alert_hot_check(const char *ip) {
    if (!ip || !ip[0] || g_alert_hot_n == 0) return -1;
    long now = (long)sloth_wall();
    for (int i = 0; i < g_alert_hot_n; i++) {
        if (strcmp(g_alert_hot[i].ip, ip) != 0) continue;
        if (now - g_alert_hot[i].t > ALERT_HOT_TTL_S) return -1;
        return g_alert_hot[i].sev;
    }
    return -1;
}

void tui_alert_hot_clear(void) {
    g_alert_hot_n = 0;
}

void tui_alert_hot_attr(int sev) {
    int pair = (sev >= ALERT_SEV_CRIT) ? CP_ALERT_HOT_CRIT
             : (sev >= ALERT_SEV_WARN) ? CP_ALERT_HOT_WARN
             :                            CP_ALERT_HOT_LOW;
    /* Bold on WARN+CRIT so they pop above LOW (yellow) noise. */
    if (sev >= ALERT_SEV_WARN) t_pair_bold(pair);
    else                       t_pair(pair);
}

void tui_ssid_addstr(const char *ssid, int cat) {
    extern int ip_color_index(const char *);
    if (!ssid || !ssid[0]) return;
    int idx = ip_color_index(ssid);
    t_pair(cp_for_ip_on_cat(cat, idx));
    t_puts(ssid);
}

/* ── Brand colourisation ─────────────────────────────────── */

static int cp_for_brand_on_cat(int cat, int brand_idx) {
    brand_idx &= 15;
    /* Slots 8..15 (corporate-identity additions) live in the
     * default-bg-only CP_BR_EXTRA_BASE bank. */
    if (brand_idx >= 8) {
        (void)cat;
        return CP_BR_EXTRA_BASE + (brand_idx - 8);
    }
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
    return base + brand_idx;
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
    /* Curated host -> brand colour table. Substring match, case-insensitive.
     * BR_GOOGLE_BLUE renders the matched substring in the Google logo's
     * letter cycle; everything else uses the single colour for its slot.
     * Add freely — order doesn't matter (the earliest match position in
     * the input wins, ties go to the first table entry). */
    static const struct { int brand; const char *sub; } tbl[] = {
        /* Google + its many surfaces */
        { BR_GOOGLE_BLUE, "google"            },
        { BR_GOOGLE_BLUE, "youtu"             },   /* youtube / youtu.be */
        { BR_GOOGLE_BLUE, "gmail"             },
        { BR_GOOGLE_BLUE, "ytimg"             },
        { BR_GOOGLE_BLUE, "gstatic"           },
        { BR_GOOGLE_BLUE, "googleusercontent" },
        /* Mozilla family */
        { BR_FIREFOX,     "firefox"           },
        { BR_FIREFOX,     "mozilla"           },
        { BR_FIREFOX,     "duckduckgo"        },
        { BR_FIREFOX,     "anthropic"         },
        { BR_FIREFOX,     "claude"            },
        /* Generic reds (CLOUDFLARE slot) */
        { BR_CLOUDFLARE,  "cloudflare"        },
        { BR_CLOUDFLARE,  "datadoghq"         },
        { BR_CLOUDFLARE,  "pinterest"         },
        { BR_CLOUDFLARE,  "adobe"             },
        { BR_CLOUDFLARE,  "ebay"              },
        { BR_CLOUDFLARE,  "debian"            },
        { BR_CLOUDFLARE,  "npmjs"             },
        /* example.com placeholders + grey/black brands */
        { BR_EXAMPLE,     "example.org"       },
        { BR_EXAMPLE,     "example.com"       },
        { BR_EXAMPLE,     "example.net"       },
        { BR_EXAMPLE,     "github"            },
        { BR_EXAMPLE,     "apple"             },
        { BR_EXAMPLE,     "icloud"            },
        { BR_EXAMPLE,     "wikipedia"         },
        /* Discord */
        { BR_DISCORD,     "discord"           },
        /* Facebook / Meta + similar-blue brands */
        { BR_FACEBOOK,    "facebook"          },
        { BR_FACEBOOK,    "fbcdn"             },
        { BR_FACEBOOK,    "fb.com"            },
        { BR_FACEBOOK,    "twitter"           },
        { BR_FACEBOOK,    "twimg"             },
        { BR_FACEBOOK,    "dropbox"           },
        { BR_FACEBOOK,    "paypal"            },
        { BR_FACEBOOK,    "zoom.us"           },
        /* Spotify + greens */
        { BR_SPOTIFY,     "spotify"           },
        { BR_SPOTIFY,     "whatsapp"          },
        { BR_SPOTIFY,     "openai"            },
        { BR_SPOTIFY,     "chatgpt"           },
        { BR_SPOTIFY,     "shopify"           },
        { BR_SPOTIFY,     "xbox"              },
        /* Twitch + purple brands */
        { BR_TWITCH,      "twitch"            },
        { BR_TWITCH,      "yahoo"             },
        /* Amazon + amber brands */
        { BR_AMAZON,      "amazon"            },
        { BR_AMAZON,      "amazonaws"         },
        { BR_AMAZON,      "aws.amazon"        },
        { BR_AMAZON,      "a2z.com"           },
        { BR_AMAZON,      "stackoverflow"     },
        { BR_AMAZON,      "ubuntu"            },
        /* LinkedIn / Microsoft */
        { BR_LINKEDIN,    "linkedin"          },
        { BR_LINKEDIN,    "microsoft"         },
        { BR_LINKEDIN,    "msftncsi"          },
        { BR_LINKEDIN,    "windowsupdate"     },
        /* Netflix */
        { BR_NETFLIX,     "netflix"           },
        { BR_NETFLIX,     "nflx"              },
        /* Reddit */
        { BR_REDDIT,      "reddit"            },
        { BR_REDDIT,      "redd.it"           },
        /* Instagram / TikTok / Snapchat — pink/magenta cluster */
        { BR_INSTAGRAM,   "instagram"         },
        { BR_INSTAGRAM,   "cdninstagram"      },
        { BR_INSTAGRAM,   "tiktok"            },
        { BR_INSTAGRAM,   "snapchat"          },
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
        t_pair(cp_for_bg_cat(cat));
        t_puts(text);
        return;
    }

    /* Prefix in default colour */
    if (start > 0) {
        t_pair(cp_for_bg_cat(cat));
        t_putn(text, start);
    }

    if (brand == BR_GOOGLE_BLUE) {
        /* G-o-o-g-l-e: blue / red / yellow / blue / green / red */
        static const int gseq[] = {
            BR_GOOGLE_BLUE, BR_GOOGLE_RED, BR_GOOGLE_YELLOW,
            BR_GOOGLE_BLUE, BR_GOOGLE_GREEN, BR_GOOGLE_RED,
        };
        for (int i = 0; i < mlen; i++) {
            int slot = gseq[i % 6];
            t_pair(cp_for_brand_on_cat(cat, slot));
            t_putc(text[start + i]);
        }
    } else {
        t_pair(cp_for_brand_on_cat(cat, brand));
        t_putn(text + start, mlen);
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
        t_pair(CP_NORMAL);
        return;
    }
    int idx = ip_color_index(info);
    t_pair(CP_INFO_BASE + (idx & 7));
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

/* Generated from include/sloth_views.def (#117): every row's slug names
 * view_<slug>_draw, so a view added to the list without a draw function
 * fails to compile here. No `default:`, so -Wswitch names any view_t
 * value the expansion misses. */
static void dispatch_view(const sloth_state_t *s) {
    switch (s->active_view) {
#define X(id, label, key, slug) case VIEW_##id: view_##slug##_draw(s); break;
#include "sloth_views.def"
#undef X
    case VIEW_COUNT: break;
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

/* Shared by tui_init() and tui_init_offscreen(), so the test binary
 * renders with the same pair table the operator's terminal gets. */
static void init_palette(void) {
    if (has_colors() && tui_color_enabled()) {
        start_color();
        if (COLORS >= 256) {
            /* Colours come from tui_palette.c so the ANSI fallback
             * renders the same phosphor (#48). */
            /* nuclear teal-green pairs */
            init_pair(CP_BRIGHT, TUI_C_BRIGHT, 0);
            init_pair(CP_NORMAL, TUI_C_NORMAL, 0);
            init_pair(CP_DIM,    TUI_C_DIM,    0);
            /* heat gradient pairs: grey → amber → orange → red */
            init_pair(CP_HEAT_LO,   TUI_C_HEAT_LO,   0);
            init_pair(CP_HEAT_MID,  TUI_C_HEAT_MID,  0);
            init_pair(CP_HEAT_HI,   TUI_C_HEAT_HI,   0);
            init_pair(CP_HEAT_PEAK, TUI_C_HEAT_PEAK, 0);
            /* Backgrounds disabled: every row sits on the terminal's
             * default bg. Hue and category cues are carried entirely by
             * the IP / brand / SSID foreground palettes. */
            short grey_bg[7] = { 0, 0, 0, 0, 0, 0, 0 };
            /* 8 IP fg colours × 5 row bgs — palette in tui_palette.c. */
            const short *ip_fg = tui_ip_fg;
            for (int i = 0; i < 8; i++) {
                init_pair(CP_IP_BASE_OTHER + i, ip_fg[i], grey_bg[0]);
                init_pair(CP_IP_BASE_TCP   + i, ip_fg[i], grey_bg[1]);
                init_pair(CP_IP_BASE_UDP   + i, ip_fg[i], grey_bg[2]);
                init_pair(CP_IP_BASE_DNS   + i, ip_fg[i], grey_bg[3]);
                init_pair(CP_IP_BASE_ICMP  + i, ip_fg[i], grey_bg[4]);
                init_pair(CP_IP_BASE_HTTP  + i, ip_fg[i], grey_bg[5]);
                init_pair(CP_IP_BASE_TLS   + i, ip_fg[i], grey_bg[6]);
            }
            /* Brand colour palette — 16 slots; indices map to BR_* in
             * tui.h, colours in tui_palette.c. Slots 0..7 mirror the
             * original layout (per-cat pairs); slots 8..15 are the
             * corporate-identity additions and live only on the
             * default-bg pair range CP_BR_EXTRA_BASE..+7. */
            const short *brand_fg = tui_brand_fg;
            for (int i = 0; i < 8; i++) {
                init_pair(CP_BR_BASE_OTHER + i, brand_fg[i], grey_bg[0]);
                init_pair(CP_BR_BASE_TCP   + i, brand_fg[i], grey_bg[1]);
                init_pair(CP_BR_BASE_UDP   + i, brand_fg[i], grey_bg[2]);
                init_pair(CP_BR_BASE_DNS   + i, brand_fg[i], grey_bg[3]);
                init_pair(CP_BR_BASE_ICMP  + i, brand_fg[i], grey_bg[4]);
                init_pair(CP_BR_BASE_HTTP  + i, brand_fg[i], grey_bg[5]);
                init_pair(CP_BR_BASE_TLS   + i, brand_fg[i], grey_bg[6]);
            }
            /* Slots 8..15 — default bg only, at CP_BR_EXTRA_BASE. */
            for (int i = 0; i < 8; i++)
                init_pair(CP_BR_EXTRA_BASE + i, brand_fg[8 + i], 0);
            /* Earth-tone palette for the packets info column. */
            for (int i = 0; i < 8; i++)
                init_pair(CP_INFO_BASE + i, tui_info_fg[i], 0);
            /* Border pair: same hue family as CP_DIM (user wanted the
             * original dim phosphor — not the darker variant). */
            init_pair(CP_BORDER, TUI_C_BORDER, 0);
            /* Cross-panel highlight: white-on-dim-phosphor.
             *   xterm 22 = #005f00 ~ 22% green = roughly 10-15% of cursor
             *   brightness (cursor is CP_BRIGHT = #00ffaf). */
            init_pair(CP_HIGHLIGHT, TUI_C_HL_FG, TUI_C_HL_BG);
            /* Alert-hot IP — three-tier palette. Same hue family as the
             * heat gradient so the eye reads them as escalating danger:
             *   LOW  = xterm 220 (#ffd700) bright amber-yellow
             *   WARN = xterm 208 (#ff8700) orange (matches CP_HEAT_HI)
             *   CRIT = xterm 196 (#ff0000) red    (matches CP_HEAT_PEAK)
             * Render sites OR A_BOLD on WARN and CRIT so the eye picks
             * them out from yellow noise. */
            init_pair(CP_ALERT_HOT_LOW,  TUI_C_HOT_LOW,  0);
            init_pair(CP_ALERT_HOT_WARN, TUI_C_HOT_WARN, 0);
            init_pair(CP_ALERT_HOT_CRIT, TUI_C_HOT_CRIT, 0);

            init_pair(CP_MON_ROW,        TUI_C_NORMAL, TUI_C_MON_BG);
            init_pair(CP_MON_ROW_DIM,    TUI_C_DIM,    TUI_C_MON_BG);
            init_pair(CP_MON_ROW_BRIGHT, TUI_C_BRIGHT, TUI_C_MON_BG);
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
            init_pair(CP_HIGHLIGHT, COLOR_WHITE, COLOR_GREEN);
            /* 8-colour fallback — three-tier alert-hot palette. */
            init_pair(CP_ALERT_HOT_LOW,  COLOR_YELLOW, COLOR_BLACK);
            init_pair(CP_ALERT_HOT_WARN, COLOR_YELLOW, COLOR_BLACK);
            init_pair(CP_ALERT_HOT_CRIT, COLOR_RED,    COLOR_BLACK);

            /* No dark grey in the 8-colour cube — white bg would shout,
             * so monitor rows fall back to plain phosphor on black. */
            init_pair(CP_MON_ROW,        COLOR_GREEN, COLOR_BLACK);
            init_pair(CP_MON_ROW_DIM,    COLOR_GREEN, COLOR_BLACK);
            init_pair(CP_MON_ROW_BRIGHT, COLOR_GREEN, COLOR_BLACK);
        }
    }
}

void tui_init(void) {
    setlocale(LC_ALL, "");  /* must precede initscr() for UTF-8 to work */
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    init_palette();
}

/* ── Offscreen screen for the test binary (#116) ─────────── *
 *
 * The suite used to link a no-op renderer and build every view with
 * TPRINT as printf, a configuration no operator runs. This gives it the
 * shipped one instead: a real ncurses SCREEN whose terminal output goes
 * to /dev/null, read back cell by cell. TPRINT is tui_printf (sanitise,
 * then addstr) onto stdscr either way, so what a test reads is what
 * `sloth` would have drawn.
 *
 * use_env(FALSE) keeps LINES/COLUMNS from the caller's environment out
 * of the geometry; resize_term() then sets the size the test asked for.
 * Terminal names are tried best first: xterm-256color takes the
 * 256-colour pair table tui_init() would, and a host without it still
 * renders text on the plainer entries. LC_CTYPE only — the wide-char
 * path needs a UTF-8 ctype, and nothing else should move under the
 * tests. */
static SCREEN *g_off_scr;
static FILE   *g_off_null;   /* one stream, both directions */

int tui_init_offscreen(int rows, int cols) {
    static const char *terms[] = { "xterm-256color", "xterm", "vt100", "dumb" };
    if (g_off_scr) return resize_term(rows, cols) == OK ? 0 : -1;
    if (!setlocale(LC_CTYPE, "C.UTF-8")) setlocale(LC_CTYPE, "");
    g_off_null = fopen("/dev/null", "r+");
    if (!g_off_null) {
        tui_offscreen_end();
        return -1;
    }
    use_env(FALSE);
    for (size_t i = 0; i < sizeof(terms) / sizeof(terms[0]) && !g_off_scr; i++)
        g_off_scr = newterm(terms[i], g_off_null, g_off_null);
    if (!g_off_scr) {
        tui_offscreen_end();
        return -1;
    }
    set_term(g_off_scr);
    if (resize_term(rows, cols) != OK) {
        tui_offscreen_end();
        return -1;
    }
    init_palette();
    erase();
    return 0;
}

void tui_offscreen_end(void) {
    if (g_off_scr) {
        endwin();
        delscreen(g_off_scr);
        g_off_scr = NULL;
    }
    if (g_off_null) { fclose(g_off_null); g_off_null = NULL; }
}

void tui_test_erase(void) {
    if (!g_off_scr) return;
    erase();
    attrset(A_NORMAL);
    move(0, 0);
}

/* Alternate-charset cells (hline(ACS_HLINE), box()) hold the VT100
 * line-drawing letter, not the glyph the terminal shows; a test reads
 * the glyph. Only the letters sloth's ACS_* uses are mapped. */
static wchar_t acs_glyph(wchar_t c) {
    switch (c) {
    case L'q': return 0x2500;  /* U+2500 light horizontal */
    case L'x': return 0x2502;  /* U+2502 light vertical */
    case L'l': return 0x250C;
    case L'k': return 0x2510;
    case L'm': return 0x2514;
    case L'j': return 0x2518;
    case L't': return 0x251C;
    case L'u': return 0x2524;
    case L'w': return 0x252C;
    case L'v': return 0x2534;
    case L'n': return 0x253C;
    default:   return c;
    }
}

/* Row y as UTF-8, trailing blanks trimmed. Read cell by cell through
 * the wide-char API so a box-drawing glyph comes back as the glyph, not
 * as the low byte of its cell. The cursor is restored: a view mid-draw
 * must not notice it was read. */
int tui_test_line(int y, char *out, size_t n) {
    if (!out || n == 0) return -1;
    out[0] = '\0';
    if (!g_off_scr || y < 0 || y >= LINES) return -1;
    int cy, cx;
    getyx(stdscr, cy, cx);
    size_t len = 0;
    int full = 0;
    mbstate_t st;
    memset(&st, 0, sizeof(st));
    for (int x = 0; x < COLS && !full; x++) {
        cchar_t cc;
        wchar_t wch[CCHARW_MAX + 1];
        attr_t  attr;
        short   pair;
        if (mvin_wch(y, x, &cc) == ERR) break;
        if (getcchar(&cc, wch, &attr, &pair, NULL) == ERR) continue;
        if (attr & A_ALTCHARSET) wch[0] = acs_glyph(wch[0]);
        for (int i = 0; wch[i] && !full; i++) {
            char mb[MB_LEN_MAX];
            size_t k = wcrtomb(mb, wch[i], &st);
            if (k == (size_t)-1) { mb[0] = '?'; k = 1; memset(&st, 0, sizeof(st)); }
            if (len + k >= n) { full = 1; break; }
            memcpy(out + len, mb, k);
            len += k;
        }
    }
    move(cy, cx);
    while (len > 0 && out[len - 1] == ' ') len--;
    out[len] = '\0';
    return (int)len;
}

int tui_test_rows(void) { return g_off_scr ? LINES : 0; }

/* Cell attributes, so a test can see a decision the view makes only in
 * colour or reverse video — invisible to every test before #116. */
static int off_cell_attr(int y, int x, attr_t *attr, short *pair) {
    if (!g_off_scr || y < 0 || y >= LINES || x < 0 || x >= COLS) return -1;
    cchar_t cc;
    wchar_t wch[CCHARW_MAX + 1];
    int cy, cx;
    getyx(stdscr, cy, cx);
    int rc = mvin_wch(y, x, &cc);
    move(cy, cx);
    if (rc == ERR) return -1;
    return getcchar(&cc, wch, attr, pair, NULL) == ERR ? -1 : 0;
}

int tui_test_is_reverse(int y, int x) {
    attr_t a; short p;
    if (off_cell_attr(y, x, &a, &p) != 0) return -1;
    return (a & A_REVERSE) ? 1 : 0;
}

int tui_test_pair(int y, int x) {
    attr_t a; short p;
    if (off_cell_attr(y, x, &a, &p) != 0) return -1;
    return (int)p;
}

/* Every row joined by '\n', for a needle whose row a test cannot know
 * in advance. Trailing empty rows are dropped. */
int tui_test_screen(char *out, size_t n) {
    if (!out || n == 0) return -1;
    out[0] = '\0';
    if (!g_off_scr) return -1;
    size_t len = 0, keep = 0;
    char line[4096];
    for (int y = 0; y < LINES; y++) {
        int k = tui_test_line(y, line, sizeof(line));
        if (k < 0) k = 0;
        if (len + (size_t)k + 2 > n) break;
        memcpy(out + len, line, (size_t)k);
        len += (size_t)k;
        if (k > 0) keep = len;
        out[len++] = '\n';
    }
    len = keep;
    out[len] = '\0';
    return (int)len;
}

void tui_test_dump(FILE *fp) {
    char line[4096];
    if (!fp) return;
    int last = -1;
    for (int y = 0; y < tui_test_rows(); y++)
        if (tui_test_line(y, line, sizeof(line)) > 0) last = y;
    for (int y = 0; y <= last; y++) {
        tui_test_line(y, line, sizeof(line));
        fprintf(fp, "%3d|%s\n", y, line);
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
    tui_printf("%s", banner);
    x = banner_w;

    /* #96: a sink that cannot persist is a sensor-level fault, so the
     * badge rides the tab bar rather than any one view, in the alert
     * grade.
     *
     * The bar is not on every screen: tui_draw() returns early for
     * VIEW_DASH, the startup view, which draws no tab bar. The
     * dashboard therefore draws the same badge itself, on its
     * Interfaces title rule (draw_persist_badge in
     * src/views/dashboard_bands.c). The ANSI fallback below draws the
     * bar on every view. */
    char persist[96];
    if (persist_badge(&s->persist_health, persist, sizeof(persist)) > 0) {
        tui_heat(1.0);
        tui_printf("  %s", persist);
        x += (int)strlen(persist) + 2;
        tui_bright();
    }

    for (int i = 0; i < VIEW_COUNT; i++) {
        /* "  [n] Label "  ≈ 2 sep + 2 label-padding + label width */
        int lbl_w = (int)strlen(view_label((view_t)i)) + 4;
        if (x + lbl_w >= max_x) {
            y++; x = 0;
            move(y, x);
        }
        tui_dim();   tui_printf("  ");
        if (i == (int)s->active_view) tui_sel(); else tui_dim();
        tui_printf(" %s ", view_label((view_t)i));
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

int tui_poll_key(int timeout_ms, int wake_fd) {
    /* Watch stdin and the optional wake fd in one select() so a
     * non-key wakeup (alert fire, future event-driven hooks) breaks
     * the wait early and the next redraw lands within ms. */
    fd_set fds; FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    int maxfd = STDIN_FILENO;
    if (wake_fd >= 0) {
        FD_SET(wake_fd, &fds);
        if (wake_fd > maxfd) maxfd = wake_fd;
    }
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(maxfd + 1, &fds, NULL, NULL, &tv) <= 0)
        return 0;
    /* If only the wake fd is ready, return 0 — the main loop will
     * redraw on the next iteration. The wake byte is drained by
     * the caller via event_wake_drain. */
    if (!FD_ISSET(STDIN_FILENO, &fds))
        return 0;
    /* Drain a single key from ncurses without blocking. */
    timeout(0);
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

/* nuclear teal-green: rgb(0, 215, 130) bright / rgb(0, 175, 105) normal / rgb(0, 100, 58) dim
 *
 * Every one of these is a no-op under --no-color / NO_COLOR (#50), so a
 * run whose output is being read by a log shipper rather than a
 * terminal carries no escape sequences at all. */
void tui_bright(void) { if (tui_color_enabled()) printf("\033[38;2;0;215;130m\033[1m"); }
void tui_normal(void) { if (tui_color_enabled()) printf("\033[0m\033[38;2;0;175;105m"); }
void tui_dim(void)    { if (tui_color_enabled()) printf("\033[0m\033[38;2;0;100;58m");  }
void tui_sel(void)    { if (tui_color_enabled()) printf("\033[0m\033[38;2;0;175;105m\033[7m"); }
void tui_reset(void)  { if (tui_color_enabled()) printf("\033[0m\033[38;2;0;175;105m"); }

/* heat gradient: grey → amber → orange → red */
void tui_heat(double frac) {
    if (!tui_color_enabled()) return;
    if      (frac < 0.15) printf("\033[38;2;98;98;98m");
    else if (frac < 0.40) printf("\033[38;2;215;175;0m");
    else if (frac < 0.70) printf("\033[38;2;255;135;0m");
    else                  printf("\033[38;2;220;20;0m");
}

/* No screen to read back without ncurses: the offscreen API exists so
 * the link-only no-flag test build (sloth_test_noflags, #116) resolves,
 * and reports failure if anything ever does call it. */
int  tui_init_offscreen(int rows, int cols) { (void)rows; (void)cols; return -1; }
void tui_offscreen_end(void) {}
void tui_test_erase(void) {}
int  tui_test_line(int y, char *out, size_t n) {
    (void)y;
    if (out && n) out[0] = '\0';
    return -1;
}
int  tui_test_rows(void) { return 0; }
int  tui_test_is_reverse(int y, int x) { (void)y; (void)x; return -1; }
int  tui_test_pair(int y, int x) { (void)y; (void)x; return -1; }
int  tui_test_screen(char *out, size_t n) {
    if (out && n) out[0] = '\0';
    return -1;
}
void tui_test_dump(FILE *fp) { (void)fp; }

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
    if (tui_color_enabled()) printf("\033[0m");
    printf("\n");
}

static void draw_tabbar(const sloth_state_t *s) {
    tui_bright(); printf(" sloth v" SLOTH_VERSION);
    /* #96: same cannot-persist badge as the ncurses bar. */
    char persist[96];
    if (persist_badge(&s->persist_health, persist, sizeof(persist)) > 0) {
        tui_heat(1.0);
        printf("  %s", persist);
        tui_bright();
    }
    for (int i = 0; i < VIEW_COUNT; i++) {
        tui_dim(); printf("  ");
        if (i == (int)s->active_view) tui_sel(); else tui_dim();
        printf(" %s ", view_label((view_t)i));
    }
    tui_dim(); printf("  [Tab] cycle  [q]uit\n");
    printf("------------------------------------------------------------\n");
    tui_normal();
}

void tui_draw(const sloth_state_t *s) {
    /* The screen clear is a cursor-addressing sequence, not colour, so
     * it is gated on the same switch: a consumer that asked for no
     * escape sequences does not want this one either. Redrawing without
     * it simply appends, which is what a log wants (#50). */
    if (tui_color_enabled()) printf("\033[2J\033[H");
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

int tui_poll_key(int timeout_ms, int wake_fd) {
    fd_set fds;
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    FD_ZERO(&fds);
    int maxfd = -1;

    /* Only wait on stdin when it is actually a terminal.
     *
     * Under systemd (or any `< /dev/null`) stdin is at EOF, which
     * select() reports as readable immediately — every time. read()
     * then returns 0, we return 0, and the caller loops straight back
     * in, so the timeout never applies and the poll loop spins a core
     * flat out. Measured at ~76k redraws in two seconds against an
     * intended ~10 (#50). Not a terminal means there are no keys to
     * read, so the honest thing is to wait out the interval. */
    int have_tty = isatty(STDIN_FILENO);
    if (have_tty) {
        FD_SET(STDIN_FILENO, &fds);
        maxfd = STDIN_FILENO;
    }
    if (wake_fd >= 0) {
        FD_SET(wake_fd, &fds);
        if (wake_fd > maxfd) maxfd = wake_fd;
    }
    if (maxfd < 0) {                 /* nothing to wait on but the clock */
        select(0, NULL, NULL, NULL, &tv);
        return 0;
    }
    if (select(maxfd + 1, &fds, NULL, NULL, &tv) <= 0)
        return 0;
    if (!have_tty || !FD_ISSET(STDIN_FILENO, &fds))
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
