#ifndef TUI_H
#define TUI_H

#include "sloth.h"

#ifdef WITH_NCURSES
#  include <curses.h>
#  define TPRINT printw
#else
#  define TPRINT printf
#endif

void tui_init(void);
void tui_cleanup(void);
void tui_draw(const sloth_state_t *s);
int  tui_poll_key(int timeout_ms); /* blocks up to timeout_ms, returns key or 0 */
void tui_bar(double val, double max, int width, char *out); /* block bar; out needs width*3+1 bytes */

/* ── Nuclear phosphor theme — 256-color pairs ───────────── */
#define CP_BRIGHT     1   /* #00ffaf rgb(0,255,175) — intense glow  */
#define CP_NORMAL     2   /* #00d7af rgb(0,215,175) — standard text */
#define CP_DIM        3   /* #00875f rgb(0,135,95)  — faint labels  */

/* ── Heat gradient — grey→amber→orange→red ──────────────── */
#define CP_HEAT_LO    4   /* xterm-256 241  rgb(98,98,98)   — idle  */
#define CP_HEAT_MID   5   /* xterm-256 178  rgb(215,175,0)  — warm  */
#define CP_HEAT_HI    6   /* xterm-256 208  rgb(255,135,0)  — hot   */
#define CP_HEAT_PEAK  7   /* xterm-256 196  rgb(255,0,0)    — peak  */

/* ── Packet-category row backgrounds (greyscale) ─────────── */
#define CP_PKT_TCP    8   /* very-dark grey  */
#define CP_PKT_UDP    9   /* dark grey       */
#define CP_PKT_DNS   10   /* medium-dark grey */
#define CP_PKT_ICMP  11   /* medium grey     */

/* ── IP-foreground palette × category-bg ─────────────────── *
 * 8 colours per row, 5 row-bg categories.  Pair number is
 *   CP_IP_BASE_<cat> + ip_color_index */
#define CP_IP_BASE_OTHER 16   /* on default bg     (16..23) */
#define CP_IP_BASE_TCP   24   /* on TCP grey       (24..31) */
#define CP_IP_BASE_UDP   32   /* on UDP grey       (32..39) */
#define CP_IP_BASE_DNS   40   /* on DNS grey       (40..47) */
#define CP_IP_BASE_ICMP  48   /* on ICMP grey      (48..55) */

/* ── Brand-name palette × category-bg ────────────────────── *
 * 8 brand colour slots per row, 5 row-bg categories.
 * Slot index meanings — see tui.c for the actual 256-colour codes:
 *   0 = Google blue        4 = Firefox orange
 *   1 = Google red         5 = Cloudflare red
 *   2 = Google yellow      6 = example.org grey
 *   3 = Google green       7 = (reserved) */
#define CP_BR_BASE_OTHER 56   /* on default bg (56..63) */
#define CP_BR_BASE_TCP   64   /* on TCP grey   (64..71) */
#define CP_BR_BASE_UDP   72   /* on UDP grey   (72..79) */
#define CP_BR_BASE_DNS   80   /* on DNS grey   (80..87) */
#define CP_BR_BASE_ICMP  88   /* on ICMP grey  (88..95) */

/* Brand-colour slot indices (match the layout above). */
#define BR_GOOGLE_BLUE    0
#define BR_GOOGLE_RED     1
#define BR_GOOGLE_YELLOW  2
#define BR_GOOGLE_GREEN   3
#define BR_FIREFOX        4
#define BR_CLOUDFLARE     5
#define BR_EXAMPLE        6

void tui_bright(void); /* intense glow: title, active values, key fields */
void tui_normal(void); /* standard phosphor: data rows                   */
void tui_dim(void);    /* faint glow: labels, borders, hints              */
void tui_sel(void);    /* reversed: selected row highlight                */
void tui_reset(void);  /* back to normal                                  */
void tui_heat(double frac); /* heat gradient 0=grey … 1=red              */

/* If a filter is set (or being edited), emit a small status label.
 * Call after the view-specific header text on the same line. */
void tui_filter_status(const sloth_state_t *s);

/* Set the row colour-pair to white-on-<cat>-grey. Caller passes the
 * pkt_category_t value (see ip_color.h). */
void tui_pkt_bg_cat(int cat);

/* Convenience: derive the category from proto + ports and set the bg. */
void tui_pkt_bg(int proto, uint16_t sport, uint16_t dport);

/* Render the IP string with its hash-derived colour, OR-ing A_BOLD if the
 * ip is "cross-panel" (appears in >1 source — see ip_color.h). Caller must
 * pass the current row category so the bg matches.
 *
 * On exit, the current attrset is whatever this function set — typically
 * the caller will restore the row's plain-bg pair before printing the
 * non-IP portion of the line. */
void tui_ip_addstr(const char *ip, int cat);

/* Like tui_ip_addstr but for SSID strings — uses the IP colour palette
 * with a separate hash, so the same SSID has the same colour everywhere. */
void tui_ssid_addstr(const char *ssid, int cat);

/* Render `text` with brand-name highlighting:
 *   "google"      -> G-o-o-g-l-e in B-R-Y-B-G-R per the Google logo
 *   "firefox"     -> orange
 *   "cloudflare"  -> red
 *   "example.org" -> grey
 * Non-matching characters render in the row's default white-on-cat pair.
 * Matches are case-insensitive. */
void tui_brand_addstr(const char *text, int cat);

#endif /* TUI_H */
