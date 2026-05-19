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

/* ── Packet-category row backgrounds (greyscale ramp) ────── */
#define CP_PKT_TCP    8   /* 10% */
#define CP_PKT_UDP    9   /* 15% */
#define CP_PKT_DNS   10   /* 20% */
#define CP_PKT_ICMP  11   /* 25% */
#define CP_PKT_HTTP  12   /* 30% */
#define CP_PKT_TLS   13   /* 35% */

/* ── IP-foreground palette × category-bg ─────────────────── *
 * 8 colours per row, 5 row-bg categories.  Pair number is
 *   CP_IP_BASE_<cat> + ip_color_index */
#define CP_IP_BASE_OTHER 16    /* on default bg (16..23)  */
#define CP_IP_BASE_TCP   24    /* on TCP grey   (24..31)  */
#define CP_IP_BASE_UDP   32    /* on UDP grey   (32..39)  */
#define CP_IP_BASE_DNS   40    /* on DNS grey   (40..47)  */
#define CP_IP_BASE_ICMP  48    /* on ICMP grey  (48..55)  */
#define CP_IP_BASE_HTTP  128   /* on HTTP grey  (128..135) */
#define CP_IP_BASE_TLS   136   /* on TLS grey   (136..143) */

/* ── Brand-name palette × category-bg ────────────────────── *
 * 8 brand colour slots per row, 5 row-bg categories.
 * Slot index meanings — see tui.c for the actual 256-colour codes:
 *   0 = Google blue        4 = Firefox orange
 *   1 = Google red         5 = Cloudflare red
 *   2 = Google yellow      6 = example.org grey
 *   3 = Google green       7 = (reserved) */
#define CP_BR_BASE_OTHER 56    /* on default bg (56..63)   */
#define CP_BR_BASE_TCP   64    /* on TCP grey   (64..71)   */
#define CP_BR_BASE_UDP   72    /* on UDP grey   (72..79)   */
#define CP_BR_BASE_DNS   80    /* on DNS grey   (80..87)   */
#define CP_BR_BASE_ICMP  88    /* on ICMP grey  (88..95)   */
#define CP_BR_BASE_HTTP  144   /* on HTTP grey  (144..151) */
#define CP_BR_BASE_TLS   152   /* on TLS grey   (152..159) */

/* ── Earth-tone palette for the packets-row info column ──── *
 * Low-key colours: mauve / olive / tan / sage / terracotta / wheat /
 * dusty-rose / stone. Same string -> same colour (djb2 hash). */
#define CP_INFO_BASE     96    /* (96..103) earth tones on default bg */

/* ── Panel border colour (very dim phosphor — see tui.c) ── */
#define CP_BORDER       104

/* ── Cross-panel highlight: 10% of cursor brightness ────── *
 * Applied to IPs that match the currently-selected connection
 * row's local/remote when the dashboard's conn panel has focus. */
#define CP_HIGHLIGHT    105

/* Extended brand-colour palette — pairs 160..167 for the new slots 8..15.
 * These render only on the default bg (per-cat variants would have
 * collided with the existing BR_BASE_<cat> ranges). */
#define CP_BR_EXTRA_BASE 160

/* Brand-colour slot indices.
 * 0..6 keep their original mapping for binary compat. 7 (was reserved)
 * + 8..15 are the new corporate-identity slots. */
#define BR_GOOGLE_BLUE    0    /* #0087ff blue   — Google logo letter 1+4   */
#define BR_GOOGLE_RED     1    /* #d75f5f red    — Google logo letter 2+6   */
#define BR_GOOGLE_YELLOW  2    /* #ffd700 yellow — Google logo letter 3     */
#define BR_GOOGLE_GREEN   3    /* #00af5f green  — Google logo letter 5     */
#define BR_FIREFOX        4    /* #ff8700 orange — Firefox / Mozilla         */
#define BR_CLOUDFLARE     5    /* #ff0000 red    — Cloudflare / YouTube      */
#define BR_EXAMPLE        6    /* #808080 grey   — example.com / GitHub      */
#define BR_DISCORD        7    /* #875fff blurple                            */
#define BR_FACEBOOK       8    /* #005fff blue   — Facebook / Twitter / Zoom */
#define BR_SPOTIFY        9    /* #00d75f green  — Spotify / WhatsApp        */
#define BR_TWITCH        10    /* #af5fff purple — Twitch / Yahoo            */
#define BR_AMAZON        11    /* #ffaf00 orange — Amazon / AWS              */
#define BR_LINKEDIN      12    /* #0087af blue   — LinkedIn / Microsoft      */
#define BR_NETFLIX       13    /* #af0000 deep red — Netflix                 */
#define BR_REDDIT        14    /* #ff5f00 orange — Reddit                    */
#define BR_INSTAGRAM     15    /* #d75faf pink   — Instagram / TikTok        */

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

/* Set the current attrset to the earth-tone pair for `info`. Used by
 * the packets band's info column so repeating values keep their colour.
 * NULL or empty info falls back to CP_NORMAL. */
void tui_info_color(const char *info);

/* Cross-panel highlight setter. The dashboard calls this each frame:
 * when the connections panel has focus and a row is selected, the
 * row's local + remote IPs are passed here; otherwise NULL/NULL is
 * passed and the highlight clears. tui_ip_addstr() picks these up
 * and renders matching IPs in CP_HIGHLIGHT instead of their hash
 * colour so the same flow lights up across every panel. */
void tui_set_highlight_ips(const char *a, const char *b);

#endif /* TUI_H */
