/* Private header shared by dashboard.c, dashboard_primitives.c,
 * dashboard_bands.c, and dashboard_grid.c. Not part of the public
 * views/ interface — only the four dashboard translation units include it. */

#ifndef SLOTH_VIEWS_DASHBOARD_INTERNAL_H
#define SLOTH_VIEWS_DASHBOARD_INTERNAL_H

#include "sloth.h"

/* ── Layout constants ──────────────────────────────────────────── */

#define SPARK_W         24    /* sparkline width in glyph cells */
#define IFACE_FIXED_W   50    /* fixed text portion of the iface row */
#define CRIT_MAX_ROWS   5     /* visible cap for the CRIT alerts band */

/* ── Box-drawing / arrow glyphs (UTF-8) ────────────────────────── */

#define G_HORIZ "\xe2\x94\x80"   /* ─  U+2500 */
#define G_VERT  "\xe2\x94\x82"   /* │  U+2502 */
#define G_TL    "\xe2\x94\x8c"   /* ┌  U+250C */
#define G_TR    "\xe2\x94\x90"   /* ┐  U+2510 */
#define G_BL    "\xe2\x94\x94"   /* └  U+2514 */
#define G_BR    "\xe2\x94\x98"   /* ┘  U+2518 */
#define G_ARROW "\xe2\x86\x92"   /* →  U+2192 */

/* ── Panel-id enum (visible to both builds) ────────────────────── */

typedef enum {
    DASH_PANEL_IFACE = 0,
    DASH_PANEL_SUMMARY,
    DASH_PANEL_CONN,
    DASH_PANEL_TOP_HOSTS,
    DASH_PANEL_PACKETS,
    DASH_PANEL_WIFI,
    DASH_PANEL_ROAMING,
    DASH_PANEL_BEACONS,
    DASH_PANEL_MDNS,
    DASH_PANEL_DHCP,
    DASH_PANEL_SSDP,
    DASH_PANEL_ARP,
    DASH_PANEL_DEAUTH,
    DASH_PANEL_DNS,
    DASH_PANEL_ICMP,
    DASH_PANEL_CRIT_ALERTS,
    DASH_PANEL_COUNT
} dash_panel_t;

/* ── Per-frame shared state ────────────────────────────────────── */

/* Set at the top of view_dashboard_draw so panel_title can read it
 * without threading the state through every panel helper. */
extern int g_dash_focus;

/* Connections sort order — populated by draw_conn_band each frame,
 * read by the cross-panel highlight in view_dashboard_draw so
 * s->conn_sel (the ordinal in the sorted view) resolves back to the
 * underlying conn index. */
extern int g_conn_order_buf[MAX_CONNS];
extern int g_conn_order_n;

/* ── Always-compiled helpers (used by ncurses panels AND the ANSI
 *    fallback in dashboard.c) ──────────────────────────────────── */

void        fmt_bytes    (uint64_t b, char *buf, int sz);
const char *proto_short  (int p);
const char *dhcp_msg_name(uint8_t t);
const iface_hist_t *hist_lookup(const sloth_state_t *s, const char *name);

/* ── ncurses-only primitives + per-panel renderers ─────────────── */

#ifdef WITH_NCURSES

void draw_sparkline_at      (int y, int x, int width,
                             const double *vals, int head, int n);
void draw_sparkline_solid_at(int y, int x, int width,
                             const float *vals, int head, int n,
                             int color_pair);
void clipline               (int y, int x, int w, const char *fmt, ...);
void panel_title            (int y, int x, int w, const char *name, int panel_id);
void panel_title_passive    (int y, int x, int w, const char *name, int panel_id);

int  crit_alerts_count      (const sloth_state_t *s);

void draw_iface_band         (const sloth_state_t *s, int y0, int h, int x0, int w);
void draw_conn_band          (const sloth_state_t *s, int y0, int h, int x0, int w);
void draw_assoc_band         (const sloth_state_t *s, int y0, int h, int x0, int w);
void draw_top_hosts_panel    (const sloth_state_t *s, int y0, int h, int x0, int w);
void draw_packets_band       (const sloth_state_t *s, int y0, int h, int x0, int w);
void draw_crit_alerts_band   (const sloth_state_t *s, int y0, int h, int x0, int w);

void draw_wifi_panel         (const sloth_state_t *s, int y0, int h, int x, int w);
void draw_radio_clients_panel(const sloth_state_t *s, int y0, int h, int x, int w);
void draw_beacon_panel       (const sloth_state_t *s, int y0, int h, int x, int w);
void draw_mdns_panel         (const sloth_state_t *s, int y0, int h, int x, int w);
void draw_dhcp_panel         (const sloth_state_t *s, int y0, int h, int x, int w);
void draw_ssdp_panel         (const sloth_state_t *s, int y0, int h, int x, int w);
void draw_arp_panel          (const sloth_state_t *s, int y0, int h, int x, int w);
void draw_deauth_panel       (const sloth_state_t *s, int y0, int h, int x, int w);
void draw_stats_panel        (const sloth_state_t *s, int y0, int h, int x, int w);
void draw_dns_log_panel      (const sloth_state_t *s, int y0, int h, int x, int w);
void draw_icmp_log_panel     (const sloth_state_t *s, int y0, int h, int x, int w);

#endif /* WITH_NCURSES */

#endif /* SLOTH_VIEWS_DASHBOARD_INTERNAL_H */
