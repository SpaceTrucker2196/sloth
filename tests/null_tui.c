/* No-op TUI for the test binary — no terminal, no ncurses */
#include "sloth.h"
#include "tui.h"

void tui_init(void)                  {}
void tui_cleanup(void)               {}
void tui_draw(const sloth_state_t *s) { (void)s; }
int  tui_poll_key(int ms)            { (void)ms; return 0; }

void tui_bright(void)        {}
void tui_normal(void)        {}
void tui_dim(void)           {}
void tui_sel(void)           {}
void tui_reset(void)         {}
void tui_heat(double frac)   { (void)frac; }
void tui_filter_status(const sloth_state_t *s) { (void)s; }
void tui_pkt_bg_cat(int cat) { (void)cat; }
void tui_pkt_bg(int proto, uint16_t sport, uint16_t dport) {
    (void)proto; (void)sport; (void)dport;
}
void tui_ip_addstr(const char *ip, int cat) { (void)ip; (void)cat; }
void tui_ssid_addstr(const char *ssid, int cat) { (void)ssid; (void)cat; }
void tui_brand_addstr(const char *text, int cat) { (void)text; (void)cat; }
void tui_info_color(const char *info)            { (void)info; }
void tui_set_highlight_ips(const char *a, const char *b) { (void)a; (void)b; }
int  tui_ip_is_highlighted_(const char *ip)      { (void)ip; return 0; }

void tui_bar(double val, double max, int width, char *out) {
    int filled = (max > 0.0) ? (int)((val / max) * width) : 0;
    if (filled > width) filled = width;
    for (int i = 0; i < width; i++)
        out[i] = (i < filled) ? '#' : '.';
    out[width] = '\0';
}
