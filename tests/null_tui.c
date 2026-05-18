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
void tui_pkt_bg(int proto)   { (void)proto; }

void tui_bar(double val, double max, int width, char *out) {
    int filled = (max > 0.0) ? (int)((val / max) * width) : 0;
    if (filled > width) filled = width;
    for (int i = 0; i < width; i++)
        out[i] = (i < filled) ? '#' : '.';
    out[width] = '\0';
}
