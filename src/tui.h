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

void tui_bright(void); /* intense glow: title, active values, key fields */
void tui_normal(void); /* standard phosphor: data rows                   */
void tui_dim(void);    /* faint glow: labels, borders, hints              */
void tui_sel(void);    /* reversed: selected row highlight                */
void tui_reset(void);  /* back to normal                                  */
void tui_heat(double frac); /* heat gradient 0=grey … 1=red              */

/* If a filter is set (or being edited), emit a small status label.
 * Call after the view-specific header text on the same line. */
void tui_filter_status(const sloth_state_t *s);

#endif /* TUI_H */
