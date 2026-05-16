#ifndef TUI_H
#define TUI_H

#include "ntop.h"

#ifdef WITH_NCURSES
#  include <curses.h>
#  define TPRINT printw
#else
#  define TPRINT printf
#endif

void tui_init(void);
void tui_cleanup(void);
void tui_draw(const ntop_state_t *s);
int  tui_poll_key(int timeout_ms); /* blocks up to timeout_ms, returns key or 0 */
void tui_bar(double val, double max, int width, char *out); /* ASCII bar graph */

/* ── Nuclear phosphor theme — 256-color pairs ───────────── */
#define CP_BRIGHT 1   /* #00ffaf rgb(0,255,175) — intense glow  */
#define CP_NORMAL 2   /* #00d7af rgb(0,215,175) — standard text */
#define CP_DIM    3   /* #00875f rgb(0,135,95)  — faint labels  */

void tui_bright(void); /* intense glow: title, active values, key fields */
void tui_normal(void); /* standard phosphor: data rows                   */
void tui_dim(void);    /* faint glow: labels, borders, hints              */
void tui_sel(void);    /* reversed: selected row highlight                */
void tui_reset(void);  /* back to normal                                  */

#endif /* TUI_H */
