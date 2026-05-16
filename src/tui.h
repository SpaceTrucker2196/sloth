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

#endif /* TUI_H */
