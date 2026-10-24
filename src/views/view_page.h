#ifndef VIEWS_VIEW_PAGE_H
#define VIEWS_VIEW_PAGE_H

#include "tui.h"

/* How many table rows a list view can draw (#150).
 *
 * Counted from the row the cursor is on, so whatever the view has
 * already drawn above its table - the tab bar, which wraps onto several
 * rows at the 100-column minimum, a status line that wrapped, a banner
 * that only appears sometimes - is already spent. `tail` is the rows the
 * view draws under its table (legend, footer, detail pane); a view
 * calls this after its column headers, so only the tail is its to
 * count.
 *
 * Each view used to compute `LINES - 5` (or 6, 12, 16) at the top of
 * its draw, as if the tab bar were one row. At 100x33 it is six, so
 * every page overran the screen: the selection could sit below the
 * last row and any legend under the table was never drawn.
 *
 * Never below 1, so a terminal too short for the chrome still shows
 * the selected row. The ANSI build has no screen to measure and keeps
 * the view's fixed page. */
#define VIEW_NO_TAIL 0

static inline int view_page_budget(int tail, int ansi_page) {
#ifdef WITH_NCURSES
    (void)ansi_page;
    int page = LINES - getcury(stdscr) - tail;
    return page < 1 ? 1 : page;
#else
    (void)tail;
    return ansi_page;
#endif
}

#endif /* VIEWS_VIEW_PAGE_H */
