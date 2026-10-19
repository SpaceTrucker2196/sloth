#ifndef VIEWS_DASHBOARD_H
#define VIEWS_DASHBOARD_H

#include "sloth.h"

/* Tiled dashboard:
 *
 *  +-----------------------------------------------+
 *  |  Interfaces                                   |
 *  +-----------------------------------------------+
 *  |  Connections (scrollable)                     |
 *  |                                               |
 *  |                                               |
 *  +---------------+---------------+---------------+
 *  |  WiFi APs     |  Probe        |  Beacons      |
 *  +---------------+---------------+---------------+
 *
 * Up/Down scroll the connections panel (driven through s->conn_sel).
 * On ANSI builds the layout falls back to stacked sections.
 */
void view_dashboard_draw(const sloth_state_t *s);
void view_dashboard_key(sloth_state_t *s, int key);

/* Forget the packets band's cumulative info-string counts. They live for
 * the session by design; this exists for the reset registry (#114). */
void dashboard_info_clear(void);

#endif /* VIEWS_DASHBOARD_H */
