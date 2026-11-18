/* Hour-of-week presence per device, for G4's TUI form (#195;
 * docs/web-visual-spec.md §5 G4: "the Devices Enter detail can draw the
 * 7 by 24 grid").
 *
 * slothweb's G4 reads a baseline its rollup keeps across restarts; the
 * TUI has no such store, so this one is what this run has watched and
 * nothing more. A cell counts two things: the hours of that weekday and
 * hour the sensor was running (watched), and of those the hours the
 * device's record was refreshed (present). The share is present over
 * watched; an hour never watched is not an absence, and the grid says
 * which is which. Empty after every restart, and the detail says so.
 *
 * Cells are Monday-first in the sensor's local time, as the web's grid
 * is (app.js DAYS). */
#ifndef SLOTH_DEV_HOW_H
#define SLOTH_DEV_HOW_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

#define DEV_HOW_CELLS 168
/* Rows kept: one per device record, and a record dropped from the
 * device table keeps its row until a newer one needs the slot. */
#define DEV_HOW_MAX   (MAX_DEVICES * 2)

/* Monday-first cell of `t` in local time, 0..167. */
int  dev_how_cell(time_t t);
/* Once per poll, after devices_update(). */
void dev_how_observe(const sloth_state_t *s, time_t now);
/* The device's present counts and the sensor's watched counts. Returns
 * 1 when the device has a row, 0 when it has none (watched is filled
 * either way). */
int  dev_how_get(const uint8_t mac[6], uint16_t present[DEV_HOW_CELLS],
                 uint16_t watched[DEV_HOW_CELLS]);
void dev_how_clear(void);

#endif /* SLOTH_DEV_HOW_H */
