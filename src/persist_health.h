#ifndef PERSIST_HEALTH_H
#define PERSIST_HEALTH_H

#include <stddef.h>
#include "sloth.h"

/* ── Cannot-persist state (#96) ───────────────────────────────────
 *
 * Every export sink already counts its own write failures and keeps
 * retrying (sfile_fail_t: one stderr line, then silence). The JSONL
 * sensor_health record sums them for a log consumer — but a console
 * operator watching the TUI had no signal at all unless they happened
 * to sit on the one view that renders its own sink's counter. A sensor
 * that detects but cannot persist is quietly not doing its job, which
 * is exactly the "cannot persist must be visible" bullet of #96.
 *
 * persist_health_poll() aggregates the per-sink lifetime counts once
 * per poll tick into the state snapshot (same pattern as
 * capture_health_poll); persist_badge() formats the tab-bar warning
 * from that snapshot, naming only the sinks that are failing. Pure,
 * so the badge is testable without a terminal. */

void persist_health_poll(persist_health_t *p);

/* Write the badge ("!persist jsonl:3 pcap:1 eapol:2") into buf,
 * listing only failing sinks. Returns the total failure count; 0
 * means healthy and buf is set to "". Truncation-safe for any sz > 0. */
int  persist_badge(const persist_health_t *p, char *buf, size_t sz);

#endif /* PERSIST_HEALTH_H */
