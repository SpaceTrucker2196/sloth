#ifndef ALERTS_H
#define ALERTS_H

#include "sloth.h"

/* Walk the current state for trigger conditions, dedupe against any
 * previously-fired alerts, and copy the resulting set into s->alerts.
 * Safe to call once per poll. */
void alerts_update(sloth_state_t *s);

/* Drop all known alerts (clears engine state, not just the snapshot). */
void alerts_clear(void);

/* ── Tainted-BSSID tracker (evil-twin Phase 4) ─────────────────
 *
 * Maintained by rule_evil_twin_attack_chain when it correlates a
 * twin-fp pair with a DEAUTH_FLOOD targeting one half. The other
 * half (the rogue) is recorded here so downstream forensic exports
 * — currently the hashcat .22000 EAPOL writer — can mark the
 * provenance of any subsequent handshake against the tainted BSSID.
 *
 * Entries expire after EVIL_TWIN_TAINT_TTL_SECS. The tracker is
 * read-only outside alerts.c; the API is exposed here so eapol_log.c
 * can query it without taking a dep on alert internals. */
#define EVIL_TWIN_TAINT_TTL_SECS 300

int  evil_twin_bssid_is_tainted(const uint8_t bssid[6]);
/* Test-only: drop all tainted entries. */
void evil_twin_taint_clear(void);
/* Test-only: mark a BSSID tainted with the current wall clock — gives
 * tests a way to exercise downstream code paths (eapol provenance,
 * Twins view glyphs) without driving the full chain rule. */
void evil_twin_taint_mark_for_test(const uint8_t bssid[6]);

#endif /* ALERTS_H */
