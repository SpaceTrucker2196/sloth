#ifndef SLOTH_ALERT_LIFECYCLE_H
#define SLOTH_ALERT_LIFECYCLE_H

/* The finding lifecycle (#245): preliminary, confirmed, withdrawn,
 * lapsed. The engine (src/alerts/engine.c) moves an incident between
 * the states; this module holds what it reads to do so and what it
 * counts while doing so.
 *
 *   preliminary  a listed kind's rule saw its first qualifying evidence,
 *                below today's threshold (fire_prelim()). One
 *                `alert.preliminary` record; detail opens "not
 *                evaluated: first evidence only". FM 2-0 (2004) 4-25,
 *                4-26: report time-sensitive unevaluated information at
 *                once, without waiting to refine it.
 *   confirmed    today's threshold was met. An incident that began
 *                preliminary is confirmed by the next normal fire on its
 *                key (`alert` + `alert.create`, same incident_id);
 *                every other incident opens confirmed, as before.
 *   withdrawn    a preliminary incident whose kind's window passed with
 *                no confirmation, counted from its newest first evidence
 *                (its last observation, not its first), or whose
 *                evidence aged out first.
 *                Closed by one `alert.resolve`, reason "withdrawn",
 *                `withdraw_why` saying which.
 *   lapsed       a confirmed incident with no new observation for its
 *                kind's value period (FM 2-0 1-34, 4-12). The incident
 *                stays open and the 300 s resolve is unchanged; one
 *                `alert.update` (reason "lapsed") says so and nothing
 *                more is emitted until a new observation, which makes it
 *                confirmed again (one `alert.update`). Owner ruling
 *                2026-11-25: a separate state, not the resolve reason
 *                "expired", which keeps its meaning.
 *
 * On by default (owner ruling 2026-11-25); `--no-preliminary` turns the
 * whole lifecycle off, and the stream is then the pre-#245 stream: no
 * `state`, no `value_period_s`, no preliminary, no lapse. */

#include <stdint.h>
#include "sloth.h"

typedef enum {
    ALERT_STATE_NONE = 0,     /* lifecycle off: nothing is emitted */
    ALERT_STATE_PRELIMINARY,
    ALERT_STATE_CONFIRMED,
    ALERT_STATE_WITHDRAWN,
    ALERT_STATE_LAPSED,
} alert_state_t;

typedef enum {
    ALERT_WITHDRAW_NONE = 0,
    ALERT_WITHDRAW_UNCONFIRMED,   /* the window passed, no confirmation */
    ALERT_WITHDRAW_AGED,          /* the rule stopped reporting it first */
} alert_withdraw_t;

/* "preliminary", "confirmed", "withdrawn", "lapsed"; "" for NONE. */
const char *alert_state_name(int state);
/* "unconfirmed", "evidence_aged"; "" for NONE. */
const char *alert_withdraw_name(int why);

/* The prefix fire_prelim() puts on a preliminary finding's detail. */
#define ALERT_PRELIM_TEXT "not evaluated: first evidence only"

/* The longest --value-period: 30 days. */
#define ALERT_VALUE_PERIOD_MAX_S (30L * 24 * 3600)

void alert_lifecycle_set_enabled(int on);
int  alert_lifecycle_enabled(void);

/* The kind's value period in seconds (include/sloth_alert_value.def,
 * or the --value-period override); 0 for a kind outside the list. */
uint32_t alert_value_period_s(alert_type_t t);
/* The .def's own value, whatever the override. */
uint32_t alert_value_period_default_s(alert_type_t t);
/* The kind's preliminary window in seconds; 0 = not on the list. */
uint32_t alert_prelim_window_s(alert_type_t t);
/* The research/ document behind a non-default row; "" otherwise. */
const char *alert_lifecycle_basis(alert_type_t t);

/* Parse "KIND=SECS" (KIND as in sloth_alerts.def, with or without the
 * ALERT_TYPE_ prefix) and set the override. 0 on success; -1 with
 * `err` filled for an unknown kind, a SECS that is not a whole number,
 * 0, or more than ALERT_VALUE_PERIOD_MAX_S. */
int alert_value_period_set(const char *arg, char *err, int errsz);
/* Drop every override and re-enable the lifecycle (tests, alerts_clear
 * leaves them alone: they are configuration). */
void alert_lifecycle_reset(void);

/* ── Counts per kind (#245 item 5) ───────────────────────────────
 * Since the process started (alerts_clear() leaves them: the
 * withdrawal rate is a property of the rule over the run). The median
 * is over the last ALERT_LC_SAMPLES confirmations of the kind. */
#define ALERT_LC_SAMPLES 64

typedef struct {
    uint32_t preliminary;
    uint32_t confirmed;     /* of those, confirmed */
    uint32_t withdrawn;     /* of those, withdrawn */
    uint64_t median_ms;     /* preliminary to confirmed; 0 = no sample */
} alert_lc_counts_t;

void alert_lc_note_prelim(alert_type_t t);
void alert_lc_note_confirm(alert_type_t t, uint64_t ms);
void alert_lc_note_withdraw(alert_type_t t);
void alert_lc_counts(alert_type_t t, alert_lc_counts_t *out);
void alert_lc_counts_clear(void);

#endif /* SLOTH_ALERT_LIFECYCLE_H */
