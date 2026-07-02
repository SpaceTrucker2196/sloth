#ifndef POSTURE_H
#define POSTURE_H

#include <stdio.h>
#include "sloth.h"

/* Posture report export — roadmap #16 phase 5.
 *
 * Rolls up the current sloth_state_t into a human-readable Markdown
 * report or a structured JSON companion. Called once at shutdown from
 * main.c so an operator (or a CI job) can get a signed-off summary
 * of what sloth observed during the session.
 *
 * Both writers take a session_start timestamp so they can report
 * "session ran from X to Y" — main.c captures this at startup. */

int posture_render_md  (FILE *out, const sloth_state_t *s, time_t session_start);
int posture_render_json(FILE *out, const sloth_state_t *s, time_t session_start);

#endif /* POSTURE_H */
