#ifndef SLOTH_QUESTIONS_LIVE_H
#define SLOTH_QUESTIONS_LIVE_H

#include <stdio.h>
#include "sloth.h"
#include "questions.h"

/* ── Site questions, the running half (#244) ─────────────────────────
 *
 * questions.h is the pure half: the tables, the file and the status.
 * This file holds the daemon's question set (the defaults, or the
 * operator's --questions file), reads the alert snapshot and the
 * coverage status this daemon keeps (rule_coverage_live.h), and writes
 * the answers:
 *
 *   question_status   one JSONL record per question this daemon
 *                     answers, when its status, reason, coverage counts
 *                     or findings change, and on the stream's heartbeat
 *   --report          the "Site questions" section, in priority order
 *
 * Kinds, counts, words, incident ids and the operator's own question
 * text only: never an address, a name or a key. */

/* The question set: the defaults until --questions loads a file. */
void           q_live_reset(void);
const q_set_t *q_live_questions(void);
/* "" for the defaults, the file's path otherwise. */
const char    *q_live_path(void);

/* --questions PATH: load the file and make it the set. 0, or 2 with one
 * line on stderr naming the line that refused it. */
int q_live_flag(const char *path);

/* The coverage this daemon keeps, as q_derive() reads it. */
void q_live_cov(q_cov_t *c);

typedef struct {
    int        qi;      /* index in q_live_questions() */
    q_result_t r;
} q_answer_t;

/* The questions this daemon answers, by priority (1 first) and then in
 * set order. Returns how many. */
int q_live_answers(const sloth_state_t *s, q_answer_t out[Q_MAX]);

/* The report's section: Markdown `## Site questions`; JSON the member
 * `  "questions": {...}`, a comma and a newline. */
void q_report_md(FILE *out, const sloth_state_t *s);
void q_report_json(FILE *out, const sloth_state_t *s);

/* The answer's change signature, as the record and the question_status
 * table use it, and its `found` kinds and `ids` strings, written to
 * `kinds` / `ids`. */
uint64_t q_answer_sig(const q_result_t *r, int assessed, const q_question_t *q,
                      char *kinds, size_t ksz, char *ids, size_t isz);

/* ── Notification above a priority (owner ruling 2026-11-25) ─────────
 *
 * --notify-priority N (1..9, 0 off, the default): when a question of
 * priority N or more urgent turns to `finding`, gains a kind, or stops
 * being a finding, one line goes to `out` (the daemons pass stderr,
 * which systemd writes to the journal):
 *
 *   sloth: question Q1 (priority 1): finding, 1 open (EVIL_TWIN): Is a device ...?
 *   sloth: question Q1 (priority 1): no longer a finding (no_finding_partly)
 *
 * Local only: nothing is sent over any network, so MISSION §2's opt-in
 * is the flag and the announcement is the start line
 * q_live_notify_announce() prints. The line carries the question, its
 * kinds and counts: never an address, a name or a key. Delivery to a
 * phone or a mail box is sloth-mesh's (sloth-mesh#18), which reads the
 * question_status record. */
int  q_live_notify_flag(const char *arg);     /* 0, or 2 with a line on stderr */
int  q_live_notify_priority(void);            /* 0 off */
void q_live_notify_announce(FILE *out);       /* nothing when off */
/* After the alert stage: the lines that are due. Returns how many. */
int  q_notify_poll(const sloth_state_t *s, FILE *out);

/* The question_status records. */
void q_emit(const sloth_state_t *s);

#endif /* SLOTH_QUESTIONS_LIVE_H */
