#include <string.h>
#include "poll.h"
#include "sloth_clock.h"
#include "sys_status.h"
#include "rule_coverage_live.h"
#include "alerts.h"
#include "db.h"
#include "questions_live.h"

/* The poll runner, and the stages every daemon's table carries (#212).
 *
 * Nothing here names a source. The Wi-Fi, wired and BLE stages are
 * src/poll.c, the GNSS ones src/poll_gnss.c and the RF ones
 * src/poll_rf.c, so a table built from this file and the last two does
 * not pull the capture stages in with it.
 *
 * Two things left this file in #213, when sloth-rf was first linked and
 * `nm` showed what "shared" had been pulling. The EMIT stage: it calls
 * src/jsonl.c, the capture's records, so `sloth`'s is in src/poll.c and
 * sloth-rf's in src/poll_rf.c, both under the stage name "jsonl". And
 * persist_health_poll(), which reads the pcap and handshake exporters'
 * failure counts: it is in src/poll.c's health_capture now. */

/* ── PLATFORM ─────────────────────────────────────────────── */

void poll_st_health_host(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* Host status and the source inventory (src/sys_status.h): after
     * the per-source polls, whose state it reads - every table places
     * this stage behind its health_* stages. */
    sys_status_poll(s, ctx->wall, ctx->mono_ms);
    /* Which rules can fire (#242): from the rows just derived. */
    cov_live_poll(s);
}

/* ── ALERTS ───────────────────────────────────────────────── */

void poll_st_alerts(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    alerts_update(s);
    /* --notify-priority (#244): a question that turned to a finding. */
    q_notify_poll(s, stderr);
}

/* ── DURABLE ──────────────────────────────────────────────── */

void poll_st_db(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* Durable state (#42). Reads sloth_state_t directly rather than
     * hanging off the jsonl emitters: every jsonl_emit_* short-circuits
     * when no sink is open, so a --db-only run would otherwise write an
     * empty database, and durable last_seen would ride the change-only
     * cache and lag by up to the 300 s heartbeat. Its own cadence
     * (--db-interval-secs), so slow storage never paces the poll loop. */
    if (db_due(ctx->wall)) db_tick(s, ctx->wall);
}

/* ── the runner ───────────────────────────────────────────── */

void poll_ctx_init(poll_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->wall    = sloth_wall();
    ctx->mono_ms = sloth_mono_ms();
}

void poll_tick(const poll_table_t *t, sloth_state_t *s, const poll_ctx_t *ctx) {
    if (!t || !s || !ctx) return;
    for (int i = 0; i < t->count; i++)
        t->stages[i].fn(s, ctx);
}

int poll_stage_index(const poll_table_t *t, const char *name) {
    if (!t || !name) return -1;
    for (int i = 0; i < t->count; i++)
        if (strcmp(t->stages[i].name, name) == 0) return i;
    return -1;
}
