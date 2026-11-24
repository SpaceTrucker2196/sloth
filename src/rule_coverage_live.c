#include <string.h>
#include "rule_coverage_live.h"
#include "sys_status.h"
#include "sloth_clock.h"
#include "jsonl.h"
#include "jsonl_internal.h"

/* Coverage assessment, the running half (#242 slice 2). Contract:
 * rule_coverage_live.h. */

static struct {
    cov_daemon_t daemon;
    cov_side_fn  fill;
    int          valid;
    int          declined;                /* the filler said no (replay) */
    cov_env_t    env;
    uint8_t      st[ALERT_TYPE_COUNT];    /* cov_status_t */
    uint8_t      why[ALERT_TYPE_COUNT];   /* cov_reason_t */
    int          n[3];                    /* by cov_status_t */
} g;

void cov_live_reset(void) {
    cov_daemon_t d = g.daemon;
    cov_side_fn  f = g.fill;
    memset(&g, 0, sizeof(g));
    /* Which daemon this is and its filler are the binary's shape, not
     * state: a reset between tests keeps them, as sys_status_reset()
     * keeps its two sides. */
    g.daemon = d;
    g.fill   = f;
}

void cov_live_set_side(cov_daemon_t daemon, cov_side_fn fill) {
    memset(&g, 0, sizeof(g));
    g.daemon = daemon;
    g.fill   = fill;
}

static cov_avail_t avail_of(const sys_source_t *o) {
    if (!o->name) return COV_AV_NONE;
    switch ((sys_src_state_t)o->state) {
    case SYS_ST_OK:    return COV_AV_UP;
    case SYS_ST_STALE: return COV_AV_STALE;
    case SYS_ST_DOWN:  return COV_AV_DOWN;
    case SYS_ST_NOT_CONFIGURED:
    case SYS_ST_NOT_INSTALLED:
        break;
    }
    return COV_AV_NONE;
}

/* Two sources of one input: the better one is what the rule has. */
static void offer(cov_env_t *e, cov_input_t in, cov_avail_t av) {
    if (av > e->input[in]) e->input[in] = av;
}

void cov_env_from_sources(const sys_snapshot_t *sn, cov_env_t *env) {
    if (!env) return;
    memset(env, 0, sizeof(*env));
    if (!sn || !sn->valid) return;
    /* The sampler is what wrote `sn`. */
    env->input[COV_IN_SYS] = COV_AV_UP;

    /* The capture interface delivers one of two things: 802.11 frames
     * when it is itself in monitor mode, IP packets otherwise. */
    const sys_source_t *cap = &sn->src[SYS_SRC_CAPTURE];
    offer(env, strcmp(cap->kind, "wifi-monitor") == 0 ? COV_IN_DOT11 : COV_IN_IP,
          avail_of(cap));
    offer(env, COV_IN_DOT11, avail_of(&sn->src[SYS_SRC_MONITOR]));
    /* The HCI monitor channel carries the controller's commands and the
     * advertising it reports; an Ubertooth stream carries advertising
     * only. */
    cov_avail_t btmon = avail_of(&sn->src[SYS_SRC_BTMON]);
    offer(env, COV_IN_BLE_HCI, btmon);
    offer(env, COV_IN_BLE_ADV, btmon);
    offer(env, COV_IN_BLE_ADV, avail_of(&sn->src[SYS_SRC_BTCAP]));
    offer(env, COV_IN_GNSS, avail_of(&sn->src[SYS_SRC_GNSS]));
    offer(env, COV_IN_ADSB, avail_of(&sn->src[SYS_SRC_ADSB]));
}

void cov_live_poll(const sloth_state_t *s) {
    const sys_snapshot_t *sn = sys_status_get();
    if (!s || !sn || !sn->valid) return;
    cov_env_from_sources(sn, &g.env);
    if (g.fill && !g.fill(s, &g.env)) { g.valid = 0; g.declined = 1; return; }
    g.declined = 0;
    g.n[0] = g.n[1] = g.n[2] = 0;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        if (!cov_daemon_raises(g.daemon, (alert_type_t)t)) continue;
        cov_reason_t why = COV_R_NONE;
        cov_status_t st = cov_rule_status((alert_type_t)t, &g.env, &why);
        g.st[t]  = (uint8_t)st;
        g.why[t] = (uint8_t)why;
        g.n[st]++;
    }
    g.valid = 1;
}

int cov_live_valid(void) { return g.valid; }

cov_live_state_t cov_live_state(void) {
    if (g.valid)    return COV_LIVE_VALID;
    if (g.declined) return COV_LIVE_DECLINED;
    return COV_LIVE_PENDING;
}

const char *cov_live_state_why(cov_live_state_t st) {
    switch (st) {
    case COV_LIVE_PENDING:
        return "no status sample has been taken yet";
    case COV_LIVE_DECLINED:
        return "a --replay run reads files, and the assessment is of the "
               "sensor's own radios and sources";
    case COV_LIVE_VALID:
        break;
    }
    return "";
}

const char *const cov_limits[COV_LIMIT_COUNT] = {
    "Observable means: on the channels the radios visit. A transmitter on "
    "a channel in no radio's plan is not heard, and the status does not say so.",
    "The status is about the sensor, not the site. Observable with no "
    "finding is \"looked and found nothing\", not \"nothing is there\".",
};

const char *cov_kind_name(alert_type_t t) {
    const char *name = alert_type_name(t);
    if (strncmp(name, "ALERT_TYPE_", 11) == 0) name += 11;
    return name;
}

int cov_live_gaps(cov_gap_t *out, int max) {
    /* cov_rule_status()'s precedence (rule_coverage.h): blind in enum
     * order, then partly with `suppressed` after `source_stale`. */
    static const struct { cov_status_t st; cov_reason_t why; } order[] = {
        { COV_BLIND,  COV_R_NO_SOURCE },    { COV_BLIND,  COV_R_SOURCE_DOWN },
        { COV_BLIND,  COV_R_NO_OWN_NET },   { COV_BLIND,  COV_R_NO_ROSTER },
        { COV_BLIND,  COV_R_NO_DB },        { COV_BLIND,  COV_R_BAND },
        { COV_PARTLY, COV_R_SOURCE_STALE }, { COV_PARTLY, COV_R_SUPPRESSED },
        { COV_PARTLY, COV_R_FIXED_CHANNEL },{ COV_PARTLY, COV_R_HOP },
    };
    if (!g.valid || !out) return 0;
    int n = 0;
    for (size_t o = 0; o < sizeof(order) / sizeof(*order) && n < max; o++) {
        cov_gap_t *gp = &out[n];
        gp->st = order[o].st;
        gp->why = order[o].why;
        gp->n = 0;
        for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
            if (!cov_daemon_raises(g.daemon, (alert_type_t)t)) continue;
            if (g.st[t] == (uint8_t)gp->st && g.why[t] == (uint8_t)gp->why)
                gp->kind[gp->n++] = (alert_type_t)t;
        }
        if (gp->n) n++;
    }
    return n;
}

int cov_live_get(alert_type_t t, cov_status_t *st, cov_reason_t *why) {
    if (!g.valid || (int)t < 0 || t >= ALERT_TYPE_COUNT) return 0;
    if (!cov_daemon_raises(g.daemon, t)) return 0;
    if (st)  *st  = (cov_status_t)g.st[t];
    if (why) *why = (cov_reason_t)g.why[t];
    return 1;
}

void cov_live_counts(int *observable, int *partly, int *blind) {
    if (observable) *observable = g.valid ? g.n[COV_OBSERVABLE] : 0;
    if (partly)     *partly     = g.valid ? g.n[COV_PARTLY] : 0;
    if (blind)      *blind      = g.valid ? g.n[COV_BLIND] : 0;
}

const cov_env_t *cov_live_env(void) { return &g.env; }

/* ── Emit ────────────────────────────────────────────────────────── */

void cov_live_emit(void) {
    if (!g.valid) return;
    time_t wall = sloth_wall();

    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        if (!cov_daemon_raises(g.daemon, (alert_type_t)t)) continue;
        /* Status and reason are words from short lists: the signature
         * holds nothing that moves by itself. */
        uint8_t  key = (uint8_t)t;
        uint64_t sig = ((uint64_t)g.st[t] << 8) | g.why[t];
        if (!jsonl_changed(JD_RULE_STATUS, &key, 1, sig, wall)) continue;
        const cov_inputs_t *d = cov_inputs((alert_type_t)t);
        /* "ALERT_TYPE_X" without its prefix: the spelling of
         * sloth_alerts.def and of the contract's alert-daemons.tsv. */
        const char *name = cov_kind_name((alert_type_t)t);
        const jsonl_field_t f[] = {
            { "ty",     JSONL_F_INT, NULL, t, 0.0, 0 },
            { "kind",   JSONL_F_STR, name, 0, 0.0, 0 },
            { "status", JSONL_F_STR, cov_status_name((cov_status_t)g.st[t]), 0, 0.0, 0 },
            { "why",    JSONL_F_STR, cov_reason_name((cov_reason_t)g.why[t]), 0, 0.0, 0 },
            { "input",  JSONL_F_STR, cov_input_name(d->input), 0, 0.0, 0 },
        };
        jsonl_emit_fields("rule_status", wall, f, (int)(sizeof(f) / sizeof(*f)));
    }

    {
        const cov_env_t *e = &g.env;
        uint8_t  key = 0;
        uint64_t sig = jsonl_fnv1a(g.n, sizeof(g.n), 0);
        const int radio[4] = { e->radios, e->channels, e->hopping, (int)e->bands };
        sig = jsonl_fnv1a(radio, sizeof(radio), sig);
        if (!jsonl_changed(JD_COVERAGE, &key, 1, sig, wall)) return;
        char bands[24];
        cov_bands_str(e->bands, bands, sizeof(bands));
        const jsonl_field_t f[] = {
            { "daemon",     JSONL_F_STR, g.daemon == COV_DAEMON_RF ? "rf" : "wifi", 0, 0.0, 0 },
            { "rules",      JSONL_F_INT, NULL, g.n[0] + g.n[1] + g.n[2], 0.0, 0 },
            { "observable", JSONL_F_INT, NULL, g.n[COV_OBSERVABLE], 0.0, 0 },
            { "partly",     JSONL_F_INT, NULL, g.n[COV_PARTLY], 0.0, 0 },
            { "blind",      JSONL_F_INT, NULL, g.n[COV_BLIND], 0.0, 0 },
            { "radios",     JSONL_F_INT, NULL, e->radios, 0.0, 0 },
            { "channels",   JSONL_F_INT, NULL, e->channels, 0.0, 0 },
            { "hopping",    JSONL_F_INT, NULL, e->hopping, 0.0, 0 },
            { "bands",      JSONL_F_STR, bands, 0, 0.0, 0 },
        };
        jsonl_emit_fields("coverage", wall, f, (int)(sizeof(f) / sizeof(*f)));
    }
}
