#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "alert_lifecycle.h"
#include "alerts.h"
#include "rule_coverage.h"
#include "sloth_compat.h"

/* The finding lifecycle's per-kind table and counts (#245). Contract:
 * alert_lifecycle.h. */

typedef struct {
    uint32_t    value_s;
    uint32_t    prelim_s;
    const char *basis;
} lc_row_t;

static const lc_row_t lc_table[] = {
#define X(id, value_s, prelim_s, basis) \
    [ALERT_TYPE_##id] = { (value_s), (prelim_s), (basis) },
#include "sloth_alert_value.def"
#undef X
};
SLOTH_STATIC_ASSERT(sizeof(lc_table) / sizeof(*lc_table) == ALERT_TYPE_COUNT,
                    lc_table_covers_every_type);

static int      g_on = 1;
static uint32_t g_override[ALERT_TYPE_COUNT];   /* 0 = the .def's */

static int in_range(alert_type_t t) {
    return (int)t >= 0 && t < ALERT_TYPE_COUNT;
}

const char *alert_state_name(int state) {
    switch (state) {
    case ALERT_STATE_PRELIMINARY: return "preliminary";
    case ALERT_STATE_CONFIRMED:   return "confirmed";
    case ALERT_STATE_WITHDRAWN:   return "withdrawn";
    case ALERT_STATE_LAPSED:      return "lapsed";
    default:                      return "";
    }
}

const char *alert_withdraw_name(int why) {
    switch (why) {
    case ALERT_WITHDRAW_UNCONFIRMED: return "unconfirmed";
    case ALERT_WITHDRAW_AGED:        return "evidence_aged";
    default:                         return "";
    }
}

void alert_lifecycle_set_enabled(int on) { g_on = on ? 1 : 0; }
int  alert_lifecycle_enabled(void)       { return g_on; }

uint32_t alert_value_period_default_s(alert_type_t t) {
    return in_range(t) ? lc_table[t].value_s : 0;
}

/* A standing condition never lapses (owner ruling 2026-11-25, after the
 * #245 review): its rule re-asserts it every poll while it is true, but
 * its detail stops moving, so "no new observation" says nothing about
 * whether it still holds, and slothweb hides a lapsed finding by
 * default. Two groups, both read from tables that already exist:
 *   - sloth's own state: the SYS kinds (SENSOR_SOURCE_DOWN, the sensor
 *     is blind; SENSOR_UNDERVOLT; SENSOR_SUPPRESSED), NO_MONITOR_MODE
 *     and BT_OWN_TRANSMIT;
 *   - the 802.11 kinds whose evidence is a standing state, SHAPE STATE
 *     in sloth_alert_inputs.def (a beacon's content: EVIL_TWIN,
 *     COUNTRY_ABSENT, ...).
 * Such a finding stays confirmed until the 300 s resolve. */
int alert_kind_is_standing(alert_type_t t) {
    if (!in_range(t)) return 0;
    if (t == ALERT_TYPE_NO_MONITOR_MODE || t == ALERT_TYPE_BT_OWN_TRANSMIT)
        return 1;
    const cov_inputs_t *in = cov_inputs(t);
    return in && (in->input == COV_IN_SYS || in->shape == COV_SHAPE_STATE);
}

uint32_t alert_value_period_s(alert_type_t t) {
    if (!in_range(t) || alert_kind_is_standing(t)) return 0;
    return g_override[t] ? g_override[t] : lc_table[t].value_s;
}

uint32_t alert_prelim_window_s(alert_type_t t) {
    return in_range(t) ? lc_table[t].prelim_s : 0;
}

const char *alert_lifecycle_basis(alert_type_t t) {
    return in_range(t) && lc_table[t].basis ? lc_table[t].basis : "";
}

int alert_value_period_set(const char *arg, char *err, int errsz) {
    if (!arg || !arg[0]) {
        snprintf(err, (size_t)errsz, "needs KIND=SECS");
        return -1;
    }
    const char *eq = strchr(arg, '=');
    if (!eq || eq == arg) {
        snprintf(err, (size_t)errsz, "%s: needs KIND=SECS", arg);
        return -1;
    }
    char kind[64];
    size_t kl = (size_t)(eq - arg);
    if (kl >= sizeof(kind)) {
        snprintf(err, (size_t)errsz, "%s: unknown alert kind", arg);
        return -1;
    }
    memcpy(kind, arg, kl);
    kind[kl] = '\0';
    static const char pfx[] = "ALERT_TYPE_";
    const char *bare = strncmp(kind, pfx, sizeof(pfx) - 1) == 0
                     ? kind + sizeof(pfx) - 1 : kind;
    int found = -1;
    for (int t = 0; t < (int)ALERT_TYPE_COUNT && found < 0; t++) {
        const char *n = alert_type_name((alert_type_t)t);
        if (strncmp(n, pfx, sizeof(pfx) - 1) == 0) n += sizeof(pfx) - 1;
        if (bare[0] && strcmp(n, bare) == 0) found = t;
    }
    if (found < 0) {
        snprintf(err, (size_t)errsz, "%s: unknown alert kind", kind);
        return -1;
    }
    if (alert_kind_is_standing((alert_type_t)found)) {
        snprintf(err, (size_t)errsz,
                 "%s: a standing condition, it never lapses", kind);
        return -1;
    }
    const char *v = eq + 1;
    char *end = NULL;
    long secs = strtol(v, &end, 10);
    if (!v[0] || !end || *end || secs < 1 || secs > ALERT_VALUE_PERIOD_MAX_S) {
        snprintf(err, (size_t)errsz, "%s: want 1..%ld seconds", arg,
                 (long)ALERT_VALUE_PERIOD_MAX_S);
        return -1;
    }
    g_override[found] = (uint32_t)secs;
    return 0;
}

/* ── Counts ─────────────────────────────────────────────────── */

typedef struct {
    alert_lc_counts_t c;
    uint32_t samples[ALERT_LC_SAMPLES];
    int      n;      /* samples held, <= ALERT_LC_SAMPLES */
    int      next;   /* ring cursor */
} lc_count_row_t;

static lc_count_row_t g_counts[ALERT_TYPE_COUNT];

void alert_lifecycle_reset(void) {
    g_on = 1;
    memset(g_override, 0, sizeof(g_override));
}

void alert_lc_counts_clear(void) {
    memset(g_counts, 0, sizeof(g_counts));
}

void alert_lc_note_prelim(alert_type_t t) {
    if (in_range(t)) g_counts[t].c.preliminary++;
}

void alert_lc_note_withdraw(alert_type_t t) {
    if (in_range(t)) g_counts[t].c.withdrawn++;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

void alert_lc_note_confirm(alert_type_t t, uint64_t ms) {
    if (!in_range(t)) return;
    lc_count_row_t *r = &g_counts[t];
    r->c.confirmed++;
    r->samples[r->next] = ms > UINT32_MAX ? UINT32_MAX : (uint32_t)ms;
    r->next = (r->next + 1) % ALERT_LC_SAMPLES;
    if (r->n < ALERT_LC_SAMPLES) r->n++;
    /* Lower median of what the ring holds: an observed value, never an
     * average of two. */
    uint32_t sorted[ALERT_LC_SAMPLES];
    memcpy(sorted, r->samples, (size_t)r->n * sizeof(*sorted));
    qsort(sorted, (size_t)r->n, sizeof(*sorted), cmp_u32);
    r->c.median_ms = sorted[(r->n - 1) / 2];
}

void alert_lc_counts(alert_type_t t, alert_lc_counts_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (in_range(t)) *out = g_counts[t].c;
}
