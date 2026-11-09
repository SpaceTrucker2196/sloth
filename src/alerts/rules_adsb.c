/* ADS-B rule (#186): an aircraft the --adsb decoder lists declaring an
 * emergency. Basis in research/adsb/emergency-squawks.md; the input and
 * its caveats in docs/wiki/adsb.md.
 *
 * The rule reads the table adsb_health_poll() copied onto the state
 * (s->adsb, s->adsb_rows), never src/adsb.c, and measures every hold on
 * the monotonic clock the rows carry (last_mono_ms), never wall time.
 *
 * What it cannot do, stated once here: tell a real emergency from a
 * spoofed one. ADS-B carries no authentication (Costin & Francillon
 * 2012 §III: "lack of entity authentication to protect against message
 * injection"), and Schafer et al. 2013 §3.2 name the "False Alarm
 * Attack" - re-injecting or modifying a real aircraft's messages "in
 * order to indicate a fake alarm" - outright. One receiver has no
 * second opinion. So the finding is flag-only: sloth surfaces it, never
 * acts on it, and never rates it CRIT. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "adsb.h"
#include "tune.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"

/* The three ICAO emergency codes (SERA.13005(a): 7700 emergency, 7600
 * radio-communication failure, 7500 unlawful interference). The rule
 * keys on these literals, never on the decoder's bytes. */
static const char *const k_codes[] = { "7500", "7600", "7700" };

/* The squawk as one of k_codes[], or NULL. */
static const char *emerg_code(const char *squawk) {
    for (size_t i = 0; i < sizeof(k_codes) / sizeof(k_codes[0]); i++)
        if (strcmp(squawk, k_codes[i]) == 0) return k_codes[i];
    return NULL;
}

/* What the condition is keyed on: the 7x00 code when the squawk is one,
 * else the status word (readsb's "a superset of the 7x00 squawks").
 * NULL when there is no condition: no code, and the status absent or
 * "none". A squawk of 7700 whose status follows it from "none" to
 * "general" a document later is one condition, not two. */
static const char *condition(const adsb_aircraft_t *a) {
    const char *c = emerg_code(a->squawk);
    if (c) return c;
    if (a->emergency > ADSB_EMERG_NONE) return adsb_emergency_name(a->emergency);
    return NULL;
}

/* Each address's condition and when, by its own messages, it began.
 * Rebuilt every pass from the rows that hold one, so an address whose
 * condition clears, changes or whose row leaves the table starts over. */
typedef struct {
    uint32_t    icao;
    uint8_t     non_icao;
    const char *cond;          /* a k_codes[] or k_emerg[] literal */
    uint64_t    since_mono;    /* the row's last_mono_ms when first seen */
} adsb_hold_t;

static struct {
    adsb_hold_t h[ADSB_MAX_AIRCRAFT];
    int         n;
} g_adsb;

void rules_adsb_forget(void) {
    memset(&g_adsb, 0, sizeof(g_adsb));
}

static const adsb_hold_t *hold_find(uint32_t icao, uint8_t non_icao,
                                    const char *cond) {
    for (int i = 0; i < g_adsb.n; i++)
        if (g_adsb.h[i].icao == icao && g_adsb.h[i].non_icao == non_icao &&
            g_adsb.h[i].cond == cond)
            return &g_adsb.h[i];
    return NULL;
}

/* ── ADSB_EMERGENCY ──────────────────────────────────────────────────
 *
 * Fires per address while the source is LIVE and its row is listed with
 * a squawk of 7500, 7600 or 7700, or an emergency/priority status other
 * than none (general, lifeguard, minfuel, nordo, unlawful, downed,
 * reserved; readsb README-json.md, DO-260B 2.2.3.2.7.8.1.1).
 *
 * Key `adsbemerg:<icao>:<kind>:<condition>`: a change of code re-keys
 * and so re-fires as a new incident; the same condition re-asserted
 * every pass is one incident whose detail holds still (#173). A row
 * that leaves the table, or a source gone STALE, is no longer evaluated
 * and its incident expires on the engine's quiet period, as every
 * rule's does.
 *
 * Severity: LOW on first sight, WARN once the condition has held for
 * adsb.emerg_hold_s (10 s) of the aircraft's own message time - the
 * span from the row's last_mono_ms when the condition was first seen to
 * its last_mono_ms now, so a row the decoder relists without hearing
 * the aircraft again does not age into WARN. Persistence, not
 * corroboration, because the two fields are not independent: DO-260B
 * carries the code and the status in the same Aircraft Status message,
 * and a transponder set to 7x00 sets the status with it, so agreeing
 * fields are one observation, not two. A single corrupted reply that
 * decodes as 7x00, or a code dialled through in passing, is the case
 * the hold keeps at LOW. Never CRIT: see the head of this file. */
void rule_adsb_emergency(const sloth_state_t *s, time_t now) {
    static adsb_hold_t next[ADSB_MAX_AIRCRAFT];
    int nn = 0;
    if (s->adsb.state == ADSB_LIVE && s->adsb_rows) {
        const uint64_t hold_ms = (uint64_t)tune_val(TUNE_ADSB_EMERG_HOLD_S) * 1000;
        for (int i = 0; i < s->adsb_count && nn < ADSB_MAX_AIRCRAFT; i++) {
            const adsb_aircraft_t *a = &s->adsb_rows[i];
            const char *cond = condition(a);
            if (!cond) continue;
            const adsb_hold_t *prev = hold_find(a->icao, a->non_icao, cond);
            adsb_hold_t *h = &next[nn++];
            h->icao = a->icao;
            h->non_icao = a->non_icao;
            h->cond = cond;
            h->since_mono = prev ? prev->since_mono : a->last_mono_ms;
            const int held = a->last_mono_ms >= h->since_mono &&
                             a->last_mono_ms - h->since_mono >= hold_ms;

            const uint8_t ab[3] = { (uint8_t)(a->icao >> 16),
                                    (uint8_t)(a->icao >> 8),
                                    (uint8_t)a->icao };
            char key[48];
            akey_t ak;
            akey_begin(&ak, key, sizeof(key), "adsbemerg");
            akey_hex(&ak, ab, sizeof(ab));
            akey_tok(&ak, a->non_icao ? "nonicao" : "icao");
            akey_tok(&ak, cond);
            if (!akey_end(&ak)[0]) continue;

            const char *sq = a->squawk[0] ? a->squawk : "-";
            const char *ew = a->emergency >= ADSB_EMERG_NONE
                             ? adsb_emergency_name(a->emergency) : "-";
            const char *callsign = a->flight[0] ? a->flight : "-";
            char detail[ALERT_DETAIL_LEN];
            snprintf(detail, sizeof(detail),
                     "%s%06x callsign %s squawk %s emergency %s%s - flag "
                     "only: ADS-B is unauthenticated and a false alarm can "
                     "be injected; sloth cannot verify it and takes no action",
                     a->non_icao ? "non-ICAO ~" : "ICAO ", (unsigned)a->icao,
                     callsign, sq, ew,
                     held ? "; held past adsb.emerg_hold_s" : "; first sight");
            fire(ALERT_TYPE_ADSB_EMERGENCY, held ? ALERT_SEV_WARN : ALERT_SEV_LOW,
                 "ADSB_EMERGENCY", detail, key, NULL, 0, now);
        }
    }
    memcpy(g_adsb.h, next, (size_t)nn * sizeof(next[0]));
    g_adsb.n = nn;
}
