/* The sensor's own state (owner ruling 2026-11-11: "alerts for
 * under-voltage and a source going down"). Both rules read the snapshot
 * src/sys_status.c re-derives every poll (sys_status_get()), never a
 * platform op, and both are the FIRST exemption form of agents/AGENTS.md
 * "Detectors cite their sources": sloth's own operational state, no
 * adversary, so no technique and nothing in research/ to cite. The set
 * is pinned by tests/test_research_corpus.c ::
 * test_own_state_kinds_are_named.
 *
 * One incident per condition, not one per swing. Both rules hold an
 * incident open across a flap and close it themselves, with the
 * `alert.resolve` reason `recovered`, only once the condition has been
 * clear for SENSOR_RECOVER_S without a break. A supply or a decoder that
 * toggles every few seconds is therefore one incident for as long as it
 * keeps toggling, not a create/resolve pair per toggle. SENSOR_RECOVER_S
 * is under the engine's 300 s quiet period (ALERT_RESOLVE_AFTER_S), so a
 * recovery is reported by this rule rather than by the quiet period,
 * and two minutes is two of sys_status's 60 s batches: a consumer reading
 * the batches sees at least one whole batch of the condition clear
 * before the incident closes.
 *
 * Every clock here is sloth_mono_ms(): durations, never wall time. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sys_status.h"
#include "sloth_clock.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"

typedef struct {
    int      open;              /* this rule holds an incident open */
    int      ok_on;             /* the condition is clear ... */
    uint64_t ok_since;          /* ... since this mono ms */
    int      down_on;           /* source: DOWN without a break ... */
    uint64_t down_since;
    int      notok_on;          /* source: anything but OK without a break ... */
    uint64_t notok_since;
} sensor_hold_t;

static struct {
    sensor_hold_t uv;
    sensor_hold_t src[SYS_SRC_COUNT];
} g_sensor;

void rules_sensor_forget(void) {
    memset(&g_sensor, 0, sizeof(g_sensor));
}

static uint64_t held_ms(uint64_t now, uint64_t since) {
    return now >= since ? now - since : 0;
}

/* The condition is clear this tick. Closes the incident once it has been
 * clear for SENSOR_RECOVER_S; an incident the engine already ended (the
 * operator's `c`, an eviction) is simply forgotten. */
static void hold_clear(sensor_hold_t *h, const char *key, uint64_t mono, time_t now) {
    h->down_on = h->notok_on = 0;
    if (!h->ok_on) { h->ok_on = 1; h->ok_since = mono; }
    if (!h->open) return;
    if (!alert_key_open(key)) { h->open = 0; return; }
    if (held_ms(mono, h->ok_since) >= (uint64_t)SENSOR_RECOVER_S * 1000u) {
        alert_key_resolve(key, now, "recovered");
        h->open = 0;
    }
}

/* ── SENSOR_UNDERVOLT ────────────────────────────────────────────────
 *
 * Fires while the host's under-voltage alarm reads 1: any hwmon
 * inN_lcrit_alarm, which on a Raspberry Pi is the firmware's flag
 * (rpi_volt in0_lcrit_alarm, src/sys_status.c sample_hwmon()). The
 * snapshot is sampled every SYS_SAMPLE_SECS, so an alarm shorter than
 * that is not seen, as sys_status.h says.
 *
 * WARN, never CRIT. A brown-out can corrupt an SD card and wedge a USB
 * radio, but the alarm says the supply dipped, not that either
 * happened, and no source read for this rule gives a held duration past
 * which damage is to be expected; a CRIT on a span chosen here would be
 * a guess presented as a threshold. The sources going quiet are
 * SENSOR_SOURCE_DOWN's to report, with their own severity.
 *
 * Key `undervolt:host`: the host has one supply, whichever node reports
 * it. The detail names the first alarming sensor (id and label) and how
 * many others agree. A host with no alarm node never fires. */
void rule_sensor_undervolt(const sloth_state_t *s, time_t now) {
    (void)s;
    const sys_snapshot_t *sn = sys_status_get();
    static const char key[] = "undervolt:host";
    sensor_hold_t *h = &g_sensor.uv;
    if (!sn->valid || !sn->has_undervolt) return;
    const uint64_t mono = sloth_mono_ms();
    if (!sn->undervolt) { hold_clear(h, key, mono, now); return; }
    h->ok_on = 0;

    const sys_reading_t *first = NULL;
    int others = 0;
    for (int i = 0; i < sn->nvolt; i++) {
        const sys_reading_t *r = &sn->volt[i];
        if (!r->has_alarm || !r->alarm) continue;
        if (!first) first = r; else others++;
    }
    const char *sid = first ? first->id : "?";
    const char *slabel = first && first->label[0] ? first->label : "no label";
    char detail[ALERT_DETAIL_LEN];
    snprintf(detail, sizeof(detail),
             "under-voltage alarm on %s (%s)%s%s: the host's supply is below "
             "what the board needs; brown-outs corrupt SD cards and can "
             "wedge USB radios - check the power supply and cable",
             sid, slabel, others ? ", and " : "",
             others ? (others == 1 ? "1 other sensor" : "more sensors") : "");
    fire(ALERT_TYPE_SENSOR_UNDERVOLT, ALERT_SEV_WARN, "SENSOR_UNDERVOLT",
         detail, key, NULL, 0, now);
    h->open = 1;
}

/* ── SENSOR_SOURCE_DOWN ──────────────────────────────────────────────
 *
 * Per configured source (every source_status row whose state is not
 * not_configured: what the command line enabled, and the monitor radio
 * sloth found and opened), keyed `srcdown:<name>`:
 *
 *   opens  when it has read `down` for SENSOR_SRC_DOWN_HOLD_S without a
 *          break, or has not read `ok` for SENSOR_SRC_STALE_S without a
 *          break (stale, or stale and down in turn). The down hold is
 *          one sample interval: a gpsd or decoder reconnect that
 *          succeeds within seconds is not an incident. The stale span
 *          is five of sys_status's 60 s stale threshold and the engine's
 *          own quiet period: a source quiet that long while configured
 *          is not a lull. A source that is down from the first poll -
 *          a capture that never opened - opens after the hold like any
 *          other.
 *   holds  while it reads anything but `ok`, so down -> stale -> down
 *          is one incident;
 *   closes reading `ok` for SENSOR_RECOVER_S without a break.
 *
 * A source that is not configured never fires: its row says nothing
 * about the sensor's health, only about what was asked for.
 *
 * Severity: CRIT for the monitor radio and the IP capture, WARN for the
 * rest. Those two are the sensor's main function - every 802.11 rule
 * and view reads the monitor radio and nothing else, every wired rule
 * the capture and nothing else - so with one configured and gone, the
 * sensor is silent on its whole domain while it looks like a quiet
 * network. The others feed one domain each beside it (Bluetooth,
 * position, aircraft, APRS).
 *
 * The detail carries the reader's own word, the state and the freshness
 * band, never an age in seconds: a figure that moves every tick would
 * make every evaluation an observation (#173). */
void rule_sensor_source_down(const sloth_state_t *s, time_t now) {
    (void)s;
    const sys_snapshot_t *sn = sys_status_get();
    if (!sn->valid) return;
    const uint64_t mono = sloth_mono_ms();
    for (int i = 0; i < SYS_SRC_COUNT; i++) {
        const sys_source_t *o = &sn->src[i];
        sensor_hold_t *h = &g_sensor.src[i];
        if (!o->name) continue;
        char key[48];
        akey_t ak;
        akey_begin(&ak, key, sizeof(key), "srcdown");
        akey_tok(&ak, o->name);
        if (!akey_end(&ak)[0]) continue;

        if (o->state == SYS_ST_NOT_CONFIGURED) {
            /* Not configured now: nothing to judge. A source cannot
             * become unconfigured mid-run; if it ever does, an open
             * incident expires on the engine's quiet period. */
            memset(h, 0, sizeof(*h));
            continue;
        }
        if (o->state == SYS_ST_OK) { hold_clear(h, key, mono, now); continue; }

        h->ok_on = 0;
        if (!h->notok_on) { h->notok_on = 1; h->notok_since = mono; }
        if (o->state == SYS_ST_DOWN) {
            if (!h->down_on) { h->down_on = 1; h->down_since = mono; }
        } else {
            h->down_on = 0;
        }
        const int down_held = h->down_on &&
            held_ms(mono, h->down_since) >= (uint64_t)SENSOR_SRC_DOWN_HOLD_S * 1000u;
        const int notok_held =
            held_ms(mono, h->notok_since) >= (uint64_t)SENSOR_SRC_STALE_S * 1000u;
        if (h->open && !alert_key_open(key)) h->open = 0;
        if (!h->open && !down_held && !notok_held) continue;

        const int main_fn = i == SYS_SRC_CAPTURE || i == SYS_SRC_MONITOR;
        const char *state = sys_src_state_name(o->state);
        const char *band = sys_age_band_name(sys_age_band(o->age_s));
        const char *ep = o->endpoint[0] ? o->endpoint : "-";
        const char *why = o->detail[0] ? o->detail : "-";
        char detail[ALERT_DETAIL_LEN];
        snprintf(detail, sizeof(detail),
                 "configured source %s (%s, %s) is %s: %s; last delivery %s%s",
                 o->name, o->kind, ep, state, why, band,
                 main_fn ? " - the sensor is blind on this source's whole "
                           "domain while it is gone" : "");
        fire(ALERT_TYPE_SENSOR_SOURCE_DOWN, main_fn ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
             "SENSOR_SOURCE_DOWN", detail, key, NULL, 0, now);
        h->open = 1;
    }
}
