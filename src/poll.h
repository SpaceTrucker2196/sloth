#ifndef SLOTH_POLL_H
#define SLOTH_POLL_H

/* One poll tick, as a declared phase table (#113).
 *
 * poll_data() in main.c used to sequence ~45 snapshot, derive, alert and
 * emit calls by hand, and the order had drifted into five verified stale
 * reads: JSONL state emitted before the snapshots that fill it, the twin
 * view built before the beacon table it walks, sensors and the merged
 * Wi-Fi model emitted before they were registered, recurring-transit
 * alerts evaluated before transit_snapshot(), and two derive stages
 * reading the wall clock directly while the alert engine read the seam.
 * A sixth turned up while moving them: channel_summary_update() reads
 * s->beacon_aps and ran ahead of beacon_snapshot(). None was visible to
 * a test, because poll_data() was static in a file no test binary links.
 *
 * The fix is structural rather than six local reorders: every stage
 * names its phase, the phases run in a fixed order, and
 * test_phases_are_monotonic pins that the table never goes backwards.
 *
 *   PLATFORM  kernel-facing reads through g_platform, the health polls
 *             (capture, GNSS, RF, then the host's own state), and the
 *             first-tick stats baseline over the interface list
 *   SNAPSHOT  capture_ring_snapshot() first, then every module's
 *             *_snapshot(s): copy each capture-fed table into s
 *   DERIVE    everything computed from those snapshots: history,
 *             bandwidth, channel summary + control-frame annotation,
 *             RF quality, scan, beacon detection, recurring transit,
 *             sensor registration + the merged Wi-Fi model, twins
 *   ALERTS    alerts_update() — reads only what the phases above built
 *   POST      consumers of this tick's alerts: research coverage, KARMA,
 *             the tui alert-hot list, devices, top hosts, channel hop
 *   EMIT      JSONL. Last but one, so every record describes this tick
 *   DURABLE   the database, on its own cadence
 *
 * Within a phase stages keep their table order; across phases the order
 * is the contract.
 *
 * Deliberately NOT in the table: the (out,max)-style snapshots —
 * pm_forge, wps_track and queue_evict copy out under their own locks at
 * the point a rule reads them, inside alerts_update(). They have no
 * s-field for a stage to fill, so there is nothing to order. */

#include <stdint.h>
#include <time.h>
#include "sloth.h"
#include "query.h"

typedef struct {
    /* One clock reading per tick, taken through the seam (sloth_wall /
     * sloth_mono_ms) so every stage that stamps or ages this tick agrees
     * with the alert engine — which reads the same seam — and a test can
     * drive the whole tick deterministically. */
    time_t       wall;
    uint64_t     mono_ms;
    /* Research corpus for the coverage stage. NULL is fine: the view
     * then shows every fired kind with no sources. */
    rq_handle_t *research;
    /* Two consumers live in the app, not the core library: the tui's
     * alert-hot list (src/tui.c) and the channel-hop scheduler (static
     * in src/main.c, it owns the retune state). Hooks rather than calls
     * so the core links without either and a test tick runs the rest of
     * the table unchanged. NULL skips the stage. */
    void (*alert_hot)(const char *ip, long t, int sev);
    void (*chanhop)(sloth_state_t *s);
} poll_ctx_t;

typedef enum {
    PH_PLATFORM,
    PH_SNAPSHOT,
    PH_DERIVE,
    PH_ALERTS,
    PH_POST,
    PH_EMIT,
    PH_DURABLE
} poll_phase_t;

typedef struct {
    const char   *name;
    poll_phase_t  phase;
    void        (*fn)(sloth_state_t *s, const poll_ctx_t *ctx);
} poll_stage_t;

/* A stage table is data the application supplies (#212). There was one
 * table, hard-coded in src/poll.c; since the sensor is to be two daemons
 * (#211, ADR 0010) each passes its own.
 *
 *   g_poll_wifi   the capture, the monitor radio, BLE, the
 *                 receiver, the engine and the sinks - what
 *                 sloth-wifi runs                          src/poll.c
 *   g_poll_rf     the receiver, the decoders, the engine
 *                 and the sinks; no capture stage - what
 *                 sloth-rf runs (#213)                     src/poll_rf.c
 *
 * Until the cutover (#216) a third, g_poll_sloth, was their union and
 * what the one binary ran. The two share the GNSS stages, health_host,
 * alerts, positions and db, and nothing else; tests/test_poll.c holds
 * each table's stages by name and the shared ones to one function. */
typedef struct {
    const poll_stage_t *stages;
    int                 count;
} poll_table_t;

extern const poll_table_t g_poll_wifi;
extern const poll_table_t g_poll_rf;

/* The stages more than one table carries, so more than one file names
 * them. Everything else is static beside its table.
 *
 *   health_gnss, sensors_gnss,
 *   positions                   src/poll_gnss.c   both daemons
 *   health_rf, sensors_rf       src/poll_rf.c     sloth-rf (and `sloth`)
 *   health_host, alerts, db     src/poll_core.c   both daemons
 *   jsonl                       src/poll.c        `sloth`: the capture's
 *                                                 records (poll_st_jsonl)
 *                               src/poll_rf.c     sloth-rf: its own
 *                                                 (poll_st_jsonl_rf)
 *
 * Two orders are part of the contract and every table keeps them:
 * health_gnss before health_rf (the APRS region check reads s->gps),
 * and both before health_host (sys_status reads every source's state);
 * and sensors_wifi, sensors_gnss, sensors_rf in that order, because a
 * sensor's id is the registry slot it was given and wifi_merged
 * publishes it. */
void poll_st_health_gnss(sloth_state_t *s, const poll_ctx_t *ctx);
void poll_st_sensors_gnss(sloth_state_t *s, const poll_ctx_t *ctx);
void poll_st_health_rf(sloth_state_t *s, const poll_ctx_t *ctx);
void poll_st_sensors_rf(sloth_state_t *s, const poll_ctx_t *ctx);
void poll_st_health_host(sloth_state_t *s, const poll_ctx_t *ctx);
void poll_st_alerts(sloth_state_t *s, const poll_ctx_t *ctx);
void poll_st_positions(sloth_state_t *s, const poll_ctx_t *ctx);
void poll_st_jsonl(sloth_state_t *s, const poll_ctx_t *ctx);
void poll_st_jsonl_rf(sloth_state_t *s, const poll_ctx_t *ctx);
void poll_st_db(sloth_state_t *s, const poll_ctx_t *ctx);

/* Fill ctx's clocks from the seam; research and hooks are left NULL. */
void poll_ctx_init(poll_ctx_t *ctx);

/* Run every stage of `t` in table order. */
void poll_tick(const poll_table_t *t, sloth_state_t *s, const poll_ctx_t *ctx);

/* Index in `t` of the stage named `name`, or -1. Tests use it to assert
 * one stage runs before another without hard-coding table positions. */
int poll_stage_index(const poll_table_t *t, const char *name);

#endif /* SLOTH_POLL_H */
