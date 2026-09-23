#ifndef SENSOR_HEALTH_H
#define SENSOR_HEALTH_H

#include <stdint.h>

/* ── Table-overflow accounting (#91 slice 3) ──────────────────────
 *
 * Every synthesis table in sloth is bounded, and every one of them
 * silently discards an observation when it fills — LRU eviction in most,
 * a plain refusal in the device table. That is the correct behaviour for
 * a passive sensor (an attacker spraying identities must not be able to
 * make sloth allocate), but until now it was *invisible*: a sensor at max
 * occupancy and a sensor on a quiet segment produced the same empty
 * delta, which is the "healthy with no detections vs. not observing"
 * confusion this issue is about.
 *
 * These counters are deliberately a tally, not a rate or a ring: the
 * question a consumer asks is "is this sensor losing observations at
 * all", and a monotonic lifetime count answers it from any two samples.
 *
 * Counted tables are exactly the ones listed below. Others (the beacon,
 * seqnum, assoc and per-protocol flow rings) are not instrumented yet —
 * stating which are covered is the point, since a tally that silently
 * omits a table reads as "no loss" when it means "not measured".
 *
 * Thread safety: the probe-side tables are written from the capture
 * threads and the rest from the poll loop, so the tally takes a mutex.
 * Eviction only happens on a full table, so the lock is cold by
 * construction. */
typedef enum {
    SH_EVICT_ALERT = 0,     /* src/alerts.c — oldest incident dropped (resolved first) */
    SH_EVICT_TOP_HOST,      /* src/top_hosts.c — oldest/quietest remote IP dropped */
    SH_EVICT_PNL_CLIENT,    /* src/probe_pnl.c — oldest client dropped from the PNL table */
    SH_EVICT_PNL_SSID,      /* src/probe_pnl.c — oldest SSID dropped from one client's list */
    SH_EVICT_DHCP_EVENT,    /* src/dhcp_snoop.c — oldest DHCP client dropped */
    SH_EVICT_EAP_SESSION,   /* src/eap_track.c — oldest 802.1X conversation dropped */
    SH_EVICT_DEVICE,        /* src/devices.c — a NEW device refused (drop-on-full, not LRU) */
    SH_EVICT_KIND_COUNT
} sh_evict_t;

/* Record one discarded observation. Out-of-range kinds are ignored so a
 * caller can never corrupt the tally. */
void sh_evict_note(sh_evict_t kind);

/* Lifetime tally for one kind, and across all kinds. */
uint64_t sh_evict_count(sh_evict_t kind);
uint64_t sh_evict_total(void);

/* Stable lower-case name, part of the `sensor_health` JSONL contract:
 * "alert", "top_host", "pnl_client", "pnl_ssid", "dhcp_event",
 * "eap_session", "device". Unknown kinds return "". */
const char *sh_evict_name(sh_evict_t kind);

/* Zero every tally. For tests — nothing in the running binary resets
 * these, because a counter that clears has no lifetime meaning. */
void sh_evict_reset(void);

#endif /* SENSOR_HEALTH_H */
