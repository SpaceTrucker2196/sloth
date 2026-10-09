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
 * Counted tables are exactly the ones listed below, and that list is now
 * every bounded synthesis table in sloth — stating which are covered is
 * the point, since a tally that silently omits a table reads as "no
 * loss" when it means "not measured". The beacon, seqnum and assoc
 * tables joined the tally in the #91 wave-6 slice; wps_session followed,
 * then evidence_frame with the #92 evidence ring, then probe_client on
 * 2026-10-08. The six per-protocol flow rings were the last family left
 * uncounted and joined on 2026-10-09.
 *
 * The flow rings differ from every other counted table in what their
 * count *means*, and a consumer reading `evict_dns_log` has to know it:
 * `*_log_record()` hands the record to the JSONL / data-socket export
 * BEFORE touching the ring, unconditionally. So a flow-ring eviction is
 * the loss of the operator's in-memory scrollback — the 256 newest
 * records a view can show — not the loss of an observation from the
 * forensic log. On a busy segment these counters climb steadily by
 * design and a rising value is not in itself a fault, the same caveat
 * evidence_frame carries. What they answer is "is the live view a
 * complete picture of this protocol right now", which is a real
 * question and was previously unanswerable. */
typedef enum {
    SH_EVICT_ALERT = 0,     /* src/alerts.c — oldest incident dropped (resolved first) */
    SH_EVICT_TOP_HOST,      /* src/top_hosts.c — oldest/quietest remote IP dropped */
    SH_EVICT_PNL_CLIENT,    /* src/probe_pnl.c — oldest client dropped from the PNL table */
    SH_EVICT_PNL_SSID,      /* src/probe_pnl.c — oldest SSID dropped from one client's list */
    SH_EVICT_DHCP_EVENT,    /* src/dhcp_snoop.c — oldest DHCP client dropped */
    SH_EVICT_EAP_SESSION,   /* src/eap_track.c — oldest 802.1X conversation dropped */
    SH_EVICT_DEVICE,        /* src/devices.c — a NEW device refused (drop-on-full, not LRU) */
    SH_EVICT_BEACON_AP,     /* src/beacon_snoop.c — oldest AP record dropped */
    SH_EVICT_SEQNUM_CLIENT, /* src/seqnum_track.c — least-recently-seen client dropped */
    SH_EVICT_ASSOC_PAIR,    /* src/assoc_track.c — oldest (BSSID,STA) grant pair dropped */
    SH_EVICT_ASSOC_REQ,     /* src/assoc_track.c — oldest pending assoc request dropped */
    SH_EVICT_WPS_SESSION,   /* src/wps_track.c — oldest WPS registration session dropped */
    SH_EVICT_EVIDENCE_FRAME,/* src/evidence_ring.c — oldest retained raw 802.11 frame dropped */
    SH_EVICT_PROBE_CLIENT,  /* src/capture/probe.c — least-recently-seen probing client dropped */
    /* The six per-protocol flow rings: plain circular buffers, so the
     * oldest record is overwritten by an append onto a full ring. */
    SH_EVICT_DNS_LOG,       /* src/dns_log.c  — oldest DNS record overwritten */
    SH_EVICT_TLS_LOG,       /* src/tls_log.c  — oldest TLS ClientHello overwritten */
    SH_EVICT_QUIC_LOG,      /* src/quic_log.c — oldest QUIC initial overwritten */
    SH_EVICT_HTTP_LOG,      /* src/http_log.c — oldest HTTP request/response overwritten */
    SH_EVICT_NTP_LOG,       /* src/ntp_log.c  — oldest NTP exchange overwritten */
    SH_EVICT_ICMP_LOG,      /* src/icmp_log.c — oldest ICMP record overwritten */
    SH_EVICT_KIND_COUNT
} sh_evict_t;

/* Record one discarded observation. Out-of-range kinds are ignored so a
 * caller can never corrupt the tally. */
void sh_evict_note(sh_evict_t kind);

/* Lifetime tally for one kind, and across all kinds. */
uint64_t sh_evict_count(sh_evict_t kind);
uint64_t sh_evict_total(void);

/* True for the six per-protocol flow rings, false for every synthesis
 * table. The distinction is not cosmetic: a flow ring rolls over
 * continuously on a busy segment by design, so the two cannot share a
 * "has this sensor lost anything" test. */
int sh_evict_is_flow_ring(sh_evict_t kind);

/* Lifetime tally over the synthesis tables only — every kind for which
 * sh_evict_is_flow_ring() is false.
 *
 * This is the figure for anything that treats a non-zero tally as news:
 * the faults-only TUI health strip, and the change-only signature on the
 * `sensor_health` JSONL record. Both exist on the principle that a
 * counter which climbs every tick of a *working* sensor must not drive
 * them — the same reason `ps_recv` and `stale_secs` are kept out of that
 * signature. The flow rings are exactly such a counter.
 *
 * The `evictions` JSONL field stays sh_evict_total(), because it is
 * published as the sum of the per-table breakout and changing that
 * would be a non-additive schema change. */
uint64_t sh_evict_total_tables(void);

/* Stable lower-case name, part of the `sensor_health` JSONL contract:
 * "alert", "top_host", "pnl_client", "pnl_ssid", "dhcp_event",
 * "eap_session", "device", "beacon_ap", "seqnum_client", "assoc_pair",
 * "assoc_req", "wps_session", "evidence_frame", "probe_client",
 * "dns_log", "tls_log", "quic_log", "http_log", "ntp_log", "icmp_log".
 * Unknown kinds return "". */
const char *sh_evict_name(sh_evict_t kind);

/* Zero every tally. For tests — nothing in the running binary resets
 * these, because a counter that clears has no lifetime meaning. */
void sh_evict_reset(void);

#endif /* SENSOR_HEALTH_H */
