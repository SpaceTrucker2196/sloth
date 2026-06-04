#ifndef JSONL_H
#define JSONL_H

#include "sloth.h"

/* Optional JSONL forensic export.
 *
 * Disabled until jsonl_open() is called. All emit functions are no-ops
 * when the file isn't open, so log modules can call them unconditionally. */

int  jsonl_open  (const char *path);     /* returns 0 on failure */
void jsonl_close (void);
int  jsonl_is_open(void);

/* Per-type emitters. Each writes one JSON object terminated by '\n'. */
void jsonl_emit_dns  (const dns_log_entry_t  *e);
void jsonl_emit_tls  (const tls_log_entry_t  *e);
void jsonl_emit_quic (const quic_log_entry_t *e);
void jsonl_emit_http (const http_log_entry_t *e);
void jsonl_emit_ntp  (const ntp_log_entry_t  *e);
void jsonl_emit_icmp (const icmp_log_entry_t *e);
void jsonl_emit_alert(const alert_t          *a);

/* Snapshot emitter — one line per active flow in s->conns. Driven by the
 * poll loop (≈1 Hz), not by an event ring. Consumers rebuild their table
 * from the latest snapshot keyed by (src, dst, proto). */
void jsonl_emit_connections(const sloth_state_t *s);

/* Snapshot emitter — one line per detected twin episode. Same cadence
 * and pattern as jsonl_emit_connections; consumers key by
 * (ssid, real_bssid, twin_bssid). */
void jsonl_emit_twin_episodes(const sloth_state_t *s);

/* ── Per-view snapshot emitters ──────────────────────────────
 *
 * Each emits one JSONL line per entry in the named table, once per
 * poll. Designed for live consumers (e.g. the iOS client) that
 * reconstruct each view from the latest snapshot — late-joining
 * clients pick up state on the next tick. Aggregate driver below
 * walks them all in one call. */
void jsonl_emit_ifaces        (const sloth_state_t *s);
void jsonl_emit_arp           (const sloth_state_t *s);
void jsonl_emit_dhcp_leases   (const sloth_state_t *s);
void jsonl_emit_wifi_aps      (const sloth_state_t *s);
void jsonl_emit_wifi_stas     (const sloth_state_t *s);
void jsonl_emit_top_hosts     (const sloth_state_t *s);
void jsonl_emit_devices       (const sloth_state_t *s);
void jsonl_emit_beacons       (const sloth_state_t *s);
void jsonl_emit_deauths       (const sloth_state_t *s);
void jsonl_emit_probe_clients (const sloth_state_t *s);
void jsonl_emit_pnl_clients   (const sloth_state_t *s);
void jsonl_emit_seqnum_clients(const sloth_state_t *s);
void jsonl_emit_seqnum_correlations(const sloth_state_t *s);
void jsonl_emit_channels      (const sloth_state_t *s);
void jsonl_emit_assocs        (const sloth_state_t *s);
void jsonl_emit_eapol_events  (const sloth_state_t *s);
void jsonl_emit_mdns_services (const sloth_state_t *s);
void jsonl_emit_nbns_names    (const sloth_state_t *s);
void jsonl_emit_ssdp_devices  (const sloth_state_t *s);
void jsonl_emit_scan_entries  (const sloth_state_t *s);
void jsonl_emit_packets       (const sloth_state_t *s);
void jsonl_emit_processes     (const sloth_state_t *s);
void jsonl_emit_ndp_ras       (const sloth_state_t *s);

/* Umbrella — calls every per-view snapshot emitter. Driven once per
 * poll from main.c after the underlying tables have been refreshed.
 * Connections and twin_episode are emitted separately because they
 * predate this set; this function is purely additive. */
void jsonl_emit_state_snapshots(const sloth_state_t *s);

#endif /* JSONL_H */
