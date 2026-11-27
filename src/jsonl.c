#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "jsonl.h"
#include "jsonl_internal.h"
#include "exposure.h"
#include "gps.h"
#include "position_track.h"
#include "sloth_clock.h"
#include "netstr.h"
#include "tune.h"
#include "capture/probe.h"
#include "capture/df_radio.h"
#include "mon_radios.h"
#include "df.h"
#include "alerts.h"
#include "attack_hw.h"
#include "wired_attach.h"
#include "secure_file.h"
#include "beacon_snoop.h"
#include "captive_portal.h"
#include "sensors.h"
#include "bandwidth.h"
#include "data_socket.h"
#include "formatter.h"
#include "views/procs.h"
#include "sensor_health.h"
#include "ownership.h"
#include "harvest_track.h"    /* harvest_station, harvest_chain (JSONL 1.3.0) */
#include "sys_status.h"
#include "rule_coverage_live.h"
#include "cov_interval.h"
#include "ble_hci.h"        /* Bluetooth host source names (#144 slice 2) */
#include "bt_stream.h"      /* Ubertooth stream state names (#144 slice 3) */
#include "ble_detect.h"     /* ble_alert findings (#144 slice 4) */
#include "ble_flood.h"
#include "wifi_chanhop.h"     /* chanhop_retune_reason() (#91) */
#include "libver.h"
#include "capture/capture.h"
#include "alert_pcap.h"
#include "eapol_log.h"
#include "reg_obs.h"           /* wifi_regulatory (#101 slice B) */
#include "camera_join.h"       /* device_class_label() (#106 round 2) */
#include "rf_distance.h"       /* est_dist_* (2026-10-26) */
#include "probe_latency.h"     /* beacon.probe_lat (JSONL 1.6.0, #187 S3) */
#include "alerts/twin_field.h" /* sensor_health twin193_* (JSONL 1.7.0, #193) */
#include "db.h"                /* sensor_health db_max_mb (JSONL 1.7.0) */

/* The RSSI distance data point (src/rf_distance.h), additive on the
 * records that already carry the RSSI it came from. All four fields are
 * omitted when the row has no estimate — an absent est_dist_m means
 * "no estimate", never 0 m. Metres leave quantised (rf_quantise_m): an
 * estimate of a third party's proximity is not exported finer than it
 * can honestly be known, and is never put in a change-only signature —
 * the band and the trend are (see jsonl_emit_ble_devices). */
static void emit_dist(char *buf, int *off, const rf_track_t *t) {
    if (!t || !t->valid) return;
    kv_double(buf, LINEBUF, off, "est_dist_m", rf_quantise_m(t->est_dm / 10.0));
    kv_str(buf, LINEBUF, off, "est_dist_band",  rf_band_name(t->band));
    kv_str(buf, LINEBUF, off, "est_dist_trend", rf_trend_name(t->trend));
    kv_str(buf, LINEBUF, off, "est_ptx_source", rf_ptx_source_name(t->ptx_source));
}

/* ── emitters ────────────────────────────────────────────── */

void jsonl_emit_dns(const dns_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "dns", e->ts);
    kv_str(buf, LINEBUF, &off, "src",    e->src);
    kv_str(buf, LINEBUF, &off, "qname",  e->qname);
    kv_str(buf, LINEBUF, &off, "qtype",  e->qtype);
    kv_str(buf, LINEBUF, &off, "answer", e->answer);
    kv_int(buf, LINEBUF, &off, "is_resp", e->is_resp ? 1 : 0);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_tls(const tls_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "tls", e->ts);
    kv_str(buf, LINEBUF, &off, "src",  e->src);
    kv_str(buf, LINEBUF, &off, "dst",  e->dst);
    kv_str(buf, LINEBUF, &off, "host", e->host);
    kv_str(buf, LINEBUF, &off, "ver",  e->tls_ver);
    kv_str(buf, LINEBUF, &off, "ja3",  e->ja3);
    if (e->ja4[0])
        kv_str(buf, LINEBUF, &off, "ja4",  e->ja4);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_quic(const quic_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "quic", e->ts);
    kv_str(buf, LINEBUF, &off, "src",  e->src);
    kv_str(buf, LINEBUF, &off, "dst",  e->dst);
    kv_str(buf, LINEBUF, &off, "host", e->host);
    kv_str(buf, LINEBUF, &off, "ver",  e->ver);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_http(const http_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "http", e->ts);
    kv_str(buf, LINEBUF, &off, "src",    e->src);
    kv_str(buf, LINEBUF, &off, "host",   e->host);
    kv_str(buf, LINEBUF, &off, "method", e->method);
    kv_str(buf, LINEBUF, &off, "path",   e->path);
    if (e->ja4h[0])
        kv_str(buf, LINEBUF, &off, "ja4h", e->ja4h);
    /* Response side (#71), additive. body_complete is the field a
     * consumer must key on before comparing bytes: sloth does not
     * reassemble TCP, so "different" and "incomplete" are different
     * answers and only the first means anything. The body itself is
     * deliberately not emitted — it can be page content of any kind,
     * and the forensic value is in the status and the completeness. */
    if (e->is_response) {
        kv_int(buf, LINEBUF, &off, "status",         e->status);
        kv_int(buf, LINEBUF, &off, "content_length", e->content_length);
        kv_int(buf, LINEBUF, &off, "chunked",        e->chunked ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "body_complete",  e->body_complete ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "body_len",       e->resp_body_len);
    }
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_ntp(const ntp_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "ntp", e->ts);
    kv_str(buf, LINEBUF, &off, "src",  e->src);
    kv_str(buf, LINEBUF, &off, "dst",  e->dst);
    kv_str(buf, LINEBUF, &off, "mode", e->mode);
    kv_int(buf, LINEBUF, &off, "version", e->version);
    kv_int(buf, LINEBUF, &off, "stratum", e->stratum);
    kv_str(buf, LINEBUF, &off, "ref",  e->ref);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_icmp(const icmp_log_entry_t *e) {
    if (!any_sink() || !e) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "icmp", e->ts);
    kv_str(buf, LINEBUF, &off, "src", e->src);
    kv_str(buf, LINEBUF, &off, "dst", e->dst);
    kv_str(buf, LINEBUF, &off, "desc", e->desc);
    kv_int(buf, LINEBUF, &off, "ty",   e->type);
    kv_int(buf, LINEBUF, &off, "code", e->code);
    kv_int(buf, LINEBUF, &off, "seq",  e->seq);
    kv_int(buf, LINEBUF, &off, "plen", e->payload_len);
    kv_int(buf, LINEBUF, &off, "v6",   e->is_v6 ? 1 : 0);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_cleartext_cred(const cleartext_cred_t *r) {
    /* Never emit a password field, even NULL/empty. That's the whole
     * point of this event class — the exposure fact, not the secret. */
    if (!any_sink() || !r) return;
    char  buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "cleartext_cred", r->ts);
    kv_str(buf, LINEBUF, &off, "src",       r->src);
    kv_str(buf, LINEBUF, &off, "dst",       r->dst);
    kv_int(buf, LINEBUF, &off, "dst_port",  (int)r->dst_port);
    kv_str(buf, LINEBUF, &off, "protocol",  r->protocol);
    kv_str(buf, LINEBUF, &off, "username",  r->username);
    kv_int(buf, LINEBUF, &off, "pw_observed", r->password_observed);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

/* TCP states map to the Linux kernel's TCP_* enum (1=ESTABLISHED..11=CLOSING).
 * Same table the conns view uses; duplicated here to keep jsonl independent
 * of view code (one-way layering: views read state, emitters serialize it). */
static const char *jsonl_tcp_state_name(int st) {
    static const char *names[] = {
        "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
        "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE",
        "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"
    };
    if (st < 0 || st > 11) return "UNKNOWN";
    return names[st];
}

/* IPv6 literal addresses contain ':' (IPv4 dotted-quads never do). */
static int addr_is_v6(const char *a) { return strchr(a, ':') != NULL; }

static void fmt_endpoint(char *out, int sz, const char *addr, uint16_t port) {
    if (addr_is_v6(addr)) snprintf(out, (size_t)sz, "[%s]:%u", addr, port);
    else                  snprintf(out, (size_t)sz, "%s:%u",   addr, port);
}

static void fmt_bssid_lower(char out[20], const uint8_t b[6]) {
    snprintf(out, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}

void jsonl_emit_twin_episodes(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->twin_episode_count; i++) {
        const twin_episode_t *e = &s->twin_episodes[i];
        char buf[LINEBUF]; int off = 0;
        char real_bssid[20], twin_bssid[20];
        fmt_bssid_lower(real_bssid, e->real_bssid);
        fmt_bssid_lower(twin_bssid, e->twin_bssid);
        start_obj(buf, LINEBUF, &off, "twin_episode", now);
        kv_str(buf, LINEBUF, &off, "ssid",                e->ssid);
        kv_str(buf, LINEBUF, &off, "real_bssid",          real_bssid);
        kv_str(buf, LINEBUF, &off, "twin_bssid",          twin_bssid);
        kv_str(buf, LINEBUF, &off, "enc",                 e->enc);
        kv_int(buf, LINEBUF, &off, "real_rssi",           (long long)e->real_rssi);
        kv_int(buf, LINEBUF, &off, "twin_rssi",           (long long)e->twin_rssi);
        kv_int(buf, LINEBUF, &off, "rssi_swing_dbm",      (long long)e->rssi_swing_dbm);
        kv_int(buf, LINEBUF, &off, "attack_in_progress",  e->attack_in_progress ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "attacker_oui",        e->attacker_oui       ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "hash_mismatch",       e->hash_mismatch      ? 1 : 0);
        /* Additive (#188): the scorer counted the later half's arrival
         * as evidence. Absent from a record an older build wrote. */
        kv_int(buf, LINEBUF, &off, "late_arrival",        e->late_arrival       ? 1 : 0);
        /* Additive (#89). `attributed` 0 means `real_bssid`/`twin_bssid`
         * hold the pair in canonical BSSID order and nothing has
         * established which half is the impostor — a consumer must not
         * read `twin_bssid` as an accusation. RSSI used to decide this
         * and RSSI is not ownership. */
        kv_int(buf, LINEBUF, &off, "attributed",           e->attributed ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "confidence",           (long long)e->confidence);
        /* The two pair axes (#89 slice 3), same shape and same omission
         * rule as on the alert records. `wired_attachment` absent means
         * nothing that can see the wire has answered — not that the AP
         * is off the wire. */
        if (e->ap_class != (uint8_t)TWIN_CLASS_UNKNOWN)
            kv_str(buf, LINEBUF, &off, "ap_class",
                   twin_class_label((twin_class_t)e->ap_class));
        if (e->wired_attach != (uint8_t)WIRED_ATTACH_UNKNOWN)
            kv_str(buf, LINEBUF, &off, "wired_attachment",
                   wired_attach_label((wired_attach_t)e->wired_attach));
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_connections(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        char  buf[LINEBUF]; int off = 0;
        char  src[64], dst[64];
        fmt_endpoint(src, sizeof(src), c->local_addr,  c->local_port);
        fmt_endpoint(dst, sizeof(dst), c->remote_addr, c->remote_port);

        start_obj(buf, LINEBUF, &off, "connections", now);
        kv_str(buf, LINEBUF, &off, "src",   src);
        kv_str(buf, LINEBUF, &off, "dst",   dst);
        kv_str(buf, LINEBUF, &off, "proto", c->proto == PROTO_TCP ? "tcp" : "udp");
        if (c->proto == PROTO_TCP) {
            kv_str(buf, LINEBUF, &off, "state", jsonl_tcp_state_name(c->state));
            if (c->rtt_us) {
                /* RTT formatted with one decimal — emit as raw number, not via kv_int. */
                appendf(buf, LINEBUF, &off, ",\"rtt_ms\":%.1f", c->rtt_us / 1000.0);
            }
            kv_int(buf, LINEBUF, &off, "retx", (long long)c->retrans);
        }
        const conn_bw_t *bw = bw_lookup(s, c);
        kv_int(buf, LINEBUF, &off, "rx_bytes", bw ? (long long)bw->rx_bytes : 0);
        kv_int(buf, LINEBUF, &off, "tx_bytes", bw ? (long long)bw->tx_bytes : 0);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* ── Per-view snapshot emitters ──────────────────────────────
 *
 * One JSONL line per entry in each table. Cadence is the poll
 * loop (≈1 Hz); consumers rebuild the view from the latest
 * snapshot, keyed by an obvious natural identity field documented
 * in each emitter. Any-sink gating up front means the format work
 * is skipped entirely when nobody is listening. */

void jsonl_emit_ifaces(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->iface_count; i++) {
        const iface_stat_t *e = &s->ifaces[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "iface", now);
        kv_str(buf, LINEBUF, &off, "name",       e->name);
        kv_int(buf, LINEBUF, &off, "rx_bytes",   (long long)e->rx_bytes);
        kv_int(buf, LINEBUF, &off, "tx_bytes",   (long long)e->tx_bytes);
        kv_int(buf, LINEBUF, &off, "rx_packets", (long long)e->rx_packets);
        kv_int(buf, LINEBUF, &off, "tx_packets", (long long)e->tx_packets);
        kv_int(buf, LINEBUF, &off, "rx_errors",  (long long)e->rx_errors);
        kv_int(buf, LINEBUF, &off, "rx_drops",   (long long)e->rx_drops);
        kv_int(buf, LINEBUF, &off, "tx_errors",  (long long)e->tx_errors);
        kv_int(buf, LINEBUF, &off, "tx_drops",   (long long)e->tx_drops);
        kv_double(buf, LINEBUF, &off, "rx_rate", e->rx_rate);
        kv_double(buf, LINEBUF, &off, "tx_rate", e->tx_rate);
        kv_int(buf, LINEBUF, &off, "mtu",        (long long)e->mtu);
        kv_int(buf, LINEBUF, &off, "speed_mbps", (long long)e->speed_mbps);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_arp(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->arp_count; i++) {
        const arp_entry_t *e = &s->arp_entries[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "arp", now);
        kv_str(buf, LINEBUF, &off, "ip",    e->ip);
        kv_mac(buf, LINEBUF, &off, "mac",   e->mac);
        kv_str(buf, LINEBUF, &off, "iface", e->iface);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_dhcp_leases(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->dhcp_count; i++) {
        const dhcp_lease_t *e = &s->dhcp_leases[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "dhcp_lease", now);
        kv_str(buf, LINEBUF, &off, "ip",       e->ip);
        kv_str(buf, LINEBUF, &off, "hostname", e->hostname);
        kv_int(buf, LINEBUF, &off, "expire",   (long long)e->expire);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_wifi_aps(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->ap_count; i++) {
        const wifi_ap_t *e = &s->aps[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_ap", now);
        kv_str(buf, LINEBUF, &off, "ssid",       e->ssid);
        kv_str(buf, LINEBUF, &off, "bssid",      e->bssid);
        kv_int(buf, LINEBUF, &off, "signal_dbm", e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "channel",    e->channel);
        kv_str(buf, LINEBUF, &off, "enc",        e->enc);
        kv_int(buf, LINEBUF, &off, "status",     e->status);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_wifi_stas(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->wifi_sta_count; i++) {
        const wifi_sta_t *e = &s->wifi_stas[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_sta", now);
        kv_str(buf, LINEBUF, &off, "mac",            e->mac);
        kv_int(buf, LINEBUF, &off, "signal_dbm",     e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "tx_rate_kbps",   (long long)e->tx_rate_kbps);
        kv_int(buf, LINEBUF, &off, "rx_rate_kbps",   (long long)e->rx_rate_kbps);
        kv_int(buf, LINEBUF, &off, "connected_secs", (long long)e->connected_secs);
        kv_int(buf, LINEBUF, &off, "inactive_ms",    (long long)e->inactive_ms);
        kv_int(buf, LINEBUF, &off, "tx_bytes",       (long long)e->tx_bytes);
        kv_int(buf, LINEBUF, &off, "rx_bytes",       (long long)e->rx_bytes);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_top_hosts(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->top_host_count; i++) {
        const top_host_t *e = &s->top_hosts[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "top_host", now);
        kv_str(buf, LINEBUF, &off, "ip",         e->ip);
        kv_str(buf, LINEBUF, &off, "hostname",   e->hostname);
        kv_str(buf, LINEBUF, &off, "owner",      e->owner);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "conn_count", (long long)e->conn_count);
        kv_double(buf, LINEBUF, &off, "rx_rate", e->rx_rate);
        kv_double(buf, LINEBUF, &off, "tx_rate", e->tx_rate);
        kv_int(buf, LINEBUF, &off, "rx_bytes",   (long long)e->rx_bytes);
        kv_int(buf, LINEBUF, &off, "tx_bytes",   (long long)e->tx_bytes);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_devices(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->device_count; i++) {
        const device_t *e = &s->devices[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "device", now);
        /* An IP-only camera record (#106 round 2) has no MAC; "" says
         * so, where 00:00:00:00:00:00 would read as an address. */
        static const uint8_t zmac[6] = {0};
        if (memcmp(e->mac, zmac, 6) == 0)
            kv_str(buf, LINEBUF, &off, "mac", "");
        else
            kv_mac(buf, LINEBUF, &off, "mac",     e->mac);
        kv_str(buf, LINEBUF, &off, "ip",          e->ip);
        kv_str(buf, LINEBUF, &off, "hostname",    e->hostname);
        kv_str(buf, LINEBUF, &off, "vendor",      e->vendor);
        kv_str(buf, LINEBUF, &off, "last_ssid",   e->last_ssid);
        kv_int(buf, LINEBUF, &off, "is_ap",       e->is_ap ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "signal_dbm",  e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "probe_count", (long long)e->probe_count);
        kv_int(buf, LINEBUF, &off, "sources",     (long long)e->sources);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_str(buf, LINEBUF, &off, "risk",         device_risk_label(e->risk_level));
        kv_int(buf, LINEBUF, &off, "risk_signals", (long long)e->risk_signals);
        /* Additive (#106 round 2): camera identity, every one a discrete
         * value. This record has no change-only signature today; if it
         * gains one these can enter it as they are. The per-signal
         * cam_seen[] times stay off it: each source row already carries
         * its own last_seen on its own record (onvif_device,
         * mdns_service, ssdp_device, beacon). */
        kv_str(buf, LINEBUF, &off, "device_class",  device_class_label(e->device_class));
        kv_str(buf, LINEBUF, &off, "camera_vendor", e->camera_vendor);
        kv_str(buf, LINEBUF, &off, "camera_model",  e->camera_model);
        kv_int(buf, LINEBUF, &off, "setup_mode",    e->setup_mode ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "cam_signals",   (long long)e->cam_signal_mask);
        /* Additive (#155): the classifier's score, what it rests on and
         * what vetoed it, as stable slugs (camera_join.h), the conflict
         * flag, and the client's DHCP options 55 / 60, display-only. All
         * discrete, so a future change-only signature can take them. */
        {
            char evs[128], vts[96];
            cam_evidence_list(e->cam_evidence, evs, sizeof(evs));
            cam_veto_list(e->cam_vetoes, vts, sizeof(vts));
            kv_int(buf, LINEBUF, &off, "cam_score",    (long long)e->cam_score);
            kv_str(buf, LINEBUF, &off, "cam_evidence", evs);
            kv_str(buf, LINEBUF, &off, "cam_vetoes",   vts);
            kv_int(buf, LINEBUF, &off, "cam_conflict", e->cam_conflict ? 1 : 0);
            kv_str(buf, LINEBUF, &off, "dhcp_prl",     e->dhcp_prl);
            kv_str(buf, LINEBUF, &off, "dhcp_vci",     e->dhcp_vci);
        }
        emit_dist(buf, &off, &e->dist);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* beacon.probe_lat (JSONL 1.6.0, #187 S3): this BSSID's probe-response
 * latency, the nearest-rank figures over its last PLAT_SAMPLES pairs per
 * kind (probe_latency.h). Absent until a pair was recorded, so a consumer
 * can tell "not measured" from a figure. An observation only: no cited
 * threshold exists and nothing in sloth reads it for a verdict.
 *
 * Change-only emission: `beacon` has no change-only signature — it is
 * written on every pass — so these raw microseconds sign nothing. Should
 * the record gain one, they stay out of it (agents/AGENTS.md): a median
 * moves on nearly every new pair. */
static void emit_probe_lat(char *buf, int *off, const uint8_t bssid[6]) {
    probe_latency_row_t pl;
    if (!probe_latency_get(bssid, &pl) || pl.src == PLAT_SRC_NONE) return;
    const plat_stats_t *d = &pl.kind[PLAT_KIND_DIRECTED];
    const plat_stats_t *w = &pl.kind[PLAT_KIND_WILDCARD];
    if (d->n == 0 && w->n == 0) return;
    appendf(buf, LINEBUF, off,
            ",\"probe_lat\":{\"src\":\"%s\",\"n_dir\":%u,\"med_dir_us\":%u,"
            "\"p10_dir_us\":%u,\"p90_dir_us\":%u,\"min_dir_us\":%u,"
            "\"n_wild\":%u,\"med_wild_us\":%u}",
            pl.src == PLAT_SRC_TSFT ? "tsft" : "pcap",
            (unsigned)d->n, (unsigned)d->med_us, (unsigned)d->p10_us,
            (unsigned)d->p90_us, (unsigned)d->min_us,
            (unsigned)w->n, (unsigned)w->med_us);
}

void jsonl_emit_beacons(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *e = &s->beacon_aps[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "beacon", now);
        kv_str(buf, LINEBUF, &off, "ssid",       e->ssid);
        kv_mac(buf, LINEBUF, &off, "bssid",      e->bssid);
        kv_int(buf, LINEBUF, &off, "signal_dbm", e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "channel",    e->channel);
        kv_str(buf, LINEBUF, &off, "enc",        e->enc);
        kv_int(buf, LINEBUF, &off, "beacon_ms",  (long long)e->beacon_ms);
        kv_str(buf, LINEBUF, &off, "pairwise",   e->pairwise);
        kv_str(buf, LINEBUF, &off, "group",      e->group);
        kv_str(buf, LINEBUF, &off, "akm",        e->akm);
        kv_int(buf, LINEBUF, &off, "mfp",        e->mfp);
        /* Additive (#62): WPA_DG_* bits — the downgrade lanes this
         * AP advertises about itself. 0 for a clean posture. */
        kv_int(buf, LINEBUF, &off, "downgrade_flags", e->downgrade_flags);
        kv_int(buf, LINEBUF, &off, "akm_bits",   (long long)e->akm_bits);
        /* Additive (#66): what the BSS is actually operating on, as
         * distinct from what its radio can do. channel_source names
         * which IE supplied the primary channel, so a wrong one is
         * attributable — DS Param is absent on much 6 GHz gear. */
        kv_int(buf, LINEBUF, &off, "operating_width",  e->operating_width);
        kv_int(buf, LINEBUF, &off, "primary_channel",  e->primary_channel);
        kv_int(buf, LINEBUF, &off, "channel_source",   e->channel_source);
        kv_int(buf, LINEBUF, &off, "secondary_offset", e->secondary_offset);
        kv_str(buf, LINEBUF, &off, "vendor",     e->vendor);
        kv_int(buf, LINEBUF, &off, "has_wps",    e->has_wps ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "wps_state",  e->wps_state);
        kv_int(buf, LINEBUF, &off, "wps_locked", e->wps_locked);
        /* Additive (#82): Config Methods bitmap / Device Password ID.
         * 0 = not observed for both; 0x0004 on the latter means the AP
         * is advertising an active WPS Push-Button session right now.
         * Not sticky — reflects the most recent beacon only. */
        kv_int(buf, LINEBUF, &off, "wps_config_methods", e->wps_config_methods);
        kv_int(buf, LINEBUF, &off, "wps_device_pwd_id",  e->wps_device_pwd_id);
        /* Additive (#77): WPS Manufacturer / Model Name / Model Number /
         * Serial Number, when the beacon's WPS IE leaks them.
         *
         * "" means EITHER absent or present-but-unprintable: these are
         * filtered to printable ASCII at the parse boundary, because the
         * bytes are chosen by whoever is transmitting and reached the
         * operator's terminal unfiltered in non-ncurses builds. An
         * attribute whose every byte was a control character therefore
         * reads exactly like a missing one. That is deliberate — a
         * consumer has nothing useful to do with "present but entirely
         * unprintable" that it would not also do with absent — but it is
         * not the same convention as `vendor` above, which is only ever
         * empty when absent. */
        kv_str(buf, LINEBUF, &off, "wps_manufacturer", e->wps_manufacturer);
        kv_str(buf, LINEBUF, &off, "wps_model_name",    e->wps_model_name);
        kv_str(buf, LINEBUF, &off, "wps_model_number",  e->wps_model_number);
        kv_str(buf, LINEBUF, &off, "wps_serial",        e->wps_serial);
        kv_str(buf, LINEBUF, &off, "phy",        e->phy);
        kv_int(buf, LINEBUF, &off, "revealed",   e->revealed ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count",(long long)e->frame_count);
        /* fp — flags + vendor-IE hash; OUI is the BSSID prefix, omit. */
        kv_int(buf, LINEBUF, &off, "fp_flags",       e->fp.flags);
        kv_int(buf, LINEBUF, &off, "vendor_ies_hash",(long long)e->fp.vendor_ies_hash);
        /* Additive (#77): IE-ordering fingerprint; 0 = not decoded. */
        kv_int(buf, LINEBUF, &off, "ie_order_hash",  (long long)e->fp.ie_order_hash);
        kv_int(buf, LINEBUF, &off, "ie_order_count", e->fp.ie_order_count);
        /* Additive (#77): beacon TBTT jitter — stddev of the AP's own
         * medium-access deferral, in µs on the AP's clock. 0 samples
         * means the BSSID was heard once, or on the managed-mode path
         * that carries no timestamp; the sample count says which. */
        uint32_t tbtt_sd = 0;
        (void)beacon_tbtt_jitter(&e->tbtt, &tbtt_sd, NULL);
        kv_int(buf, LINEBUF, &off, "tbtt_jitter_us",      (long long)tbtt_sd);
        kv_int(buf, LINEBUF, &off, "tbtt_jitter_samples", (long long)e->tbtt.samples);
        kv_int(buf, LINEBUF, &off, "tbtt_jitter_resets",  (long long)e->tbtt.resets);
        kv_int(buf, LINEBUF, &off, "rssi_min_60s", e->rssi_min_60s);
        kv_int(buf, LINEBUF, &off, "rssi_max_60s", e->rssi_max_60s);
        emit_dist(buf, &off, &e->dist);
        /* QBSS Load — AP self-reported occupancy (omitted when the IE
         * was absent so consumers can tell "no data" from "0"). */
        if (e->has_qbss) {
            kv_int(buf, LINEBUF, &off, "qbss_stations",  e->qbss_stations);
            kv_int(buf, LINEBUF, &off, "qbss_chan_util", e->qbss_chan_util);
        }
        /* Malformed-IE counters — only when non-zero, so a clean AP's
         * record stays uncluttered (mgmt-frame fuzz detector, #33). */
        if (e->fuzz_ie_overruns || e->fuzz_oversize_ssid || e->fuzz_truncated_rsn) {
            kv_int(buf, LINEBUF, &off, "fuzz_ie_overruns",   e->fuzz_ie_overruns);
            kv_int(buf, LINEBUF, &off, "fuzz_oversize_ssid", e->fuzz_oversize_ssid);
            kv_int(buf, LINEBUF, &off, "fuzz_truncated_rsn", e->fuzz_truncated_rsn);
        }
        /* ssid_history as a JSON array — bounded by MAX_AP_SSID_HISTORY. */
        appendf(buf, LINEBUF, &off, ",\"ssid_history\":[");
        for (int k = 0; k < e->ssid_history_n; k++) {
            appendf(buf, LINEBUF, &off, "%s\"", k ? "," : "");
            json_escape(e->ssid_history[k], buf, LINEBUF, &off);
            appendf(buf, LINEBUF, &off, "\"");
        }
        appendf(buf, LINEBUF, &off, "]");
        /* neighbors[] — array of {bssid, channel, phy_type}. */
        appendf(buf, LINEBUF, &off, ",\"neighbors\":[");
        for (int k = 0; k < e->neighbor_count; k++) {
            const ap_neighbor_t *n = &e->neighbors[k];
            char nb[20];
            snprintf(nb, sizeof(nb),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     n->bssid[0], n->bssid[1], n->bssid[2],
                     n->bssid[3], n->bssid[4], n->bssid[5]);
            appendf(buf, LINEBUF, &off, "%s{\"bssid\":\"%s\",\"channel\":%d,\"phy_type\":%d}",
                            k ? "," : "", nb, n->channel, n->phy_type);
        }
        appendf(buf, LINEBUF, &off, "]");
        /* Additive (JSONL 1.6.0, #187 S3), last so every earlier field
         * keeps its position. */
        emit_probe_lat(buf, &off, e->bssid);
        /* Additive (JSONL 1.7.0, #172): the harvest-friendly posture,
         * present only once this BSSID was heard handing out the PMKID
         * KDE in an M1 — 1 with a PSK-family AKM on its beacon (the
         * value is attackable offline, Steube 2018), 0 without one (SAE
         * or 802.1X: the KDE is there but the PMK is not the
         * passphrase's). Absent means not observed, never "no". The
         * name avoids slothweb's credential words (web_secret.c). */
        {
            int hp = harvest_posture_psk(e->bssid, e->akm_bits);
            if (hp >= 0)
                kv_int(buf, LINEBUF, &off, "harvest_posture", hp);
        }
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* wifi_regulatory (#101 slice B) — the regulatory envelope each BSSID
 * claims, as its own record beside `beacon` rather than as more beacon
 * fields: the beacon record is emitted every tick and carries RSSI, and
 * this one is change-only, so a consumer tracking claims reads only the
 * lines where a claim changed.
 *
 * Emitted only for a BSSID that ever sent a regulatory element (a
 * malformed one included); an AP that never did has made no claim, and
 * a record of zeros would read as one. Every value is the raw field the
 * element carried, next to its *_present flag — check the flag first.
 *
 * The change-only signature holds discrete claim values and nothing
 * else (agents/AGENTS.md, change-only emission): codes, flags, dB and
 * dBm integers, the raw TPE octets. The malformed_* counters climb on
 * every crafted frame, so they enter it only as "any malformed" and
 * otherwise ride the heartbeat. */
static const char *reg_env_name(uint8_t env) {
    switch (env) {
    case REG_ENV_ABSENT:        return "absent";
    case REG_ENV_ANY:           return "any";
    case REG_ENV_INDOOR:        return "indoor";
    case REG_ENV_OUTDOOR:       return "outdoor";
    case REG_ENV_NON_COUNTRY:   return "non_country";
    case REG_ENV_OPCLASS_TABLE: return "opclass_table";
    default:                    return "unknown";
    }
}

static uint64_t wifi_reg_signature(const reg_ie_t *r, const reg_6g_t *g) {
    uint64_t h = FNV64_OFFSET;
    h = fnv1a(&r->country_present, 1, h);
    h = fnv1a(r->country, sizeof(r->country), h);
    h = fnv1a(&r->env_raw, 1, h);
    h = fnv1a(&r->triplet_count, 1, h);
    h = fnv1a(&r->triplets_truncated, 1, h);
    for (int k = 0; k < r->triplet_count && k < REG_MAX_COUNTRY_TRIPLETS; k++) {
        const reg_triplet_t *t = &r->triplets[k];
        uint8_t b[7] = { t->is_operating, t->first_channel, t->num_channels,
                         (uint8_t)t->max_tx_power_dbm, t->ext_id,
                         t->operating_class, t->coverage_class };
        h = fnv1a(b, sizeof(b), h);
    }
    uint8_t p[6] = { r->power_constraint_present, r->power_constraint_db,
                     r->tpc_present, (uint8_t)r->tpc_tx_power_dbm,
                     (uint8_t)r->tpc_link_margin_db,
                     (uint8_t)(r->malformed_country ||
                               r->malformed_power_constraint ||
                               r->malformed_tpc ||
                               g->malformed_he6 || g->malformed_tpe) };
    h = fnv1a(p, sizeof(p), h);
    uint8_t q[4] = { g->he6_present, g->he6_control_raw, g->tpe_count,
                     g->tpe_truncated };
    h = fnv1a(q, sizeof(q), h);
    for (int k = 0; k < g->tpe_count && k < REG_6G_MAX_TPE; k++) {
        const reg_tpe_t *e = &g->tpe[k];
        uint8_t b[3] = { e->info_raw, e->n_values, e->ext_octets };
        h = fnv1a(b, sizeof(b), h);
        h = fnv1a(e->values_half_db, e->n_values, h);
    }
    return h;
}

void jsonl_emit_wifi_regulatory(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *e = &s->beacon_aps[i];
        const reg_ie_t *r = &e->reg;
        const reg_6g_t *g = &e->reg6g;
        if (!reg_obs_any(r, g)) continue;
        if (!jsonl_changed(JD_WIFI_REG, e->bssid, sizeof(e->bssid),
                           wifi_reg_signature(r, g), now))
            continue;

        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_regulatory", now);
        kv_mac(buf, LINEBUF, &off, "bssid", e->bssid);
        kv_int(buf, LINEBUF, &off, "country_present", r->country_present);
        kv_str(buf, LINEBUF, &off, "country", r->country);
        kv_str(buf, LINEBUF, &off, "env", reg_env_name(r->env));
        kv_int(buf, LINEBUF, &off, "env_raw", r->env_raw);
        kv_int(buf, LINEBUF, &off, "triplets_truncated", r->triplets_truncated);
        appendf(buf, LINEBUF, &off, ",\"triplets\":[");
        for (int k = 0; k < r->triplet_count && k < REG_MAX_COUNTRY_TRIPLETS; k++) {
            const reg_triplet_t *t = &r->triplets[k];
            if (t->is_operating)
                appendf(buf, LINEBUF, &off,
                        "%s{\"ext_id\":%u,\"operating_class\":%u,\"coverage_class\":%u}",
                        k ? "," : "", (unsigned)t->ext_id,
                        (unsigned)t->operating_class,
                        (unsigned)t->coverage_class);
            else
                appendf(buf, LINEBUF, &off,
                        "%s{\"first_channel\":%u,\"num_channels\":%u,\"max_tx_power_dbm\":%d}",
                        k ? "," : "", (unsigned)t->first_channel,
                        (unsigned)t->num_channels, (int)t->max_tx_power_dbm);
        }
        appendf(buf, LINEBUF, &off, "]");
        kv_int(buf, LINEBUF, &off, "power_constraint_present",
               r->power_constraint_present);
        kv_int(buf, LINEBUF, &off, "power_constraint_db", r->power_constraint_db);
        kv_int(buf, LINEBUF, &off, "tpc_present", r->tpc_present);
        kv_int(buf, LINEBUF, &off, "tpc_tx_power_dbm", r->tpc_tx_power_dbm);
        kv_int(buf, LINEBUF, &off, "tpc_link_margin_db", r->tpc_link_margin_db);
        kv_int(buf, LINEBUF, &off, "he6_present", g->he6_present);
        kv_int(buf, LINEBUF, &off, "he6_reg_info", g->he6_reg_info);
        kv_str(buf, LINEBUF, &off, "he6_reg_info_name",
               g->he6_present ? reg_6g_info_name(g->he6_reg_info) : "");
        kv_int(buf, LINEBUF, &off, "tpe_truncated", g->tpe_truncated);
        appendf(buf, LINEBUF, &off, ",\"tpe\":[");
        for (int k = 0; k < g->tpe_count && k < REG_6G_MAX_TPE; k++) {
            const reg_tpe_t *t = &g->tpe[k];
            appendf(buf, LINEBUF, &off,
                    "%s{\"interp\":%u,\"interp_name\":\"%s\",\"category\":%u,"
                    "\"count\":%u,\"reserved\":%u,\"ext_octets\":%u,"
                    "\"values_half_db\":[",
                    k ? "," : "", (unsigned)t->interp,
                    reg_tpe_interp_name(t->interp), (unsigned)t->category,
                    (unsigned)t->count, (unsigned)t->reserved,
                    (unsigned)t->ext_octets);
            for (int v = 0; v < t->n_values && v < REG_TPE_MAX_VALUES; v++)
                appendf(buf, LINEBUF, &off, "%s%d", v ? "," : "",
                        (int)t->values_half_db[v]);
            appendf(buf, LINEBUF, &off, "]}");
        }
        appendf(buf, LINEBUF, &off, "]");
        kv_int(buf, LINEBUF, &off, "malformed_country", r->malformed_country);
        kv_int(buf, LINEBUF, &off, "malformed_power_constraint",
               r->malformed_power_constraint);
        kv_int(buf, LINEBUF, &off, "malformed_tpc", r->malformed_tpc);
        kv_int(buf, LINEBUF, &off, "malformed_he6", g->malformed_he6);
        kv_int(buf, LINEBUF, &off, "malformed_tpe", g->malformed_tpe);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_deauths(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->deauth_count; i++) {
        const deauth_event_t *e = &s->deauth_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "deauth", now);
        kv_mac(buf, LINEBUF, &off, "src",        e->src);
        kv_mac(buf, LINEBUF, &off, "dst",        e->dst);
        kv_mac(buf, LINEBUF, &off, "bssid",      e->bssid);
        kv_int(buf, LINEBUF, &off, "reason",     e->reason);
        kv_int(buf, LINEBUF, &off, "subtype",    e->subtype);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "count",      (long long)e->count);
        kv_int(buf, LINEBUF, &off, "flood",      e->flood ? 1 : 0);
        /* #88, additive: "reason" is 0 and meaningless unless
         * reason_valid; retries/protected/truncated are subsets of
         * count; flood_last is when the window threshold was last met
         * (0 = never). */
        kv_int(buf, LINEBUF, &off, "reason_valid", e->reason_valid ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "retries",      (long long)e->retries);
        kv_int(buf, LINEBUF, &off, "protected",    (long long)e->protected_count);
        kv_int(buf, LINEBUF, &off, "truncated",    (long long)e->truncated_count);
        kv_int(buf, LINEBUF, &off, "flood_last",   (long long)e->flood_last);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_probe_clients(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->probe_count; i++) {
        const probe_client_t *e = &s->probe_clients[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "probe_client", now);
        kv_mac(buf, LINEBUF, &off, "mac",         e->mac);
        kv_str(buf, LINEBUF, &off, "ssid",        e->ssid);
        kv_int(buf, LINEBUF, &off, "signal_dbm",  e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "channel",     e->channel);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count", (long long)e->frame_count);
        /* #88, additive: probe-flood window evidence. */
        kv_int(buf, LINEBUF, &off, "flood",         e->flood ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "flood_last",    (long long)e->flood_last);
        kv_int(buf, LINEBUF, &off, "burst_frames",  (long long)e->burst_frames);
        kv_int(buf, LINEBUF, &off, "burst_span_ms", (long long)e->burst_span_ms);
        emit_dist(buf, &off, &e->dist);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_pnl_clients(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->pnl_count; i++) {
        const pnl_client_t *e = &s->pnl_clients[i];

        /* Suppress rows unchanged since last emit (issue #42). Signature
         * covers identity + every observation field serialised below,
         * excluding only the envelope ts. */
        uint64_t sig = fnv1a(&e->mac_random,  sizeof(e->mac_random),  FNV64_OFFSET);
        sig = fnv1a(&e->probe_count, sizeof(e->probe_count), sig);
        sig = fnv1a(e->os_fp, sizeof(e->os_fp), sig);
        sig = fnv1a(e->phy,   sizeof(e->phy),   sig);
        sig = fnv1a(&e->first_seen, sizeof(e->first_seen), sig);
        sig = fnv1a(&e->last_seen,  sizeof(e->last_seen),  sig);
        sig = fnv1a(&e->ssid_count, sizeof(e->ssid_count), sig);
        for (int k = 0; k < e->ssid_count; k++)
            sig = fnv1a(e->ssids[k], strlen(e->ssids[k]), sig);
        if (!jsonl_changed(JD_PNL, e->mac, sizeof(e->mac), sig, now)) continue;

        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "pnl_client", now);
        kv_mac(buf, LINEBUF, &off, "mac",         e->mac);
        kv_int(buf, LINEBUF, &off, "mac_random",  e->mac_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "probe_count", (long long)e->probe_count);
        kv_str(buf, LINEBUF, &off, "os_fp",       e->os_fp);
        kv_str(buf, LINEBUF, &off, "phy",         e->phy);
        /* Additive (#60): 1 when an association request corroborated
         * the tier, 0 when it is inferred from probes alone. A consumer
         * that ignores it sees exactly what it saw before. */
        kv_int(buf, LINEBUF, &off, "phy_confirmed", e->phy_confirmed ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        appendf(buf, LINEBUF, &off, ",\"ssids\":[");
        for (int k = 0; k < e->ssid_count; k++) {
            appendf(buf, LINEBUF, &off, "%s\"", k ? "," : "");
            json_escape(e->ssids[k], buf, LINEBUF, &off);
            appendf(buf, LINEBUF, &off, "\"");
        }
        appendf(buf, LINEBUF, &off, "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_seqnum_clients(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->seqnum_count; i++) {
        const seqnum_client_t *e = &s->seqnum_clients[i];

        /* Suppress rows unchanged since last emit (issue #42). frame_count
         * and hist advance whenever the client is actively seen, so active
         * devices still emit each cycle; only idle repeats are dropped. */
        uint64_t sig = fnv1a(&e->mac_random,  sizeof(e->mac_random),  FNV64_OFFSET);
        sig = fnv1a(&e->last_seen,   sizeof(e->last_seen),   sig);
        sig = fnv1a(&e->frame_count, sizeof(e->frame_count), sig);
        sig = fnv1a(&e->hist_n,      sizeof(e->hist_n),      sig);
        sig = fnv1a(e->hist, (size_t)e->hist_n * sizeof(e->hist[0]), sig);
        if (!jsonl_changed(JD_SEQNUM, e->mac, sizeof(e->mac), sig, now)) continue;

        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "seqnum_client", now);
        kv_mac(buf, LINEBUF, &off, "mac",         e->mac);
        kv_int(buf, LINEBUF, &off, "mac_random",  e->mac_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count", (long long)e->frame_count);
        appendf(buf, LINEBUF, &off, ",\"hist\":[");
        for (int k = 0; k < e->hist_n; k++) {
            appendf(buf, LINEBUF, &off, "%s%u", k ? "," : "", e->hist[k]);
        }
        appendf(buf, LINEBUF, &off, "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_seqnum_correlations(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->seqnum_correlation_count; i++) {
        const seqnum_correlation_t *e = &s->seqnum_correlations[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "seqnum_correlation", now);
        kv_mac(buf, LINEBUF, &off, "mac_a",        e->mac_a);
        kv_mac(buf, LINEBUF, &off, "mac_b",        e->mac_b);
        kv_int(buf, LINEBUF, &off, "mac_a_random", e->mac_a_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "mac_b_random", e->mac_b_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "gap",          e->gap);
        kv_int(buf, LINEBUF, &off, "dt_ms",        (long long)e->dt_ms);
        kv_int(buf, LINEBUF, &off, "a_count",      (long long)e->a_count);
        kv_int(buf, LINEBUF, &off, "b_count",      (long long)e->b_count);
        /* Additive (#94). A consumer that stored `gap` alone could not
         * tell a forward transition from a coincidence nearby, nor how
         * much evidence the pair rested on — so it had no way to avoid
         * treating every row as an identification. Existing fields keep
         * their meaning exactly; no rename, no removal, no schema bump. */
        kv_int(buf, LINEBUF, &off, "fwd_gap",      e->fwd_gap);
        kv_int(buf, LINEBUF, &off, "confidence",   e->confidence);
        kv_int(buf, LINEBUF, &off, "window_start", (long long)e->window_start);
        kv_int(buf, LINEBUF, &off, "window_end",   (long long)e->window_end);
        kv_int(buf, LINEBUF, &off, "a_hist_n",     e->a_hist_n);
        kv_int(buf, LINEBUF, &off, "b_hist_n",     e->b_hist_n);
        kv_int(buf, LINEBUF, &off, "a_is_earlier", e->a_is_earlier ? 1 : 0);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_channels(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->channel_count; i++) {
        const channel_summary_t *e = &s->channels[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "channel_summary", now);
        kv_int(buf, LINEBUF, &off, "channel",     e->channel);
        /* Additive: a 5 GHz and a 6 GHz channel can share a number (37,
         * 149, …), so `channel` alone cannot say which band a consumer
         * is looking at. ap_band_label() is the same function the [m]
         * Channel view renders, so a JSONL reader and the TUI cannot
         * disagree about what band row `channel` describes. */
        kv_str(buf, LINEBUF, &off, "band",
               ap_band_label(e->channel, e->channel_source));
        kv_int(buf, LINEBUF, &off, "ap_count",    e->ap_count);
        kv_int(buf, LINEBUF, &off, "assoc_count", e->assoc_count);
        kv_int(buf, LINEBUF, &off, "best_signal", e->best_signal);
        kv_str(buf, LINEBUF, &off, "top_ssid",    e->top_ssid);
        /* Additive (#64): observed control-frame volume. The measured
         * half of channel occupancy, as distinct from the QBSS Load IE
         * an AP reports about itself. CTS and ACK carry no transmitter
         * address, so these are per-channel and cannot be finer. */
        kv_int(buf, LINEBUF, &off, "ctrl_total",    (long long)e->ctrl_total);
        kv_int(buf, LINEBUF, &off, "ctrl_rts",      (long long)e->ctrl_rts);
        kv_int(buf, LINEBUF, &off, "ctrl_cts",      (long long)e->ctrl_cts);
        kv_int(buf, LINEBUF, &off, "ctrl_ack",      (long long)e->ctrl_ack);
        kv_int(buf, LINEBUF, &off, "ctrl_blockack", (long long)e->ctrl_blockack);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* What clients asked for, and what they gave up asking for it (#60).
 * Emitted alongside `assoc` rather than folded into it: the ask and the
 * grant are separate observations, and a request exists even when no
 * association follows — which is exactly the case worth seeing. */
void jsonl_emit_assoc_reqs(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->assoc_req_count; i++) {
        const assoc_req_t *e = &s->assoc_reqs[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_assoc_req", now);
        kv_mac(buf, LINEBUF, &off, "bssid",           e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",         e->sta);
        kv_str(buf, LINEBUF, &off, "requested_ssid",  e->requested_ssid);
        kv_int(buf, LINEBUF, &off, "is_reassoc",      e->is_reassoc ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "listen_interval", e->listen_interval);
        kv_int(buf, LINEBUF, &off, "capability_info", e->capability_info);
        kv_int(buf, LINEBUF, &off, "akm_bits",        (long long)e->akm_bits);
        kv_int(buf, LINEBUF, &off, "pairwise_bits",   (long long)e->pairwise_bits);
        kv_int(buf, LINEBUF, &off, "requested_mfp",   e->requested_mfp);
        kv_int(buf, LINEBUF, &off, "supported_rates", (long long)e->supported_rates);
        kv_str(buf, LINEBUF, &off, "phy",             e->phy);
        kv_int(buf, LINEBUF, &off, "vendor_ie_hash",  (long long)e->vendor_ie_hash);
        kv_int(buf, LINEBUF, &off, "downgrade_flags", e->downgrade_flags);
        kv_int(buf, LINEBUF, &off, "prev_akm_bits",   (long long)e->prev_akm_bits);
        kv_int(buf, LINEBUF, &off, "prev_mfp",        e->prev_mfp);
        kv_int(buf, LINEBUF, &off, "last_seen",       (long long)e->ts);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* 802.11v steering (#59). One record per (BSSID, STA) the AP has sent
 * a BTM Request to, forcing or not — a consumer correlating an alert
 * needs the ordinary steering around it to tell an attack from a
 * roaming policy. `imminent_count` is the subset the alert acts on. */
void jsonl_emit_btm_steers(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->btm_steer_count; i++) {
        const btm_steer_t *e = &s->btm_steers[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "btm_request", now);
        kv_mac(buf, LINEBUF, &off, "bssid",             e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",           e->sta);
        kv_int(buf, LINEBUF, &off, "req_count",         e->req_count);
        kv_int(buf, LINEBUF, &off, "imminent_count",    e->imminent_count);
        kv_int(buf, LINEBUF, &off, "request_mode",      e->last_request_mode);
        kv_int(buf, LINEBUF, &off, "disassoc_timer",    e->last_disassoc_timer);
        kv_int(buf, LINEBUF, &off, "validity_interval", e->last_validity_interval);
        kv_int(buf, LINEBUF, &off, "candidate_count",   e->candidate_count);
        kv_int(buf, LINEBUF, &off, "candidates_truncated",
               e->candidates_truncated ? 1 : 0);
        for (int c = 0; c < e->candidate_count && c < MAX_AP_NEIGHBORS; c++) {
            char key[16];
            snprintf(key, sizeof(key), "candidate_%d", c);
            kv_mac(buf, LINEBUF, &off, key, e->candidates[c]);
        }
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* Channel-switch announcements (#63). Every announcement, legitimate
 * or not — a consumer judging one needs the ordinary DFS traffic around
 * it, and `ta` versus `bssid` is the forgery signal.
 *
 * `event_ts` (#255): `start_obj()` already writes `ts` as this line's
 * *emit* time, the convention every other record follows. A second
 * `kv_int(..., "ts", e->ts)` here repeated that key with the frame's
 * own time instead of adding a new one — a duplicate key most parsers
 * silently resolve with last-value-wins, but one slothweb's decoder
 * flags and drops, so every wifi_csa_event record was lost rather than
 * read. `event_ts` is additive and carries what the duplicate used to:
 * the identity key is `bssid`+`event_ts`, not `bssid`+`ts`. */
void jsonl_emit_csa_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->csa_count; i++) {
        const sloth_csa_event_t *e = &s->csa_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_csa_event", now);
        kv_mac(buf, LINEBUF, &off, "bssid",        e->bssid);
        kv_mac(buf, LINEBUF, &off, "ta",           e->ta);
        kv_int(buf, LINEBUF, &off, "new_channel",  e->new_channel);
        kv_int(buf, LINEBUF, &off, "new_op_class", e->new_op_class);
        kv_int(buf, LINEBUF, &off, "switch_mode",  e->switch_mode);
        kv_int(buf, LINEBUF, &off, "switch_count", e->switch_count);
        kv_int(buf, LINEBUF, &off, "source",       e->source);
        kv_int(buf, LINEBUF, &off, "from_channel", e->from_channel);
        kv_int(buf, LINEBUF, &off, "event_ts",     (long long)e->ts);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* 802.11k survey activity (#61). Targeted and broadcast requests are
 * separate fields because only the first is the signal, and reports are
 * separate again — a reply is evidence a survey succeeded, not that one
 * was attempted. */
void jsonl_emit_rrm_pairs(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->rrm_pair_count; i++) {
        const sloth_rrm_pair_t *e = &s->rrm_pairs[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "rrm_beacon_request", now);
        kv_mac(buf, LINEBUF, &off, "bssid",          e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",        e->sta);
        kv_int(buf, LINEBUF, &off, "targeted_reqs",  e->targeted_reqs);
        kv_int(buf, LINEBUF, &off, "broadcast_reqs", e->broadcast_reqs);
        kv_int(buf, LINEBUF, &off, "reports_seen",   e->reports_seen);
        kv_str(buf, LINEBUF, &off, "last_ssid",      e->last_ssid);
        kv_int(buf, LINEBUF, &off, "last_channel",   e->last_channel);
        kv_int(buf, LINEBUF, &off, "measurement_mode", e->last_mode);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* Wi-Fi 7 Multi-Link Devices (#67). One record per MLD, listing the
 * per-link addresses its radios use simultaneously — the mapping that
 * lets a consumer stop counting one handset as three devices. */
void jsonl_emit_mlds(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->mld_count; i++) {
        const sloth_mld_t *e = &s->mlds[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_mld", now);
        kv_mac(buf, LINEBUF, &off, "mld_mac",    e->mld_mac);
        kv_int(buf, LINEBUF, &off, "link_count", e->link_count);
        kv_int(buf, LINEBUF, &off, "links_truncated",
               e->links_truncated ? 1 : 0);
        for (int j = 0; j < e->link_count && j < SLOTH_MLD_MAX_LINKS; j++) {
            char key[16];
            snprintf(key, sizeof(key), "link_%d_mac", j);
            kv_mac(buf, LINEBUF, &off, key, e->link_mac[j]);
            snprintf(key, sizeof(key), "link_%d_id", j);
            kv_int(buf, LINEBUF, &off, key, e->link_id[j]);
        }
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* Captive-portal interception events (#69). One record per detection,
 * carrying which of the three independent signals fired — a consumer
 * correlating them wants to know whether the body, the DNS answer or
 * the TLS destination gave it away, because a portal evading one still
 * has to pass the others.
 *
 * `event_ts` (#255): same fix as wifi_csa_event's — `start_obj()`
 * already writes `ts` as this line's emit time, so a second `kv_int`
 * of the detection's own time under the same key was a duplicate, not
 * a second field. The identity key is `host`+`event_ts`, not
 * `host`+`ts`. */
void jsonl_emit_cp_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->cp_event_count; i++) {
        const cp_event_t *e = &s->cp_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "captive_portal_event", now);
        kv_str(buf, LINEBUF, &off, "host",     e->host);
        kv_str(buf, LINEBUF, &off, "src",      e->src);
        kv_int(buf, LINEBUF, &off, "kind",     e->kind);
        kv_str(buf, LINEBUF, &off, "kind_label", cp_kind_label(e->kind));
        kv_str(buf, LINEBUF, &off, "evidence", e->evidence);
        /* #169: who answered, so a consumer can join the event to the
         * flow, and which named kit's page it was ("" for none). */
        kv_str(buf, LINEBUF, &off, "server",   e->server);
        kv_int(buf, LINEBUF, &off, "server_port", e->server_port);
        kv_str(buf, LINEBUF, &off, "kit",      cp_kit_name(e->kit));
        kv_int(buf, LINEBUF, &off, "event_ts", (long long)e->ts);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_assocs(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->assoc_count; i++) {
        const assoc_t *e = &s->assocs[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "assoc", now);
        kv_mac(buf, LINEBUF, &off, "bssid",       e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",     e->sta_mac);
        kv_str(buf, LINEBUF, &off, "ssid",        e->ssid);
        kv_int(buf, LINEBUF, &off, "sta_random",  e->sta_random ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "source",      e->source);
        kv_int(buf, LINEBUF, &off, "channel",     e->channel);
        kv_int(buf, LINEBUF, &off, "signal_dbm",  e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "frame_count", (long long)e->frame_count);
        /* The AP's distance: every frame behind an assoc row is the AP's. */
        emit_dist(buf, &off, &e->dist);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_eapol_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->eapol_count; i++) {
        const eapol_event_t *e = &s->eapol_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "eapol", now);
        kv_mac(buf, LINEBUF, &off, "bssid",      e->bssid);
        kv_mac(buf, LINEBUF, &off, "sta_mac",    e->sta_mac);
        kv_str(buf, LINEBUF, &off, "ssid",       e->ssid);
        kv_int(buf, LINEBUF, &off, "event_ts",   (long long)e->ts);
        kv_int(buf, LINEBUF, &off, "msg_num",    e->msg_num);
        kv_int(buf, LINEBUF, &off, "has_pmkid",  e->has_pmkid ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "handshake_complete",
                                                 e->handshake_complete ? 1 : 0);
        /* Added #97: handshake_complete on its own says "a candidate
         * message pair", which a consumer used to have to read as
         * "associated". These three keep the claims apart. */
        kv_int(buf, LINEBUF, &off, "handshake_progress",
                                                 e->handshake_progress);
        kv_int(buf, LINEBUF, &off, "replay_counter_ok",
                                                 e->replay_counter_ok ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "assoc_evidence",
                                                 e->assoc_evidence ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "signal_dbm", e->signal_dbm);
        kv_int(buf, LINEBUF, &off, "channel",    e->channel);
        /* Additive (JSONL 1.7.0, #172): the harvest tracker's row this
         * message was counted in, 0 for none. Joins the frame to the
         * harvest_station / harvest_chain record and the alert detail
         * that name the same cluster; non-zero alone is not a finding
         * (eapol_event_t.harvest_cluster_id). */
        kv_int(buf, LINEBUF, &off, "harvest_cluster_id",
                                                 (long long)e->harvest_cluster_id);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_mdns_services(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->mdns_count; i++) {
        const mdns_service_t *e = &s->mdns_services[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "mdns_service", now);
        kv_str(buf, LINEBUF, &off, "instance",  e->instance);
        kv_str(buf, LINEBUF, &off, "service",   e->service);
        kv_str(buf, LINEBUF, &off, "host",      e->host);
        kv_str(buf, LINEBUF, &off, "ip",        e->ip);
        kv_int(buf, LINEBUF, &off, "port",      e->port);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_nbns_names(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->nbns_count; i++) {
        const nbns_name_t *e = &s->nbns_names[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "nbns_name", now);
        kv_str(buf, LINEBUF, &off, "name",      e->name);
        kv_str(buf, LINEBUF, &off, "ip",        e->ip);
        kv_int(buf, LINEBUF, &off, "suffix",    e->suffix);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_ssdp_devices(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->ssdp_count; i++) {
        const ssdp_device_t *e = &s->ssdp_devices[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ssdp_device", now);
        kv_str(buf, LINEBUF, &off, "ip",        e->ip);
        kv_str(buf, LINEBUF, &off, "kind",      e->type);  /* "type" is JSON-reserved-ish; rename */
        kv_str(buf, LINEBUF, &off, "usn",       e->usn);
        kv_str(buf, LINEBUF, &off, "location",  e->location);
        kv_str(buf, LINEBUF, &off, "nts",       e->nts);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_onvif_devices(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->onvif_count; i++) {
        const onvif_device_t *e = &s->onvif_devices[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "onvif_device", now);
        kv_str(buf, LINEBUF, &off, "ip",        e->ip);
        kv_str(buf, LINEBUF, &off, "uuid",      e->uuid);
        kv_str(buf, LINEBUF, &off, "types",     e->types);
        kv_str(buf, LINEBUF, &off, "scopes",    e->scopes);
        kv_str(buf, LINEBUF, &off, "xaddrs",    e->xaddrs);
        kv_str(buf, LINEBUF, &off, "kind",      e->kind);
        kv_int(buf, LINEBUF, &off, "is_camera", e->is_camera);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_scan_entries(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->scan_count; i++) {
        const scan_entry_t *e = &s->scan_entries[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "scan_entry", now);
        kv_str(buf, LINEBUF, &off, "ip",         e->ip);
        kv_int(buf, LINEBUF, &off, "port_count", e->port_count);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",  (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "flagged",    e->flagged ? 1 : 0);
        /* Distinct ports as a small array — bounded by MAX_SCAN_PORTS. */
        appendf(buf, LINEBUF, &off, ",\"ports\":[");
        for (int k = 0; k < e->port_count && k < MAX_SCAN_PORTS; k++) {
            appendf(buf, LINEBUF, &off, "%s%u", k ? "," : "", e->ports[k]);
        }
        appendf(buf, LINEBUF, &off, "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_packets(sloth_state_t *s) {
    if (!s) return;
    /* A packet record is event-like: each captured frame must be emitted
     * exactly once, not re-serialised every refresh cycle (issue #20). We
     * track progress with a monotonic counter (pkt_total, bumped by the
     * capture thread on every write) and a per-consumer high-water mark
     * (pkt_jsonl_emitted). A monotonic pair — rather than comparing the
     * wrapping pkt_head — lets us tell "0 new" from "a whole ring turned
     * over since the last tick" and cap the emit to what's still resident.
     *
     * With no sink, advance the mark to the write head so a client that
     * connects later streams forward (tail -f) instead of getting a
     * backlog dump. */
    if (!any_sink()) { s->pkt_jsonl_emitted = s->pkt_total; return; }
    time_t now = sloth_wall();
    uint64_t pending = s->pkt_total - s->pkt_jsonl_emitted;
    /* If more than a ring's worth arrived between ticks, the oldest were
     * overwritten and are unrecoverable — emit only the survivors. */
    if (pending > MAX_PACKETS) pending = MAX_PACKETS;
    uint64_t first = s->pkt_total - pending;   /* absolute index of oldest survivor */
    for (uint64_t k = first; k < s->pkt_total; k++) {
        const packet_info_t *e = &s->packets[k % MAX_PACKETS];
        /* raw bytes are deliberately omitted (would leak frame contents
         * into log files); only the metadata ships. */
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "packet", now);
        kv_int(buf, LINEBUF, &off, "ts_sec",   (long long)e->ts_sec);
        kv_int(buf, LINEBUF, &off, "ts_usec",  (long long)e->ts_usec);
        kv_str(buf, LINEBUF, &off, "src",      e->src);
        kv_str(buf, LINEBUF, &off, "dst",      e->dst);
        kv_int(buf, LINEBUF, &off, "src_port", e->src_port);
        kv_int(buf, LINEBUF, &off, "dst_port", e->dst_port);
        kv_int(buf, LINEBUF, &off, "proto",    e->proto);
        kv_int(buf, LINEBUF, &off, "len",      (long long)e->len);
        kv_str(buf, LINEBUF, &off, "info",     e->info);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
    s->pkt_jsonl_emitted = s->pkt_total;
}

void jsonl_emit_processes(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    /* Procs view aggregates over s->conns; reuse the same aggregator
     * the view itself calls so the wire shape exactly matches what an
     * operator sees in [5]. Stack-allocated buffer (~6 KB at the
     * default MAX_PROCS). */
    proc_stat_t procs[MAX_PROCS];
    int n = procs_aggregate(s, procs, MAX_PROCS);
    for (int i = 0; i < n; i++) {
        const proc_stat_t *e = &procs[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "process", now);
        kv_int(buf, LINEBUF, &off, "pid",        e->pid);
        kv_str(buf, LINEBUF, &off, "proc",       e->proc);
        kv_int(buf, LINEBUF, &off, "ppid",       e->ppid);
        kv_int(buf, LINEBUF, &off, "depth",      e->depth);
        kv_int(buf, LINEBUF, &off, "conn_count", e->conn_count);
        kv_int(buf, LINEBUF, &off, "tcp_count",  e->tcp_count);
        kv_int(buf, LINEBUF, &off, "udp_count",  e->udp_count);
        kv_int(buf, LINEBUF, &off, "tx_bytes",   (long long)e->tx_bytes);
        kv_int(buf, LINEBUF, &off, "rx_bytes",   (long long)e->rx_bytes);
        kv_double(buf, LINEBUF, &off, "tx_rate", e->tx_rate);
        kv_double(buf, LINEBUF, &off, "rx_rate", e->rx_rate);
        appendf(buf, LINEBUF, &off, ",\"ports\":[");
        for (int k = 0; k < e->port_count; k++) {
            appendf(buf, LINEBUF, &off, "%s%u", k ? "," : "", e->ports[k]);
        }
        appendf(buf, LINEBUF, &off, "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_ndp_ras(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->ndp_ra_count; i++) {
        const ndp_ra_event_t *e = &s->ndp_ras[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ndp_ra", now);
        kv_str(buf, LINEBUF, &off, "src_ip",          e->src_ip);
        if (e->has_src_mac) kv_mac(buf, LINEBUF, &off, "src_mac", e->src_mac);
        kv_int(buf, LINEBUF, &off, "cur_hop_limit",   e->cur_hop_limit);
        kv_int(buf, LINEBUF, &off, "flags",           e->flags);
        kv_int(buf, LINEBUF, &off, "router_lifetime", e->router_lifetime);
        kv_int(buf, LINEBUF, &off, "first_seen",      (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",       (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "count",           (long long)e->count);
        appendf(buf, LINEBUF, &off, ",\"prefixes\":[");
        for (int k = 0; k < e->prefix_count; k++) {
            appendf(buf, LINEBUF, &off, "%s\"", k ? "," : "");
            json_escape(e->prefixes[k], buf, LINEBUF, &off);
            appendf(buf, LINEBUF, &off, "\"");
        }
        appendf(buf, LINEBUF, &off, "]");
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_smb_sessions(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->smb_session_count; i++) {
        const smb_session_t *e = &s->smb_sessions[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "smb_session", now);
        kv_str(buf, LINEBUF, &off, "client_ip",   e->client_ip);
        kv_str(buf, LINEBUF, &off, "server_ip",   e->server_ip);
        kv_int(buf, LINEBUF, &off, "server_port", e->server_port);
        kv_str(buf, LINEBUF, &off, "dialect",     e->dialect);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        kv_int(buf, LINEBUF, &off, "count",       (long long)e->count);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_kerb_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->kerb_event_count; i++) {
        const kerb_event_t *e = &s->kerb_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "kerb_event", now);
        kv_str(buf, LINEBUF, &off, "src_ip",                  e->src_ip);
        kv_int(buf, LINEBUF, &off, "as_req_count",            e->as_req_count);
        kv_int(buf, LINEBUF, &off, "as_rep_count",            e->as_rep_count);
        kv_int(buf, LINEBUF, &off, "tgs_req_count",           e->tgs_req_count);
        kv_int(buf, LINEBUF, &off, "tgs_rep_count",           e->tgs_rep_count);
        kv_int(buf, LINEBUF, &off, "preauth_required_count",  e->preauth_required_count);
        kv_int(buf, LINEBUF, &off, "preauth_failed_count",    e->preauth_failed_count);
        kv_int(buf, LINEBUF, &off, "principal_unknown_count", e->principal_unknown_count);
        kv_int(buf, LINEBUF, &off, "error_other_count",       e->error_other_count);
        kv_int(buf, LINEBUF, &off, "first_seen",              (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",               (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_ldap_events(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->ldap_event_count; i++) {
        const ldap_event_t *e = &s->ldap_events[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ldap_event", now);
        kv_str(buf, LINEBUF, &off, "src_ip",           e->src_ip);
        kv_int(buf, LINEBUF, &off, "bind_count",       e->bind_count);
        kv_int(buf, LINEBUF, &off, "bind_anon_count",  e->bind_anon_count);
        kv_int(buf, LINEBUF, &off, "search_count",     e->search_count);
        kv_int(buf, LINEBUF, &off, "search_ref_count", e->search_ref_count);
        kv_int(buf, LINEBUF, &off, "first_seen",       (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",        (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_bgp_sessions(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->bgp_session_count; i++) {
        const bgp_session_t *e = &s->bgp_sessions[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "bgp_session", now);
        kv_str(buf, LINEBUF, &off, "peer_a",             e->peer_a);
        kv_str(buf, LINEBUF, &off, "peer_b",             e->peer_b);
        kv_int(buf, LINEBUF, &off, "open_count",         e->open_count);
        kv_int(buf, LINEBUF, &off, "update_count",       e->update_count);
        kv_int(buf, LINEBUF, &off, "notification_count", e->notification_count);
        kv_int(buf, LINEBUF, &off, "keepalive_count",    e->keepalive_count);
        kv_int(buf, LINEBUF, &off, "first_seen",         (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",          (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_ssh_flows(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->ssh_flow_count; i++) {
        const ssh_flow_t *e = &s->ssh_flows[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ssh_flow", now);
        kv_str(buf, LINEBUF, &off, "src_ip",         e->src_ip);
        kv_str(buf, LINEBUF, &off, "dst_ip",         e->dst_ip);
        kv_int(buf, LINEBUF, &off, "banner_count",   e->banner_count);
        kv_str(buf, LINEBUF, &off, "server_banner",  e->server_banner);
        kv_int(buf, LINEBUF, &off, "first_seen",     (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",      (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_rdp_flows(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->rdp_flow_count; i++) {
        const rdp_flow_t *e = &s->rdp_flows[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "rdp_flow", now);
        kv_str(buf, LINEBUF, &off, "src_ip",            e->src_ip);
        kv_str(buf, LINEBUF, &off, "dst_ip",            e->dst_ip);
        kv_int(buf, LINEBUF, &off, "connect_req_count", e->connect_req_count);
        kv_str(buf, LINEBUF, &off, "last_cookie",       e->last_cookie);
        kv_int(buf, LINEBUF, &off, "proto_mask",        (int)e->proto_mask);
        kv_int(buf, LINEBUF, &off, "first_seen",        (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",         (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_snmp_flows(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->snmp_flow_count; i++) {
        const snmp_flow_t *e = &s->snmp_flows[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "snmp_flow", now);
        kv_str(buf, LINEBUF, &off, "src_ip",          e->src_ip);
        kv_str(buf, LINEBUF, &off, "dst_ip",          e->dst_ip);
        kv_int(buf, LINEBUF, &off, "version",         e->version);
        kv_int(buf, LINEBUF, &off, "get_count",       e->get_count);
        kv_int(buf, LINEBUF, &off, "getnext_count",   e->getnext_count);
        kv_int(buf, LINEBUF, &off, "getbulk_count",   e->getbulk_count);
        kv_int(buf, LINEBUF, &off, "set_count",       e->set_count);
        kv_int(buf, LINEBUF, &off, "response_count",  e->response_count);
        kv_int(buf, LINEBUF, &off, "trap_count",      e->trap_count);
        kv_int(buf, LINEBUF, &off, "community_count", e->community_count);
        kv_str(buf, LINEBUF, &off, "last_community",  e->last_community);
        kv_int(buf, LINEBUF, &off, "first_seen",      (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",       (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

void jsonl_emit_mqtt_flows(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->mqtt_flow_count; i++) {
        const mqtt_flow_t *e = &s->mqtt_flows[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "mqtt_flow", now);
        kv_str(buf, LINEBUF, &off, "src_ip",             e->src_ip);
        kv_str(buf, LINEBUF, &off, "dst_ip",             e->dst_ip);
        kv_int(buf, LINEBUF, &off, "connect_count",      e->connect_count);
        kv_int(buf, LINEBUF, &off, "connack_fail_count", e->connack_fail_count);
        kv_int(buf, LINEBUF, &off, "subscribe_count",    e->subscribe_count);
        kv_int(buf, LINEBUF, &off, "publish_count",      e->publish_count);
        kv_int(buf, LINEBUF, &off, "proto_level",        e->proto_level);
        kv_str(buf, LINEBUF, &off, "last_username",      e->last_username);
        kv_int(buf, LINEBUF, &off, "first_seen",         (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",          (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* Multi-radio merged 802.11 world model (#21). One line per observed
 * entity, carrying observer metadata: how many radios saw it, which ones
 * (bitmask), the strongest signal heard and which radio heard it. */
void jsonl_emit_wifi_merged(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->wifi_merged.count; i++) {
        const wifi_merged_t *e = &s->wifi_merged.ents[i];
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_merged", now);
        kv_mac(buf, LINEBUF, &off, "key",         e->key);
        kv_int(buf, LINEBUF, &off, "seen_by",     e->seen_by);
        kv_int(buf, LINEBUF, &off, "sensor_mask", e->sensor_mask);
        kv_int(buf, LINEBUF, &off, "best_rssi",   e->best_rssi);
        kv_int(buf, LINEBUF, &off, "best_sensor", e->best_sensor);
        kv_int(buf, LINEBUF, &off, "channel",     e->channel);
        kv_int(buf, LINEBUF, &off, "freq_mhz",    e->freq_mhz);
        kv_int(buf, LINEBUF, &off, "observations",(long long)e->observations);
        kv_int(buf, LINEBUF, &off, "first_seen",  (long long)e->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen",   (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* Direction finding (src/df.h, --df-iface). `df_radio`: one line per
 * radio, change-only on whether it is open, running, hearing anything
 * and has refused a retune - never the frame count, which moves every
 * tick. `wifi_df`: one line per transmitter two or more radios hold a
 * fresh level for, change-only on which radio is loudest, the quality
 * word, the margin in 3 dB bands, the baseline point in 0.25 m bands
 * and the bearing (already one of eight points, held with hysteresis:
 * src/df.h) with its error; the levels themselves ride the line and do
 * not sign it. */
#define DF_EMIT_MAX 128
void jsonl_emit_wifi_df(const sloth_state_t *s) {
    if (!any_sink() || !s || !df_active()) return;
    time_t now = sloth_wall();
    int nr = df_radio_count();
    df_radio_t radios[DF_MAX_RADIOS];
    for (int i = 0; i < nr; i++) {
        df_radio_health_t h;
        memset(&h, 0, sizeof(h));
        if (!df_radio_get(i, &radios[i])) { nr = i; break; }
        /* Radio 0 is the sensor radio (probe.c); the others are
         * df_radio.c's, one place down in its table. */
        int aux = i > 0 && df_radio_health(i - 1, &h);
        uint64_t sig = FNV64_OFFSET;
        int st[5] = { i == 0 || h.open, i == 0 || h.running,
                      radios[i].frames > 0, h.retune_failures > 0,
                      radios[i].calibrated ? (int)floor(radios[i].bias_db / 3.0 + 0.5)
                                           : 1 << 30 };
        sig = fnv1a(st, sizeof(st), sig);
        uint8_t key[2] = { (uint8_t)i, 0 };
        if (!jsonl_changed(JD_DF_RADIO, key, sizeof(key), sig, now)) continue;
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "df_radio", now);
        kv_int(buf, LINEBUF, &off, "radio", i);
        kv_str(buf, LINEBUF, &off, "iface", radios[i].iface);
        kv_str(buf, LINEBUF, &off, "role", i == 0 ? "sensor" : "df");
        if (radios[i].has_pos) kv_double(buf, LINEBUF, &off, "pos_m", radios[i].pos_m);
        if (radios[i].has_xy) {
            kv_double(buf, LINEBUF, &off, "x_m", radios[i].x_m);
            kv_double(buf, LINEBUF, &off, "y_m", radios[i].y_m);
        }
        kv_int(buf, LINEBUF, &off, "open", st[0]);
        kv_int(buf, LINEBUF, &off, "running", st[1]);
        kv_int(buf, LINEBUF, &off, "noted", (long long)radios[i].frames);
        if (i > 0 && radios[i].calibrated)
            kv_double(buf, LINEBUF, &off, "bias_db", radios[i].bias_db);
        if (aux) {
            kv_int(buf, LINEBUF, &off, "frames", (long long)h.frames);
            kv_int(buf, LINEBUF, &off, "rejects", (long long)h.rejects);
            kv_int(buf, LINEBUF, &off, "retune_failures", (long long)h.retune_failures);
        }
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
    static df_est_t est[DF_EMIT_MAX];
    int n = df_snapshot(est, DF_EMIT_MAX, now);
    for (int i = 0; i < n; i++) {
        const df_est_t *e = &est[i];
        int mask = 0;
        for (int r = 0; r < nr; r++) if (e->has[r]) mask |= 1 << r;
        int st[7] = { (int)e->quality, e->best_radio, mask,
                      (int)(e->margin_db / 3.0),
                      e->has_along ? (int)floor(e->along_m / 0.25 + 0.5) : 1 << 30,
                      e->has_bearing ? e->bearing_deg : -1,
                      e->has_bearing ? e->bearing_err_deg : -1 };
        uint64_t sig = fnv1a(st, sizeof(st), FNV64_OFFSET);
        if (!jsonl_changed(JD_WIFI_DF, e->mac, 6, sig, now)) continue;
        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "wifi_df", now);
        kv_mac(buf, LINEBUF, &off, "mac", e->mac);
        kv_int(buf, LINEBUF, &off, "channel", e->channel);
        kv_int(buf, LINEBUF, &off, "heard_by", e->heard_by);
        kv_str(buf, LINEBUF, &off, "quality", df_quality_name(e->quality));
        kv_int(buf, LINEBUF, &off, "best_radio", e->best_radio);
        if (e->best_radio >= 0 && e->best_radio < nr)
            kv_str(buf, LINEBUF, &off, "best_iface", radios[e->best_radio].iface);
        kv_double(buf, LINEBUF, &off, "margin_db", e->margin_db);
        if (e->has_along) kv_double(buf, LINEBUF, &off, "along_m", e->along_m);
        if (e->has_bearing) {
            kv_int(buf, LINEBUF, &off, "bearing_deg", e->bearing_deg);
            kv_int(buf, LINEBUF, &off, "bearing_err_deg", e->bearing_err_deg);
        }
        appendf(buf, LINEBUF, &off, ",\"rssi\":[");
        for (int r = 0; r < nr; r++) {
            if (e->has[r]) appendf(buf, LINEBUF, &off, "%s%.1f", r ? "," : "", e->rssi[r]);
            else           appendf(buf, LINEBUF, &off, "%snull", r ? "," : "");
        }
        appendf(buf, LINEBUF, &off, "],\"level\":[");
        for (int r = 0; r < nr; r++) {
            if (e->has[r]) appendf(buf, LINEBUF, &off, "%s%.1f", r ? "," : "", e->level[r]);
            else           appendf(buf, LINEBUF, &off, "%snull", r ? "," : "");
        }
        appendf(buf, LINEBUF, &off, "]");
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)e->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* ── sensor_health (#91 slice 3) ─────────────────────────────
 *
 * One singleton record per tick, carrying what slices 1 and 2 collect.
 * Additive — a new record type; nothing existing is renamed or reshaped
 * (MISSION §4.3).
 *
 * Emitted through the same change-only cache as the entity snapshots,
 * but the signature is chosen carefully. `ps_recv` climbs on every tick
 * of a working sensor, so signing over it would mean a line per second
 * forever and the suppression would be decorative. The signature is
 * therefore the *qualitative* health — liveness, exit reasons, which hop
 * slots have ever refused, whether any retune was ever acknowledged,
 * whether one has failed and every reason seen so far — plus
 * the cumulative drop/ifdrop
 * counters and the eviction tally, all of which moving is genuinely
 * news. A healthy sensor emits one line per JSONL_HEARTBEAT_SECS; a
 * degrading one emits the moment it degrades. */
/* A stream is "stale" once this long has passed with no frame. Chosen
 * well under the 300 s heartbeat so a transition is reported by the
 * change path rather than waiting for the next beat, and well above a
 * poll interval so an idle second does not flap it. */
#define JSONL_STALE_SECS 60

/* -1 never delivered, 0 fresh, 1 stale. Bucketed because only a
 * crossing belongs in the change-only signature. */
static int stale_state(int stale_secs) {
    if (stale_secs < 0) return -1;
    return stale_secs > JSONL_STALE_SECS ? 1 : 0;
}

static void health_kv(char *buf, int *off, const char *prefix,
                      const capture_health_t *h) {
    char key[40];
    snprintf(key, sizeof(key), "%s_open", prefix);
    kv_int(buf, LINEBUF, off, key, h->open);
    snprintf(key, sizeof(key), "%s_running", prefix);
    kv_int(buf, LINEBUF, off, key, h->running);
    snprintf(key, sizeof(key), "%s_exit", prefix);
    kv_str(buf, LINEBUF, off, key,
           capture_exit_name((capture_exit_t)h->exit_reason));
    snprintf(key, sizeof(key), "%s_exit_detail", prefix);
    kv_str(buf, LINEBUF, off, key, h->exit_detail);
    snprintf(key, sizeof(key), "%s_stats_valid", prefix);
    kv_int(buf, LINEBUF, off, key, h->stats_valid);
    snprintf(key, sizeof(key), "%s_recv", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->ps_recv);
    snprintf(key, sizeof(key), "%s_drop", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->ps_drop);
    snprintf(key, sizeof(key), "%s_ifdrop", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->ps_ifdrop);
    snprintf(key, sizeof(key), "%s_recv_delta", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->d_recv);
    snprintf(key, sizeof(key), "%s_drop_delta", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->d_drop);
    snprintf(key, sizeof(key), "%s_ifdrop_delta", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->d_ifdrop);
    /* Freshness (#91). Two fields because they answer different
     * questions: the frame's own clock is what to correlate against,
     * the age is whether this stream is still delivering. */
    snprintf(key, sizeof(key), "%s_last_frame_ts", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->last_frame_ts);
    snprintf(key, sizeof(key), "%s_stale_secs", prefix);
    kv_int(buf, LINEBUF, off, key, (long long)h->stale_secs);
}

/* A lifetime count as its decade band, for a field whose exact value
 * would say more than its order of magnitude should (#156). */
static const char *count_band(uint64_t n) {
    if (n == 0)    return "0";
    if (n < 10)    return "1-9";
    if (n < 100)   return "10-99";
    if (n < 1000)  return "100-999";
    return "1000+";
}

/* A count as its decade, 0 for none and 1 for 1-9 up to 7 for a
 * million and more: the shape a monotonic tally enters the change-only
 * signature in. A crossing is news; the next file swept is not. */
static int decade_band(unsigned long long n) {
    int b = 0;
    while (n > 0 && b < 7) { b++; n /= 10; }
    return b;
}

void jsonl_emit_sensor_health(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();

    /* chan_requested == 0 means the hopper has never ticked, which is not
     * a failure — only a request that was never confirmed is. */
    int chan_ok = s->chan_requested == 0 ||
                  s->chan_requested == s->chan_confirmed;

    uint64_t evict_total = sh_evict_total();

    /* Storage write failures (#92) — sensor_health is the sensor's own
     * self-report, and "I could not write the evidence I detected" is
     * exactly that kind of fact. Each sink already counted its own
     * failures (stderr-only, or a view header); this just gives a JSONL/
     * socket consumer the same visibility a console operator always had.
     * Read from each module's own accessor rather than from
     * s->eapol_export_failures — that field is synced by eapol_snapshot()
     * later in the same tick's poll loop, so reading it here would report
     * last tick's count instead of this one's. */
    int jsonl_fail  = jsonl_write_failures();
    int pcap_fail   = alert_pcap_failures();
    int eapol_fail  = eapol_export_failures();
    int storage_fail = jsonl_fail + pcap_fail + eapol_fail;

    /* See the note above on what is deliberately NOT in the signature. */
    struct {
        int      cap_open, cap_run, cap_exit;
        int      mon_open, mon_run, mon_exit;
        int      retune_fail_any, chan_ever_confirmed;
        uint32_t chan_refused_mask, retune_reason_mask;
        uint64_t cap_drop, cap_ifdrop, mon_drop, mon_ifdrop, evicted;
        int      storage_fail;
        int      scope_state, scope_req, scope_enf;
        uint32_t scope_gen;
        uint64_t scope_dropped;
        int      tuned;
        uint64_t mon_bad_clock;
        int      cap_stale_state, mon_stale_state;
        /* BANDS, never the free figures. Free bytes and free inodes move
         * on a live sensor every time anything writes, so signing over
         * them would emit this record once a second forever — the
         * firehose stale_secs and the flow rings are already excluded to
         * avoid. A band crosses a handful of times over a filesystem's
         * life, which is the news: not "it moved", but "it crossed". */
        int      pcap_dir_byte_band, pcap_dir_file_band;
        /* #135. Client count moves only on connect/disconnect, bounded
         * 0..16, so it signs as itself. The refusal tally is an event
         * counter that a reconnect loop would advance every tick, so it
         * signs as a two-state band (none / some): the first refusal is
         * the transition worth a line, the running count rides the
         * heartbeat like `evictions` of a flow ring. */
        int      socket_clients, socket_refused_any;
        /* #144 slice 2, the Bluetooth host source. Liveness and the
         * stale BAND, as for the other two streams. Own transmission
         * enters as its recency bucket and the set of kinds ever seen —
         * never the seconds-since, never the last kind, which a stack
         * alternating scan and advertising would flip on every command.
         * Scan enable is left out for the same reason: BlueZ discovery
         * toggles it every few seconds. The kinds BT_OWN_TRANSMIT asserts
         * (on, or recent) enter as a mask rather than the raw on-state,
         * because an active scan toggled by the kernel flips on and off
         * just as fast while staying recent throughout. The record
         * counters are none/some bands, like the socket refusals above. */
        int      bt_open, bt_run, bt_exit, bt_stale_state;
        int      ble_tx_recency, ble_scan_mode, ble_filter_policy;
        uint32_t ble_tx_kind_mask, ble_tx_asserted;
        int      ble_tx_baseline;
        int      ble_controllers;
        int      ble_ext_adv_any, ble_malformed_any;
        int      ble_ext_evicted_any;
        /* #144 slice 3, the Ubertooth stream: its state, the link type
         * taken or refused, the freshness bucket, and none/some bands
         * for drops, truncation and (2.7.0) failed CRCs. recv, the PDU
         * and the CRC counters move with every record and stay out. */
        int      btcap_state, btcap_dlt, btcap_refused_dlt, btcap_stale_state;
        int      btcap_drop_any, btcap_truncated_any, btcap_crc_bad_any;
        /* #156, --ble-rotation-hints: on/off only. Its counts stay out,
         * so a link committing never writes a line at that moment (the
         * moment would tell a consumer which address pair it was). */
        int      ble_rot_on;
        /* #166, the --pcap-dir age sweep: decade bands of the removed
         * and error tallies, never the counts. A sweep clearing a
         * backlog removes up to a budget's worth of files per tick, so
         * the raw count would sign a new line on every one of them. -1
         * without --pcap-dir. */
        int      pcap_swept_band, pcap_sweep_err_band;
        /* What the IP stream is: its pcap link type while it is open
         * (-1 otherwise) and --monitor-only. Both discrete and set at
         * start; a change is a reopen, which is news. */
        int      cap_linktype, monitor_only;
        /* The receiver and the position: the block both daemons write
         * (#213), signed on states and bands only. src/jsonl_internal.h
         * has the fields and why each is one. The decoders' half
         * (jsonl_sh_rf_sig_t) is sloth-rf's alone since JSONL 2.0.0. */
        jsonl_sh_gnss_sig_t gnss;
        /* --db's size ceiling (JSONL 1.7.0): a tune knob, so it moves
         * only when the operator moves it. */
        int      db_max_mb;
        /* Several sensor radios (JSONL 2.3.0, src/mon_radios.h): how
         * many, each one's state, whether its share of the hop list is
         * empty, whether a retune of it has ever failed or ever been
         * acknowledged, and its duplicate tally as a decade. Never the
         * frame counts, the frequency or the channel, which move every
         * tick or every dwell; never the raw duplicate count, which
         * moves with every frame two radios hear. */
        int      mon_extra;
        int      mon_state[MON_RADIO_MAX], mon_hops[MON_RADIO_MAX];
        int      mon_retune_fail_any[MON_RADIO_MAX];
        int      mon_ever_confirmed[MON_RADIO_MAX];
        int      mon_dup_band[MON_RADIO_MAX];
        int      mon_dd_evicted_any;
        /* --cue (JSONL 2.13.0, #248): on, the cues running now (0..4),
         * and decades of the started and refused tallies - never the
         * counts, which a flood of false triggers would move every
         * tick. */
        int      cue_on, cue_active, cue_started_band, cue_refused_band;
    } sig;
    memset(&sig, 0, sizeof(sig));
    sig.cap_open    = s->cap_health.open;
    sig.cap_run     = s->cap_health.running;
    const int cap_linktype = s->cap_health.open ? s->pkt_linktype : -1;
    sig.cap_linktype = cap_linktype;
    sig.monitor_only = s->monitor_only != 0;
    sig.cap_exit    = s->cap_health.exit_reason;
    sig.mon_open    = s->mon_health.open;
    sig.mon_run     = s->mon_health.running;
    sig.mon_exit    = s->mon_health.exit_reason;
    /* #91: neither the channel numbers nor whether they agree. With
     * --hop on, chanhop is the only writer of both numbers and moves
     * them every dwell - every poll at the default 250 ms - so signing
     * over them made a healthy hopping sensor emit this record once a
     * second. Their agreement (chan_confirmed_ok) is no better: with one
     * channel in the rotation that the regdomain or driver always
     * refuses (EINVAL for a --hop list entry it will not take - the
     * normal case, not an edge), each rotation goes agree, refuse,
     * agree again on the next channel, so the bit flips twice a
     * rotation for the life of the run. What is stable under a
     * persistent pattern and still moves on news: which rotation slots
     * have ever refused (a new refusing channel), the reason (a new
     * cause), whether any retune has failed, and whether any has ever
     * been acknowledged (a radio that never got anywhere vs one that
     * did). The numbers, the agreement bit and the count ride every
     * emitted line and the 300 s heartbeat. The trade, named: a radio
     * that refused for a while and then recovered says so on the next
     * heartbeat, not immediately. */
    /* #91: the failure COUNT is an event counter. A radio that refuses
     * every retune (EPERM without CAP_NET_ADMIN is the common case)
     * fails once per retry, so signing over the count emitted this
     * record on every retry for the life of the run. Two-state band
     * instead; the count itself rides every emitted line. */
    sig.retune_fail_any     = s->chan_retune_failures > 0;
    /* The reasons ever seen, not the last one: two persistent refusals
     * with different causes alternate the last errno every rotation. */
    sig.retune_reason_mask  = s->chan_retune_reason_mask
                            | (s->chan_retune_last_errno
                               ? 1u << chanhop_retune_reason_bit(s->chan_retune_last_errno)
                               : 0u);
    sig.chan_ever_confirmed = s->chan_confirmed != 0;
    sig.chan_refused_mask   = s->chan_refused_mask;
    sig.cap_drop    = s->cap_health.ps_drop;
    sig.cap_ifdrop  = s->cap_health.ps_ifdrop;
    sig.mon_drop    = s->mon_health.ps_drop;
    sig.mon_ifdrop  = s->mon_health.ps_ifdrop;
    /* Synthesis tables only (#91). The flow rings are in `evict_total`
     * and therefore in the emitted `evictions` field, but they must stay
     * out of the signature: a ring rolls over continuously on a busy
     * segment, so signing over it would emit this record every second
     * forever — the same firehose `ps_recv` and `stale_secs` are
     * excluded to avoid, and it would bury the transitions this record
     * exists to surface. */
    sig.evicted     = sh_evict_total_tables();
    sig.storage_fail = storage_fail;
    /* #85: a pin failing closed is a transition, never a heartbeat's
     * worth of news — generation moves even if the counts coincide. */
    sig.scope_state = s->scope_health.state;
    sig.scope_req   = s->scope_health.requested;
    sig.scope_enf   = s->scope_health.enforced;
    sig.scope_gen   = s->scope_health.generation;
    sig.scope_dropped = capture_out_of_scope_dropped();
    sig.tuned         = tune_non_default();
    const int db_cap_mb = db_is_open() ? db_max_mb() : -1;
    sig.db_max_mb     = db_cap_mb;
    sig.mon_bad_clock = mon_bad_clock_total();
    const int   mon_extra = mon_radios_extra();
    mon_radio_t mon_r[MON_RADIO_MAX];
    memset(mon_r, 0, sizeof(mon_r));
    sig.mon_extra = mon_extra;
    for (int k = 0; mon_extra && k < MON_RADIO_MAX; k++) {
        if (!mon_radios_get(k, &mon_r[k])) continue;
        sig.mon_state[k]           = (int)mon_r[k].state;
        sig.mon_hops[k]            = mon_r[k].hop_channels > 0;
        sig.mon_retune_fail_any[k] = mon_r[k].retune_failures > 0;
        sig.mon_ever_confirmed[k]  = mon_r[k].chan_confirmed != 0;
        sig.mon_dup_band[k]        = decade_band(mon_r[k].dup_dropped);
    }
    const unsigned long long mon_dd_evicted = mon_dedup_evicted();
    sig.mon_dd_evicted_any = mon_dd_evicted > 0;
    /* The STATE, never the raw seconds. stale_secs ticks up every
     * second, so putting it in the change-only signature would make
     * this record emit once a second forever — turning a
     * change-plus-heartbeat stream into a firehose and burying the
     * transitions it exists to surface. Three states: never delivered,
     * fresh, stale past the threshold. Only a crossing is news. */
    sig.cap_stale_state = stale_state(s->cap_health.stale_secs);
    sig.mon_stale_state = stale_state(s->mon_health.stale_secs);
    sig.cue_on           = s->cue.on != 0;
    sig.cue_active       = s->cue.on ? s->cue.active : 0;
    sig.cue_started_band = s->cue.on ? decade_band(s->cue.started) : 0;
    sig.cue_refused_band = s->cue.on ? decade_band(s->cue.refused) : 0;
    /* #96. -1 when no --pcap-dir is configured or the probe failed —
     * stable values, so not a source of churn. */
    fs_capacity_t pcap_cap;
    const int pcap_cap_ok = alert_pcap_capacity(&pcap_cap) == 0;
    sig.pcap_dir_byte_band = pcap_cap_ok
        ? fs_capacity_band(pcap_cap.free_bytes, pcap_cap.total_bytes) : -1;
    sig.pcap_dir_file_band = (pcap_cap_ok && pcap_cap.files_known)
        ? fs_capacity_band(pcap_cap.free_files, pcap_cap.total_files) : -1;
    const int                socket_clients = data_socket_client_count();
    const unsigned long long socket_refused = data_socket_peer_refused_total();
    sig.socket_clients     = socket_clients;
    sig.socket_refused_any = socket_refused > 0;
    const ble_host_t *bh = &s->ble_host;
    sig.bt_open           = s->bt_health.open;
    sig.bt_run            = s->bt_health.running;
    sig.bt_exit           = s->bt_health.exit_reason;
    sig.bt_stale_state    = stale_state(s->bt_health.stale_secs);
    sig.ble_tx_recency    = bt_tx_recency(bh->last_tx_wall, now);
    sig.ble_scan_mode     = bh->scan_mode;
    sig.ble_filter_policy = bh->filter_policy;
    sig.ble_tx_kind_mask  = bh->tx_kind_mask;
    sig.ble_tx_asserted   = bt_tx_asserted_mask(bh, now);
    sig.ble_tx_baseline   = bh->tx_baseline;
    sig.ble_controllers   = bh->controllers;
    sig.ble_ext_adv_any   = bh->ext_adv_undecoded > 0;
    sig.ble_ext_evicted_any = bh->ext_trains_evicted > 0;
    sig.ble_malformed_any = bh->malformed > 0;
    sig.btcap_state         = s->btcap.state;
    sig.btcap_dlt           = s->btcap.dlt;
    sig.btcap_refused_dlt   = s->btcap.refused_dlt;
    sig.btcap_stale_state   = stale_state(s->btcap.stale_secs);
    sig.btcap_drop_any      = s->btcap.drop > 0;
    sig.btcap_truncated_any = s->btcap.truncated > 0;
    sig.btcap_crc_bad_any   = s->btcap.crc_bad > 0;
    sig.ble_rot_on           = s->ble_rot.enabled != 0;
    jsonl_sh_gnss_sig(s, &sig.gnss);
    const int pcap_on = alert_pcap_enabled();
    sig.pcap_swept_band     = pcap_on ? decade_band(alert_pcap_swept()) : -1;
    sig.pcap_sweep_err_band = pcap_on
        ? decade_band((unsigned long long)alert_pcap_sweep_errors()) : -1;

    /* Singleton: one fixed key, so the slot is this record's alone. */
    static const char health_key[] = "sensor";
    if (!jsonl_changed(JD_SENSOR_HEALTH, health_key, sizeof(health_key) - 1,
                       fnv1a(&sig, sizeof(sig), FNV64_OFFSET), now))
        return;

    char buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "sensor_health", now);
    kv_str(buf, LINEBUF, &off, "capture_iface",        s->pkt_iface);
    /* The IP stream's pcap DLT (1 Ethernet, 113/276 Linux cooked, 127
     * radiotap: IP decoded from 802.11 data frames heard on the air,
     * #72), -1 while it is not open; and --monitor-only, the monitor
     * radio on its allow-list. Raw facts: a consumer (slothweb's
     * capture scope) decides what counts as heard off the air. */
    kv_int(buf, LINEBUF, &off, "capture_linktype",     cap_linktype);
    kv_int(buf, LINEBUF, &off, "monitor_only",         s->monitor_only ? 1 : 0);
    kv_str(buf, LINEBUF, &off, "monitor_iface",        s->probe_iface);
    kv_str(buf, LINEBUF, &off, "monitor_err",          s->probe_err);
    /* #92: frames whose capture timestamp was <= 0. Nothing is
     * substituted when it happens — a record is stamped with what the
     * capture said — so this is the only way a consumer can tell a
     * quiet radio from a capture whose clock is broken. */
    kv_int(buf, LINEBUF, &off, "mon_bad_clock",
           (long long)mon_bad_clock_total());
    kv_int(buf, LINEBUF, &off, "chan_requested",       s->chan_requested);
    kv_int(buf, LINEBUF, &off, "chan_confirmed",       s->chan_confirmed);
    kv_int(buf, LINEBUF, &off, "chan_confirmed_ok",    chan_ok);
    kv_int(buf, LINEBUF, &off, "chan_retune_failures", s->chan_retune_failures);
    kv_int(buf, LINEBUF, &off, "chan_retune_last_errno", s->chan_retune_last_errno);
    kv_str(buf, LINEBUF, &off, "chan_retune_reason",
           chanhop_retune_reason(s->chan_retune_last_errno));
    /* Hop activity (#91). hop_channels == 0 means --hop is off, which is
     * why the visit/frame counters are emitted unconditionally rather
     * than suppressed when zero: absent fields would read as "hopping,
     * nothing heard" to a consumer that cannot see the flags. */
    kv_int(buf, LINEBUF, &off, "hop_channels", s->hop_activity.channels);
    kv_int(buf, LINEBUF, &off, "hop_visits",
           (long long)s->hop_activity.visits);
    kv_int(buf, LINEBUF, &off, "hop_frames",
           (long long)s->hop_activity.frames);
    kv_int(buf, LINEBUF, &off, "hop_silent_channels",
           s->hop_activity.silent_channels);
    kv_int(buf, LINEBUF, &off, "hop_cur_visits",
           (long long)s->hop_activity.cur_visits);
    kv_int(buf, LINEBUF, &off, "hop_cur_frames",
           (long long)s->hop_activity.cur_frames);
    /* Measured vs configured dwell (#91). Both means are emitted so a
     * consumer can see the ratio without knowing sloth's poll interval. */
    kv_int(buf, LINEBUF, &off, "hop_dwell_planned_ms",
           s->hop_dwell.mean_planned_ms);
    kv_int(buf, LINEBUF, &off, "hop_dwell_measured_ms",
           s->hop_dwell.mean_measured_ms);
    kv_int(buf, LINEBUF, &off, "hop_dwell_last_planned_ms",
           s->hop_dwell.last_planned_ms);
    kv_int(buf, LINEBUF, &off, "hop_dwell_last_measured_ms",
           s->hop_dwell.last_measured_ms);
    kv_int(buf, LINEBUF, &off, "hop_dwell_worst_overshoot_ms",
           s->hop_dwell.worst_overshoot_ms);
    kv_int(buf, LINEBUF, &off, "hop_dwells_completed",
           (long long)s->hop_dwell.completed);
    /* Passive cueing (JSONL 2.13.0, #248): present only under --cue.
     * cue_refused counts every refusal, cue_refused_limit those at a
     * limit (the SENSOR_SUPPRESSED input), cue_cued_ms radio 0's
     * measured time in cued dwells. */
    if (s->cue.on) {
        kv_int(buf, LINEBUF, &off, "cue_active",        s->cue.active);
        kv_int(buf, LINEBUF, &off, "cue_started",       (long long)s->cue.started);
        kv_int(buf, LINEBUF, &off, "cue_refused",       (long long)s->cue.refused);
        kv_int(buf, LINEBUF, &off, "cue_refused_limit", (long long)s->cue.refused_limit);
        kv_int(buf, LINEBUF, &off, "cue_cued_ms",       (long long)s->cue.cued_ms);
    }
    health_kv(buf, &off, "capture", &s->cap_health);
    health_kv(buf, &off, "monitor", &s->mon_health);
    /* Several sensor radios (JSONL 2.3.0, src/mon_radios.h).
     * mon_extra_radios is how many --monitor-iface radios were named
     * beside the first; 0 is the one-radio run and the mon_rK_* members
     * are then absent. With any, K = 0 is the first radio (monitor_iface
     * above) and each named radio has its block whether or not it could
     * be opened: state "not_open" with the reason in mon_rK_err is the
     * record of one that could not. mon_rK_chan is the channel its last
     * retune confirmed (0: not hopping, or none yet) and mon_rK_freq
     * the frequency of the last frame it received, which is where the
     * radio is whether or not sloth tuned it. */
    kv_int(buf, LINEBUF, &off, "mon_extra_radios", mon_extra);
    if (mon_extra) {
        kv_int(buf, LINEBUF, &off, "mon_dup_dropped",
               (long long)mon_radios_dup_total());
        kv_int(buf, LINEBUF, &off, "mon_dedup_evicted", (long long)mon_dd_evicted);
    }
    for (int k = 0; mon_extra && k <= mon_extra && k < MON_RADIO_MAX; k++) {
        const mon_radio_t *r = &mon_r[k];
        char key[40];
#define MON_KEY(name) (snprintf(key, sizeof(key), "mon_r%d_" name, k), key)
        kv_str(buf, LINEBUF, &off, MON_KEY("iface"), r->iface);
        kv_str(buf, LINEBUF, &off, MON_KEY("state"), mon_radio_state_name(r->state));
        kv_str(buf, LINEBUF, &off, MON_KEY("err"),   r->err);
        kv_int(buf, LINEBUF, &off, MON_KEY("freq"),  r->freq_mhz);
        kv_int(buf, LINEBUF, &off, MON_KEY("chan"),
               k == 0 ? s->chan_confirmed : r->chan_confirmed);
        kv_int(buf, LINEBUF, &off, MON_KEY("hop_channels"),
               k == 0 ? s->hop_activity.channels : r->hop_channels);
        kv_int(buf, LINEBUF, &off, MON_KEY("frames"), (long long)r->frames);
        kv_int(buf, LINEBUF, &off, MON_KEY("dup_dropped"),
               (long long)r->dup_dropped);
        kv_int(buf, LINEBUF, &off, MON_KEY("retune_failures"),
               k == 0 ? s->chan_retune_failures : r->retune_failures);
#undef MON_KEY
    }
    jsonl_sh_evictions(buf, &off, evict_total, storage_fail);
    /* Headroom of the --pcap-dir filesystem (#96). The free figures are
     * emitted raw because a consumer wants the number; the signature
     * above carries only the band, for the firehose reason stated there.
     * -1 means not measured: no --pcap-dir, fstatvfs failed, or — for
     * inodes specifically — a filesystem with no fixed inode table
     * (btrfs and most network filesystems report f_files == 0, which is
     * not the same as "none left").
     *
     * Inodes are reported because bytes alone would have called this
     * sensor healthy: measured on the owner's monitor host, --pcap-dir
     * held 15.9M alert pcaps and ~93% of the filesystem's inodes while
     * disk read 39% used. */
    kv_int(buf, LINEBUF, &off, "pcap_dir_free_mb",
           pcap_cap_ok ? (long long)(pcap_cap.free_bytes / (1024u * 1024u)) : -1);
    kv_int(buf, LINEBUF, &off, "pcap_dir_free_inodes",
           (pcap_cap_ok && pcap_cap.files_known)
               ? (long long)pcap_cap.free_files : -1);
    kv_int(buf, LINEBUF, &off, "storage_jsonl_failures", jsonl_fail);
    kv_int(buf, LINEBUF, &off, "storage_pcap_failures",  pcap_fail);
    kv_int(buf, LINEBUF, &off, "storage_eapol_failures", eapol_fail);
    /* Capture scope (#85 slice 2). Appended, so every existing field
     * keeps its name and position. */
    capture_scope_state_t sst = (capture_scope_state_t)s->scope_health.state;
    kv_str(buf, LINEBUF, &off, "scope", capture_scope_state_name(sst));
    kv_int(buf, LINEBUF, &off, "scope_not_enforced",
           capture_scope_not_enforced(sst));
    kv_int(buf, LINEBUF, &off, "scope_requested",  s->scope_health.requested);
    kv_int(buf, LINEBUF, &off, "scope_enforced",   s->scope_health.enforced);
    kv_int(buf, LINEBUF, &off, "scope_generation",
           (long long)s->scope_health.generation);
    kv_int(buf, LINEBUF, &off, "scope_dropped",
           (long long)capture_out_of_scope_dropped());
    /* The process's own figures: tuned knobs, the data socket, parse
     * faults, memory and the loaded libraries. One block, shared with
     * sloth-rf's record (#213). */
    {
        char lbuf[192];
        libver_format(lbuf, sizeof(lbuf));
        jsonl_sh_process(buf, &off, socket_refused, socket_clients, lbuf);
    }
    /* Bluetooth host source (#144 slice 2). Appended, so every earlier
     * field keeps its name and position. Counters and decoded state
     * only: nothing that crossed the monitor channel is written here
     * verbatim (src/ble_hci.h). `btmon_iface` is "" when no Bluetooth
     * source is configured, which is what tells a consumer the zeros
     * below mean "not listening" rather than "nothing heard". */
    {
        const ble_host_t *h = &s->ble_host;
        int rec = bt_tx_recency(h->last_tx_wall, now);
        kv_str(buf, LINEBUF, &off, "btmon_iface", s->bt_iface);
        kv_str(buf, LINEBUF, &off, "btmon_err",   s->bt_err);
        health_kv(buf, &off, "btmon", &s->bt_health);
        kv_int(buf, LINEBUF, &off, "ble_controllers",  h->controllers);
        kv_int(buf, LINEBUF, &off, "ble_devices",      s->ble_device_count);
        kv_int(buf, LINEBUF, &off, "ble_records",      (long long)h->records);
        kv_int(buf, LINEBUF, &off, "ble_adv_reports",  (long long)h->adv_reports);
        /* Always 0 since multi-report events are decoded (Core v5.4
         * Vol 4 Part E §5.2, src/ble_snoop.h). Kept so an archive's
         * series continues rather than ends; a multi-report event that
         * does not account for its bytes is ble_records_malformed. */
        kv_int(buf, LINEBUF, &off, "ble_multi_report_rejected", 0);
        kv_int(buf, LINEBUF, &off, "ble_ext_adv_undecoded",
               (long long)h->ext_adv_undecoded);
        /* LE Extended Advertising Reports (0x0D slice): events decoded,
         * then the per-report fragment-train accounting
         * (docs/wiki/ble.md). */
        kv_int(buf, LINEBUF, &off, "ble_ext_adv_reports",
               (long long)h->ext_adv_reports);
        kv_int(buf, LINEBUF, &off, "ble_ext_adv_fragments",
               (long long)h->ext_fragments);
        kv_int(buf, LINEBUF, &off, "ble_ext_adv_partial",
               (long long)h->ext_adv_partial);
        kv_int(buf, LINEBUF, &off, "ble_ext_trains_evicted",
               (long long)h->ext_trains_evicted);
        kv_int(buf, LINEBUF, &off, "ble_records_ignored",   (long long)h->ignored);
        kv_int(buf, LINEBUF, &off, "ble_records_malformed", (long long)h->malformed);
        kv_int(buf, LINEBUF, &off, "ble_host_commands",     (long long)h->commands);
        kv_str(buf, LINEBUF, &off, "ble_scan_mode", ble_scan_mode_name(h->scan_mode));
        kv_str(buf, LINEBUF, &off, "ble_scan_filter",
               ble_filter_policy_name(h->filter_policy));
        kv_int(buf, LINEBUF, &off, "ble_scan_accept_list",
               h->filter_policy < 0 ? -1
                   : ble_filter_policy_is_accept_list(h->filter_policy));
        kv_int(buf, LINEBUF, &off, "ble_scan_enabled", h->scan_enabled);
        kv_str(buf, LINEBUF, &off, "ble_own_tx", bt_tx_recency_name(rec));
        kv_str(buf, LINEBUF, &off, "ble_own_tx_kind", bt_tx_kind_name(h->last_tx_kind));
        kv_int(buf, LINEBUF, &off, "ble_own_tx_count", (long long)h->tx_count);
        kv_int(buf, LINEBUF, &off, "ble_own_tx_secs",
               h->last_tx_wall > 0 ? (long long)(now - h->last_tx_wall) : -1);
        /* What is on the air now, as far as the commands show it, and
         * whether that view is complete: without a Reset seen on every
         * controller, state set before sloth opened the channel is not
         * in it, and "" here is not "listening only". */
        char on[192];
        bt_tx_kinds_format(h->tx_on_mask, on, sizeof(on));
        kv_str(buf, LINEBUF, &off, "ble_own_tx_on", on);
        bt_tx_kinds_format(bt_tx_asserted_mask(h, now), on, sizeof(on));
        kv_str(buf, LINEBUF, &off, "ble_own_tx_asserted", on);
        kv_int(buf, LINEBUF, &off, "ble_own_tx_baseline", h->tx_baseline);
        kv_int(buf, LINEBUF, &off, "ble_index_records",
               (long long)h->index_records);
    }
    /* Ubertooth capture stream (#144 slice 3). Appended. `btcap_iface`
     * is "" when --bt-capture is not given, which is what tells the
     * zeros below apart from a stream that heard nothing. Every count
     * is a sample: `btcap_sampling` names how small a one ("1_of_40_channels"
     * for BLE, "1_of_79_channels" for BR/EDR, "" before the header). */
    {
        const bt_capture_health_t *c = &s->btcap;
        char samp[32] = "";
        if (c->channels_of > 0)
            snprintf(samp, sizeof(samp), "1_of_%d_channels", c->channels_of);
        kv_str(buf, LINEBUF, &off, "btcap_iface",
               c->configured ? BT_CAPTURE_IFACE : "");
        kv_str(buf, LINEBUF, &off, "btcap_state", bt_cap_state_name(c->state));
        kv_str(buf, LINEBUF, &off, "btcap_err", c->err);
        kv_int(buf, LINEBUF, &off, "btcap_dlt", c->dlt);
        kv_int(buf, LINEBUF, &off, "btcap_refused_dlt", c->refused_dlt);
        kv_str(buf, LINEBUF, &off, "btcap_sampling", samp);
        kv_int(buf, LINEBUF, &off, "btcap_stale_secs", c->stale_secs);
        kv_int(buf, LINEBUF, &off, "btcap_recv",        (long long)c->recv);
        kv_int(buf, LINEBUF, &off, "btcap_drop",        (long long)c->drop);
        kv_int(buf, LINEBUF, &off, "btcap_truncated",   (long long)c->truncated);
        kv_int(buf, LINEBUF, &off, "btcap_adv",         (long long)c->adv);
        kv_int(buf, LINEBUF, &off, "btcap_scan_req",    (long long)c->scan_req);
        kv_int(buf, LINEBUF, &off, "btcap_connect_ind", (long long)c->connect_ind);
        kv_int(buf, LINEBUF, &off, "btcap_ext_adv_undecoded", (long long)c->ext_adv);
        kv_int(buf, LINEBUF, &off, "btcap_data_pdus",   (long long)c->data_pdus);
        kv_int(buf, LINEBUF, &off, "btcap_other_pdus",  (long long)c->other);
        kv_int(buf, LINEBUF, &off, "btcap_bredr",       (long long)c->bredr);
        kv_int(buf, LINEBUF, &off, "btcap_bredr_iac",   (long long)c->bredr_iac);
        kv_int(buf, LINEBUF, &off, "btcap_bredr_laps",  s->bredr_lap_count);
        /* JSONL 2.7.0: the BLE CRC sloth checks itself, appended. */
        kv_int(buf, LINEBUF, &off, "btcap_crc_bad",     (long long)c->crc_bad);
        kv_int(buf, LINEBUF, &off, "btcap_crc_ok",      (long long)c->crc_ok);
        kv_int(buf, LINEBUF, &off, "btcap_crc_unchecked", (long long)c->crc_unchecked);
    }
    /* #156: BLE address-rotation hints, ONLY while --ble-rotation-hints
     * is on, so a run without it writes exactly what it wrote before.
     * Decade bands of lifetime aggregates, payload and timing summed:
     * no address, link, token or digest, and no exact count a consumer
     * could match to one departure/arrival pair (src/ble_rotation.h).
     * Appended. */
    if (s->ble_rot.enabled) {
        const ble_rot_stats_t *r = &s->ble_rot;
        kv_str(buf, LINEBUF, &off, "ble_rot_hints",
               count_band(r->hints_payload + r->hints_timing));
        kv_str(buf, LINEBUF, &off, "ble_rot_poisoned",       count_band(r->poisoned));
        kv_str(buf, LINEBUF, &off, "ble_rot_seam_evictions", count_band(r->seam_evictions));
    }
    /* #166: the --pcap-dir age sweep, ONLY while --pcap-dir is set, so
     * a run without it writes exactly what it wrote before. The exact
     * counts ride every line; the signature above carries their decade.
     * pcap_retain_days 0 is "kept forever" (pcap.retain_days=0), which is
     * why the window is here and not only in `tuned`: a consumer needs
     * to see the sweep is off, not infer it from a missing knob.
     * Appended. */
    if (pcap_on) {
        kv_int(buf, LINEBUF, &off, "pcap_retain_days",  alert_pcap_retain_days());
        kv_int(buf, LINEBUF, &off, "pcap_swept",        (long long)alert_pcap_swept());
        kv_int(buf, LINEBUF, &off, "pcap_sweep_errors", alert_pcap_sweep_errors());
    }
    /* The receiver and position block, written only with --location
     * or --gps and shared with sloth-rf's record (#213). The adsb_*
     * and aprs_* blocks stood after it until JSONL 2.0.0 (#216); they
     * are in sloth-rf's sensor_health only. */
    jsonl_sh_gps(buf, &off, s);
    /* #193 field data (JSONL 1.7.0, src/alerts/twin_field.h): how often
     * a deauth flood met a late locally administered same-SSID copy the
     * chain rule left unnamed, with its denominators. Appended after the
     * flag-gated blocks and before jsonl_version, which stays last
     * (test_jsonl.c pins it). Outside `sig`: lifetime counts that ride
     * the heartbeat, the way the parse faults do; nothing waits on
     * them. Integers only. */
    {
        twin_field_counts_t tf;
        twin_field_counts(&tf);
        kv_int(buf, LINEBUF, &off, "twin193_since",    (long long)tf.since);
        kv_int(buf, LINEBUF, &off, "twin193_floods",   (long long)tf.floods);
        kv_int(buf, LINEBUF, &off, "twin193_floods_chain",
               (long long)tf.floods_chain);
        kv_int(buf, LINEBUF, &off, "twin193_named",    (long long)tf.named);
        kv_int(buf, LINEBUF, &off, "twin193_late_laa", (long long)tf.late_laa);
        kv_int(buf, LINEBUF, &off, "twin193_coincide", (long long)tf.coincide);
        kv_int(buf, LINEBUF, &off, "twin193_excl_carrier",
               (long long)tf.excl_carrier);
        kv_int(buf, LINEBUF, &off, "twin193_excl_faint",
               (long long)tf.excl_faint);
        kv_int(buf, LINEBUF, &off, "twin193_excl_sibling",
               (long long)tf.excl_sibling);
        kv_int(buf, LINEBUF, &off, "twin193_excl_any", (long long)tf.excl_any);
    }
    /* The APRS region, rtl_433 and Victron blocks stood here until
     * JSONL 2.0.0 (#216): sloth-rf's sensor_health only. */
    /* "daemon", then db_max_mb and jsonl_version, which stay last. */
    jsonl_sh_tail(buf, &off, "wifi", db_cap_mb);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

/* ── credential-lure findings (JSONL 1.3.0, #187 / #172) ─────────────
 *
 * The evidence tables behind KARMA_AP / KARMA_PROBE_FORGE (s->karma_aps,
 * karma_update()) and PMKID_HARVEST / HANDSHAKE_HARVEST
 * (s->harvest_sta, s->harvest_chain, harvest_snapshot()), one record per
 * row, so a consumer can show what the rules judged and not only that
 * they fired: the alert record says "this BSSID, CRIT"; these say "it
 * answered for 3 names it never beaconed, to 2 stations".
 *
 *   karma_suspect    one per [y] row: a BSSID beacon-fanning past
 *                    karma.ssid_thresh, or answering directed probes
 *                    for names it never beaconed. The [y] view's columns.
 *   harvest_station  one per soliciting station with at least one M1
 *                    left unanswered. A station whose every M1 drew an
 *                    M2 is a station joining its network, and the table
 *                    holds a row for every station that asked anything;
 *                    it is not written.
 *   harvest_chain    one per BSSID whose claimed deauths were followed
 *                    by a victim's fresh M1/M2 (every row of the table).
 *
 * Counts only. A victim's address, the stations a forging BSSID
 * answered and the SSIDs it answered for stay in the TUI and the alert
 * evidence; the record says how many. Member names avoid the credential
 * words slothweb's readers hold every name to (sloth-mesh's src/web_secret.c):
 * `unanswered_kde` for the M1s that carried the PMKID KDE, `disconnects`
 * for the deauthentication and disassociation frames, `lure_chain` for
 * the deauth-then-lure flag.
 *
 * Change-only on the shared cache, signed on every count and string and
 * never on a timestamp, so a row writes when its evidence moves and on
 * the 300 s heartbeat. A row that leaves its table (aged out, evicted,
 * or a station whose unanswered M1s aged to none) is written once more
 * as `"state":"gone"` with its key alone, so a consumer drops it rather
 * than holding it until its own timeout. Every other row says
 * `"state":"live"`. */
enum { LURE_KARMA, LURE_STA, LURE_CHAIN, LURE_KINDS };
#define LURE_PREV_MAX MAX_KARMA_APS
static uint8_t g_lure_prev[LURE_KINDS][LURE_PREV_MAX][6];
static int     g_lure_prev_n[LURE_KINDS];

static const char *const LURE_TYPE[LURE_KINDS] = {
    "karma_suspect", "harvest_station", "harvest_chain" };
static const char *const LURE_KEYM[LURE_KINDS] = { "bssid", "sta", "bssid" };
static const uint8_t LURE_JD[LURE_KINDS] = {
    JD_KARMA_SUSPECT, JD_HARVEST_STA, JD_HARVEST_CHAIN };

static int lure_has(const uint8_t (*keys)[6], int n, const uint8_t k[6]) {
    for (int i = 0; i < n; i++)
        if (!memcmp(keys[i], k, 6)) return 1;
    return 0;
}

/* The rows of `kind` now (cur, n) against those written last pass:
 * each one missing now goes out as gone, and cur becomes the
 * remembered set. The cache slot is re-signed with 0, which no live
 * row carries, so a row that returns with the same counts is written
 * again. */
static void lure_retire(int kind, const uint8_t (*cur)[6], int n, time_t now) {
    char buf[256]; int off = 0;
    for (int i = 0; i < g_lure_prev_n[kind]; i++) {
        const uint8_t *k = g_lure_prev[kind][i];
        if (lure_has(cur, n, k)) continue;
        (void)jsonl_changed(LURE_JD[kind], k, 6, 0, now);
        start_obj(buf, (int)sizeof(buf), &off, LURE_TYPE[kind], now);
        kv_mac(buf, (int)sizeof(buf), &off, LURE_KEYM[kind], k);
        kv_str(buf, (int)sizeof(buf), &off, "state", "gone");
        end_obj(buf, (int)sizeof(buf), &off);
        emit_line(buf);
    }
    if (n > 0) memcpy(g_lure_prev[kind], cur, (size_t)n * 6);
    g_lure_prev_n[kind] = n;
}

static uint64_t sig_int(uint64_t h, long long v) { return fnv1a(&v, sizeof(v), h); }
static uint64_t sig_str(uint64_t h, const char *v) { return fnv1a(v, strlen(v) + 1, h); }

void jsonl_emit_lures(const sloth_state_t *s) {
    if (!s || !any_sink()) return;
    time_t now = sloth_wall();
    char buf[LINEBUF]; int off = 0;
    uint8_t cur[LURE_PREV_MAX][6];
    int n = 0;

    for (int i = 0; i < s->karma_count && n < LURE_PREV_MAX; i++) {
        const karma_ap_t *k = &s->karma_aps[i];
        memcpy(cur[n++], k->bssid, 6);
        uint64_t sig = sig_int(FNV64_OFFSET, k->ssid_count);
        sig = sig_int(sig, k->ie_fp_distinct);
        sig = sig_int(sig, k->ie_uniform);
        sig = sig_int(sig, k->forged);
        sig = sig_int(sig, k->forge_stations);
        sig = sig_int(sig, k->pnl_best);
        sig = sig_int(sig, k->deauth_chain);
        sig = sig_int(sig, k->score);
        sig = sig_str(sig, k->top_ssid);
        sig = sig_str(sig, k->tool);
        if (sig == 0) sig = 1;              /* 0 is a retired row's */
        if (!jsonl_changed(JD_KARMA_SUSPECT, k->bssid, 6, sig, now)) continue;
        start_obj(buf, LINEBUF, &off, "karma_suspect", now);
        kv_mac(buf, LINEBUF, &off, "bssid", k->bssid);
        kv_str(buf, LINEBUF, &off, "state", "live");
        kv_int(buf, LINEBUF, &off, "ssids", k->ssid_count);
        kv_int(buf, LINEBUF, &off, "ie_postures", k->ie_fp_distinct);
        kv_int(buf, LINEBUF, &off, "ie_collapsed", k->ie_uniform ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "forged", k->forged);
        kv_int(buf, LINEBUF, &off, "forge_stations", k->forge_stations);
        kv_int(buf, LINEBUF, &off, "pnl_best", k->pnl_best);
        kv_int(buf, LINEBUF, &off, "lure_chain", k->deauth_chain ? 1 : 0);
        kv_int(buf, LINEBUF, &off, "score", k->score);
        kv_str(buf, LINEBUF, &off, "top_ssid", k->top_ssid);
        kv_str(buf, LINEBUF, &off, "tool", k->tool);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)k->last_seen);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
    lure_retire(LURE_KARMA, (const uint8_t (*)[6])cur, n, now);

    n = 0;
    for (int i = 0; s->harvest_sta && i < s->harvest_sta_count; i++) {
        const harvest_sta_t *h = &s->harvest_sta[i];
        if (h->unanswered < 1 || n >= LURE_PREV_MAX) continue;
        memcpy(cur[n++], h->sta, 6);
        uint64_t sig = sig_int(FNV64_OFFSET, h->solicited);
        sig = sig_int(sig, h->m1_bssids);
        sig = sig_int(sig, h->unanswered);
        sig = sig_int(sig, h->pmkid_unanswered);
        sig = sig_int(sig, h->answered);
        sig = sig_int(sig, h->dropped);
        sig = sig_int(sig, (long long)h->cluster_id);
        sig = sig_int(sig, h->qevict);
        if (sig == 0) sig = 1;
        if (!jsonl_changed(JD_HARVEST_STA, h->sta, 6, sig, now)) continue;
        start_obj(buf, LINEBUF, &off, "harvest_station", now);
        kv_mac(buf, LINEBUF, &off, "sta", h->sta);
        kv_str(buf, LINEBUF, &off, "state", "live");
        kv_int(buf, LINEBUF, &off, "asked", h->solicited);
        kv_int(buf, LINEBUF, &off, "m1_bssids", h->m1_bssids);
        kv_int(buf, LINEBUF, &off, "unanswered", h->unanswered);
        kv_int(buf, LINEBUF, &off, "unanswered_kde", h->pmkid_unanswered);
        kv_int(buf, LINEBUF, &off, "answered", h->answered);
        kv_int(buf, LINEBUF, &off, "dropped", h->dropped);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)h->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)h->last_seen);
        /* Additive (JSONL 1.7.0): the row's cluster, the id its eapol
         * records and its alert detail carry, and how many of its
         * (BSSID, station) pairs had a QUEUE_EVICT release inside the
         * window. A count, as the rest of the record. */
        kv_int(buf, LINEBUF, &off, "cluster_id", (long long)h->cluster_id);
        kv_int(buf, LINEBUF, &off, "qevict", h->qevict);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
    lure_retire(LURE_STA, (const uint8_t (*)[6])cur, n, now);

    n = 0;
    for (int i = 0; s->harvest_chain && i < s->harvest_chain_count &&
                    n < LURE_PREV_MAX; i++) {
        const harvest_chain_t *c = &s->harvest_chain[i];
        memcpy(cur[n++], c->bssid, 6);
        uint64_t sig = sig_int(FNV64_OFFSET, c->victims);
        sig = sig_int(sig, c->deauth_frames);
        sig = sig_int(sig, c->dropped);
        sig = sig_int(sig, (long long)c->cluster_id);
        sig = sig_int(sig, c->qevict);
        if (sig == 0) sig = 1;
        if (!jsonl_changed(JD_HARVEST_CHAIN, c->bssid, 6, sig, now)) continue;
        start_obj(buf, LINEBUF, &off, "harvest_chain", now);
        kv_mac(buf, LINEBUF, &off, "bssid", c->bssid);
        kv_str(buf, LINEBUF, &off, "state", "live");
        kv_int(buf, LINEBUF, &off, "victims", c->victims);
        kv_int(buf, LINEBUF, &off, "disconnects", c->deauth_frames);
        kv_int(buf, LINEBUF, &off, "dropped", c->dropped);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)c->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)c->last_seen);
        /* Additive (JSONL 1.7.0), as harvest_station's: a victim count,
         * never the victim's address. */
        kv_int(buf, LINEBUF, &off, "cluster_id", (long long)c->cluster_id);
        kv_int(buf, LINEBUF, &off, "qevict", c->qevict);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
    lure_retire(LURE_CHAIN, (const uint8_t (*)[6])cur, n, now);
}

void jsonl_lures_reset(void) {
    memset(g_lure_prev, 0, sizeof(g_lure_prev));
    memset(g_lure_prev_n, 0, sizeof(g_lure_prev_n));
}

/* ── ownership (2026-11-11) ─────────────────────────────────────────
 *
 * The operator's designated networks, so a consumer (slothweb's SSID
 * drawer, its Probes and WiFi views) can mark them: until this record
 * the rosters were in neither sloth.db nor the stream, and slothweb
 * could only say it did not know.
 *
 * Flat, one member per designation (`ssid_0` .. `ssid_15`, `bssid_0`
 * .. `bssid_15`) beside their counts, rather than an array: slothweb's
 * decoder keeps top-level scalars only, and the bounds are sloth's own
 * (MAX_MY_SSIDS, MAX_MY_BSSIDS). An SSID goes through the same escaping
 * as every string (json_escape: a control byte as \u00YY, an octet
 * that is not UTF-8 as \ufffd), the operator's text as given, which is
 * exactly what ownership_is_my_ssid() compares against: a designation
 * with a control byte in it matches no stored SSID (those hold '?'),
 * here or in a consumer that compares as sloth does.
 *
 * The known-device roster travels as a count. Its MACs are the
 * operator's own devices, a list a stream that is forwarded to a SIEM
 * or bundled for a colleague has no need to carry; what a consumer can
 * use is whether the roster gates UNKNOWN_DEVICE (non-zero) or not.
 * The sensor's own addresses (the self roster) are not here either:
 * they are the host's interfaces, already in the `iface` records.
 *
 * Change-only, keyed as a singleton. The rosters are fixed for the life
 * of the process today (flags only; no reload, no SIGHUP handler), so
 * in practice it is the first tick and then a heartbeat every 300 s;
 * the signature is there so a future reload is a line at once. */
void jsonl_emit_ownership(void) {
    if (!any_sink()) return;
    time_t now = sloth_wall();
    const int ns = ownership_ssid_count(), nb = ownership_bssid_count();
    const int nk = ownership_known_count();
    uint64_t sig = fnv1a(&ns, sizeof(ns), FNV64_OFFSET);
    sig = fnv1a(&nb, sizeof(nb), sig);
    sig = fnv1a(&nk, sizeof(nk), sig);
    for (int i = 0; i < ns; i++) {
        const char *x = ownership_ssid_at(i);
        sig = fnv1a(x, strlen(x) + 1, sig);   /* the NUL: "ab","c" is not "a","bc" */
    }
    for (int i = 0; i < nb; i++) sig = fnv1a(ownership_bssid_at(i), 6, sig);
    static const char own_key[] = "ownership";
    if (!jsonl_changed(JD_OWNERSHIP, own_key, sizeof(own_key) - 1, sig, now)) return;

    char buf[LINEBUF]; int off = 0;
    char key[24];
    start_obj(buf, LINEBUF, &off, "ownership", now);
    kv_int(buf, LINEBUF, &off, "ssids", ns);
    for (int i = 0; i < ns; i++) {
        snprintf(key, sizeof(key), "ssid_%d", i);
        kv_str(buf, LINEBUF, &off, key, ownership_ssid_at(i));
    }
    kv_int(buf, LINEBUF, &off, "bssids", nb);
    for (int i = 0; i < nb; i++) {
        snprintf(key, sizeof(key), "bssid_%d", i);
        kv_mac(buf, LINEBUF, &off, key, ownership_bssid_at(i));
    }
    kv_int(buf, LINEBUF, &off, "known_macs", nk);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

/* ── BLE (#144 slice 4) ─────────────────────────────────────────────
 *
 * ble_device: one record per advertiser row, change-only. The
 * signature holds the row's discrete facts, its best RSSI quantised to
 * 10 dB, and the BLE_JSONL_LIVE_S slot its last_seen falls in;
 * adv_count, the timestamps and the LL channel (an Ubertooth row hops
 * between 37, 38 and 39) are written but never signed. So an
 * advertiser sloth keeps hearing writes one record per slot, a quiet
 * one rides the heartbeat, and neither is a firehose (below).
 *
 * ble_alert: one record per finding ble_findings_build() returns — the
 * same list the three BLE rules fire from — with its structured fields.
 * Signed on the finding's identity and its counts quantised by powers
 * of two (distinct addresses, advertisements, rate, address count) and
 * its median RSSI by 10 dB. Neither record carries a raw AD byte. */

static unsigned log2_bucket(uint64_t v) {
    unsigned b = 0;
    while (v) { b++; v >>= 1; }
    return b;
}

static int rssi_bucket(int has, int rssi) {
    return has ? (rssi + 200) / 10 : -1;
}

/* The ble_device liveness slot (2026-11-02, slothweb's BLE waterfall).
 * The beacon record goes out on every pass (jsonl_emit_beacons(), at
 * POLL_MS); ble_device was change-only on facts that settle, so a
 * steady advertiser reached a consumer once per JSONL_HEARTBEAT_SECS
 * and a time series of it was one point in five minutes. The same
 * mechanism as beacon - the row is re-sent while sloth keeps hearing
 * it - bounded to one record per slot of this many seconds: the
 * signature folds last_seen / BLE_JSONL_LIVE_S, a quantised term and
 * never the raw counter (agents/AGENTS.md, change-only emission). A
 * heard row's frame-clock last_seen crosses a slot boundary every
 * BLE_JSONL_LIVE_S seconds; a silent row's last_seen is frozen, so it
 * writes nothing until the heartbeat. Ten seconds is slothweb's fine
 * bucket (web_rollup.h WEB_FINE_S), the finest cell anything draws.
 * Worst case MAX_BLE_DEVICES rows heard at once is 25.6 lines/s,
 * against beacon's MAX_BEACON_APS x 4 a second at the default 250 ms
 * pass. The frame clock, not sloth_wall(): a replay and a test stay
 * deterministic. */
#define BLE_JSONL_LIVE_S 10

void jsonl_emit_ble_devices(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    for (int i = 0; i < s->ble_device_count && i < MAX_BLE_DEVICES; i++) {
        const ble_device_t *d = &s->ble_devices[i];
        uint8_t key[16];
        memset(key, 0, sizeof(key));
        memcpy(key, d->addr, 6);
        key[6] = d->addr_type;
        key[7] = d->sensor_kind;
        memcpy(key + 8, d->sensor_iface, 8);

        uint64_t h = FNV64_OFFSET;
        h = fnv1a(d->addr, 6, h);
        h = fnv1a(d->sensor_iface,
                  strnlen(d->sensor_iface, sizeof(d->sensor_iface)), h);
        /* Only facts that appear once or only ratchet: presence bits
         * (set, never cleared), the HID bits (OR-ed), pdu_mask (OR-ed),
         * the first-seen mfr_id / mfr_sub, whether a watch category was
         * ever matched, and the bucket of the BEST RSSI. Every other
         * field on the row - name and name_complete, uuid16, appearance,
         * tx_power, flags, service-data UUID, the current RSSI - takes
         * the last report's value, and an ordinary advertiser alternates
         * them (an ADV_IND with a shortened name and its SCAN_RSP with
         * the complete one; two UUID lists): signing any of them wrote a
         * record on every snapshot (#144 slice 4 second review). Those
         * values still go out on every line this emits and on the
         * heartbeat. ext_adv is not signed on its own: it is set exactly
         * when an EXT_ADV or EXT_SCAN_RSP PDU is heard, which sets that
         * PDU's pdu_mask bit, so a change in it is already a change in
         * pdu_mask. */
        /* The distance enters as its band only, held by a noise-sized
         * margin and a hold (src/rf_distance.h), never as metres: a
         * moving figure here would write the record on every snapshot.
         * The trend is written but not signed. It is a slope over a
         * few medians, and under ordinary RSSI noise it entered and
         * left approaching / leaving for a stationary advertiser
         * several times a minute (tests/test_rf_distance.c's
         * seeded-noise hour: ~260 records with it signed); a change in
         * it reaches a consumer on the next record. */
        uint8_t b[18] = { d->addr_type, d->sensor_kind, d->sampled,
                          d->pdu_mask, d->has_name, d->has_uuid16,
                          d->has_mfr, d->has_mfr_sub, d->mfr_sub,
                          d->has_svc_data, d->has_appearance, d->hid,
                          d->has_tx_power, d->has_flags,
                          (uint8_t)rssi_bucket(d->has_rssi, d->rssi_best),
                          (uint8_t)(d->watch_cat[0] != '\0'),
                          (uint8_t)(d->adapter & 0xff),
                          d->dist.valid ? d->dist.band : 0 };
        h = fnv1a(b, sizeof(b), h);
        h = fnv1a(&d->mfr_id, sizeof(d->mfr_id), h);
        uint32_t live = (uint32_t)(d->last_seen / BLE_JSONL_LIVE_S);
        h = fnv1a(&live, sizeof(live), h);
        if (!jsonl_changed(JD_BLE_DEVICE, key, sizeof(key), h, now)) continue;

        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ble_device", now);
        kv_mac(buf, LINEBUF, &off, "addr", d->addr);
        kv_int(buf, LINEBUF, &off, "addr_type", d->addr_type);
        kv_str(buf, LINEBUF, &off, "sensor", sensor_kind_name(d->sensor_kind));
        kv_str(buf, LINEBUF, &off, "iface", d->sensor_iface);
        kv_int(buf, LINEBUF, &off, "adapter", d->adapter);
        kv_int(buf, LINEBUF, &off, "sampled", d->sampled);
        kv_int(buf, LINEBUF, &off, "channel", d->channel);
        kv_str(buf, LINEBUF, &off, "last_pdu", ble_adv_type_name(d->last_event_type));
        kv_int(buf, LINEBUF, &off, "pdu_mask", d->pdu_mask);
        kv_str(buf, LINEBUF, &off, "name", d->has_name ? d->name : "");
        kv_int(buf, LINEBUF, &off, "name_complete", d->name_complete);
        kv_int(buf, LINEBUF, &off, "uuid16", d->has_uuid16 ? d->uuid16 : -1);
        kv_int(buf, LINEBUF, &off, "mfr_id", d->has_mfr ? d->mfr_id : -1);
        kv_int(buf, LINEBUF, &off, "mfr_subtype", d->has_mfr_sub ? d->mfr_sub : -1);
        kv_int(buf, LINEBUF, &off, "svc_data_uuid16",
               d->has_svc_data ? d->svc_data_uuid16 : -1);
        kv_int(buf, LINEBUF, &off, "appearance",
               d->has_appearance ? d->appearance : -1);
        kv_int(buf, LINEBUF, &off, "hid", d->hid);
        kv_int(buf, LINEBUF, &off, "tx_power",
               d->has_tx_power ? d->tx_power : -128);
        kv_int(buf, LINEBUF, &off, "ext_tx_power",
               d->has_ext_tx_power ? d->ext_tx_power : -128);
        kv_int(buf, LINEBUF, &off, "flags", d->has_flags ? d->flags : -1);
        kv_int(buf, LINEBUF, &off, "has_rssi", d->has_rssi);
        kv_int(buf, LINEBUF, &off, "rssi", d->has_rssi ? d->rssi : 0);
        kv_int(buf, LINEBUF, &off, "rssi_best", d->has_rssi ? d->rssi_best : 0);
        kv_int(buf, LINEBUF, &off, "adv_count", (long long)d->adv_count);
        kv_str(buf, LINEBUF, &off, "watch_category", d->watch_cat);
        kv_int(buf, LINEBUF, &off, "ext_adv", d->ext_adv);
        kv_int(buf, LINEBUF, &off, "primary_phy", d->primary_phy);
        kv_int(buf, LINEBUF, &off, "secondary_phy", d->secondary_phy);
        kv_int(buf, LINEBUF, &off, "adv_sid", d->adv_sid == 0xFF ? -1 : d->adv_sid);
        kv_int(buf, LINEBUF, &off, "first_seen", (long long)d->first_seen);
        kv_int(buf, LINEBUF, &off, "last_seen", (long long)d->last_seen);
        emit_dist(buf, &off, &d->dist);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

static const char *ble_find_kind_name(int k) {
    switch (k) {
    case BLE_FIND_FLOOD:      return "adv_flood";
    case BLE_FIND_HID_OUI:    return "hid_oui";
    case BLE_FIND_HID_ROTATE: return "hid_rotate";
    case BLE_FIND_WATCH:      return "watchlist";
    default:                  return "unknown";
    }
}

void jsonl_emit_ble_alerts(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();
    ble_finding_t f[BLE_FINDINGS_MAX];
    int n = ble_findings_build(s, now, f, BLE_FINDINGS_MAX, NULL);
    for (int i = 0; i < n; i++) {
        const ble_finding_t *x = &f[i];
        /* The key string is the identity; two independent hashes of it
         * fill the 16-byte dedup key. */
        size_t kl = strnlen(x->key, sizeof(x->key));
        uint64_t k1 = fnv1a(x->key, kl, FNV64_OFFSET);
        uint64_t k2 = fnv1a(x->key, kl, 0x84222325cbf29ce4ULL);
        uint8_t key[16];
        memcpy(key, &k1, 8);
        memcpy(key + 8, &k2, 8);

        /* Signed on the finding's STATE. A flood's counts are those of
         * the last closed window, never the window in progress: that
         * one climbs from zero every ble.flood_window_s, and signing it
         * re-emitted a steady flood several times a window. A steady
         * flood is two records (onset, then its first closed window)
         * and the heartbeat after that. */
        unsigned q[5] = {
            (unsigned)x->kind,
            log2_bucket(x->prev_fresh), log2_bucket(x->prev_total),
            log2_bucket((uint64_t)(x->addrs > 0 ? x->addrs : 0)),
            (unsigned)(rssi_bucket(x->prev_has_rssi, x->prev_rssi_median) + 1) };
        uint64_t h = fnv1a(q, sizeof(q), k1);
        if (!jsonl_changed(JD_BLE_ALERT, key, sizeof(key), h, now)) continue;

        char buf[LINEBUF]; int off = 0;
        start_obj(buf, LINEBUF, &off, "ble_alert", now);
        kv_str(buf, LINEBUF, &off, "kind", ble_find_kind_name(x->kind));
        kv_str(buf, LINEBUF, &off, "alert",
               alert_type_name((alert_type_t)x->alert_type));
        kv_int(buf, LINEBUF, &off, "ty", x->alert_type);
        kv_str(buf, LINEBUF, &off, "key", x->key);
        kv_str(buf, LINEBUF, &off, "sensor", sensor_kind_name(x->sensor_kind));
        kv_str(buf, LINEBUF, &off, "iface", x->sensor_iface);
        kv_int(buf, LINEBUF, &off, "sampled", x->sampled);
        switch (x->kind) {
        case BLE_FIND_FLOOD:
            kv_str(buf, LINEBUF, &off, "adv_type", ble_adv_type_name(x->adv_type));
            kv_str(buf, LINEBUF, &off, "family", ble_family_name(x->family));
            kv_int(buf, LINEBUF, &off, "id", x->id);
            kv_int(buf, LINEBUF, &off, "subtype", x->subtype);
            kv_str(buf, LINEBUF, &off, "window", x->window ? "previous" : "current");
            kv_int(buf, LINEBUF, &off, "window_s", x->window_s);
            kv_int(buf, LINEBUF, &off, "distinct_addrs", x->distinct);
            kv_int(buf, LINEBUF, &off, "distinct_capped", x->distinct_capped);
            kv_int(buf, LINEBUF, &off, "fresh_addrs", x->fresh);
            kv_int(buf, LINEBUF, &off, "total_adv", x->total);
            kv_double(buf, LINEBUF, &off, "rate", x->rate_x10 / 10.0);
            kv_int(buf, LINEBUF, &off, "has_rssi", x->has_rssi);
            kv_int(buf, LINEBUF, &off, "median_rssi", x->has_rssi ? x->rssi_median : 0);
            kv_str(buf, LINEBUF, &off, "spam_source",
                   x->spam_source ? x->spam_source : "");
            break;
        case BLE_FIND_HID_OUI:
            kv_mac(buf, LINEBUF, &off, "addr", x->addr);
            kv_int(buf, LINEBUF, &off, "addr_type", x->addr_type);
            kv_int(buf, LINEBUF, &off, "hid", x->hid);
            kv_int(buf, LINEBUF, &off, "appearance", x->appearance);
            kv_str(buf, LINEBUF, &off, "oui_table", x->oui_table ? x->oui_table : "");
            break;
        case BLE_FIND_HID_ROTATE:
            kv_int(buf, LINEBUF, &off, "addrs", x->addrs);
            kv_int(buf, LINEBUF, &off, "window_s", x->window_s);
            kv_int(buf, LINEBUF, &off, "appearance", x->appearance);
            break;
        case BLE_FIND_WATCH:
            kv_str(buf, LINEBUF, &off, "category", x->category);
            kv_int(buf, LINEBUF, &off, "addrs", x->addrs);
            kv_int(buf, LINEBUF, &off, "window_s", x->window_s);
            break;
        default:
            break;
        }
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* What sloth-wifi writes each tick: every record of the capture, the
 * monitor radio and BLE. The sink, the primitives, the alert records
 * and the blocks sensor_health shares are src/jsonl_core.c; the GNSS,
 * ADS-B, APRS, rtl_433 and Victron records are src/jsonl_rf.c, which
 * has the list sloth-rf writes (jsonl_emit_state_rf(), #213) and which
 * this daemon does not link (#216). This file is the capture's records
 * and needs the capture to link. */
void jsonl_emit_state_snapshots(sloth_state_t *s) {
    /* Cheap gating — every emitter checks any_sink() too, but the
     * batch-level skip avoids the per-call setup when nobody's there. */
    if (!any_sink() || !s) return;
    jsonl_emit_ifaces            (s);
    jsonl_emit_sensors           (s);
    jsonl_emit_wifi_merged       (s);
    jsonl_emit_wifi_df           (s);
    jsonl_emit_arp               (s);
    jsonl_emit_dhcp_leases       (s);
    jsonl_emit_wifi_aps          (s);
    jsonl_emit_wifi_stas         (s);
    jsonl_emit_top_hosts         (s);
    jsonl_emit_devices           (s);
    jsonl_emit_beacons           (s);
    jsonl_emit_wifi_regulatory   (s);
    jsonl_emit_deauths           (s);
    jsonl_emit_probe_clients     (s);
    jsonl_emit_pnl_clients       (s);
    jsonl_emit_seqnum_clients    (s);
    jsonl_emit_seqnum_correlations(s);
    jsonl_emit_channels          (s);
    jsonl_emit_assocs            (s);
    jsonl_emit_assoc_reqs        (s);
    jsonl_emit_btm_steers        (s);
    jsonl_emit_csa_events        (s);
    jsonl_emit_rrm_pairs         (s);
    jsonl_emit_mlds              (s);
    jsonl_emit_cp_events         (s);
    jsonl_emit_eapol_events      (s);
    jsonl_emit_mdns_services     (s);
    jsonl_emit_nbns_names        (s);
    jsonl_emit_ssdp_devices      (s);
    jsonl_emit_onvif_devices     (s);
    jsonl_emit_scan_entries      (s);
    jsonl_emit_packets           (s);
    jsonl_emit_processes         (s);
    jsonl_emit_ndp_ras           (s);
    jsonl_emit_smb_sessions      (s);
    jsonl_emit_kerb_events       (s);
    jsonl_emit_ldap_events       (s);
    jsonl_emit_bgp_sessions      (s);
    jsonl_emit_ssh_flows         (s);
    jsonl_emit_rdp_flows         (s);
    jsonl_emit_snmp_flows        (s);
    jsonl_emit_mqtt_flows        (s);
    jsonl_emit_ble_devices       (s);   /* #144 slice 4 */
    jsonl_emit_ble_alerts        (s);
    /* No gnss_fix / gnss_sky / gnss_sat, adsb_aircraft, aprs_station /
     * aprs_packet, rtl433_device or victron_device since JSONL 2.0.0
     * (#216, ADR 0010): those records are sloth-rf's
     * (jsonl_emit_state_rf()). The receiver's health stays in this
     * daemon's sensor_health, below. */
    /* The host's status and the source inventory (src/sys_status.h):
     * a batch on its own cadence, nothing on most ticks. */
    sys_status_emit              (s);
    /* Which rules can fire (#242, JSONL 2.8.0): rows on change. */
    cov_live_emit                ();
    /* What the radios did in the last minute (#242 item 2, JSONL
     * 2.9.0): one line per interval closed, on its fixed cadence. */
    cov_iv_emit                  ();
    /* What the site reveals, by group (#243, JSONL 2.11.0): one row per
     * group on change, kinds and counts only. */
    exp_emit                     (s);
    /* The operator's designated networks: change-only, a heartbeat. */
    jsonl_emit_ownership         ();
    /* The KARMA and key-harvest evidence tables (JSONL 1.3.0). */
    jsonl_emit_lures             (s);
    /* Last: the sensor's self-report about this tick, after every
     * observation in it has been emitted (#91 slice 3). */
    jsonl_emit_sensor_health     (s);
}
