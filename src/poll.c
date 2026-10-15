#include <string.h>
#include "poll.h"
#include "sloth_clock.h"
#include "capture/capture.h"
#include "capture/probe.h"
#include "persist_health.h"
#include "history.h"
#include "bandwidth.h"
#include "views/conns.h"
#include "views/stats.h"
#include "views/channel.h"
#include "sensors.h"
#include "wifi_merge.h"
#include "coverage.h"
#include "karma_detect.h"
#include "eap_track.h"
#include "twins.h"
#include "probe_pnl.h"
#include "eapol_log.h"
#include "seqnum_track.h"
#include "assoc_track.h"
#include "action_snoop.h"
#include "ctrl_frames.h"
#include "rf_quality.h"
#include "mle.h"
#include "captive_portal.h"
#include "fragattack.h"
#include "mdns_snoop.h"
#include "nbns_snoop.h"
#include "dhcp_snoop.h"
#include "ndp_snoop.h"
#include "smb_snoop.h"
#include "kerb_snoop.h"
#include "ldap_snoop.h"
#include "bgp_snoop.h"
#include "ssh_snoop.h"
#include "rdp_snoop.h"
#include "snmp_snoop.h"
#include "mqtt_snoop.h"
#include "ssdp_snoop.h"
#include "onvif_discovery.h"
#include "beacon_snoop.h"
#include "deauth_snoop.h"
#include "http_log.h"
#include "tls_log.h"
#include "quic_log.h"
#include "dns_log.h"
#include "ntp_log.h"
#include "icmp_log.h"
#include "cleartext_creds.h"
#include "alerts.h"
#include "devices.h"
#include "top_hosts.h"
#include "scan.h"
#include "beacon_detect.h"
#include "transit.h"
#include "presence.h"
#include "jsonl.h"
#include "db.h"

/* Stage bodies. Each is the code poll_data() ran at that point, moved
 * verbatim except where the move is the fix — those say so. Phase
 * membership and order live in g_poll_stages below, not here. */

/* ── PLATFORM ─────────────────────────────────────────────── */

static void st_platform_net(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    s->iface_count = g_platform.get_ifaces(s->ifaces, MAX_IFACES);
    s->conn_count  = g_platform.get_conns(s->conns, MAX_CONNS);
#ifdef WITH_WIFI
    s->ap_count       = g_platform.wifi_scan(s->aps, MAX_WIFI_APS);
    s->wifi_sta_count = g_platform.get_wifi_stations(s->wifi_stas, MAX_WIFI_STAS);
#endif
    s->arp_count  = g_platform.get_arp(s->arp_entries, MAX_ARP_ENTRIES);
    s->dhcp_count = g_platform.get_dhcp(s->dhcp_leases, MAX_DHCP_LEASES);
    /* clamp selections in case counts shrunk */
    if (s->iface_sel >= s->iface_count && s->iface_count > 0)
        s->iface_sel = s->iface_count - 1;
    if (s->wifi_sel >= s->ap_count && s->ap_count > 0)
        s->wifi_sel = s->ap_count - 1;
    if (s->arp_sel >= s->arp_count && s->arp_count > 0)
        s->arp_sel = s->arp_count - 1;
}

static void st_health(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* #91 slice 2: both capture workers' liveness and pcap_stats(). Both
     * calls self-stub without WITH_PCAP, where "off" is the honest health
     * state rather than a missing one. */
    capture_health_poll(&s->cap_health);
    probe_health_poll(&s->mon_health);
    /* #96: per-sink write-failure counts, for the cannot-persist badge. */
    persist_health_poll(&s->persist_health);
    /* #85: re-check each pinned ifindex still names its interface; a
     * replugged, renamed or reused one fails closed and reads DEGRADED. */
    capture_scope_poll(s);
}

static void st_stats_baseline(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* First tick only; reads the interface counters just polled. */
    if (!s->stats_init) stats_take_baseline(s);
}

/* ── SNAPSHOT ─────────────────────────────────────────────── */

static void st_capture_ring(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* #111: the wired packet ring is private to the capture thread; take
     * this tick's copy before anything reads s->packets — bw_update()
     * walks it from pkt_bw_cursor and the JSONL packet emitter from
     * pkt_jsonl_emitted. */
    capture_ring_snapshot(s);
}

#ifdef WITH_PCAP
static void st_wifi_snapshots(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    probe_snapshot(s);
    mon_frame_snapshot(s);
    probe_pnl_snapshot(s);
    eapol_snapshot(s);
    seqnum_snapshot(s);
    assoc_snapshot(s);
    assoc_request_snapshot(s);
    btm_snapshot(s);
    action_snapshot(s);   /* protected-frame tally (#124) */
    csa_snapshot(s);
    rrm_snapshot(s);
    frag_snapshot(s);     /* VIEW_FRAGATTACK (#75 slice 5) */
    mle_snapshot(s);
    cp_snapshot(s);
    beacon_snapshot(s);
    deauth_snapshot(s);
}

static void st_wired_snapshots(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    mdns_snapshot(s);
    nbns_snapshot(s);
    dhcp_snoop_snapshot(s);
    ndp_snoop_snapshot(s);
    smb_snoop_snapshot(s);
    kerb_snoop_snapshot(s);
    ldap_snoop_snapshot(s);
    bgp_snoop_snapshot(s);
    ssh_snoop_snapshot(s);
    rdp_snoop_snapshot(s);
    snmp_snoop_snapshot(s);
    mqtt_snoop_snapshot(s);
    ssdp_snapshot(s);
    onvif_snapshot(s);
    http_log_snapshot(s);
    tls_log_snapshot(s);
    quic_log_snapshot(s);
    dns_log_snapshot(s);
    ntp_log_snapshot(s);
    icmp_log_snapshot(s);
    cleartext_creds_snapshot(s);
}
#endif

static void st_eap_track(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    eap_track_snapshot(s);   /* 802.1X EAP methods for ROGUE_RADIUS (#31) */
}

/* ── DERIVE ───────────────────────────────────────────────── */

static void st_history_bw(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    history_update(s);
    conn_rebuild_idx(s);
    bw_update(s);
}

#ifdef WITH_PCAP
static void st_channel_rf(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* Moved behind beacon_snapshot() (#113): channel_summary_update()
     * aggregates s->beacon_aps and used to run before the table was
     * refreshed, so the channel rows lagged the beacon view by a tick. */
    channel_summary_update(s);
    ctrl_snapshot(s);   /* annotates the channel rows built above (#64) */
    rf_quality_snapshot(s, ctx->wall);
}
#endif

static void st_scan(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    scan_update(s);
}

static void st_beacon_detect(sloth_state_t *s, const poll_ctx_t *ctx) {
    bd_update(s, ctx->wall);
}

#ifdef WITH_PCAP
static void st_transit(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* Recurring transit (#54): feed every client currently classified
     * as passing into the episode tracker, keyed by a canonical identity
     * so a randomising device's rotated MACs count as one.
     *
     * DERIVE, not after the alerts (#113): rule_recurring_transit reads
     * s->transits, which only this stage fills, so running it after
     * alerts_update() left the rule a full tick behind every pass. */
    for (int i = 0; i < s->probe_count; i++) {
        const probe_client_t *c = &s->probe_clients[i];
        if (presence_classify(&c->rssi_ring, c->first_seen,
                              c->last_seen, ctx->wall) != PRESENCE_TRANSIENT)
            continue;
        uint8_t id[6];
        transit_canonical_mac(s, c->mac, id);
        transit_observe(id, c->last_seen, c->signal_dbm);
    }
    transit_snapshot(s, ctx->wall);
}
#endif

static void st_sensors(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* #28: register the monitor radio as the Wi-Fi sensor and record its
     * cumulative observation count. Future RF families register the same
     * way. Ahead of EMIT (#113): the sensor and wifi_merged records used
     * to be written before this ran, so a new sensor's first tick was
     * never in the stream. */
    if (!s->probe_iface[0]) return;
    sensor_t *sn = sensor_register(s, SENSOR_WIFI, "Wi-Fi monitor",
                                   s->probe_iface, ctx->wall);
    sensor_observe(sn, mon_frame_total(), ctx->wall);
    /* #21: fold this radio's beacon observations into the merged
     * multi-radio world model. With one adapter this is an identity map;
     * a second monitor radio would merge under its own sensor id. Rebuilt
     * each poll so aged-out APs drop from the merged view too. */
    if (sn) {
        wifi_merge_reset(&s->wifi_merged);
        wifi_merge_from_beacons(s, (int)(sn - s->sensors));
    }
}

static void st_twins(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* After beacon_snapshot() (#113): twins walk s->beacon_aps, and used
     * to walk the previous tick's copy. */
    twins_snapshot(s);
}

/* ── ALERTS ───────────────────────────────────────────────── */

static void st_alerts(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    alerts_update(s);
}

/* ── POST ─────────────────────────────────────────────────── */

static void st_research_coverage(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* After alerts_update so coverage sees this poll's alerts. */
    research_coverage_snapshot(s, ctx->research);
}

static void st_karma(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    karma_update(s);   /* KARMA/PineAP candidate table for VIEW_KARMA (#30) */
}

static void st_alert_hot(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* Feed the tui's alert-hot list: every alert with a concrete match_ip
     * gets the severity-coloured override for ALERT_HOT_TTL_S (1h).
     * Promotion-only — a later LOW won't downgrade an earlier CRIT on the
     * same IP within the TTL window. */
    if (!ctx->alert_hot) return;
    for (int i = 0; i < s->alert_count; i++) {
        const alert_t *a = &s->alerts[i];
        if (!a->match_ip[0]) continue;
        ctx->alert_hot(a->match_ip, (long)a->last_seen, (int)a->sev);
    }
}

static void st_devices_hosts(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    devices_update(s);
    top_hosts_update(s);
}

static void st_chanhop(sloth_state_t *s, const poll_ctx_t *ctx) {
    if (ctx->chanhop) ctx->chanhop(s);
}

/* ── EMIT ─────────────────────────────────────────────────── */

static void st_jsonl(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* Last before durable state (#113): every state record now describes
     * this tick. It used to run ahead of the snapshot block, so beacons,
     * deauths, probe clients, PNL, devices, top hosts, sensors and the
     * merged Wi-Fi model all reached the stream one tick late. */
    jsonl_emit_connections(s);
    jsonl_emit_twin_episodes(s);
    jsonl_emit_state_snapshots(s);
}

/* ── DURABLE ──────────────────────────────────────────────── */

static void st_db(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* Durable state (#42). Reads sloth_state_t directly rather than
     * hanging off the jsonl emitters: every jsonl_emit_* short-circuits
     * when no sink is open, so a --db-only run would otherwise write an
     * empty database, and durable last_seen would ride the change-only
     * cache and lag by up to the 300 s heartbeat. Its own cadence
     * (--db-interval-secs), so slow storage never paces the poll loop. */
    if (db_due(ctx->wall)) db_tick(s, ctx->wall);
}

const poll_stage_t g_poll_stages[] = {
    { "platform_net",      PH_PLATFORM, st_platform_net      },
    { "health",            PH_PLATFORM, st_health            },
    { "stats_baseline",    PH_PLATFORM, st_stats_baseline    },

    { "capture_ring",      PH_SNAPSHOT, st_capture_ring      },
#ifdef WITH_PCAP
    { "wifi_snapshots",    PH_SNAPSHOT, st_wifi_snapshots    },
    { "wired_snapshots",   PH_SNAPSHOT, st_wired_snapshots   },
#endif
    { "eap_track",         PH_SNAPSHOT, st_eap_track         },

    { "history_bw",        PH_DERIVE,   st_history_bw        },
#ifdef WITH_PCAP
    { "channel_rf",        PH_DERIVE,   st_channel_rf        },
#endif
    { "scan",              PH_DERIVE,   st_scan              },
    { "beacon_detect",     PH_DERIVE,   st_beacon_detect     },
#ifdef WITH_PCAP
    { "transit",           PH_DERIVE,   st_transit           },
#endif
    { "sensors",           PH_DERIVE,   st_sensors           },
    { "twins",             PH_DERIVE,   st_twins             },

    { "alerts",            PH_ALERTS,   st_alerts            },

    { "research_coverage", PH_POST,     st_research_coverage },
    { "karma",             PH_POST,     st_karma             },
    { "alert_hot",         PH_POST,     st_alert_hot         },
    { "devices_hosts",     PH_POST,     st_devices_hosts     },
    { "chanhop",           PH_POST,     st_chanhop           },

    { "jsonl",             PH_EMIT,     st_jsonl             },

    { "db",                PH_DURABLE,  st_db                },
};
const int g_poll_stage_count =
    (int)(sizeof(g_poll_stages) / sizeof(g_poll_stages[0]));

void poll_ctx_init(poll_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->wall    = sloth_wall();
    ctx->mono_ms = sloth_mono_ms();
}

void poll_tick(sloth_state_t *s, const poll_ctx_t *ctx) {
    if (!s || !ctx) return;
    for (int i = 0; i < g_poll_stage_count; i++)
        g_poll_stages[i].fn(s, ctx);
}

int poll_stage_index(const char *name) {
    if (!name) return -1;
    for (int i = 0; i < g_poll_stage_count; i++)
        if (strcmp(g_poll_stages[i].name, name) == 0) return i;
    return -1;
}
