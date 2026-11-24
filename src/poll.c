#include "poll.h"
#include "capture/capture.h"
#include "mon_radios.h"
#include "capture/probe.h"
#include "capture/bt_monitor.h"
#include "bt_stream.h"
#include "ble_hci.h"
#include "persist_health.h"
#include "jsonl.h"
#include "history.h"
#include "dev_how.h"
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
#include "harvest_track.h"
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
#include "lan_role.h"
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
#include "rtsp_snoop.h"
#include "beacon_snoop.h"
#include "deauth_snoop.h"
#include "http_log.h"
#include "tls_log.h"
#include "quic_log.h"
#include "dns_log.h"
#include "ntp_log.h"
#include "icmp_log.h"
#include "cleartext_creds.h"
#include "devices.h"
#include "top_hosts.h"
#include "scan.h"
#include "beacon_detect.h"
#include "transit.h"
#include "presence.h"
#include "rf_distance.h"
#include "ownership.h"
#include "cov_interval_capture.h"

/* The Wi-Fi, wired and BLE stage bodies, and the table that uses
 * them: g_poll_wifi, what sloth-wifi runs. The runner and
 * the stages both daemons share are src/poll_core.c; the GNSS stages are
 * src/poll_gnss.c and the RF ones src/poll_rf.c (#212).
 *
 * Each body is the code poll_data() ran at that point, moved verbatim
 * except where the move is the fix — those say so. Phase membership and
 * order live in the tables below, not here. */

/* ── PLATFORM ─────────────────────────────────────────────── */

static void st_platform_net(sloth_state_t *s, const poll_ctx_t *ctx) {
    s->iface_count = g_platform.get_ifaces(s->ifaces, MAX_IFACES);
    /* #183: every address this host answers on, into the self roster,
     * from the records that already carry them. Here rather than at
     * startup alone because an interface can appear, be renamed or be
     * replugged mid-run; and here rather than later in the tick because
     * the PLATFORM phase runs ahead of the alert rules, so no rule ever
     * sees a frame from the host's own card before the roster has the
     * address. No syscall is added - this reads what get_ifaces()
     * returned (MISSION §2). */
    ownership_self_sync_ifaces(s->ifaces, s->iface_count);
    /* The addresses those rows do not carry: a card's permanent address
     * while it uses a randomised one, each phy's address pool (the one
     * a monitor vif created later will take), and wireless devices with
     * no netdev, such as a P2P device probing from a locally
     * administered address. Throttled, see ownership_self_scan_due(). */
    if (g_platform.get_self_macs &&
        ownership_self_scan_due(s->ifaces, s->iface_count, ctx->mono_ms)) {
        uint8_t own[MAX_SELF_MACS][6];
        int n = g_platform.get_self_macs(own, MAX_SELF_MACS);
        ownership_self_add_list((const uint8_t (*)[6])own, n);
    }
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

/* st_health() was one stage that polled every source in turn. It is
 * five since #212, so a daemon's table can carry the halves it has: the
 * capture workers here, the receiver in poll_gnss.c, the decoders in
 * poll_rf.c, the host's own state in poll_core.c, and the scope check
 * below. The union table lists them in the order the one function made
 * its calls, so `sloth` runs the same sequence it always did. */
static void st_health_capture(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* #91 slice 2: both capture workers' liveness and pcap_stats(). Both
     * calls self-stub without WITH_PCAP, where "off" is the honest health
     * state rather than a missing one. */
    capture_health_poll(&s->cap_health);
    probe_health_poll(&s->mon_health);
    /* Several sensor radios (src/mon_radios.h): radio 0's place in that
     * table follows its worker; the others report their own. */
    if (mon_radios_active())
        mon_radios_set_state(0, s->mon_health.running ? MON_RADIO_RUNNING
                                : s->mon_health.open  ? MON_RADIO_LOST
                                                      : MON_RADIO_STOPPED,
                             s->mon_health.exit_detail);
    bt_monitor_health_poll(&s->bt_health);   /* #144 slice 2 */
    /* #96: per-sink write-failure counts, for the cannot-persist badge.
     * Here since #213 and not in health_host: two of the three sinks it
     * reads are the pcap and handshake exporters, which only a daemon
     * with a capture links. The counts move in ALERTS and EMIT, so
     * where in PLATFORM they are read changes nothing. */
    persist_health_poll(&s->persist_health);
}

static void st_capture_scope(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* #85: re-check each pinned ifindex still names its interface; a
     * replugged, renamed or reused one fails closed and reads DEGRADED.
     * Its own stage only because it ran after the host polls in
     * st_health() and still does. */
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
    harvest_snapshot(s);  /* PMKID / handshake harvesting (#172) */
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
    /* After the beacon table: KARMA_PROBE_FORGE judges these answers
     * against it (#187 S2). */
    karma_forge_snapshot(s);
    /* The operator's own AP sets the distance calibration (--tune
     * rf.ref_dist_dm with --my-bssid); the capture threads read it
     * from the next frame on. */
    rf_calibration_update(s);
    deauth_snapshot(s);
}

static void st_wired_snapshots(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    mdns_snapshot(s);
    nbns_snapshot(s);
    dhcp_snoop_snapshot(s);
    lan_role_snapshot(s);   /* camera router-role vetoes (#155) */
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
    rtsp_snoop_snapshot(s);
    http_log_snapshot(s);
    tls_log_snapshot(s);
    quic_log_snapshot(s);
    dns_log_snapshot(s);
    ntp_log_snapshot(s);
    icmp_log_snapshot(s);
    cleartext_creds_snapshot(s);
}
#endif

static void st_ble(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* #144 slice 2. Pure module, every config: a WITH_PCAP=0 build has
     * no source to feed it and copies an empty table. */
    ble_snapshot(s);
    /* #144 slice 3: the Ubertooth stream's health and LAP table. Its
     * advertisers are already in the device table copied above. */
    bt_stream_snapshot(s);
}

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
    channel_hz_update(s, ctx->wall);   /* G3's minutes, from those totals (#195) */
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

/* st_sensors() was one stage registering every source. It is three
 * since #212: the radios here, the receiver in poll_gnss.c, the decoders
 * in poll_rf.c. A sensor's id is its registry slot (sensor_register()
 * appends) and wifi_merged publishes it, so the order the three run in
 * is part of the stream: radios, then GNSS, then RF, as the one function
 * had it. tests/test_poll.c pins the slots. */
static void st_sensors_wifi(sloth_state_t *s, const poll_ctx_t *ctx) {
    /* #28: register the monitor radio as the Wi-Fi sensor and record its
     * cumulative observation count. Future RF families register the same
     * way. Ahead of EMIT (#113): the sensor and wifi_merged records used
     * to be written before this ran, so a new sensor's first tick was
     * never in the stream. */
    if (s->probe_iface[0]) {
        sensor_t *sn = sensor_register(s, SENSOR_WIFI, "Wi-Fi monitor",
                                       s->probe_iface, ctx->wall);
        /* With further sensor radios (below) the total is all of
         * theirs, and this sensor's count is radio 0's own. */
        mon_radio_t r0;
        sensor_observe(sn, mon_radios_active() && mon_radios_get(0, &r0)
                               ? r0.frames : mon_frame_total(), ctx->wall);
        /* #21: fold this radio's beacon observations into the merged
         * multi-radio world model. With one adapter this is an identity
         * map; a second monitor radio would merge under its own sensor
         * id. Rebuilt each poll so aged-out APs drop from the merged view
         * too. */
        if (sn) {
            wifi_merge_reset(&s->wifi_merged);
            wifi_merge_from_beacons(s, (int)(sn - s->sensors));
        }
    }
    /* The further sensor radios (src/mon_radios.h), one sensor each,
     * observing the frames that radio delivered. After the first radio
     * so it keeps id 0; a run without them registers nothing here and
     * every later id is where it was. Their beacons are in the one AP
     * table with radio 0's (it does not record which radio heard a
     * beacon), so wifi_merged still attributes them to sensor 0. One
     * that was never opened is not a sensor. */
    for (int k = 1; s->probe_iface[0] && k < mon_radios_count(); k++) {
        mon_radio_t r;
        if (!mon_radios_get(k, &r) || r.state == MON_RADIO_NAMED) continue;
        sensor_t *xn = sensor_register(s, SENSOR_WIFI, "Wi-Fi monitor",
                                       r.iface, ctx->wall);
        if (xn) sensor_observe(xn, r.frames, ctx->wall);
    }
    /* #144 slice 2: the Bluetooth host source registers as the BLE
     * sensor, observing decoded advertising reports. After the Wi-Fi
     * radio, not before: a sensor's id is its registry slot and
     * wifi_merged publishes it (sensor_mask, best_sensor), so the radio
     * keeps id 0 whether or not a Bluetooth source is configured. */
    if (s->bt_iface[0]) {
        sensor_t *bt = sensor_register(s, SENSOR_BLE, "BLE HCI monitor",
                                       s->bt_iface, ctx->wall);
        /* Both report events: a stack scanning with the extended
         * commands delivers everything, legacy PDUs included, as 0x0D. */
        sensor_observe(bt, s->ble_host.adv_reports + s->ble_host.ext_adv_reports,
                       ctx->wall);
    }
    /* #144 slice 3: the Ubertooth stream is a second BLE sensor, on its
     * own iface, so the registry keeps the two apart. */
    if (s->btcap.configured) {
        sensor_t *ub = sensor_register(s, SENSOR_BLE, "Ubertooth capture",
                                       BT_CAPTURE_IFACE, ctx->wall);
        sensor_observe(ub, s->btcap.adv + s->btcap.bredr, ctx->wall);
    }
}

static void st_twins(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* After beacon_snapshot() (#113): twins walk s->beacon_aps, and used
     * to walk the previous tick's copy. */
    twins_snapshot(s);
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
    devices_update(s);
    dev_how_observe(s, ctx->wall);   /* G4's TUI grid (#195) */
    top_hosts_update(s);
}

static void st_chanhop(sloth_state_t *s, const poll_ctx_t *ctx) {
    if (ctx->chanhop) ctx->chanhop(s);
}

/* The per-interval coverage record (#242 item 2): after the hop stage,
 * so a retune this tick has closed its dwell, and before the emit and
 * the database stages that write a closed interval. */
static void st_coverage_iv(sloth_state_t *s, const poll_ctx_t *ctx) {
    cov_iv_capture_poll(s, ctx->wall, ctx->mono_ms);
}

/* ── EMIT ─────────────────────────────────────────────────── */

/* sloth-wifi's EMIT stage, here since #213: it writes the capture's records
 * (src/jsonl.c), so it cannot live with the stages every table shares.
 * sloth-rf's is poll_st_jsonl_rf() in src/poll_rf.c. */
void poll_st_jsonl(sloth_state_t *s, const poll_ctx_t *ctx) {
    (void)ctx;
    /* Last before durable state (#113): every state record now describes
     * this tick. It used to run ahead of the snapshot block, so beacons,
     * deauths, probe clients, PNL, devices, top hosts, sensors and the
     * merged Wi-Fi model all reached the stream one tick late. */
    jsonl_emit_connections(s);
    jsonl_emit_twin_episodes(s);
    jsonl_emit_state_snapshots(s);
}

/* ── the tables ───────────────────────────────────────────── */

/* What sloth-wifi runs (src/main.c passes it), in the order poll_data()
 * always ran its stages. Until the cutover (#216) there was a union
 * table beside it, g_poll_sloth, with health_rf after health_gnss and
 * sensors_rf after sensors_gnss; those two stages are sloth-rf's alone
 * now (g_poll_rf, src/poll_rf.c). The GNSS stages stay: both daemons
 * link the receiver (ADR 0010). */
static const poll_stage_t wifi_stages[] = {
    { "platform_net",      PH_PLATFORM, st_platform_net      },
    { "health_capture",    PH_PLATFORM, st_health_capture    },
    { "health_gnss",       PH_PLATFORM, poll_st_health_gnss  },
    { "health_host",       PH_PLATFORM, poll_st_health_host  },
    { "capture_scope",     PH_PLATFORM, st_capture_scope     },
    { "stats_baseline",    PH_PLATFORM, st_stats_baseline    },

    { "capture_ring",      PH_SNAPSHOT, st_capture_ring      },
#ifdef WITH_PCAP
    { "wifi_snapshots",    PH_SNAPSHOT, st_wifi_snapshots    },
    { "wired_snapshots",   PH_SNAPSHOT, st_wired_snapshots   },
#endif
    { "eap_track",         PH_SNAPSHOT, st_eap_track         },
    { "ble",               PH_SNAPSHOT, st_ble               },

    { "history_bw",        PH_DERIVE,   st_history_bw        },
#ifdef WITH_PCAP
    { "channel_rf",        PH_DERIVE,   st_channel_rf        },
#endif
    { "scan",              PH_DERIVE,   st_scan              },
    { "beacon_detect",     PH_DERIVE,   st_beacon_detect     },
#ifdef WITH_PCAP
    { "transit",           PH_DERIVE,   st_transit           },
#endif
    { "sensors_wifi",      PH_DERIVE,   st_sensors_wifi      },
    { "sensors_gnss",      PH_DERIVE,   poll_st_sensors_gnss },
    { "twins",             PH_DERIVE,   st_twins             },

    { "alerts",            PH_ALERTS,   poll_st_alerts       },

    { "research_coverage", PH_POST,     st_research_coverage },
    { "karma",             PH_POST,     st_karma             },
    { "alert_hot",         PH_POST,     st_alert_hot         },
    { "devices_hosts",     PH_POST,     st_devices_hosts     },
    { "positions",         PH_POST,     poll_st_positions    },
    { "chanhop",           PH_POST,     st_chanhop           },
    { "coverage_iv",       PH_POST,     st_coverage_iv       },

    { "jsonl",             PH_EMIT,     poll_st_jsonl        },

    { "db",                PH_DURABLE,  poll_st_db           },
};
const poll_table_t g_poll_wifi = {
    wifi_stages, (int)(sizeof(wifi_stages) / sizeof(wifi_stages[0]))
};
