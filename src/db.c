/* Embedded SQLite sink. Contract in db.h, schema in db_schema.c (#42). */

#include "db.h"

#ifdef WITH_SQLITE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "ownership.h"
#include "presence.h"

#define DB_DEFAULT_INTERVAL_S 1
/* Maintenance is hourly: pruning is a scan over every table, and the
 * thing it defends against (a disk filling over days) does not move
 * fast enough to need checking at poll rate. */
#define DB_MAINT_INTERVAL_S  3600
#define DB_SECS_PER_DAY      86400

static sqlite3 *g_db;
static int      g_disabled;      /* set once on error — fail-open */
static int      g_interval  = DB_DEFAULT_INTERVAL_S;
static int      g_retain_days = DB_DEFAULT_RETAIN_DAYS;
static int      g_max_mb      = DB_DEFAULT_MAX_MB;
static time_t   g_last_tick;
static time_t   g_last_maint;
static int      g_over_ceiling_reported;

/* ── retention tiers ─────────────────────────────────────
 *
 * Ordered by how long the row stays useful to an investigator, not by
 * how it was produced. Observation rows answer "what was happening",
 * entities answer "who was here", findings answer "what did we
 * conclude" — and that is the order they stop mattering in. */

/* 1x the configured window. Also the only tier the size ceiling may
 * touch: these are the rows a full disk should cost you. */
static const char *const TIER_OBSERVATION[] = {
    "bgp_sessions", "ssh_flows", "rdp_flows", "snmp_flows", "mqtt_flows",
    "ldap_events", "kerb_events", "smb_sessions",
    "deauth_events", "seqnum_correlations", "twin_episodes",
    "eapol_events", "scan_entries", "scan_entry_ports",
};

/* 3x — the inventory. "Which devices were on this network in March"
 * outlives the individual observations that established it. */
static const char *const TIER_ENTITY[] = {
    "devices", "pnl_clients", "pnl_ssids", "probe_clients",
    "beacon_aps", "beacon_ap_ssids", "wifi_aps", "wifi_stas",
    "assocs", "wifi_merged", "arp", "dhcp_leases", "top_hosts",
    "mdns_services", "nbns_names", "ssdp_devices",
    "ndp_ras", "ndp_ra_prefixes", "sensors",
};

/* 12x — the findings. These are why the operator kept the file. */
static const char *const TIER_FINDING[] = {
    "alerts", "cleartext_creds",
    /* Detector evidence sits here, not in the entity tier, so it lives
     * exactly as long as the alert it justifies. At 3x the evidence
     * would expire while the CRIT it supports was still retained,
     * recreating the #30/#31 hole through retention instead of through
     * a missing emitter. 96 rows maximum, so the cost is nil. */
    "karma_candidates", "rogue_radius",
};

#define NELEMS(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* Report the first error and stop writing. A database problem must
 * never take a capture down with it: the operator loses persistence,
 * not visibility. Subsequent failures are silent — one line in the
 * journal, not one per poll. */
static void db_fail(const char *what) {
    if (!g_disabled) {
        fprintf(stderr, "sloth: db %s failed: %s — persistence disabled\n",
                what, g_db ? sqlite3_errmsg(g_db) : "?");
        g_disabled = 1;
    }
}

/* ── prepared statements ─────────────────────────────────── */

enum {
    ST_DEVICE, ST_PNL_CLIENT, ST_PNL_SSID, ST_PROBE_CLIENT,
    ST_BEACON_AP, ST_BEACON_SSID, ST_WIFI_AP, ST_WIFI_STA, ST_ASSOC,
    ST_WIFI_MERGED, ST_ARP, ST_DHCP_LEASE, ST_TOP_HOST,
    ST_MDNS, ST_NBNS, ST_SSDP, ST_NDP_RA, ST_NDP_PREFIX, ST_SENSOR,
    ST_BGP, ST_SSH, ST_RDP, ST_SNMP, ST_MQTT, ST_LDAP, ST_KERB, ST_SMB,
    ST_ALERT, ST_CRED, ST_EAPOL, ST_DEAUTH, ST_SEQCORR, ST_TWIN,
    ST_SCAN, ST_SCAN_PORT, ST_KARMA, ST_ROGUE_RADIUS,
    ST_COUNT
};

static sqlite3_stmt *g_st[ST_COUNT];

/* Upsert shape shared by every entity table.
 *
 * first_seen uses excluded-vs-existing MIN so a re-observation never
 * moves the start of the entity's history, and last_seen uses MAX so
 * an out-of-order tick cannot rewind it. Both matter because the whole
 * point of the sink is that the time range is trustworthy. */
static const char *const SQL[ST_COUNT] = {
[ST_DEVICE] =
    "INSERT INTO devices (mac,ip,hostname,vendor,last_ssid,is_ap,signal_dbm,"
    "probe_count,sources,risk_signals,risk_level,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)"
    " ON CONFLICT(mac) DO UPDATE SET"
    "  ip=excluded.ip, hostname=excluded.hostname, vendor=excluded.vendor,"
    "  last_ssid=excluded.last_ssid, is_ap=excluded.is_ap,"
    "  signal_dbm=excluded.signal_dbm, probe_count=excluded.probe_count,"
    "  sources=excluded.sources, risk_signals=excluded.risk_signals,"
    "  risk_level=excluded.risk_level,"
    "  first_seen=MIN(devices.first_seen,excluded.first_seen),"
    "  last_seen=MAX(devices.last_seen,excluded.last_seen)",
[ST_PNL_CLIENT] =
    "INSERT INTO pnl_clients (mac,mac_random,probe_count,os_fp,phy,"
    "first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7)"
    " ON CONFLICT(mac) DO UPDATE SET"
    "  mac_random=excluded.mac_random, probe_count=excluded.probe_count,"
    "  os_fp=excluded.os_fp, phy=excluded.phy,"
    "  first_seen=MIN(pnl_clients.first_seen,excluded.first_seen),"
    "  last_seen=MAX(pnl_clients.last_seen,excluded.last_seen)",
[ST_PNL_SSID] =
    "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4)"
    " ON CONFLICT(mac,ssid) DO UPDATE SET"
    "  first_seen=MIN(pnl_ssids.first_seen,excluded.first_seen),"
    "  last_seen=MAX(pnl_ssids.last_seen,excluded.last_seen)",
[ST_PROBE_CLIENT] =
    "INSERT INTO probe_clients (mac,ssid,signal_dbm,channel,frame_count,"
    "presence,first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"
    " ON CONFLICT(mac) DO UPDATE SET"
    "  ssid=excluded.ssid, signal_dbm=excluded.signal_dbm,"
    "  channel=excluded.channel, frame_count=excluded.frame_count,"
    /* Strongest verdict wins and is never walked back. The live ring
     * only holds 60 s, so a device that drove past would otherwise
     * revert to "unknown" the moment its trajectory aged out — losing
     * the one observation the operator was looking for (#53). */
    "  presence=MAX(probe_clients.presence,excluded.presence),"
    "  first_seen=MIN(probe_clients.first_seen,excluded.first_seen),"
    "  last_seen=MAX(probe_clients.last_seen,excluded.last_seen)",
[ST_BEACON_AP] =
    "INSERT INTO beacon_aps (bssid,ssid,signal_dbm,channel,enc,beacon_ms,"
    "pairwise,group_ciph,akm,mfp,vendor,has_wps,wps_state,wps_locked,phy,"
    "revealed,frame_count,has_qbss,qbss_stations,qbss_chan_util,"
    "first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,"
    "?18,?19,?20,?21,?22)"
    " ON CONFLICT(bssid) DO UPDATE SET"
    "  ssid=excluded.ssid, signal_dbm=excluded.signal_dbm,"
    "  channel=excluded.channel, enc=excluded.enc,"
    "  beacon_ms=excluded.beacon_ms, pairwise=excluded.pairwise,"
    "  group_ciph=excluded.group_ciph, akm=excluded.akm, mfp=excluded.mfp,"
    "  vendor=excluded.vendor, has_wps=excluded.has_wps,"
    "  wps_state=excluded.wps_state, wps_locked=excluded.wps_locked,"
    "  phy=excluded.phy, revealed=excluded.revealed,"
    "  frame_count=excluded.frame_count, has_qbss=excluded.has_qbss,"
    "  qbss_stations=excluded.qbss_stations,"
    "  qbss_chan_util=excluded.qbss_chan_util,"
    "  first_seen=MIN(beacon_aps.first_seen,excluded.first_seen),"
    "  last_seen=MAX(beacon_aps.last_seen,excluded.last_seen)",
[ST_BEACON_SSID] =
    "INSERT INTO beacon_ap_ssids (bssid,ssid,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4)"
    " ON CONFLICT(bssid,ssid) DO UPDATE SET"
    "  first_seen=MIN(beacon_ap_ssids.first_seen,excluded.first_seen),"
    "  last_seen=MAX(beacon_ap_ssids.last_seen,excluded.last_seen)",
[ST_WIFI_AP] =
    "INSERT INTO wifi_aps (bssid,ssid,signal_dbm,channel,enc,status,"
    "first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"
    " ON CONFLICT(bssid) DO UPDATE SET"
    "  ssid=excluded.ssid, signal_dbm=excluded.signal_dbm,"
    "  channel=excluded.channel, enc=excluded.enc, status=excluded.status,"
    "  first_seen=MIN(wifi_aps.first_seen,excluded.first_seen),"
    "  last_seen=MAX(wifi_aps.last_seen,excluded.last_seen)",
[ST_WIFI_STA] =
    "INSERT INTO wifi_stas (mac,signal_dbm,tx_rate_kbps,rx_rate_kbps,"
    "connected_secs,inactive_ms,tx_bytes,rx_bytes,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"
    " ON CONFLICT(mac) DO UPDATE SET"
    "  signal_dbm=excluded.signal_dbm, tx_rate_kbps=excluded.tx_rate_kbps,"
    "  rx_rate_kbps=excluded.rx_rate_kbps,"
    "  connected_secs=excluded.connected_secs,"
    "  inactive_ms=excluded.inactive_ms, tx_bytes=excluded.tx_bytes,"
    "  rx_bytes=excluded.rx_bytes,"
    "  first_seen=MIN(wifi_stas.first_seen,excluded.first_seen),"
    "  last_seen=MAX(wifi_stas.last_seen,excluded.last_seen)",
[ST_ASSOC] =
    "INSERT INTO assocs (bssid,sta_mac,ssid,sta_random,source,channel,"
    "signal_dbm,frame_count,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"
    " ON CONFLICT(bssid,sta_mac) DO UPDATE SET"
    "  ssid=excluded.ssid, sta_random=excluded.sta_random,"
    /* Evidence grade only ever strengthens: a later weaker observation
     * must not downgrade a confirmed EAPOL association.
     *
     * ASSOC_SRC_* is ordered strongest-FIRST (EAPOL=1, ASSOC=2,
     * REASSOC=3), so "stronger" is the *smaller* value — but 0 is
     * UNKNOWN, i.e. no evidence at all, and must never win. Hence the
     * non-zero guards rather than a bare MIN(). */
    "  source=CASE"
    "    WHEN excluded.source=0 THEN assocs.source"
    "    WHEN assocs.source=0   THEN excluded.source"
    "    ELSE MIN(assocs.source,excluded.source) END,"
    "  channel=excluded.channel, signal_dbm=excluded.signal_dbm,"
    "  frame_count=excluded.frame_count,"
    "  first_seen=MIN(assocs.first_seen,excluded.first_seen),"
    "  last_seen=MAX(assocs.last_seen,excluded.last_seen)",
[ST_WIFI_MERGED] =
    "INSERT INTO wifi_merged (entity,sensor_mask,seen_by,best_rssi,"
    "best_sensor,channel,freq_mhz,observations,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"
    " ON CONFLICT(entity) DO UPDATE SET"
    /* Coverage only accumulates — a radio that heard this entity once
     * still heard it, even if it is tuned elsewhere now. */
    "  sensor_mask=(wifi_merged.sensor_mask | excluded.sensor_mask),"
    "  seen_by=MAX(wifi_merged.seen_by,excluded.seen_by),"
    "  best_rssi=MAX(wifi_merged.best_rssi,excluded.best_rssi),"
    "  best_sensor=excluded.best_sensor, channel=excluded.channel,"
    "  freq_mhz=excluded.freq_mhz, observations=excluded.observations,"
    "  first_seen=MIN(wifi_merged.first_seen,excluded.first_seen),"
    "  last_seen=MAX(wifi_merged.last_seen,excluded.last_seen)",
[ST_ARP] =
    "INSERT INTO arp (ip,mac,iface,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5)"
    " ON CONFLICT(ip,mac) DO UPDATE SET iface=excluded.iface,"
    "  first_seen=MIN(arp.first_seen,excluded.first_seen),"
    "  last_seen=MAX(arp.last_seen,excluded.last_seen)",
[ST_DHCP_LEASE] =
    "INSERT INTO dhcp_leases (ip,hostname,expire,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5)"
    " ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname,"
    "  expire=excluded.expire,"
    "  first_seen=MIN(dhcp_leases.first_seen,excluded.first_seen),"
    "  last_seen=MAX(dhcp_leases.last_seen,excluded.last_seen)",
[ST_TOP_HOST] =
    "INSERT INTO top_hosts (ip,hostname,owner,conn_count,rx_bytes,tx_bytes,"
    "first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"
    " ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname,"
    "  owner=excluded.owner, conn_count=excluded.conn_count,"
    /* Byte counters are cumulative-since-first_seen in state and reset
     * when a host ages out of the ring, so keep the high-water mark
     * rather than letting a fresh entry zero the history. */
    "  rx_bytes=MAX(top_hosts.rx_bytes,excluded.rx_bytes),"
    "  tx_bytes=MAX(top_hosts.tx_bytes,excluded.tx_bytes),"
    "  first_seen=MIN(top_hosts.first_seen,excluded.first_seen),"
    "  last_seen=MAX(top_hosts.last_seen,excluded.last_seen)",
[ST_MDNS] =
    "INSERT INTO mdns_services (instance,service,host,ip,port,first_seen,"
    "last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7)"
    " ON CONFLICT(instance) DO UPDATE SET service=excluded.service,"
    "  host=excluded.host, ip=excluded.ip, port=excluded.port,"
    "  first_seen=MIN(mdns_services.first_seen,excluded.first_seen),"
    "  last_seen=MAX(mdns_services.last_seen,excluded.last_seen)",
[ST_NBNS] =
    "INSERT INTO nbns_names (name,suffix,ip,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5)"
    " ON CONFLICT(name,suffix) DO UPDATE SET ip=excluded.ip,"
    "  first_seen=MIN(nbns_names.first_seen,excluded.first_seen),"
    "  last_seen=MAX(nbns_names.last_seen,excluded.last_seen)",
[ST_SSDP] =
    "INSERT INTO ssdp_devices (usn,ip,type,location,nts,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7)"
    " ON CONFLICT(usn) DO UPDATE SET ip=excluded.ip, type=excluded.type,"
    "  location=excluded.location, nts=excluded.nts,"
    "  first_seen=MIN(ssdp_devices.first_seen,excluded.first_seen),"
    "  last_seen=MAX(ssdp_devices.last_seen,excluded.last_seen)",
[ST_NDP_RA] =
    "INSERT INTO ndp_ras (src_ip,src_mac,cur_hop_limit,flags,"
    "router_lifetime,ra_count,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"
    " ON CONFLICT(src_ip) DO UPDATE SET src_mac=excluded.src_mac,"
    "  cur_hop_limit=excluded.cur_hop_limit, flags=excluded.flags,"
    "  router_lifetime=excluded.router_lifetime,"
    "  ra_count=excluded.ra_count,"
    "  first_seen=MIN(ndp_ras.first_seen,excluded.first_seen),"
    "  last_seen=MAX(ndp_ras.last_seen,excluded.last_seen)",
[ST_NDP_PREFIX] =
    "INSERT INTO ndp_ra_prefixes (src_ip,prefix,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4)"
    " ON CONFLICT(src_ip,prefix) DO UPDATE SET"
    "  first_seen=MIN(ndp_ra_prefixes.first_seen,excluded.first_seen),"
    "  last_seen=MAX(ndp_ra_prefixes.last_seen,excluded.last_seen)",
[ST_SENSOR] =
    "INSERT INTO sensors (kind,iface,name,state,observed,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7)"
    " ON CONFLICT(kind,iface) DO UPDATE SET name=excluded.name,"
    "  state=excluded.state, observed=excluded.observed,"
    "  first_seen=MIN(sensors.first_seen,excluded.first_seen),"
    "  last_seen=MAX(sensors.last_seen,excluded.last_seen)",
[ST_BGP] =
    "INSERT INTO bgp_sessions (peer_a,peer_b,open_count,update_count,"
    "notification_count,keepalive_count,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"
    " ON CONFLICT(peer_a,peer_b) DO UPDATE SET"
    /* Counters keep a high-water mark: the in-memory ring resets a
     * flow's counts when it is evicted, and the durable row means
     * "what has this pair done", not "since the last eviction". Every
     * protocol-flow table below follows the same rule. */
    "  open_count=MAX(bgp_sessions.open_count,excluded.open_count),"
    "  update_count=MAX(bgp_sessions.update_count,excluded.update_count),"
    "  notification_count=MAX(bgp_sessions.notification_count,excluded.notification_count),"
    "  keepalive_count=MAX(bgp_sessions.keepalive_count,excluded.keepalive_count),"
    "  first_seen=MIN(bgp_sessions.first_seen,excluded.first_seen),"
    "  last_seen=MAX(bgp_sessions.last_seen,excluded.last_seen)",
[ST_SSH] =
    "INSERT INTO ssh_flows (src_ip,dst_ip,banner_count,server_banner,"
    "first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6)"
    " ON CONFLICT(src_ip,dst_ip) DO UPDATE SET"
    "  banner_count=MAX(ssh_flows.banner_count,excluded.banner_count),"
    "  server_banner=excluded.server_banner,"
    "  first_seen=MIN(ssh_flows.first_seen,excluded.first_seen),"
    "  last_seen=MAX(ssh_flows.last_seen,excluded.last_seen)",
[ST_RDP] =
    "INSERT INTO rdp_flows (src_ip,dst_ip,connect_req_count,last_cookie,"
    "proto_mask,first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7)"
    " ON CONFLICT(src_ip,dst_ip) DO UPDATE SET"
    "  connect_req_count=MAX(rdp_flows.connect_req_count,excluded.connect_req_count),"
    "  last_cookie=excluded.last_cookie,"
    /* Requested-protocol bits accumulate — a client that once asked for
     * legacy RDP did ask for it, whatever it negotiates later. */
    "  proto_mask=(rdp_flows.proto_mask | excluded.proto_mask),"
    "  first_seen=MIN(rdp_flows.first_seen,excluded.first_seen),"
    "  last_seen=MAX(rdp_flows.last_seen,excluded.last_seen)",
[ST_SNMP] =
    "INSERT INTO snmp_flows (src_ip,dst_ip,get_count,getnext_count,"
    "getbulk_count,set_count,response_count,trap_count,version,"
    "community_count,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"
    " ON CONFLICT(src_ip,dst_ip) DO UPDATE SET"
    "  get_count=MAX(snmp_flows.get_count,excluded.get_count),"
    "  getnext_count=MAX(snmp_flows.getnext_count,excluded.getnext_count),"
    "  getbulk_count=MAX(snmp_flows.getbulk_count,excluded.getbulk_count),"
    "  set_count=MAX(snmp_flows.set_count,excluded.set_count),"
    "  response_count=MAX(snmp_flows.response_count,excluded.response_count),"
    "  trap_count=MAX(snmp_flows.trap_count,excluded.trap_count),"
    "  version=excluded.version,"
    "  community_count=MAX(snmp_flows.community_count,excluded.community_count),"
    "  first_seen=MIN(snmp_flows.first_seen,excluded.first_seen),"
    "  last_seen=MAX(snmp_flows.last_seen,excluded.last_seen)",
[ST_MQTT] =
    "INSERT INTO mqtt_flows (src_ip,dst_ip,connect_count,connack_fail_count,"
    "subscribe_count,publish_count,proto_level,last_username,"
    "first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"
    " ON CONFLICT(src_ip,dst_ip) DO UPDATE SET"
    "  connect_count=MAX(mqtt_flows.connect_count,excluded.connect_count),"
    "  connack_fail_count=MAX(mqtt_flows.connack_fail_count,excluded.connack_fail_count),"
    "  subscribe_count=MAX(mqtt_flows.subscribe_count,excluded.subscribe_count),"
    "  publish_count=MAX(mqtt_flows.publish_count,excluded.publish_count),"
    "  proto_level=excluded.proto_level, last_username=excluded.last_username,"
    "  first_seen=MIN(mqtt_flows.first_seen,excluded.first_seen),"
    "  last_seen=MAX(mqtt_flows.last_seen,excluded.last_seen)",
[ST_LDAP] =
    "INSERT INTO ldap_events (src_ip,bind_count,bind_anon_count,"
    "search_count,search_ref_count,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7)"
    " ON CONFLICT(src_ip) DO UPDATE SET"
    "  bind_count=MAX(ldap_events.bind_count,excluded.bind_count),"
    "  bind_anon_count=MAX(ldap_events.bind_anon_count,excluded.bind_anon_count),"
    "  search_count=MAX(ldap_events.search_count,excluded.search_count),"
    "  search_ref_count=MAX(ldap_events.search_ref_count,excluded.search_ref_count),"
    "  first_seen=MIN(ldap_events.first_seen,excluded.first_seen),"
    "  last_seen=MAX(ldap_events.last_seen,excluded.last_seen)",
[ST_KERB] =
    "INSERT INTO kerb_events (src_ip,as_req_count,as_rep_count,tgs_req_count,"
    "tgs_rep_count,preauth_required_count,preauth_failed_count,"
    "principal_unknown_count,error_other_count,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
    " ON CONFLICT(src_ip) DO UPDATE SET"
    "  as_req_count=MAX(kerb_events.as_req_count,excluded.as_req_count),"
    "  as_rep_count=MAX(kerb_events.as_rep_count,excluded.as_rep_count),"
    "  tgs_req_count=MAX(kerb_events.tgs_req_count,excluded.tgs_req_count),"
    "  tgs_rep_count=MAX(kerb_events.tgs_rep_count,excluded.tgs_rep_count),"
    "  preauth_required_count=MAX(kerb_events.preauth_required_count,excluded.preauth_required_count),"
    "  preauth_failed_count=MAX(kerb_events.preauth_failed_count,excluded.preauth_failed_count),"
    "  principal_unknown_count=MAX(kerb_events.principal_unknown_count,excluded.principal_unknown_count),"
    "  error_other_count=MAX(kerb_events.error_other_count,excluded.error_other_count),"
    "  first_seen=MIN(kerb_events.first_seen,excluded.first_seen),"
    "  last_seen=MAX(kerb_events.last_seen,excluded.last_seen)",
[ST_SMB] =
    "INSERT INTO smb_sessions (client_ip,server_ip,server_port,dialect,"
    "obs_count,first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7)"
    " ON CONFLICT(client_ip,server_ip,server_port) DO UPDATE SET"
    /* Dialect is sticky to SMB1, mirroring the in-memory rule: once a
     * flow has spoken SMB1 that is the finding, and a later SMB2
     * negotiation on the same pair must not erase it. */
    "  dialect=CASE WHEN smb_sessions.dialect='SMB1' OR excluded.dialect='SMB1'"
    "    THEN 'SMB1' ELSE excluded.dialect END,"
    "  obs_count=MAX(smb_sessions.obs_count,excluded.obs_count),"
    "  first_seen=MIN(smb_sessions.first_seen,excluded.first_seen),"
    "  last_seen=MAX(smb_sessions.last_seen,excluded.last_seen)",
[ST_ALERT] =
    "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
    "technique,match_ip,match_port,count) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
    " ON CONFLICT(key,first_seen) DO UPDATE SET"
    /* An episode's detail and severity are regenerated each tick and
     * the latest observation wins, matching the live engine. */
    "  last_seen=MAX(alerts.last_seen,excluded.last_seen),"
    "  sev=excluded.sev, detail=excluded.detail,"
    "  count=MAX(alerts.count,excluded.count)",
[ST_CRED] =
    "INSERT INTO cleartext_creds (ts,src,dst,dst_port,protocol,username,"
    "pw_observed,first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"
    " ON CONFLICT(ts,src,dst,dst_port,protocol) DO UPDATE SET"
    "  username=excluded.username,"
    /* Once a password was observed on an exposure, that stays true. */
    "  pw_observed=MAX(cleartext_creds.pw_observed,excluded.pw_observed),"
    "  last_seen=MAX(cleartext_creds.last_seen,excluded.last_seen)",
[ST_EAPOL] =
    "INSERT INTO eapol_events (bssid,sta_mac,ts,msg_num,ssid,has_pmkid,"
    "handshake_complete,signal_dbm,channel,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
    " ON CONFLICT(bssid,sta_mac,ts,msg_num) DO UPDATE SET"
    "  ssid=excluded.ssid,"
    /* Both flags are monotonic: an M2 that later completes its
     * handshake, or a frame re-parsed with its PMKID recognised, must
     * not be downgraded by a subsequent partial observation. */
    "  has_pmkid=MAX(eapol_events.has_pmkid,excluded.has_pmkid),"
    "  handshake_complete=MAX(eapol_events.handshake_complete,"
    "                         excluded.handshake_complete),"
    "  signal_dbm=excluded.signal_dbm, channel=excluded.channel,"
    "  last_seen=MAX(eapol_events.last_seen,excluded.last_seen)",
[ST_DEAUTH] =
    "INSERT INTO deauth_events (src,dst,bssid,first_seen,last_seen,reason,"
    "subtype,obs_count,flood) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"
    " ON CONFLICT(src,dst,bssid,first_seen) DO UPDATE SET"
    "  last_seen=MAX(deauth_events.last_seen,excluded.last_seen),"
    "  obs_count=MAX(deauth_events.obs_count,excluded.obs_count),"
    /* Once a burst crossed the flood threshold the episode was a
     * flood, even if the rate later drops below it. */
    "  flood=MAX(deauth_events.flood,excluded.flood)",
[ST_SEQCORR] =
    "INSERT INTO seqnum_correlations (mac_a,mac_b,mac_a_random,mac_b_random,"
    "gap,dt_ms,a_count,b_count,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"
    " ON CONFLICT(mac_a,mac_b) DO UPDATE SET"
    "  mac_a_random=excluded.mac_a_random, mac_b_random=excluded.mac_b_random,"
    "  gap=excluded.gap, dt_ms=excluded.dt_ms,"
    "  a_count=MAX(seqnum_correlations.a_count,excluded.a_count),"
    "  b_count=MAX(seqnum_correlations.b_count,excluded.b_count),"
    "  first_seen=MIN(seqnum_correlations.first_seen,excluded.first_seen),"
    "  last_seen=MAX(seqnum_correlations.last_seen,excluded.last_seen)",
[ST_TWIN] =
    "INSERT INTO twin_episodes (ssid,real_bssid,twin_bssid,enc,real_rssi,"
    "twin_rssi,rssi_swing_dbm,attack_in_progress,attacker_oui,hash_mismatch,"
    "first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"
    " ON CONFLICT(ssid,real_bssid,twin_bssid) DO UPDATE SET"
    "  enc=excluded.enc, real_rssi=excluded.real_rssi,"
    "  twin_rssi=excluded.twin_rssi,"
    "  rssi_swing_dbm=MAX(twin_episodes.rssi_swing_dbm,excluded.rssi_swing_dbm),"
    /* Evidence flags latch: a twin that was caught mid-attack once was
     * caught mid-attack, whatever the next poll sees. */
    "  attack_in_progress=MAX(twin_episodes.attack_in_progress,"
    "                         excluded.attack_in_progress),"
    "  attacker_oui=MAX(twin_episodes.attacker_oui,excluded.attacker_oui),"
    "  hash_mismatch=MAX(twin_episodes.hash_mismatch,excluded.hash_mismatch),"
    "  first_seen=MIN(twin_episodes.first_seen,excluded.first_seen),"
    "  last_seen=MAX(twin_episodes.last_seen,excluded.last_seen)",
[ST_SCAN] =
    "INSERT INTO scan_entries (ip,port_count,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4)"
    " ON CONFLICT(ip) DO UPDATE SET"
    "  port_count=MAX(scan_entries.port_count,excluded.port_count),"
    "  first_seen=MIN(scan_entries.first_seen,excluded.first_seen),"
    "  last_seen=MAX(scan_entries.last_seen,excluded.last_seen)",
[ST_SCAN_PORT] =
    "INSERT INTO scan_entry_ports (ip,port,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4)"
    " ON CONFLICT(ip,port) DO UPDATE SET"
    "  first_seen=MIN(scan_entry_ports.first_seen,excluded.first_seen),"
    "  last_seen=MAX(scan_entry_ports.last_seen,excluded.last_seen)",
[ST_KARMA] =
    "INSERT INTO karma_candidates (bssid,ssid_count,pnl_overlap,"
    "pnl_jaccard_ppm,ie_uniform,deauth_chain,score,top_ssid,"
    "first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"
    " ON CONFLICT(bssid) DO UPDATE SET"
    /* Evidence is high-water: the table is rebuilt from scratch each
     * poll, so a radio that is briefly quiet would otherwise erase the
     * peak that justified the alert. */
    "  ssid_count=MAX(karma_candidates.ssid_count,excluded.ssid_count),"
    "  pnl_overlap=MAX(karma_candidates.pnl_overlap,excluded.pnl_overlap),"
    "  pnl_jaccard_ppm=MAX(karma_candidates.pnl_jaccard_ppm,"
    "                      excluded.pnl_jaccard_ppm),"
    "  ie_uniform=MAX(karma_candidates.ie_uniform,excluded.ie_uniform),"
    "  deauth_chain=MAX(karma_candidates.deauth_chain,excluded.deauth_chain),"
    "  score=MAX(karma_candidates.score,excluded.score),"
    "  top_ssid=excluded.top_ssid,"
    "  first_seen=MIN(karma_candidates.first_seen,excluded.first_seen),"
    "  last_seen=MAX(karma_candidates.last_seen,excluded.last_seen)",
[ST_ROGUE_RADIUS] =
    "INSERT INTO rogue_radius (bssid,eap_types_seen,weak_method,"
    "identity_leaks,last_identity,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7)"
    " ON CONFLICT(bssid) DO UPDATE SET"
    /* Offered EAP methods accumulate — an AP that once offered MD5
     * offered it, whatever it advertises on the next handshake. */
    "  eap_types_seen=(rogue_radius.eap_types_seen | excluded.eap_types_seen),"
    "  weak_method=MAX(rogue_radius.weak_method,excluded.weak_method),"
    "  identity_leaks=MAX(rogue_radius.identity_leaks,excluded.identity_leaks),"
    "  last_identity=excluded.last_identity,"
    "  first_seen=MIN(rogue_radius.first_seen,excluded.first_seen),"
    "  last_seen=MAX(rogue_radius.last_seen,excluded.last_seen)",
};

/* ── helpers ─────────────────────────────────────────────── */

static void mac_str(const uint8_t mac[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Bind a C string; SQLITE_TRANSIENT because the source is a stack
 * buffer or a state field that may be overwritten before step(). */
static void bind_txt(sqlite3_stmt *st, int i, const char *s) {
    sqlite3_bind_text(st, i, s ? s : "", -1, SQLITE_TRANSIENT);
}

/* Run one prepared upsert and reset it for the next row. Any error
 * disables the sink; the caller keeps going either way. */
static void step_reset(int which) {
    sqlite3_stmt *st = g_st[which];
    if (!st) return;
    if (sqlite3_step(st) != SQLITE_DONE) db_fail("write");
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
}

static int exec(const char *sql, const char *what) {
    char *err = NULL;
    if (sqlite3_exec(g_db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sloth: db %s failed: %s\n", what,
                err ? err : sqlite3_errmsg(g_db));
        sqlite3_free(err);
        return 0;
    }
    return 1;
}

/* ── schema version ──────────────────────────────────────── */

/* Refuse a file written by a newer sloth rather than silently writing
 * rows the other version's readers will misinterpret. An older file is
 * also refused for now: there is exactly one schema version, so a
 * mismatch can only mean a hand-edited or corrupt file. */
static int check_version(void) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT value FROM meta WHERE key='schema_version'", -1,
            &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "sloth: db version query failed: %s\n",
                sqlite3_errmsg(g_db));
        return 0;
    }
    int found = 0, ok = 1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        found = 1;
        int have = v ? atoi((const char *)v) : -1;
        if (have != DB_SCHEMA_VERSION) {
            fprintf(stderr,
                    "sloth: db schema v%d, this build writes v%d — "
                    "use a separate file\n", have, DB_SCHEMA_VERSION);
            ok = 0;
        }
    }
    sqlite3_finalize(st);
    if (!ok) return 0;
    if (!found) {
        char sql[128];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO meta (key,value) VALUES "
                 "('schema_version','%d')", DB_SCHEMA_VERSION);
        if (!exec(sql, "version stamp")) return 0;
    }
    return 1;
}

/* ── open / close ────────────────────────────────────────── */

int db_open(const char *path) {
    if (!path || !path[0]) return 0;
    if (sqlite3_open(path, &g_db) != SQLITE_OK) {
        fprintf(stderr, "sloth: could not open db %s: %s\n", path,
                g_db ? sqlite3_errmsg(g_db) : "?");
        sqlite3_close(g_db);
        g_db = NULL;
        return 0;
    }
    /* WAL so a reader (the operator's sqlite3 CLI) never blocks the
     * writer mid-capture. synchronous=NORMAL fsyncs at checkpoint
     * rather than per commit — at 1 Hz on an SD card the difference is
     * the card's lifetime, and the exposure is the last few seconds of
     * telemetry on a power cut, which is an acceptable trade for a
     * passive sensor. */
    /* auto_vacuum must be set before the first table exists, so this
     * only takes effect on a newly created file; an older one keeps
     * auto_vacuum=NONE and reuses freed pages instead of returning
     * them. Either way the file stops growing. */
    if (!exec("PRAGMA auto_vacuum=INCREMENTAL", "auto_vacuum") ||
        !exec("PRAGMA journal_mode=WAL", "WAL")            ||
        !exec("PRAGMA synchronous=NORMAL", "synchronous")  ||
        !exec("PRAGMA foreign_keys=ON", "foreign_keys")    ||
        !exec(db_schema_sql(), "schema")                   ||
        !check_version()) {
        sqlite3_close(g_db);
        g_db = NULL;
        return 0;
    }
    for (int i = 0; i < ST_COUNT; i++) {
        if (!SQL[i]) continue;
        if (sqlite3_prepare_v2(g_db, SQL[i], -1, &g_st[i], NULL) != SQLITE_OK) {
            fprintf(stderr, "sloth: db prepare %d failed: %s\n", i,
                    sqlite3_errmsg(g_db));
            db_close();
            return 0;
        }
    }
    g_disabled   = 0;
    g_last_tick  = 0;
    g_last_maint = 0;
    g_over_ceiling_reported = 0;
    return 1;
}

void db_close(void) {
    for (int i = 0; i < ST_COUNT; i++) {
        if (g_st[i]) { sqlite3_finalize(g_st[i]); g_st[i] = NULL; }
    }
    if (g_db) { sqlite3_close(g_db); g_db = NULL; }
    g_disabled   = 0;
    g_last_tick  = 0;
    g_last_maint = 0;
    g_over_ceiling_reported = 0;
}

int db_is_open(void) { return g_db != NULL && !g_disabled; }

void db_set_interval(int secs) {
    g_interval = secs > 0 ? secs : DB_DEFAULT_INTERVAL_S;
}
int db_interval(void) { return g_interval; }

int db_due(time_t now) {
    if (!db_is_open()) return 0;
    if (g_last_tick == 0) return 1;               /* first tick always */
    if (now < g_last_tick) return 1;              /* clock stepped back */
    return (now - g_last_tick) >= g_interval;
}

/* ── per-table writers ───────────────────────────────────── */

static void write_devices(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->device_count; i++) {
        const device_t *d = &s->devices[i];
        char mac[18]; mac_str(d->mac, mac);
        sqlite3_stmt *st = g_st[ST_DEVICE];
        bind_txt(st, 1, mac);
        bind_txt(st, 2, d->ip);
        bind_txt(st, 3, d->hostname);
        bind_txt(st, 4, d->vendor);
        bind_txt(st, 5, d->last_ssid);
        sqlite3_bind_int  (st, 6,  d->is_ap ? 1 : 0);
        sqlite3_bind_int  (st, 7,  d->signal_dbm);
        sqlite3_bind_int  (st, 8,  d->probe_count);
        sqlite3_bind_int  (st, 9,  d->sources);
        sqlite3_bind_int  (st, 10, d->risk_signals);
        sqlite3_bind_int  (st, 11, (int)d->risk_level);
        /* device_t has no first_seen; the MIN() in the upsert pins the
         * true first observation from whichever tick saw it first. */
        sqlite3_bind_int64(st, 12, (sqlite3_int64)(d->last_seen ? d->last_seen : now));
        sqlite3_bind_int64(st, 13, (sqlite3_int64)(d->last_seen ? d->last_seen : now));
        step_reset(ST_DEVICE);
    }
}

static void write_pnl(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->pnl_count; i++) {
        const pnl_client_t *p = &s->pnl_clients[i];
        char mac[18]; mac_str(p->mac, mac);
        time_t first = p->first_seen ? p->first_seen : now;
        time_t last  = p->last_seen  ? p->last_seen  : now;

        sqlite3_stmt *st = g_st[ST_PNL_CLIENT];
        bind_txt(st, 1, mac);
        sqlite3_bind_int  (st, 2, p->mac_random ? 1 : 0);
        sqlite3_bind_int  (st, 3, p->probe_count);
        bind_txt(st, 4, p->os_fp);
        bind_txt(st, 5, p->phy);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)first);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)last);
        step_reset(ST_PNL_CLIENT);

        int n = p->ssid_count;
        if (n > MAX_PNL_SSIDS_PER_CLI) n = MAX_PNL_SSIDS_PER_CLI;
        for (int k = 0; k < n; k++) {
            if (!p->ssids[k][0]) continue;
            sqlite3_stmt *ss = g_st[ST_PNL_SSID];
            bind_txt(ss, 1, mac);
            bind_txt(ss, 2, p->ssids[k]);
            sqlite3_bind_int64(ss, 3, (sqlite3_int64)first);
            sqlite3_bind_int64(ss, 4, (sqlite3_int64)last);
            step_reset(ST_PNL_SSID);
        }
    }
}

static void write_probe_clients(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->probe_count; i++) {
        const probe_client_t *p = &s->probe_clients[i];
        char mac[18]; mac_str(p->mac, mac);
        sqlite3_stmt *st = g_st[ST_PROBE_CLIENT];
        bind_txt(st, 1, mac);
        bind_txt(st, 2, p->ssid);
        sqlite3_bind_int  (st, 3, p->signal_dbm);
        sqlite3_bind_int  (st, 4, p->channel);
        sqlite3_bind_int  (st, 5, p->frame_count);
        sqlite3_bind_int  (st, 6, (int)presence_classify(&p->rssi_ring,
                                                         p->first_seen,
                                                         p->last_seen, now));
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(p->first_seen ? p->first_seen : now));
        sqlite3_bind_int64(st, 8, (sqlite3_int64)(p->last_seen  ? p->last_seen  : now));
        step_reset(ST_PROBE_CLIENT);
    }
}

static void write_beacons(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *b = &s->beacon_aps[i];
        char bssid[18]; mac_str(b->bssid, bssid);
        time_t last = b->last_seen ? b->last_seen : now;

        sqlite3_stmt *st = g_st[ST_BEACON_AP];
        bind_txt(st, 1, bssid);
        bind_txt(st, 2, b->ssid);
        sqlite3_bind_int(st, 3,  b->signal_dbm);
        sqlite3_bind_int(st, 4,  b->channel);
        bind_txt(st, 5, b->enc);
        sqlite3_bind_int(st, 6,  b->beacon_ms);
        bind_txt(st, 7,  b->pairwise);
        bind_txt(st, 8,  b->group);
        bind_txt(st, 9,  b->akm);
        sqlite3_bind_int(st, 10, b->mfp);
        bind_txt(st, 11, b->vendor);
        sqlite3_bind_int(st, 12, b->has_wps ? 1 : 0);
        sqlite3_bind_int(st, 13, b->wps_state);
        sqlite3_bind_int(st, 14, b->wps_locked);
        bind_txt(st, 15, b->phy);
        sqlite3_bind_int(st, 16, b->revealed ? 1 : 0);
        sqlite3_bind_int(st, 17, b->frame_count);
        sqlite3_bind_int(st, 18, b->has_qbss ? 1 : 0);
        sqlite3_bind_int(st, 19, b->qbss_stations);
        sqlite3_bind_int(st, 20, b->qbss_chan_util);
        sqlite3_bind_int64(st, 21, (sqlite3_int64)last);
        sqlite3_bind_int64(st, 22, (sqlite3_int64)last);
        step_reset(ST_BEACON_AP);

        int n = b->ssid_history_n;
        if (n > MAX_AP_SSID_HISTORY) n = MAX_AP_SSID_HISTORY;
        for (int k = 0; k < n; k++) {
            if (!b->ssid_history[k][0]) continue;
            sqlite3_stmt *ss = g_st[ST_BEACON_SSID];
            bind_txt(ss, 1, bssid);
            bind_txt(ss, 2, b->ssid_history[k]);
            sqlite3_bind_int64(ss, 3, (sqlite3_int64)last);
            sqlite3_bind_int64(ss, 4, (sqlite3_int64)last);
            step_reset(ST_BEACON_SSID);
        }
    }
}

static void write_wifi_aps(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->ap_count; i++) {
        const wifi_ap_t *a = &s->aps[i];
        if (!a->bssid[0]) continue;
        sqlite3_stmt *st = g_st[ST_WIFI_AP];
        bind_txt(st, 1, a->bssid);
        bind_txt(st, 2, a->ssid);
        sqlite3_bind_int(st, 3, a->signal_dbm);
        sqlite3_bind_int(st, 4, a->channel);
        bind_txt(st, 5, a->enc);
        sqlite3_bind_int(st, 6, a->status);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)now);
        sqlite3_bind_int64(st, 8, (sqlite3_int64)now);
        step_reset(ST_WIFI_AP);
    }
}

static void write_wifi_stas(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->wifi_sta_count; i++) {
        const wifi_sta_t *w = &s->wifi_stas[i];
        if (!w->mac[0]) continue;
        sqlite3_stmt *st = g_st[ST_WIFI_STA];
        bind_txt(st, 1, w->mac);
        sqlite3_bind_int  (st, 2, w->signal_dbm);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)w->tx_rate_kbps);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)w->rx_rate_kbps);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)w->connected_secs);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)w->inactive_ms);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)w->tx_bytes);
        sqlite3_bind_int64(st, 8, (sqlite3_int64)w->rx_bytes);
        sqlite3_bind_int64(st, 9,  (sqlite3_int64)now);
        sqlite3_bind_int64(st, 10, (sqlite3_int64)now);
        step_reset(ST_WIFI_STA);
    }
}

static void write_assocs(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->assoc_count; i++) {
        const assoc_t *a = &s->assocs[i];
        char bssid[18], sta[18];
        mac_str(a->bssid, bssid);
        mac_str(a->sta_mac, sta);
        sqlite3_stmt *st = g_st[ST_ASSOC];
        bind_txt(st, 1, bssid);
        bind_txt(st, 2, sta);
        bind_txt(st, 3, a->ssid);
        sqlite3_bind_int  (st, 4, a->sta_random ? 1 : 0);
        sqlite3_bind_int  (st, 5, a->source);
        sqlite3_bind_int  (st, 6, a->channel);
        sqlite3_bind_int  (st, 7, a->signal_dbm);
        sqlite3_bind_int  (st, 8, a->frame_count);
        sqlite3_bind_int64(st, 9,  (sqlite3_int64)(a->first_seen ? a->first_seen : now));
        sqlite3_bind_int64(st, 10, (sqlite3_int64)(a->last_seen  ? a->last_seen  : now));
        step_reset(ST_ASSOC);
    }
}

static void write_wifi_merged(const sloth_state_t *s, time_t now) {
    const wifi_merge_t *m = &s->wifi_merged;
    for (int i = 0; i < m->count; i++) {
        const wifi_merged_t *e = &m->ents[i];
        char key[18]; mac_str(e->key, key);
        sqlite3_stmt *st = g_st[ST_WIFI_MERGED];
        bind_txt(st, 1, key);
        sqlite3_bind_int  (st, 2, (int)e->sensor_mask);
        sqlite3_bind_int  (st, 3, e->seen_by);
        sqlite3_bind_int  (st, 4, e->best_rssi);
        sqlite3_bind_int  (st, 5, e->best_sensor);
        sqlite3_bind_int  (st, 6, e->channel);
        sqlite3_bind_int  (st, 7, e->freq_mhz);
        sqlite3_bind_int64(st, 8, (sqlite3_int64)e->observations);
        sqlite3_bind_int64(st, 9,  (sqlite3_int64)(e->first_seen ? e->first_seen : now));
        sqlite3_bind_int64(st, 10, (sqlite3_int64)(e->last_seen  ? e->last_seen  : now));
        step_reset(ST_WIFI_MERGED);
    }
}

static void write_ip_entities(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->arp_count; i++) {
        const arp_entry_t *a = &s->arp_entries[i];
        char mac[18]; mac_str(a->mac, mac);
        sqlite3_stmt *st = g_st[ST_ARP];
        bind_txt(st, 1, a->ip);
        bind_txt(st, 2, mac);
        bind_txt(st, 3, a->iface);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)now);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)now);
        step_reset(ST_ARP);
    }
    for (int i = 0; i < s->dhcp_count; i++) {
        const dhcp_lease_t *d = &s->dhcp_leases[i];
        sqlite3_stmt *st = g_st[ST_DHCP_LEASE];
        bind_txt(st, 1, d->ip);
        bind_txt(st, 2, d->hostname);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)d->expire);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)now);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)now);
        step_reset(ST_DHCP_LEASE);
    }
    for (int i = 0; i < s->top_host_count; i++) {
        const top_host_t *t = &s->top_hosts[i];
        sqlite3_stmt *st = g_st[ST_TOP_HOST];
        bind_txt(st, 1, t->ip);
        bind_txt(st, 2, t->hostname);
        bind_txt(st, 3, t->owner);
        sqlite3_bind_int  (st, 4, t->conn_count);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)t->rx_bytes);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)t->tx_bytes);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(t->first_seen ? t->first_seen : now));
        sqlite3_bind_int64(st, 8, (sqlite3_int64)(t->last_seen  ? t->last_seen  : now));
        step_reset(ST_TOP_HOST);
    }
}

static void write_discovery(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->mdns_count; i++) {
        const mdns_service_t *m = &s->mdns_services[i];
        if (!m->instance[0]) continue;
        sqlite3_stmt *st = g_st[ST_MDNS];
        bind_txt(st, 1, m->instance);
        bind_txt(st, 2, m->service);
        bind_txt(st, 3, m->host);
        bind_txt(st, 4, m->ip);
        sqlite3_bind_int  (st, 5, m->port);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(m->last_seen ? m->last_seen : now));
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(m->last_seen ? m->last_seen : now));
        step_reset(ST_MDNS);
    }
    for (int i = 0; i < s->nbns_count; i++) {
        const nbns_name_t *n = &s->nbns_names[i];
        if (!n->name[0]) continue;
        sqlite3_stmt *st = g_st[ST_NBNS];
        bind_txt(st, 1, n->name);
        sqlite3_bind_int(st, 2, n->suffix);
        bind_txt(st, 3, n->ip);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)(n->last_seen ? n->last_seen : now));
        sqlite3_bind_int64(st, 5, (sqlite3_int64)(n->last_seen ? n->last_seen : now));
        step_reset(ST_NBNS);
    }
    for (int i = 0; i < s->ssdp_count; i++) {
        const ssdp_device_t *d = &s->ssdp_devices[i];
        if (!d->usn[0]) continue;
        sqlite3_stmt *st = g_st[ST_SSDP];
        bind_txt(st, 1, d->usn);
        bind_txt(st, 2, d->ip);
        bind_txt(st, 3, d->type);
        bind_txt(st, 4, d->location);
        bind_txt(st, 5, d->nts);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(d->last_seen ? d->last_seen : now));
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(d->last_seen ? d->last_seen : now));
        step_reset(ST_SSDP);
    }
}

static void write_ndp_and_sensors(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->ndp_ra_count; i++) {
        const ndp_ra_event_t *r = &s->ndp_ras[i];
        if (!r->src_ip[0]) continue;
        char mac[18] = "";
        if (r->has_src_mac) mac_str(r->src_mac, mac);
        time_t first = r->first_seen ? r->first_seen : now;
        time_t last  = r->last_seen  ? r->last_seen  : now;

        sqlite3_stmt *st = g_st[ST_NDP_RA];
        bind_txt(st, 1, r->src_ip);
        bind_txt(st, 2, mac);
        sqlite3_bind_int  (st, 3, r->cur_hop_limit);
        sqlite3_bind_int  (st, 4, r->flags);
        sqlite3_bind_int  (st, 5, r->router_lifetime);
        sqlite3_bind_int  (st, 6, r->count);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)first);
        sqlite3_bind_int64(st, 8, (sqlite3_int64)last);
        step_reset(ST_NDP_RA);

        int n = r->prefix_count;
        if (n > NDP_RA_MAX_PREFIXES) n = NDP_RA_MAX_PREFIXES;
        for (int k = 0; k < n; k++) {
            if (!r->prefixes[k][0]) continue;
            sqlite3_stmt *ps = g_st[ST_NDP_PREFIX];
            bind_txt(ps, 1, r->src_ip);
            bind_txt(ps, 2, r->prefixes[k]);
            sqlite3_bind_int64(ps, 3, (sqlite3_int64)first);
            sqlite3_bind_int64(ps, 4, (sqlite3_int64)last);
            step_reset(ST_NDP_PREFIX);
        }
    }
    for (int i = 0; i < s->sensor_count; i++) {
        const sensor_t *sn = &s->sensors[i];
        sqlite3_stmt *st = g_st[ST_SENSOR];
        sqlite3_bind_int(st, 1, sn->kind);
        bind_txt(st, 2, sn->iface);
        bind_txt(st, 3, sn->name);
        sqlite3_bind_int  (st, 4, sn->state);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)sn->observed);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(sn->first_seen ? sn->first_seen : now));
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(sn->last_seen  ? sn->last_seen  : now));
        step_reset(ST_SENSOR);
    }
}

/* Protocol-flow aggregates. All eight follow the same shape: bind the
 * endpoint key, the counters, whatever "last seen" scalar the parser
 * keeps, then the timestamps. */
static void write_proto_flows(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->bgp_session_count; i++) {
        const bgp_session_t *b = &s->bgp_sessions[i];
        sqlite3_stmt *st = g_st[ST_BGP];
        bind_txt(st, 1, b->peer_a);
        bind_txt(st, 2, b->peer_b);
        sqlite3_bind_int(st, 3, b->open_count);
        sqlite3_bind_int(st, 4, b->update_count);
        sqlite3_bind_int(st, 5, b->notification_count);
        sqlite3_bind_int(st, 6, b->keepalive_count);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(b->first_seen ? b->first_seen : now));
        sqlite3_bind_int64(st, 8, (sqlite3_int64)(b->last_seen  ? b->last_seen  : now));
        step_reset(ST_BGP);
    }
    for (int i = 0; i < s->ssh_flow_count; i++) {
        const ssh_flow_t *f = &s->ssh_flows[i];
        sqlite3_stmt *st = g_st[ST_SSH];
        bind_txt(st, 1, f->src_ip);
        bind_txt(st, 2, f->dst_ip);
        sqlite3_bind_int(st, 3, f->banner_count);
        bind_txt(st, 4, f->server_banner);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)(f->first_seen ? f->first_seen : now));
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(f->last_seen  ? f->last_seen  : now));
        step_reset(ST_SSH);
    }
    for (int i = 0; i < s->rdp_flow_count; i++) {
        const rdp_flow_t *f = &s->rdp_flows[i];
        sqlite3_stmt *st = g_st[ST_RDP];
        bind_txt(st, 1, f->src_ip);
        bind_txt(st, 2, f->dst_ip);
        sqlite3_bind_int(st, 3, f->connect_req_count);
        /* mstshash cookie is the username being guessed — an exposed
         * identifier, not a secret. Same call cleartext_cred makes. */
        bind_txt(st, 4, f->last_cookie);
        sqlite3_bind_int(st, 5, (int)f->proto_mask);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(f->first_seen ? f->first_seen : now));
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(f->last_seen  ? f->last_seen  : now));
        step_reset(ST_RDP);
    }
    for (int i = 0; i < s->snmp_flow_count; i++) {
        const snmp_flow_t *f = &s->snmp_flows[i];
        sqlite3_stmt *st = g_st[ST_SNMP];
        bind_txt(st, 1, f->src_ip);
        bind_txt(st, 2, f->dst_ip);
        sqlite3_bind_int(st, 3, f->get_count);
        sqlite3_bind_int(st, 4, f->getnext_count);
        sqlite3_bind_int(st, 5, f->getbulk_count);
        sqlite3_bind_int(st, 6, f->set_count);
        sqlite3_bind_int(st, 7, f->response_count);
        sqlite3_bind_int(st, 8, f->trap_count);
        sqlite3_bind_int(st, 9, f->version);
        /* Count only. The community strings themselves are shared
         * secrets in v1/v2c and never reach the file — see the MISSION
         * §2 note in db_schema.c. The count is what the brute-force
         * detector keys on. */
        sqlite3_bind_int(st, 10, f->community_count);
        sqlite3_bind_int64(st, 11, (sqlite3_int64)(f->first_seen ? f->first_seen : now));
        sqlite3_bind_int64(st, 12, (sqlite3_int64)(f->last_seen  ? f->last_seen  : now));
        step_reset(ST_SNMP);
    }
    for (int i = 0; i < s->mqtt_flow_count; i++) {
        const mqtt_flow_t *f = &s->mqtt_flows[i];
        sqlite3_stmt *st = g_st[ST_MQTT];
        bind_txt(st, 1, f->src_ip);
        bind_txt(st, 2, f->dst_ip);
        sqlite3_bind_int(st, 3, f->connect_count);
        sqlite3_bind_int(st, 4, f->connack_fail_count);
        sqlite3_bind_int(st, 5, f->subscribe_count);
        sqlite3_bind_int(st, 6, f->publish_count);
        sqlite3_bind_int(st, 7, f->proto_level);
        bind_txt(st, 8, f->last_username);
        sqlite3_bind_int64(st, 9,  (sqlite3_int64)(f->first_seen ? f->first_seen : now));
        sqlite3_bind_int64(st, 10, (sqlite3_int64)(f->last_seen  ? f->last_seen  : now));
        step_reset(ST_MQTT);
    }
    for (int i = 0; i < s->ldap_event_count; i++) {
        const ldap_event_t *e = &s->ldap_events[i];
        sqlite3_stmt *st = g_st[ST_LDAP];
        bind_txt(st, 1, e->src_ip);
        sqlite3_bind_int(st, 2, e->bind_count);
        sqlite3_bind_int(st, 3, e->bind_anon_count);
        sqlite3_bind_int(st, 4, e->search_count);
        sqlite3_bind_int(st, 5, e->search_ref_count);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(e->first_seen ? e->first_seen : now));
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(e->last_seen  ? e->last_seen  : now));
        step_reset(ST_LDAP);
    }
    for (int i = 0; i < s->kerb_event_count; i++) {
        const kerb_event_t *e = &s->kerb_events[i];
        sqlite3_stmt *st = g_st[ST_KERB];
        bind_txt(st, 1, e->src_ip);
        sqlite3_bind_int(st, 2, e->as_req_count);
        sqlite3_bind_int(st, 3, e->as_rep_count);
        sqlite3_bind_int(st, 4, e->tgs_req_count);
        sqlite3_bind_int(st, 5, e->tgs_rep_count);
        sqlite3_bind_int(st, 6, e->preauth_required_count);
        sqlite3_bind_int(st, 7, e->preauth_failed_count);
        sqlite3_bind_int(st, 8, e->principal_unknown_count);
        sqlite3_bind_int(st, 9, e->error_other_count);
        sqlite3_bind_int64(st, 10, (sqlite3_int64)(e->first_seen ? e->first_seen : now));
        sqlite3_bind_int64(st, 11, (sqlite3_int64)(e->last_seen  ? e->last_seen  : now));
        step_reset(ST_KERB);
    }
    for (int i = 0; i < s->smb_session_count; i++) {
        const smb_session_t *f = &s->smb_sessions[i];
        sqlite3_stmt *st = g_st[ST_SMB];
        bind_txt(st, 1, f->client_ip);
        bind_txt(st, 2, f->server_ip);
        sqlite3_bind_int(st, 3, (int)f->server_port);
        bind_txt(st, 4, f->dialect);
        sqlite3_bind_int(st, 5, f->count);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(f->first_seen ? f->first_seen : now));
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(f->last_seen  ? f->last_seen  : now));
        step_reset(ST_SMB);
    }
}

/* Event episodes. Keyed by episode identity, so an alert that persists
 * for an hour is one row whose count and last_seen advance rather than
 * 3600 rows. */
static void write_events(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->alert_count; i++) {
        const alert_t *a = &s->alerts[i];
        sqlite3_stmt *st = g_st[ST_ALERT];
        bind_txt(st, 1, a->key);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)(a->first_seen ? a->first_seen : now));
        sqlite3_bind_int64(st, 3, (sqlite3_int64)(a->last_seen  ? a->last_seen  : now));
        sqlite3_bind_int(st, 4, (int)a->type);
        sqlite3_bind_int(st, 5, (int)a->sev);
        bind_txt(st, 6, a->title);
        bind_txt(st, 7, a->detail);
        bind_txt(st, 8, a->technique);
        bind_txt(st, 9, a->match_ip);
        sqlite3_bind_int(st, 10, (int)a->match_port);
        sqlite3_bind_int(st, 11, a->count);
        step_reset(ST_ALERT);
    }

    for (int i = 0; i < s->cleartext_cred_count; i++) {
        const cleartext_cred_t *c = &s->cleartext_creds[i];
        sqlite3_stmt *st = g_st[ST_CRED];
        sqlite3_bind_int64(st, 1, (sqlite3_int64)(c->ts ? c->ts : now));
        bind_txt(st, 2, c->src);
        bind_txt(st, 3, c->dst);
        sqlite3_bind_int(st, 4, (int)c->dst_port);
        bind_txt(st, 5, c->protocol);
        /* Username is the exposure fact and is recorded deliberately.
         * There is no password field on cleartext_cred_t to bind even
         * if we wanted one — the parser never keeps it. */
        bind_txt(st, 6, c->username);
        sqlite3_bind_int(st, 7, c->password_observed ? 1 : 0);
        sqlite3_bind_int64(st, 8, (sqlite3_int64)(c->ts ? c->ts : now));
        sqlite3_bind_int64(st, 9, (sqlite3_int64)now);
        step_reset(ST_CRED);
    }

    for (int i = 0; i < s->eapol_count; i++) {
        const eapol_event_t *e = &s->eapol_events[i];
        char bssid[18], sta[18];
        mac_str(e->bssid, bssid);
        mac_str(e->sta_mac, sta);
        sqlite3_stmt *st = g_st[ST_EAPOL];
        bind_txt(st, 1, bssid);
        bind_txt(st, 2, sta);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)(e->ts ? e->ts : now));
        sqlite3_bind_int(st, 4, e->msg_num);
        bind_txt(st, 5, e->ssid);
        /* has_pmkid only. e->pmkid / anonce / snonce / mic are never
         * bound anywhere — see the MISSION §2 note in db_schema.c. */
        sqlite3_bind_int(st, 6, e->has_pmkid ? 1 : 0);
        sqlite3_bind_int(st, 7, e->handshake_complete ? 1 : 0);
        sqlite3_bind_int(st, 8, e->signal_dbm);
        sqlite3_bind_int(st, 9, e->channel);
        sqlite3_bind_int64(st, 10, (sqlite3_int64)(e->ts ? e->ts : now));
        sqlite3_bind_int64(st, 11, (sqlite3_int64)now);
        step_reset(ST_EAPOL);
    }

    for (int i = 0; i < s->deauth_count; i++) {
        const deauth_event_t *d = &s->deauth_events[i];
        char src[18], dst[18], bssid[18];
        mac_str(d->src, src);
        mac_str(d->dst, dst);
        mac_str(d->bssid, bssid);
        sqlite3_stmt *st = g_st[ST_DEAUTH];
        bind_txt(st, 1, src);
        bind_txt(st, 2, dst);
        bind_txt(st, 3, bssid);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)(d->first_seen ? d->first_seen : now));
        sqlite3_bind_int64(st, 5, (sqlite3_int64)(d->last_seen  ? d->last_seen  : now));
        sqlite3_bind_int(st, 6, (int)d->reason);
        sqlite3_bind_int(st, 7, (int)d->subtype);
        sqlite3_bind_int(st, 8, d->count);
        sqlite3_bind_int(st, 9, d->flood ? 1 : 0);
        step_reset(ST_DEAUTH);
    }

    for (int i = 0; i < s->seqnum_correlation_count; i++) {
        const seqnum_correlation_t *c = &s->seqnum_correlations[i];
        char a[18], b[18];
        mac_str(c->mac_a, a);
        mac_str(c->mac_b, b);
        sqlite3_stmt *st = g_st[ST_SEQCORR];
        bind_txt(st, 1, a);
        bind_txt(st, 2, b);
        sqlite3_bind_int(st, 3, c->mac_a_random ? 1 : 0);
        sqlite3_bind_int(st, 4, c->mac_b_random ? 1 : 0);
        sqlite3_bind_int(st, 5, c->gap);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)c->dt_ms);
        sqlite3_bind_int(st, 7, c->a_count);
        sqlite3_bind_int(st, 8, c->b_count);
        sqlite3_bind_int64(st, 9,  (sqlite3_int64)now);
        sqlite3_bind_int64(st, 10, (sqlite3_int64)now);
        step_reset(ST_SEQCORR);
    }

    for (int i = 0; i < s->twin_episode_count; i++) {
        const twin_episode_t *t = &s->twin_episodes[i];
        char real[18], twin[18];
        mac_str(t->real_bssid, real);
        mac_str(t->twin_bssid, twin);
        sqlite3_stmt *st = g_st[ST_TWIN];
        bind_txt(st, 1, t->ssid);
        bind_txt(st, 2, real);
        bind_txt(st, 3, twin);
        bind_txt(st, 4, t->enc);
        sqlite3_bind_int(st, 5, t->real_rssi);
        sqlite3_bind_int(st, 6, t->twin_rssi);
        sqlite3_bind_int(st, 7, (int)t->rssi_swing_dbm);
        sqlite3_bind_int(st, 8, t->attack_in_progress ? 1 : 0);
        sqlite3_bind_int(st, 9, t->attacker_oui ? 1 : 0);
        sqlite3_bind_int(st, 10, t->hash_mismatch ? 1 : 0);
        sqlite3_bind_int64(st, 11, (sqlite3_int64)(t->last_seen ? t->last_seen : now));
        sqlite3_bind_int64(st, 12, (sqlite3_int64)(t->last_seen ? t->last_seen : now));
        step_reset(ST_TWIN);
    }

    for (int i = 0; i < s->scan_count; i++) {
        const scan_entry_t *e = &s->scan_entries[i];
        /* Flagged only (#41): an unflagged entry is one host touching a
         * couple of ports, i.e. ordinary traffic, and persisting it
         * would put the CDN false positives #41 removed back into the
         * durable record. */
        if (!e->flagged) continue;
        time_t first = e->first_seen ? e->first_seen : now;
        time_t last  = e->last_seen  ? e->last_seen  : now;
        sqlite3_stmt *st = g_st[ST_SCAN];
        bind_txt(st, 1, e->ip);
        sqlite3_bind_int(st, 2, e->port_count);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)first);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)last);
        step_reset(ST_SCAN);

        int n = e->port_count;
        if (n > MAX_SCAN_PORTS) n = MAX_SCAN_PORTS;
        for (int k = 0; k < n; k++) {
            sqlite3_stmt *ps = g_st[ST_SCAN_PORT];
            bind_txt(ps, 1, e->ip);
            sqlite3_bind_int(ps, 2, (int)e->ports[k]);
            sqlite3_bind_int64(ps, 3, (sqlite3_int64)first);
            sqlite3_bind_int64(ps, 4, (sqlite3_int64)last);
            step_reset(ST_SCAN_PORT);
        }
    }
}

/* Detector evidence (#30 / #31). These tables exist because the
 * detectors' supporting evidence had no durable home at all — the
 * alert survived, the reasoning behind it did not. */
static void write_detector_evidence(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->karma_count; i++) {
        const karma_ap_t *k = &s->karma_aps[i];
        char bssid[18]; mac_str(k->bssid, bssid);
        time_t last = k->last_seen ? k->last_seen : now;
        sqlite3_stmt *st = g_st[ST_KARMA];
        bind_txt(st, 1, bssid);
        sqlite3_bind_int(st, 2, k->ssid_count);
        sqlite3_bind_int(st, 3, k->pnl_overlap);
        sqlite3_bind_int(st, 4, k->pnl_jaccard_ppm);
        sqlite3_bind_int(st, 5, k->ie_uniform ? 1 : 0);
        sqlite3_bind_int(st, 6, k->deauth_chain ? 1 : 0);
        sqlite3_bind_int(st, 7, k->score);
        bind_txt(st, 8, k->top_ssid);
        sqlite3_bind_int64(st, 9,  (sqlite3_int64)last);
        sqlite3_bind_int64(st, 10, (sqlite3_int64)last);
        step_reset(ST_KARMA);
    }
    for (int i = 0; i < s->rogue_radius_count; i++) {
        const rogue_radius_ap_t *r = &s->rogue_radius[i];
        char bssid[18]; mac_str(r->bssid, bssid);
        sqlite3_stmt *st = g_st[ST_ROGUE_RADIUS];
        bind_txt(st, 1, bssid);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)r->eap_types_seen);
        sqlite3_bind_int(st, 3, r->weak_method ? 1 : 0);
        sqlite3_bind_int(st, 4, r->identity_leaks);
        /* A leaked EAP identity is a username, not a credential. */
        bind_txt(st, 5, r->last_identity);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(r->first_seen ? r->first_seen : now));
        sqlite3_bind_int64(st, 7, (sqlite3_int64)(r->last_seen  ? r->last_seen  : now));
        step_reset(ST_ROGUE_RADIUS);
    }
}

/* ── retention and the size ceiling ──────────────────────── */

void db_set_retain_days(int days) {
    g_retain_days = days > 0 ? days : DB_DEFAULT_RETAIN_DAYS;
}
int db_retain_days(void) { return g_retain_days; }

void db_set_max_mb(int mb) { g_max_mb = mb >= 0 ? mb : DB_DEFAULT_MAX_MB; }
int  db_max_mb(void)       { return g_max_mb; }

/* Scalar integer PRAGMA / SELECT. -1 on any failure, which callers
 * treat as "don't know" and skip the guard rather than guessing. */
static long long scalar(const char *sql) {
    if (!g_db) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    long long v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

long long db_size_bytes(void) {
    if (!g_db) return -1;
    long long pages = scalar("PRAGMA page_count");
    long long psize = scalar("PRAGMA page_size");
    if (pages < 0 || psize < 0) return -1;
    return pages * psize;
}

/* DELETE ... WHERE last_seen < cutoff across a tier. Errors disable the
 * sink like any other write failure. */
static void prune_tier(const char *const *tables, int n, time_t cutoff) {
    for (int i = 0; i < n; i++) {
        char sql[160];
        snprintf(sql, sizeof(sql),
                 "DELETE FROM %s WHERE last_seen < %lld",
                 tables[i], (long long)cutoff);
        if (!exec(sql, "prune")) { db_fail("prune"); return; }
    }
}

/* Delete the oldest `batch` observation rows across the whole tier.
 * Returns the number actually removed, so the caller can stop when
 * there is nothing left to give. */
static long long prune_oldest_observations(int batch) {
    long long removed = 0;
    for (int i = 0; i < NELEMS(TIER_OBSERVATION); i++) {
        char sql[240];
        snprintf(sql, sizeof(sql),
                 "DELETE FROM %s WHERE rowid IN ("
                 "SELECT rowid FROM %s ORDER BY last_seen ASC LIMIT %d)",
                 TIER_OBSERVATION[i], TIER_OBSERVATION[i], batch);
        if (!exec(sql, "ceiling prune")) { db_fail("ceiling prune"); return removed; }
        removed += sqlite3_changes(g_db);
    }
    return removed;
}

void db_maintain(time_t now) {
    if (!db_is_open()) return;

    long long day = DB_SECS_PER_DAY;
    time_t obs_cutoff  = (time_t)(now - (long long)g_retain_days * day);
    time_t ent_cutoff  = (time_t)(now - (long long)g_retain_days * day * 3);
    time_t find_cutoff = (time_t)(now - (long long)g_retain_days * day * 12);

    if (!exec("BEGIN IMMEDIATE", "maint begin")) { db_fail("maint begin"); return; }
    prune_tier(TIER_OBSERVATION, NELEMS(TIER_OBSERVATION), obs_cutoff);
    prune_tier(TIER_ENTITY,      NELEMS(TIER_ENTITY),      ent_cutoff);
    prune_tier(TIER_FINDING,     NELEMS(TIER_FINDING),     find_cutoff);
    if (g_disabled) { exec("ROLLBACK", "maint rollback"); return; }
    if (!exec("COMMIT", "maint commit")) {
        exec("ROLLBACK", "maint rollback");
        db_fail("maint commit");
        return;
    }

    /* Size ceiling. Only observation rows are eligible: a sensor that
     * fills its disk should lose telemetry, not the findings the disk
     * was being kept for. */
    if (g_max_mb <= 0) { g_last_maint = now; return; }
    long long ceiling = (long long)g_max_mb * 1024 * 1024;

    for (int round = 0; round < 64; round++) {
        long long size = db_size_bytes();
        if (size < 0 || size <= ceiling) { g_over_ceiling_reported = 0; break; }

        if (!exec("BEGIN IMMEDIATE", "ceiling begin")) { db_fail("ceiling begin"); return; }
        long long removed = prune_oldest_observations(512);
        if (g_disabled) { exec("ROLLBACK", "ceiling rollback"); return; }
        if (!exec("COMMIT", "ceiling commit")) {
            exec("ROLLBACK", "ceiling rollback");
            db_fail("ceiling commit");
            return;
        }
        /* Return freed pages to the filesystem where the file was
         * created with incremental auto-vacuum. On an older file this
         * is a no-op and the pages are simply reused, which still stops
         * the file growing — it just will not shrink. */
        exec("PRAGMA incremental_vacuum", "incremental_vacuum");

        if (removed == 0) {
            /* Nothing eligible left. Report once and stop: exceeding
             * the ceiling is better than deleting protected evidence to
             * satisfy a number, and silently looping forever is worse
             * than both. */
            if (!g_over_ceiling_reported) {
                fprintf(stderr,
                        "sloth: db over --db-max-mb (%lld MiB > %d MiB) with no "
                        "prunable telemetry left; findings are never dropped\n",
                        size / (1024 * 1024), g_max_mb);
                g_over_ceiling_reported = 1;
            }
            break;
        }
    }
    g_last_maint = now;
}

/* ── tick ────────────────────────────────────────────────── */

void db_tick(const sloth_state_t *s, time_t now) {
    if (!s || !db_is_open()) return;

    /* One transaction per tick. BEGIN IMMEDIATE takes the write lock up
     * front so we fail fast against a competing writer instead of
     * discovering it at COMMIT with a batch already staged. */
    if (!exec("BEGIN IMMEDIATE", "begin")) { db_fail("begin"); return; }

    write_devices        (s, now);
    write_pnl            (s, now);
    write_probe_clients  (s, now);
    write_beacons        (s, now);
    write_wifi_aps       (s, now);
    write_wifi_stas      (s, now);
    write_assocs         (s, now);
    write_wifi_merged    (s, now);
    write_ip_entities    (s, now);
    write_discovery      (s, now);
    write_ndp_and_sensors(s, now);
    write_proto_flows    (s, now);
    write_events         (s, now);
    write_detector_evidence(s, now);

    if (g_disabled) {
        exec("ROLLBACK", "rollback");
        return;
    }
    if (!exec("COMMIT", "commit")) {
        exec("ROLLBACK", "rollback");
        db_fail("commit");
        return;
    }
    g_last_tick = now;

    /* Hourly, after the write so a maintenance stall never delays the
     * observation it was triggered by. */
    if (g_last_maint == 0) g_last_maint = now;
    else if (now - g_last_maint >= DB_MAINT_INTERVAL_S) db_maintain(now);
}

#endif /* WITH_SQLITE */
