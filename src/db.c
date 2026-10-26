/* Embedded SQLite sink. Contract in db.h, schema in db_schema.c (#42). */

#include "db.h"
#include "beacon_snoop.h"   /* RSN_AKM_*_FAMILY */

#ifdef WITH_SQLITE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sqlite3.h>

/* The side-file checks in db_prepare_private() are advisory — a
 * symlink can appear between the lstat and SQLite's own open — and are
 * acceptable only because SQLite itself refuses to follow one with
 * SQLITE_OPEN_NOFOLLOW. That flag arrived in 3.31.0; an #ifdef around
 * it compiled silently without it on older headers (#134). */
#if defined(SQLITE_VERSION_NUMBER) && SQLITE_VERSION_NUMBER < 3031000
#error "sloth needs sqlite3 >= 3.31.0 (SQLITE_OPEN_NOFOLLOW, SQLITE_DBCONFIG_TRUSTED_SCHEMA)"
#endif

#include "libver.h"
#include "ownership.h"
#include "presence.h"
#include "secure_file.h"
#include "sloth_clock.h"
#include "tune.h"

/* Maintenance is hourly: pruning is a scan over every table, and the
 * thing it defends against (a disk filling over days) does not move
 * fast enough to need checking at poll rate. */
#define DB_MAINT_INTERVAL_S  3600
#define DB_SECS_PER_DAY      86400

static sqlite3 *g_db;

/* Regressions found at the most recent tick (#74). Declared up here
 * rather than beside its query because db_close() must clear it. */
static db_akm_regression_t g_akm_reg[DB_MAX_AKM_REGRESSIONS];
static int                 g_akm_reg_n;
static int      g_disabled;      /* set once on error — fail-open */
/* Cadence, retention and size target live in the --tune registry
 * (db.interval_secs / db.retain_days / db.max_mb, #120), so the
 * --db-* flags and --tune share one validation and a moved value
 * reaches sensor_health's `tuned`. The setters below are aliases. */
static time_t   g_last_tick;
static time_t   g_last_maint;
static int      g_over_ceiling_reported;
static sqlite3_int64 g_session_id;        /* current survey session (#56) */
static time_t        g_prev_session_end;  /* when the last visit ended */

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
    "beacon_aps", "beacon_ap_ssids", "ssid_akm_history",
    "wifi_aps", "wifi_stas",
    "assocs", "assoc_reqs", "wifi_merged", "arp", "dhcp_leases", "top_hosts",
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
    /* Same reasoning: btm_requests is what justifies a BTM_ABUSE CRIT.
     * At 3x the evidence would expire while the finding it supports was
     * still retained. Bounded at MAX_BTM_PAIRS rows, so the cost is
     * nil — and the ordinary-steering rows kept alongside are the
     * baseline that makes the forcing ones legible. */
    "btm_requests",
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
    ST_BEACON_AP, ST_BEACON_SSID, ST_SSID_AKM,
    ST_WIFI_AP, ST_WIFI_STA, ST_ASSOC,
    ST_ASSOC_REQ, ST_BTM_REQ,
    ST_WIFI_MERGED, ST_ARP, ST_DHCP_LEASE, ST_TOP_HOST,
    ST_MDNS, ST_NBNS, ST_SSDP, ST_NDP_RA, ST_NDP_PREFIX, ST_SENSOR,
    ST_BGP, ST_SSH, ST_RDP, ST_SNMP, ST_MQTT, ST_LDAP, ST_KERB, ST_SMB,
    ST_ALERT, ST_ALERT_ROW, ST_CRED, ST_EAPOL, ST_DEAUTH, ST_SEQCORR, ST_TWIN,
    ST_SCAN, ST_SCAN_PORT, ST_KARMA, ST_ROGUE_RADIUS,
    ST_COUNT
};

static sqlite3_stmt *g_st[ST_COUNT];

/* The ST_DEVICE upsert spells the MAC-keyed camera bits as literals. */
#if CAM_SIG_SETUP_SSID != 2 || CAM_SIG_SETUP_OUI != 16
#error "ST_DEVICE's cam_signals literals no longer match CAM_SIG_*"
#endif

/* The class the MAC-keyed beacon bits of a stored devices row imply:
 * CAM_SIG_SETUP_SSID (2) a camera, CAM_SIG_SETUP_OUI (16) a camera
 * vendor. */
#define DB_STICKY_CLASS \
    "(CASE WHEN devices.cam_signals&2 THEN 2" \
    " WHEN devices.cam_signals&16 THEN 1 ELSE 0 END)"

/* Upsert shape shared by every entity table.
 *
 * first_seen uses excluded-vs-existing MIN so a re-observation never
 * moves the start of the entity's history, and last_seen uses MAX so
 * an out-of-order tick cannot rewind it. Both matter because the whole
 * point of the sink is that the time range is trustworthy. */
static const char *const SQL[ST_COUNT] = {
[ST_DEVICE] =
    "INSERT INTO devices (mac,ip,hostname,vendor,last_ssid,is_ap,signal_dbm,"
    "probe_count,sources,risk_signals,risk_level,first_seen,last_seen,"
    "device_class,camera_vendor,camera_model,setup_mode,cam_signals,"
    "cam_score,cam_evidence,cam_vetoes,cam_conflict,dhcp_prl,dhcp_vci)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,"
    "?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)"
    " ON CONFLICT(mac) DO UPDATE SET"
    "  ip=excluded.ip, hostname=excluded.hostname, vendor=excluded.vendor,"
    "  last_ssid=excluded.last_ssid, is_ap=excluded.is_ap,"
    "  signal_dbm=excluded.signal_dbm, probe_count=excluded.probe_count,"
    "  sources=excluded.sources, risk_signals=excluded.risk_signals,"
    "  risk_level=excluded.risk_level,"
    /* Camera evidence (#106 round 2) is sticky only where it carries
     * its own identity. The beacon-side bits (CAM_SIG_SETUP_SSID 2,
     * CAM_SIG_SETUP_OUI 16) were keyed on this row's MAC itself, so a
     * signal seen once was seen: those bits OR, the class they imply
     * and the setup flag only rise, and the vendor is kept while one
     * of them stands. The LAN-side bits were joined by IP, and an IP
     * changes hands under a passive sensor's feet: they, the class
     * they alone gave, and the ONVIF model are the latest tick's, so a
     * lease reused by another host does not write a camera onto that
     * host's MAC for good. The alerts table keeps what each rule saw,
     * keyed by what it had. */
    /* #155: not-camera (3) is a verdict against, not a higher "for",
     * so it never MAX()es past a MAC-keyed camera class: that history
     * keeps its class, and the row says the two met (cam_conflict), the
     * way the live classifier does. For 0..2 this is the MAX it was. */
    "  device_class=CASE WHEN " DB_STICKY_CLASS " > 0 AND"
    " (excluded.device_class=3 OR excluded.device_class<" DB_STICKY_CLASS ")"
    " THEN " DB_STICKY_CLASS " ELSE excluded.device_class END,"
    "  cam_conflict=CASE WHEN " DB_STICKY_CLASS " > 0 AND"
    " excluded.device_class=3 THEN 1 ELSE excluded.cam_conflict END,"
    /* The rest of #155's output is derived each tick from IP-joined and
     * MAC-keyed rows alike and carries no history of its own: latest. */
    "  cam_score=excluded.cam_score, cam_evidence=excluded.cam_evidence,"
    "  cam_vetoes=excluded.cam_vetoes,"
    "  dhcp_prl=excluded.dhcp_prl, dhcp_vci=excluded.dhcp_vci,"
    "  camera_vendor=COALESCE(NULLIF(excluded.camera_vendor,''),"
    "CASE WHEN devices.cam_signals&18 THEN devices.camera_vendor END),"
    "  camera_model=excluded.camera_model,"
    "  setup_mode=MAX(devices.setup_mode,excluded.setup_mode),"
    "  cam_signals=((devices.cam_signals&18)|excluded.cam_signals),"
    "  first_seen=MIN(devices.first_seen,excluded.first_seen),"
    "  last_seen=MAX(devices.last_seen,excluded.last_seen)",
[ST_PNL_CLIENT] =
    "INSERT INTO pnl_clients (mac,mac_random,probe_count,os_fp,phy,"
    "phy_confirmed,first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"
    " ON CONFLICT(mac) DO UPDATE SET"
    "  mac_random=excluded.mac_random, probe_count=excluded.probe_count,"
    "  os_fp=excluded.os_fp, phy=excluded.phy,"
    /* MAX, not overwrite: corroboration is a fact about the device that
     * a later probe-only observation does not retract (#60). */
    "  phy_confirmed=MAX(pnl_clients.phy_confirmed,excluded.phy_confirmed),"
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
    "downgrade_flags,akm_bits,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,"
    "?18,?19,?20,?21,?22,?23,?24)"
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
    /* OR, not overwrite: an AP that offered a downgrade lane and later
     * stopped still offered it, and that is what history is for. Same
     * reasoning as assoc_reqs.downgrade_flags. */
    "  downgrade_flags=(beacon_aps.downgrade_flags|excluded.downgrade_flags),"
    "  akm_bits=(beacon_aps.akm_bits|excluded.akm_bits),"
    "  first_seen=MIN(beacon_aps.first_seen,excluded.first_seen),"
    "  last_seen=MAX(beacon_aps.last_seen,excluded.last_seen)",
[ST_BEACON_SSID] =
    "INSERT INTO beacon_ap_ssids (bssid,ssid,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4)"
    " ON CONFLICT(bssid,ssid) DO UPDATE SET"
    "  first_seen=MIN(beacon_ap_ssids.first_seen,excluded.first_seen),"
    "  last_seen=MAX(beacon_ap_ssids.last_seen,excluded.last_seen)",
[ST_SSID_AKM] =
    /* akm_bits is part of the primary key, which is the whole design.
     * beacon_aps ORs its akm_bits on conflict and therefore records
     * only that an AP has *ever* offered both families — transition
     * mode and a config regression are indistinguishable there. Keying
     * on the AKM set means each distinct posture gets its own row and
     * its own window, so "was SAE-only for a day, is PSK-only now" is
     * two rows that do not overlap, and transition mode is one row
     * carrying both families. ON CONFLICT can then only ever widen a
     * window, never merge two postures into one. */
    "INSERT INTO ssid_akm_history (ssid,bssid,akm_bits,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5)"
    " ON CONFLICT(ssid,bssid,akm_bits) DO UPDATE SET"
    "  first_seen=MIN(ssid_akm_history.first_seen,excluded.first_seen),"
    "  last_seen=MAX(ssid_akm_history.last_seen,excluded.last_seen)",
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

[ST_ASSOC_REQ] =
    "INSERT INTO assoc_reqs (bssid,sta_mac,requested_ssid,is_reassoc,"
    "listen_interval,akm_bits,pairwise_bits,requested_mfp,supported_rates,"
    "phy,vendor_ie_hash,downgrade_flags,prev_akm_bits,prev_mfp,"
    "first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)"
    " ON CONFLICT(bssid,sta_mac) DO UPDATE SET"
    "  requested_ssid=excluded.requested_ssid,"
    "  is_reassoc=excluded.is_reassoc,"
    "  listen_interval=excluded.listen_interval,"
    "  akm_bits=excluded.akm_bits, pairwise_bits=excluded.pairwise_bits,"
    "  requested_mfp=excluded.requested_mfp,"
    "  supported_rates=excluded.supported_rates,"
    "  phy=excluded.phy, vendor_ie_hash=excluded.vendor_ie_hash,"
    /* A downgrade already recorded is not erased by a later clean
     * request: the client having been moved is the durable fact, and
     * an operator reading history needs it to survive the recovery. */
    "  downgrade_flags=assoc_reqs.downgrade_flags|excluded.downgrade_flags,"
    "  prev_akm_bits=excluded.prev_akm_bits, prev_mfp=excluded.prev_mfp,"
    "  first_seen=MIN(assoc_reqs.first_seen,excluded.first_seen),"
    "  last_seen=MAX(assoc_reqs.last_seen,excluded.last_seen)",

[ST_BTM_REQ] =
    "INSERT INTO btm_requests (bssid,sta_mac,req_count,imminent_count,"
    "last_request_mode,disassoc_timer,validity_interval,candidates,"
    "candidate_count,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
    " ON CONFLICT(bssid,sta_mac) DO UPDATE SET"
    /* MAX, not excluded: the in-memory table is bounded and LRU-evicted,
     * so a pair that ages out and comes back restarts its counters. The
     * file is the longer memory and must not lose the earlier steering
     * — same reason the #42 flow counters upsert with MAX. */
    "  req_count=MAX(btm_requests.req_count,excluded.req_count),"
    "  imminent_count=MAX(btm_requests.imminent_count,"
    "                     excluded.imminent_count),"
    "  last_request_mode=excluded.last_request_mode,"
    "  disassoc_timer=excluded.disassoc_timer,"
    "  validity_interval=excluded.validity_interval,"
    "  candidates=excluded.candidates,"
    "  candidate_count=excluded.candidate_count,"
    "  first_seen=MIN(btm_requests.first_seen,excluded.first_seen),"
    "  last_seen=MAX(btm_requests.last_seen,excluded.last_seen)",

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
    "technique,match_ip,match_port,count,incident_id,incident_count,"
    "incident_first_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?11,?13)"
    " ON CONFLICT(key,first_seen) DO UPDATE SET"
    "  last_seen=MAX(alerts.last_seen,excluded.last_seen),"
    /* The finding's peak severity, and the detail of the latest write
     * at that peak. Latest-wins was the engine's rule for one
     * incident; once a row holds every incident of a key (#170) it
     * let a LOW reopen erase the CRIT before it from the file, and
     * the compactor's MAX(sev) and the live row meant different
     * things. A tie takes the new detail, so a steady finding still
     * shows its current evidence. */
    "  sev=MAX(alerts.sev,excluded.sev),"
    "  detail=CASE WHEN excluded.sev>=alerts.sev"
    "    THEN excluded.detail ELSE alerts.detail END,"
    /* One row per finding (#170). The same incident written again moves
     * `count` by what its own count moved since the last write; a
     * different incident on the row (a reopen, or the first write after
     * a restart or a v7 migration, where the stored id is someone
     * else's or NULL) adds its whole count and is one more reopen.
     * Every SET expression reads the row as it was, so the CASEs agree
     * with each other. */
    "  count=CASE WHEN alerts.incident_id IS excluded.incident_id"
    "    THEN alerts.count+MAX(excluded.incident_count-alerts.incident_count,0)"
    "    ELSE alerts.count+excluded.incident_count END,"
    "  incident_count=CASE WHEN alerts.incident_id IS excluded.incident_id"
    "    THEN MAX(alerts.incident_count,excluded.incident_count)"
    "    ELSE excluded.incident_count END,"
    "  reopens=alerts.reopens+"
    "    (CASE WHEN alerts.incident_id IS excluded.incident_id THEN 0 ELSE 1 END),"
    "  incident_id=excluded.incident_id,"
    "  incident_first_seen=excluded.incident_first_seen",
/* The key's newest row, which the write above continues instead of
 * starting one under the engine's first_seen (#170). The engine keeps
 * first_seen across a reopen in its side table, but that table is LRU
 * bounded and dies with the process; the file is what survives both. A
 * key prefix of the primary key, so an index seek. */
[ST_ALERT_ROW] =
    "SELECT first_seen FROM alerts WHERE key=?1"
    " ORDER BY first_seen DESC LIMIT 1",
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
    "INSERT INTO karma_candidates (bssid,ssid_count,pnl_overlap,pnl_best,"
    "pnl_jaccard_ppm,ie_uniform,deauth_chain,score,top_ssid,"
    "first_seen,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
    " ON CONFLICT(bssid) DO UPDATE SET"
    /* Evidence is high-water: the table is rebuilt from scratch each
     * poll, so a radio that is briefly quiet would otherwise erase the
     * peak that justified the alert. */
    "  ssid_count=MAX(karma_candidates.ssid_count,excluded.ssid_count),"
    "  pnl_overlap=MAX(karma_candidates.pnl_overlap,excluded.pnl_overlap),"
    "  pnl_best=MAX(karma_candidates.pnl_best,excluded.pnl_best),"
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
    "identity_leaks,last_identity,nocert_sessions,nocert_no_hello,"
    "last_nocert_sta,last_nocert_ts,first_seen,last_seen)"
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
    " ON CONFLICT(bssid) DO UPDATE SET"
    /* Offered EAP methods accumulate — an AP that once offered MD5
     * offered it, whatever it advertises on the next handshake. */
    "  eap_types_seen=(rogue_radius.eap_types_seen | excluded.eap_types_seen),"
    "  weak_method=MAX(rogue_radius.weak_method,excluded.weak_method),"
    "  identity_leaks=MAX(rogue_radius.identity_leaks,excluded.identity_leaks),"
    /* MAX for the same reason every other counter here uses it: the
     * in-memory table is bounded and LRU-evicted, so a re-created row
     * restarts at zero and taking `excluded` would erase the sessions
     * that justified an alert still in the alerts table (#65). */
    "  nocert_sessions=MAX(rogue_radius.nocert_sessions,"
    "                      excluded.nocert_sessions),"
    "  nocert_no_hello=MAX(rogue_radius.nocert_no_hello,"
    "                      excluded.nocert_no_hello),"
    "  last_nocert_sta=excluded.last_nocert_sta,"
    "  last_nocert_ts=MAX(rogue_radius.last_nocert_ts,"
    "                     excluded.last_nocert_ts),"
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

/* The migration chain (db.h). Each step takes a file from `from` to
 * `from + 1`. `tables` names every table its statements alter — all of
 * them must already exist for the ALTER to apply, since a file that
 * never got as far as creating one of them has nothing to alter there
 * and the unconditional schema below creates it with every column
 * regardless. A step with no tables (v2 -> v3: a new table rides the
 * unconditional schema, so there is no ALTER at all) always runs its
 * (empty) SQL. One BEGIN IMMEDIATE transaction per step, with that
 * step's stamp, so a crash or a refused statement leaves the file at
 * the last version it fully reached, and the failing step's own
 * changes are not in it. */
typedef struct {
    int                from;
    const char        *(*sql)(void);
    const char *const *tables;   /* NULL-terminated; empty = stamp only */
    const char        *what;     /* for the one-line journal note */
} db_step_t;

static const char *const TABLES_PROBE_CLIENTS[] = { "probe_clients", NULL };
static const char *const TABLES_NONE[]          = { NULL };
static const char *const TABLES_V3_BATCH[]      =
    { "pnl_clients", "beacon_aps", "rogue_radius", NULL };
static const char *const TABLES_KARMA[]    = { "karma_candidates", NULL };
static const char *const TABLES_DEVICES[]  = { "devices", NULL };
static const char *const TABLES_ALERTS[]   = { "alerts", NULL };

static const db_step_t g_steps[] = {
    { 1, db_schema_migrate_v1_sql, TABLES_PROBE_CLIENTS,
      "probe_clients gained presence" },
    { 2, db_schema_migrate_v2_sql, TABLES_NONE,
      "assoc_reqs rides the unconditional schema; stamp only" },
    { 3, db_schema_migrate_v3_sql, TABLES_V3_BATCH,
      "pnl_clients/beacon_aps/rogue_radius gained the #60/#62/#65 columns" },
    { 4, db_schema_migrate_v4_sql, TABLES_KARMA,
      "karma_candidates gained pnl_best" },
    { 5, db_schema_migrate_v5_sql, TABLES_DEVICES,
      "devices gained camera columns" },
    { 6, db_schema_migrate_v6_sql, TABLES_DEVICES,
      "devices gained camera classifier and DHCP option columns" },
    { 7, db_schema_migrate_v7_sql, TABLES_ALERTS,
      "alerts gained reopens, incident_id, incident_count and"
      " incident_first_seen" },
};
#define DB_STEP_N ((int)(sizeof(g_steps) / sizeof(g_steps[0])))
/* The oldest version db_open() upgrades from. */
#define DB_MIGRATES_FROM 1

/* The chain must end at the version this build writes, with no gap. */
typedef char db_steps_reach_current[
    (DB_MIGRATES_FROM + (int)(sizeof(g_steps) / sizeof(g_steps[0])) ==
     DB_SCHEMA_VERSION) ? 1 : -1];

static int have_table(const char *name, int *out) {
    sqlite3_stmt *st = NULL;
    *out = 0;
    if (sqlite3_prepare_v2(g_db,
            "SELECT COUNT(*) FROM sqlite_master"
            " WHERE type='table' AND name=?1", -1, &st, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "sloth: db migration query failed: %s\n",
                sqlite3_errmsg(g_db));
        return 0;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) *out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return 1;
}

static int migrate_step(const db_step_t *step) {
    int ready = 1;
    char stamp[96];
    for (const char *const *t = step->tables; *t; t++) {
        int have = 0;
        if (!have_table(*t, &have)) return 0;
        if (!have) { ready = 0; break; }
    }
    snprintf(stamp, sizeof(stamp),
             "UPDATE meta SET value='%d' WHERE key='schema_version'",
             step->from + 1);
    if (!exec("BEGIN IMMEDIATE", "migration begin")) return 0;
    if ((ready && !exec(step->sql(), "schema migration")) ||
        !exec(stamp, "migration stamp") ||
        !exec("COMMIT", "migration commit")) {
        exec("ROLLBACK", "migration rollback");
        fprintf(stderr, "sloth: db schema v%d could not be migrated to v%d;"
                " the file is unchanged from v%d\n", step->from,
                step->from + 1, step->from);
        return 0;
    }
    fprintf(stderr, "sloth: db schema v%d migrated to v%d (%s; no existing"
            " value changed)\n", step->from, step->from + 1, step->what);
    return 1;
}

static int migrate_from(int have) {
    for (int i = 0; i < DB_STEP_N; i++) {
        if (g_steps[i].from < have) continue;
        if (!migrate_step(&g_steps[i])) return 0;
    }
    return 1;
}

/* Refuse a file written by a newer sloth rather than silently writing
 * rows the other version's readers will misinterpret. An older file is
 * brought forward through the migration chain when its version is on
 * it (DB_MIGRATES_FROM onward), and refused otherwise until its step is
 * written (db.h). */
static int check_version(void) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT value FROM meta WHERE key='schema_version'", -1,
            &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "sloth: db version query failed: %s\n",
                sqlite3_errmsg(g_db));
        return 0;
    }
    int row_found = 0, ok = 1, migrate_from_v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        row_found = 1;
        int have = v ? atoi((const char *)v) : -1;
        if (have >= DB_MIGRATES_FROM && have < DB_SCHEMA_VERSION) {
            migrate_from_v = have;
        } else if (have != DB_SCHEMA_VERSION) {
            fprintf(stderr,
                    "sloth: db schema v%d, this build writes v%d — "
                    "use a separate file\n", have, DB_SCHEMA_VERSION);
            ok = 0;
        }
    }
    sqlite3_finalize(st);
    if (!ok) return 0;
    /* `migrate_from_v` is -1 unless `have` was actually in the
     * migratable range above — kept separate from "a row exists" so a
     * file already at DB_SCHEMA_VERSION is never re-run through
     * migrate_from() on the strength of a reused flag. Seen to fail
     * (reopening a current-version file wrongly re-migrates it, and
     * db_open() refuses it on the second ALTER) when this collapses
     * back to the single `found` variable and DB_MIGRATES_FROM <= 1. */
    if (migrate_from_v >= 0) return migrate_from(migrate_from_v);
    if (!row_found) {
        char sql[128];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO meta (key,value) VALUES "
                 "('schema_version','%d')", DB_SCHEMA_VERSION);
        if (!exec(sql, "version stamp")) return 0;
    }
    return 1;
}

/* ── open / close ────────────────────────────────────────── */

/* SQLite creates a new database 0644 & ~umask, and gives -wal / -shm
 * the main file's mode. So the main file is created (or validated)
 * 0600 here first, by descriptor, and the side files SQLite may find
 * already on disk are checked too: a permissive or symlinked one is
 * refused, never repaired (#87). */
static int db_prepare_private(const char *path) {
    char err[SFILE_ERR_MAX];
    int fd = sfile_open(AT_FDCWD, path, SFILE_APPEND, err, sizeof(err));
    if (fd < 0) {
        fprintf(stderr, "sloth: could not open db %s\n", err);
        return 0;
    }
    close(fd);
    static const char *const side[] = { "-wal", "-shm", "-journal" };
    for (size_t i = 0; i < sizeof(side) / sizeof(side[0]); i++) {
        char p[4096];
        snprintf(p, sizeof(p), "%s%s", path, side[i]);
        if (sfile_check_existing(p, err, sizeof(err)) != 0) {
            fprintf(stderr, "sloth: could not open db %s\n", err);
            return 0;
        }
    }
    return 1;
}

int db_open(const char *path) {
    if (!path || !path[0]) return 0;
    /* The #error above checks the headers; this checks the library the
     * dynamic linker actually loaded, which can be older on a host the
     * binary was copied to (#142). Before anything touches the path:
     * NOFOLLOW is the guard the side-file checks below lean on. */
    char floor_err[96];
    if (libver_sqlite_refuse(floor_err, sizeof(floor_err)) != 0) {
        fprintf(stderr, "sloth: could not open db %s: %s\n", path,
                floor_err);
        return 0;
    }
    if (!db_prepare_private(path)) return 0;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                SQLITE_OPEN_NOFOLLOW;
    if (sqlite3_open_v2(path, &g_db, flags, NULL) != SQLITE_OK) {
        fprintf(stderr, "sloth: could not open db %s: %s\n", path,
                g_db ? sqlite3_errmsg(g_db) : "?");
        sqlite3_close(g_db);
        g_db = NULL;
        return 0;
    }
    /* --db names an operator path, and the file at it may predate this
     * run or have been written by something else (#137). DEFENSIVE
     * shuts the schema-corruption doors (writable_schema, shadow-table
     * writes) that sloth never needs. Only DEFENSIVE here, not the
     * corpus's TRUSTED_SCHEMA=0: this is sloth's own read-write store
     * and its schema is the one db_schema.c writes. Read back, so a
     * library that ignores it fails the open rather than passing it. */
    int defensive = -1;
    if (sqlite3_db_config(g_db, SQLITE_DBCONFIG_DEFENSIVE, 1, &defensive)
            != SQLITE_OK || defensive != 1) {
        fprintf(stderr, "sloth: could not open db %s: DEFENSIVE refused\n",
                path);
        sqlite3_close(g_db);
        g_db = NULL;
        return 0;
    }
    sqlite3_busy_timeout(g_db, DB_BUSY_MS);
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
    /* Version is checked BEFORE the rest of the schema. A file from an
     * incompatible build otherwise fails on whatever statement happens
     * to hit its missing column first, which tells the operator
     * nothing useful — the version message tells them exactly what to
     * do. Hence the meta table alone up front. */
    if (!exec("PRAGMA auto_vacuum=INCREMENTAL", "auto_vacuum") ||
        !exec("PRAGMA journal_mode=WAL", "WAL")            ||
        !exec("PRAGMA synchronous=NORMAL", "synchronous")  ||
        !exec("PRAGMA foreign_keys=ON", "foreign_keys")    ||
        !exec(db_schema_meta_sql(), "meta schema")         ||
        !check_version()                                   ||
        !exec(db_schema_sql(), "schema")) {
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
    g_session_id = 0;
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
    g_session_id = 0;
    g_prev_session_end = 0;
    g_over_ceiling_reported = 0;
    /* The regression cache is evidence from a file we no longer have
     * open. Left behind, sloth keeps reporting a finding it can no
     * longer substantiate — and after a --db swap it would attribute
     * the old file's history to the new one. */
    g_akm_reg_n = 0;
}

int db_is_open(void) { return g_db != NULL && !g_disabled; }

int db_is_defensive(void) {
    int v = -1;
    if (!g_db) return 0;
    sqlite3_db_config(g_db, SQLITE_DBCONFIG_DEFENSIVE, -1, &v);
    return v == 1;
}

void db_set_interval(int secs) {
    (void)tune_set_id(TUNE_DB_INTERVAL_SECS,
                      secs > 0 ? secs : DB_DEFAULT_INTERVAL_S);
}
int db_interval(void) { return (int)tune_val(TUNE_DB_INTERVAL_SECS); }

int db_due(time_t now) {
    if (!db_is_open()) return 0;
    if (g_last_tick == 0) return 1;               /* first tick always */
    if (now < g_last_tick) return 1;              /* clock stepped back */
    return (now - g_last_tick) >= tune_val(TUNE_DB_INTERVAL_SECS);
}

/* ── per-table writers ───────────────────────────────────── */

static void write_devices(const sloth_state_t *s, time_t now) {
    static const uint8_t zmac[6] = {0};
    for (int i = 0; i < s->device_count; i++) {
        const device_t *d = &s->devices[i];
        /* An IP-only camera record (#106 round 2) has no MAC to key the
         * row on; its evidence is in the alerts, mdns_services and
         * ssdp_devices tables, keyed by what it does have. */
        if (memcmp(d->mac, zmac, 6) == 0) continue;
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
        sqlite3_bind_int  (st, 14, (int)d->device_class);
        bind_txt(st, 15, d->camera_vendor);
        bind_txt(st, 16, d->camera_model);
        sqlite3_bind_int  (st, 17, d->setup_mode ? 1 : 0);
        sqlite3_bind_int  (st, 18, d->cam_signal_mask);
        sqlite3_bind_int  (st, 19, d->cam_score);
        sqlite3_bind_int  (st, 20, d->cam_evidence);
        sqlite3_bind_int  (st, 21, d->cam_vetoes);
        sqlite3_bind_int  (st, 22, d->cam_conflict ? 1 : 0);
        bind_txt(st, 23, d->dhcp_prl);
        bind_txt(st, 24, d->dhcp_vci);
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
        sqlite3_bind_int  (st, 6, p->phy_confirmed ? 1 : 0);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)first);
        sqlite3_bind_int64(st, 8, (sqlite3_int64)last);
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
        sqlite3_bind_int  (st, 21, b->downgrade_flags);
        sqlite3_bind_int64(st, 22, (sqlite3_int64)b->akm_bits);
        sqlite3_bind_int64(st, 23, (sqlite3_int64)last);
        sqlite3_bind_int64(st, 24, (sqlite3_int64)last);
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

        /* Posture history (#74). Hidden SSIDs are skipped: the
         * regression this feeds is per-SSID, and every hidden AP would
         * otherwise share the empty name and be compared against every
         * other one. APs with no RSN IE at all (akm_bits 0) carry no
         * posture to record. */
        if (b->ssid[0] && b->akm_bits) {
            sqlite3_stmt *as = g_st[ST_SSID_AKM];
            bind_txt(as, 1, b->ssid);
            bind_txt(as, 2, bssid);
            sqlite3_bind_int64(as, 3, (sqlite3_int64)b->akm_bits);
            sqlite3_bind_int64(as, 4, (sqlite3_int64)last);
            sqlite3_bind_int64(as, 5, (sqlite3_int64)last);
            step_reset(ST_SSID_AKM);
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

static void write_assoc_reqs(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->assoc_req_count; i++) {
        const assoc_req_t *a = &s->assoc_reqs[i];
        char bssid[18], sta[18];
        mac_str(a->bssid, bssid);
        mac_str(a->sta,   sta);
        sqlite3_stmt *st = g_st[ST_ASSOC_REQ];
        bind_txt(st, 1, bssid);
        bind_txt(st, 2, sta);
        bind_txt(st, 3, a->requested_ssid);
        sqlite3_bind_int  (st,  4, a->is_reassoc ? 1 : 0);
        sqlite3_bind_int  (st,  5, a->listen_interval);
        sqlite3_bind_int64(st,  6, (sqlite3_int64)a->akm_bits);
        sqlite3_bind_int64(st,  7, (sqlite3_int64)a->pairwise_bits);
        sqlite3_bind_int  (st,  8, a->requested_mfp);
        sqlite3_bind_int64(st,  9, (sqlite3_int64)a->supported_rates);
        bind_txt(st, 10, a->phy);
        sqlite3_bind_int64(st, 11, (sqlite3_int64)a->vendor_ie_hash);
        sqlite3_bind_int  (st, 12, a->downgrade_flags);
        sqlite3_bind_int64(st, 13, (sqlite3_int64)a->prev_akm_bits);
        sqlite3_bind_int  (st, 14, a->prev_mfp);
        sqlite3_bind_int64(st, 15, (sqlite3_int64)(a->ts ? a->ts : now));
        sqlite3_bind_int64(st, 16, (sqlite3_int64)(a->ts ? a->ts : now));
        step_reset(ST_ASSOC_REQ);
    }
}

/* Join the candidate BSSIDs into one text column. Bounded by
 * construction: MAX_AP_NEIGHBORS entries at 18 chars each. */
static void btm_candidates_str(const btm_steer_t *b, char *out, size_t sz) {
    size_t off = 0;
    out[0] = '\0';
    for (int i = 0; i < b->candidate_count && i < MAX_AP_NEIGHBORS; i++) {
        char one[18];
        mac_str(b->candidates[i], one);
        int n = snprintf(out + off, sz - off, "%s%s", off ? "," : "", one);
        if (n < 0 || (size_t)n >= sz - off) break;
        off += (size_t)n;
    }
}

static void write_btm_requests(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->btm_steer_count; i++) {
        const btm_steer_t *b = &s->btm_steers[i];
        char bssid[18], sta[18], cand[MAX_AP_NEIGHBORS * 18 + 1];
        mac_str(b->bssid, bssid);
        mac_str(b->sta,   sta);
        btm_candidates_str(b, cand, sizeof(cand));
        sqlite3_stmt *st = g_st[ST_BTM_REQ];
        bind_txt(st, 1, bssid);
        bind_txt(st, 2, sta);
        sqlite3_bind_int(st, 3, b->req_count);
        sqlite3_bind_int(st, 4, b->imminent_count);
        sqlite3_bind_int(st, 5, b->last_request_mode);
        sqlite3_bind_int(st, 6, b->last_disassoc_timer);
        sqlite3_bind_int(st, 7, b->last_validity_interval);
        bind_txt(st, 8, cand);
        sqlite3_bind_int(st, 9, b->candidate_count);
        sqlite3_bind_int64(st, 10,
            (sqlite3_int64)(b->first_seen ? b->first_seen : now));
        sqlite3_bind_int64(st, 11,
            (sqlite3_int64)(b->last_seen ? b->last_seen : now));
        step_reset(ST_BTM_REQ);
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

/* The first_seen of `key`'s newest alerts row, or `fallback` when it
 * has none. A lookup error disables the sink like a write error. */
static sqlite3_int64 alert_row_first_seen(const char *key,
                                          sqlite3_int64 fallback) {
    sqlite3_stmt *st = g_st[ST_ALERT_ROW];
    if (!st) return fallback;
    sqlite3_int64 v = fallback;
    bind_txt(st, 1, key);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    else if (rc != SQLITE_DONE) db_fail("alert row lookup");
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    return v;
}

/* Event episodes. Keyed by finding, so an alert that persists for an
 * hour is one row whose count and last_seen advance rather than 3600
 * rows, and a key that is evicted and re-fires, goes quiet and comes
 * back, or outlives a restart is still that one row (#170):
 * docs/wiki/sqlite-schema.md has the incident semantics. */
static void write_events(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->alert_count; i++) {
        const alert_t *a = &s->alerts[i];
        sqlite3_stmt *st = g_st[ST_ALERT];
        /* first_seen <= last_seen is what slothweb's History count
         * leans on (it finds an episode begun after a time by its
         * last_seen, web/src/web_slothdb.h). The engine stamps both
         * from the unclamped wall clock, so across a backward clock
         * step an episode can arrive with last_seen before the row's
         * first_seen; it is stored as having ended where it began. */
        sqlite3_int64 fs = alert_row_first_seen(a->key,
                (sqlite3_int64)(a->first_seen ? a->first_seen : now));
        sqlite3_int64 ls = (sqlite3_int64)(a->last_seen  ? a->last_seen  : now);
        if (ls < fs) ls = fs;
        bind_txt(st, 1, a->key);
        sqlite3_bind_int64(st, 2, fs);
        sqlite3_bind_int64(st, 3, ls);
        sqlite3_bind_int(st, 4, (int)a->type);
        sqlite3_bind_int(st, 5, (int)a->sev);
        bind_txt(st, 6, a->title);
        bind_txt(st, 7, a->detail);
        bind_txt(st, 8, a->technique);
        bind_txt(st, 9, a->match_ip);
        sqlite3_bind_int(st, 10, (int)a->match_port);
        sqlite3_bind_int(st, 11, a->count);
        /* NULL, not "", for an alert with no incident (only a state a
         * test built by hand): "no incident" then compares equal to
         * itself, and is never mistaken for one. */
        if (a->incident_id[0]) bind_txt(st, 12, a->incident_id);
        else                   sqlite3_bind_null(st, 12);
        /* The incident's own start; first_seen is the finding's. */
        sqlite3_bind_int64(st, 13, (sqlite3_int64)(a->first_detected
                ? a->first_detected : (a->first_seen ? a->first_seen : now)));
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
        /* No reason is stored when none was decoded — a PMF body is
         * ciphertext, a truncated one has no field (#88). The column
         * has always been nullable. */
        if (d->reason_valid) sqlite3_bind_int(st, 6, (int)d->reason);
        else                 sqlite3_bind_null(st, 6);
        sqlite3_bind_int(st, 7, (int)d->subtype);
        sqlite3_bind_int(st, 8, d->count);
        /* flood_last too: the threshold may have been met and decayed
         * between two ticks. */
        sqlite3_bind_int(st, 9, (d->flood || d->flood_last) ? 1 : 0);
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
        sqlite3_bind_int(st, 4, k->pnl_best);
        sqlite3_bind_int(st, 5, k->pnl_jaccard_ppm);
        sqlite3_bind_int(st, 6, k->ie_uniform ? 1 : 0);
        sqlite3_bind_int(st, 7, k->deauth_chain ? 1 : 0);
        sqlite3_bind_int(st, 8, k->score);
        bind_txt(st, 9, k->top_ssid);
        sqlite3_bind_int64(st, 10, (sqlite3_int64)last);
        sqlite3_bind_int64(st, 11, (sqlite3_int64)last);
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
        sqlite3_bind_int(st, 6, r->nocert_sessions);
        sqlite3_bind_int(st, 7, r->nocert_no_hello);
        /* The client that accepted no server. A MAC, not key material —
         * the same class of identifier as last_identity above. */
        char nocert_sta[18];
        mac_str(r->last_nocert_sta, nocert_sta);
        bind_txt(st, 8, r->nocert_sessions > 0 ? nocert_sta : "");
        sqlite3_bind_int64(st, 9, (sqlite3_int64)r->last_nocert_ts);
        sqlite3_bind_int64(st, 10, (sqlite3_int64)(r->first_seen ? r->first_seen : now));
        sqlite3_bind_int64(st, 11, (sqlite3_int64)(r->last_seen  ? r->last_seen  : now));
        step_reset(ST_ROGUE_RADIUS);
    }
}

/* ── retention and the size ceiling ──────────────────────── */

void db_set_retain_days(int days) {
    (void)tune_set_id(TUNE_DB_RETAIN_DAYS,
                      days > 0 ? days : DB_DEFAULT_RETAIN_DAYS);
}
int db_retain_days(void) { return (int)tune_val(TUNE_DB_RETAIN_DAYS); }

void db_set_max_mb(int mb) {
    (void)tune_set_id(TUNE_DB_MAX_MB, mb >= 0 ? mb : DB_DEFAULT_MAX_MB);
}
int  db_max_mb(void)       { return (int)tune_val(TUNE_DB_MAX_MB); }

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
    const int retain_days = db_retain_days();
    time_t obs_cutoff  = (time_t)(now - (long long)retain_days * day);
    time_t ent_cutoff  = (time_t)(now - (long long)retain_days * day * 3);
    time_t find_cutoff = (time_t)(now - (long long)retain_days * day * 12);

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
    const int max_mb = db_max_mb();
    if (max_mb <= 0) { g_last_maint = now; return; }
    long long ceiling = (long long)max_mb * 1024 * 1024;

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
                        size / (1024 * 1024), max_mb);
                g_over_ceiling_reported = 1;
            }
            break;
        }
    }
    g_last_maint = now;
}

/* ── survey sessions and the "new since last visit" query (#56) ── */

void db_session_begin(const char *site_label, time_t now) {
    if (!db_is_open()) return;

    /* Remember where the previous visit ended before inserting this
     * one, so "new since last survey" has something to compare to. A
     * session that never recorded an end (a crash, a kill -9) falls
     * back to its start, which is the honest approximation. */
    g_prev_session_end = 0;
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(g_db,
            "SELECT COALESCE(ended, started) FROM sessions"
            " ORDER BY started DESC LIMIT 1", -1, &q, NULL) == SQLITE_OK) {
        if (sqlite3_step(q) == SQLITE_ROW)
            g_prev_session_end = (time_t)sqlite3_column_int64(q, 0);
        sqlite3_finalize(q);
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT INTO sessions (started, site_label) VALUES (?1, ?2)",
            -1, &st, NULL) != SQLITE_OK) { db_fail("session begin"); return; }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)now);
    bind_txt(st, 2, site_label);
    if (sqlite3_step(st) != SQLITE_DONE) db_fail("session begin");
    sqlite3_finalize(st);
    g_session_id = sqlite3_last_insert_rowid(g_db);
}

void db_session_end(time_t now) {
    if (!db_is_open() || g_session_id == 0) return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "UPDATE sessions SET ended = ?1 WHERE id = ?2",
            -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)now);
    sqlite3_bind_int64(st, 2, g_session_id);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

time_t db_previous_session_end(void) { return g_prev_session_end; }

/* (table, identity column, label column) per kind. The label is
 * whatever names the entity to a human reading a report. */
static int new_since_sql(db_new_kind_t kind, char *out, int sz,
                         time_t since, int limit) {
    const char *tbl, *ident, *label;
    switch (kind) {
    case DB_NEW_DEVICE:       tbl = "devices";       ident = "mac";
                              label = "COALESCE(NULLIF(hostname,''),"
                                      " NULLIF(vendor,''), '')"; break;
    case DB_NEW_PROBE_CLIENT: tbl = "probe_clients"; ident = "mac";
                              label = "COALESCE(NULLIF(ssid,''), '')"; break;
    case DB_NEW_BEACON_AP:    tbl = "beacon_aps";    ident = "bssid";
                              label = "COALESCE(NULLIF(ssid,''), '')"; break;
    default: return 0;
    }
    snprintf(out, (size_t)sz,
             "SELECT %s, %s, first_seen FROM %s WHERE first_seen >= %lld"
             " ORDER BY first_seen DESC LIMIT %d",
             ident, label, tbl, (long long)since, limit);
    return 1;
}

int db_new_since(db_new_kind_t kind, time_t since,
                 db_new_entity_t *out, int max) {
    if (!db_is_open() || !out || max <= 0) return 0;
    char sql[512];
    if (!new_since_sql(kind, sql, (int)sizeof(sql), since, max)) return 0;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *id = sqlite3_column_text(st, 0);
        const unsigned char *lb = sqlite3_column_text(st, 1);
        snprintf(out[n].ident, sizeof(out[n].ident), "%s", id ? (const char *)id : "");
        snprintf(out[n].label, sizeof(out[n].label), "%s", lb ? (const char *)lb : "");
        out[n].first_seen = (time_t)sqlite3_column_int64(st, 2);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int db_count_new_since(db_new_kind_t kind, time_t since) {
    if (!db_is_open()) return 0;
    const char *tbl;
    switch (kind) {
    case DB_NEW_DEVICE:       tbl = "devices";       break;
    case DB_NEW_PROBE_CLIENT: tbl = "probe_clients"; break;
    case DB_NEW_BEACON_AP:    tbl = "beacon_aps";    break;
    default: return 0;
    }
    char sql[192];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM %s WHERE first_seen >= %lld",
             tbl, (long long)since);
    long long v = scalar(sql);
    return v < 0 ? 0 : (int)v;
}

/* ── tick ────────────────────────────────────────────────── */


/* ── AKM regression (#74) ────────────────────────────────────────────
 *
 * Recomputed once per tick and cached: a new history row can only
 * appear at a tick, and the alert rule runs every poll. */
static void refresh_akm_regressions(void) {
    g_akm_reg_n = 0;
    if (!g_db) return;

    /* `was` is a SAE-family-only posture sustained across the window;
     * `now` is a PSK-family-only posture on the same (SSID, BSSID) that
     * is the *latest* one recorded there.
     *
     * "Latest" rather than "recent": the claim is that the AP is PSK-only
     * now, and a timestamp comparison against the clock would make the
     * same file answer differently depending on when it was asked. It
     * also stops a network that briefly went PSK a year ago and came
     * back to SAE from firing forever. */
    static const char *sql =
        "SELECT w.ssid, w.bssid, w.akm_bits, w.first_seen, w.last_seen,"
        "       n.akm_bits, n.first_seen"
        "  FROM ssid_akm_history w"
        "  JOIN ssid_akm_history n"
        "    ON n.ssid = w.ssid AND n.bssid = w.bssid"
        " WHERE (w.akm_bits & ?1) != 0 AND (w.akm_bits & ?2) = 0"
        "   AND (n.akm_bits & ?2) != 0 AND (n.akm_bits & ?1) = 0"
        "   AND (w.last_seen - w.first_seen) >= ?3"
        "   AND n.last_seen > w.last_seen"
        /* Keyed on n's own (ssid, bssid), not w's. They are equal by the
         * join, so it reads the same — but written against w it would
         * also be satisfied by a row belonging to a *different* SSID on
         * the same radio whose timestamp happened to match, which is
         * the one-BSSID-many-SSIDs shape KARMA produces. */
        "   AND n.last_seen = (SELECT MAX(m.last_seen) FROM ssid_akm_history m"
        "                       WHERE m.ssid = n.ssid AND m.bssid = n.bssid)"
        " ORDER BY n.first_seen DESC, w.ssid, w.bssid"
        " LIMIT ?4";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)RSN_AKM_SAE_FAMILY);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)RSN_AKM_PSK_FAMILY);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)DB_AKM_SUSTAIN_S);
    sqlite3_bind_int  (st, 4, DB_MAX_AKM_REGRESSIONS);

    while (g_akm_reg_n < DB_MAX_AKM_REGRESSIONS &&
           sqlite3_step(st) == SQLITE_ROW) {
        db_akm_regression_t *r = &g_akm_reg[g_akm_reg_n++];
        memset(r, 0, sizeof(*r));
        const unsigned char *v;
        v = sqlite3_column_text(st, 0);
        snprintf(r->ssid,  sizeof(r->ssid),  "%s", v ? (const char *)v : "");
        v = sqlite3_column_text(st, 1);
        snprintf(r->bssid, sizeof(r->bssid), "%s", v ? (const char *)v : "");
        r->was_akm        = (uint32_t)sqlite3_column_int64(st, 2);
        r->was_first_seen = (time_t)  sqlite3_column_int64(st, 3);
        r->was_last_seen  = (time_t)  sqlite3_column_int64(st, 4);
        r->now_akm        = (uint32_t)sqlite3_column_int64(st, 5);
        r->now_first_seen = (time_t)  sqlite3_column_int64(st, 6);
    }
    sqlite3_finalize(st);
}

int db_akm_regressions(db_akm_regression_t *out, int max) {
    if (!out || max <= 0) return 0;
    int n = g_akm_reg_n < max ? g_akm_reg_n : max;
    for (int i = 0; i < n; i++) out[i] = g_akm_reg[i];
    return n;
}

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
    write_assoc_reqs     (s, now);
    write_btm_requests   (s, now);
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

    /* After COMMIT: the query must see this tick's rows. */
    refresh_akm_regressions();

    /* Hourly, after the write so a maintenance stall never delays the
     * observation it was triggered by. */
    if (g_last_maint == 0) g_last_maint = now;
    else if (now - g_last_maint >= DB_MAINT_INTERVAL_S) db_maintain(now);
}


/* ── --db-compact-alerts (#170) ──────────────────────────────
 *
 * The offline half of #170. A pre-#170 build wrote one alerts row per
 * incident, and an evicted key re-fired as a new incident every few
 * seconds under pressure: 867,748 rows for 7,598 keys on the owner's
 * sensor. The v7 -> v8 step leaves those rows alone (it never rewrites
 * a recorded value), so folding them is this command, and it works on
 * a copy: SRC is opened immutable and nothing is written beside it,
 * DST must not exist, and swapping one for the other is the operator's
 * decision. */

/* SQL run on DST, after it has been brought to the current schema. One
 * row per key: the earliest first_seen, the latest last_seen, the summed
 * count, the peak severity with the detail of the most recent row at
 * that peak (the live writer's rule, ST_ALERT), and reopens = the rows
 * folded beyond the first plus any reopens a v8 row already carried.
 * Everything else that is one observation rather than a total (title,
 * type, technique, match_ip / match_port, the incident join and the
 * incident's start) is the key's most recent row's, as the live writer
 * would have left it. A v7 row's first_seen was its incident's start,
 * so it stands in for the incident_first_seen a v7 row lacks. */
static const char COMPACT_SQL[] =
    /* One streaming pass down the primary key for the totals, and for
     * each key the rowids of its most recent row and of its most
     * recent row at peak severity. A window-function form of the same
     * query sorted all 900,000 rows and took 10 s where this takes a
     * few (tests/test_db.c's timing line). */
    "CREATE TEMP TABLE compact_agg AS"
    " SELECT key, MIN(first_seen) AS fs, MAX(last_seen) AS ls,"
    "  SUM(count) AS cnt, MAX(sev) AS sv,"
    "  COUNT(*) - 1 + SUM(reopens) AS ro,"
    "  (SELECT b.rowid FROM alerts b WHERE b.key = a.key"
    "    ORDER BY b.last_seen DESC, b.first_seen DESC LIMIT 1) AS rid,"
    "  (SELECT b.rowid FROM alerts b WHERE b.key = a.key"
    "    ORDER BY b.sev DESC, b.last_seen DESC, b.first_seen DESC"
    "    LIMIT 1) AS pid"
    " FROM alerts a GROUP BY key;\n"
    "CREATE TEMP TABLE compact_alerts AS"
    " SELECT g.key, g.fs, g.ls, x.type, g.sv, x.title, p.detail,"
    "  x.technique, x.match_ip, x.match_port, g.cnt, g.ro, x.incident_id,"
    "  x.incident_count, COALESCE(x.incident_first_seen, x.first_seen) AS ifs"
    " FROM compact_agg g JOIN alerts x ON x.rowid = g.rid"
    " JOIN alerts p ON p.rowid = g.pid;\n"
    "DELETE FROM alerts;\n"
    "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
    " technique,match_ip,match_port,count,reopens,incident_id,incident_count,"
    " incident_first_seen)"
    " SELECT key, fs, ls, type, sv, title, detail, technique, match_ip,"
    "  match_port, cnt, ro, incident_id, incident_count, ifs"
    " FROM compact_alerts;\n"
    "DROP TABLE compact_alerts;\n"
    "DROP TABLE compact_agg;\n";

static long long scalar_on(sqlite3 *h, const char *sql) {
    sqlite3_stmt *st = NULL;
    long long v = -1;
    if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* DST and the side files SQLite would read beside it. A stale DST-wal
 * left from some other run would be replayed into the copy, so its
 * presence refuses the command as firmly as DST's own. */
static const char *const DB_SIDE[] = { "", "-wal", "-shm", "-journal" };

static void unlink_dst(const char *dst) {
    for (size_t i = 0; i < sizeof(DB_SIDE) / sizeof(DB_SIDE[0]); i++) {
        char p[4096];
        snprintf(p, sizeof(p), "%s%s", dst, DB_SIDE[i]);
        unlink(p);
    }
}

/* "file:" + `path` percent-encoded, with immutable=1: SQLite then
 * reads SRC as a plain file, taking no lock and creating no -shm or
 * -wal beside it (a READONLY open of a WAL-mode file creates both and
 * leaves them, and a stray -wal next to the original is what a swap
 * would later replay). Safe only because db_compact_alerts() has
 * already refused a SRC whose -wal or -journal holds anything, so the
 * main file is the whole database. An absolute path gets the empty
 * authority ("file:///..."), so a path that itself starts "//" is not
 * read as a host name. 1 on success, 0 if it does not fit. */
static int compact_src_uri(const char *path, char *uri, size_t n) {
    static const char hex[] = "0123456789ABCDEF";
    size_t o = (size_t)snprintf(uri, n, "file:%s", path[0] == '/' ? "//" : "");
    for (const unsigned char *c = (const unsigned char *)path; *c; c++) {
        int plain = (*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') ||
                    (*c >= '0' && *c <= '9') || strchr("/._-~", *c);
        if (o + 4 >= n) return 0;
        if (plain) uri[o++] = (char)*c;
        else { uri[o++] = '%'; uri[o++] = hex[*c >> 4]; uri[o++] = hex[*c & 15]; }
    }
    int w = snprintf(uri + o, n - o, "?mode=ro&immutable=1");
    return w > 0 && (size_t)w < n - o;
}

/* Open SRC immutable, check it is a sloth file this build can migrate,
 * count what it holds, and copy it to the (just created, empty) DST
 * with VACUUM INTO. 1 on success. */
static int compact_copy(const char *src, const char *dst,
                        db_compact_stats_t *out) {
    sqlite3 *h = NULL;
    int ok = 0;
    char uri[8192];
    if (!compact_src_uri(src, uri, sizeof(uri))) {
        fprintf(stderr, "sloth: --db-compact-alerts: %s: path too long\n", src);
        return 0;
    }
    if (sqlite3_open_v2(uri, &h, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW |
                        SQLITE_OPEN_URI, NULL) != SQLITE_OK) {
        fprintf(stderr, "sloth: --db-compact-alerts: cannot open %s: %s\n",
                src, h ? sqlite3_errmsg(h) : "?");
        sqlite3_close(h);
        return 0;
    }
    int defensive = -1;
    sqlite3_db_config(h, SQLITE_DBCONFIG_DEFENSIVE, 1, &defensive);
    sqlite3_busy_timeout(h, DB_BUSY_MS);
    long long ver = scalar_on(h, "SELECT CAST(value AS INTEGER) FROM meta"
                              " WHERE key='schema_version'");
    long long has = scalar_on(h, "SELECT COUNT(*) FROM sqlite_master"
                              " WHERE type='table' AND name='alerts'");
    if (defensive != 1) {
        fprintf(stderr, "sloth: --db-compact-alerts: DEFENSIVE refused\n");
    } else if (ver < 1 || ver > DB_SCHEMA_VERSION || has != 1) {
        fprintf(stderr, "sloth: --db-compact-alerts: %s is not a sloth"
                " database this build reads (schema v%lld, alerts table"
                " %s)\n", src, ver, has == 1 ? "present" : "missing");
    } else {
        out->rows_before = scalar_on(h, "SELECT COUNT(*) FROM alerts");
        out->keys        = scalar_on(h, "SELECT COUNT(DISTINCT key) FROM alerts");
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, "VACUUM INTO ?1", -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, dst, -1, SQLITE_STATIC);
            ok = sqlite3_step(st) == SQLITE_DONE;
        }
        if (!ok)
            fprintf(stderr, "sloth: --db-compact-alerts: copy to %s failed:"
                    " %s\n", dst, sqlite3_errmsg(h));
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return ok && out->rows_before >= 0 && out->keys >= 0;
}

int db_compact_alerts(const char *src, const char *dst,
                      db_compact_stats_t *out) {
    db_compact_stats_t local;
    if (!out) out = &local;
    memset(out, 0, sizeof(*out));
    out->rows_before = out->rows_after = out->keys = -1;
    if (!src || !src[0] || !dst || !dst[0]) return -1;
    if (g_db) {
        fprintf(stderr, "sloth: --db-compact-alerts runs offline, without"
                " --db\n");
        return -1;
    }
    char floor_err[96];
    if (libver_sqlite_refuse(floor_err, sizeof(floor_err)) != 0) {
        fprintf(stderr, "sloth: --db-compact-alerts: %s\n", floor_err);
        return -1;
    }
    for (size_t i = 0; i < sizeof(DB_SIDE) / sizeof(DB_SIDE[0]); i++) {
        char p[4096];
        struct stat sb;
        snprintf(p, sizeof(p), "%s%s", dst, DB_SIDE[i]);
        if (lstat(p, &sb) == 0) {
            fprintf(stderr, "sloth: --db-compact-alerts: %s exists; refusing"
                    " to overwrite it (pick a new DST)\n", p);
            return -1;
        }
    }
    /* SRC's own owner, for DST below. lstat: compact_copy()'s open
     * refuses a symlink anyway (NOFOLLOW). */
    struct stat src_sb;
    if (lstat(src, &src_sb) != 0 || !S_ISREG(src_sb.st_mode)) {
        fprintf(stderr, "sloth: --db-compact-alerts: %s: not a regular"
                " file\n", src);
        return -1;
    }
    /* A sensor that was killed rather than stopped leaves its last
     * writes in SRC-wal (or, in rollback mode, a hot SRC-journal). The
     * copy below reads the main file alone (compact_src_uri()), so it
     * would be missing them - and the swap would put the compacted
     * file under that old -wal, which SQLite then replays onto pages
     * it never belonged to: a corrupt database, reproduced on #170's
     * review. An empty -wal is what a clean close may leave. */
    static const char *const SRC_LOG[] = { "-wal", "-journal" };
    for (size_t i = 0; i < sizeof(SRC_LOG) / sizeof(SRC_LOG[0]); i++) {
        char p[4096];
        struct stat sb;
        snprintf(p, sizeof(p), "%s%s", src, SRC_LOG[i]);
        if (lstat(p, &sb) == 0 && sb.st_size > 0) {
            fprintf(stderr, "sloth: --db-compact-alerts: %s holds %lld bytes"
                    " not yet in %s; checkpoint it first (start and stop the"
                    " sensor cleanly, or run sqlite3 %s"
                    " 'PRAGMA wal_checkpoint(TRUNCATE)')\n", p,
                    (long long)sb.st_size, src, src);
            return -1;
        }
    }
    uint64_t t0 = sloth_mono_ms();
    /* Created here, exclusively and 0600, before SQLite sees the path:
     * VACUUM INTO accepts an existing empty file, and creating it first
     * is what gives the copy db_open()'s private mode and closes the
     * window in which another process could plant the name. */
    char err[SFILE_ERR_MAX];
    int fd = sfile_open(AT_FDCWD, dst, SFILE_EXCL, err, sizeof(err));
    if (fd < 0) {
        fprintf(stderr, "sloth: --db-compact-alerts: %s\n", err);
        return -1;
    }
    /* From here DST is ours, and a failure removes it: a half-built
     * copy is not something an operator should find and swap in. fd
     * stays open to the end for the fchown below. */
    if (!compact_copy(src, dst, out) || !db_open(dst)) {
        close(fd);
        unlink_dst(dst);
        return -1;
    }
    int ok = exec("BEGIN IMMEDIATE", "compact begin");
    if (ok && (!exec(COMPACT_SQL, "compact") ||
               !exec("COMMIT", "compact commit"))) {
        exec("ROLLBACK", "compact rollback");
        ok = 0;
    }
    /* The DELETE freed every page the duplicates held; VACUUM returns
     * them, which is most of why the operator is running this. */
    if (ok) ok = exec("VACUUM", "compact vacuum");
    if (ok) out->rows_after = scalar("SELECT COUNT(*) FROM alerts");
    db_close();
    /* Reading a 0600 sloth-owned SRC usually means running this as
     * root, and DST is then root's. The sensor opens --db after it has
     * dropped to its --user account (main.c, privdrop_apply() before
     * db_open()), and db_open() refuses a file owned by anyone else, so
     * a swapped-in root-owned copy would stop the sensor starting. DST
     * goes to SRC's owner instead: the account that already opens SRC.
     * After db_close(), because db_open() above runs as root and holds
     * DST to the same rule. Untested: a test cannot chown without
     * root. */
    if (ok && geteuid() == 0 &&
        fchown(fd, src_sb.st_uid, src_sb.st_gid) != 0) {
        fprintf(stderr, "sloth: --db-compact-alerts: chown %s to %s's owner:"
                " %s\n", dst, src, strerror(errno));
        ok = 0;
    }
    close(fd);
    if (!ok || out->rows_after < 0) { unlink_dst(dst); return -1; }
    out->elapsed_ms = (long long)(sloth_mono_ms() - t0);
    printf("sloth: compacted alerts: %lld rows for %lld keys in %s"
            " -> %lld rows in %s (%lld folded, %.2f s); %s is unchanged\n",
            out->rows_before, out->keys, src, out->rows_after, dst,
            out->rows_before - out->rows_after,
            (double)out->elapsed_ms / 1000.0, src);
    return 0;
}

#endif /* WITH_SQLITE */
