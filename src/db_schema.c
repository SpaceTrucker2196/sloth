/* Schema v1 for the embedded SQLite sink (#42).
 *
 * Kept in its own translation unit, and compiled unconditionally, so
 * the MISSION §2 guardrail tests can assert on the DDL text without
 * linking SQLite. Those tests are the enforcement mechanism for the
 * rules in the comments below — a future column addition that violates
 * one turns the suite red rather than relying on a reviewer noticing.
 *
 * Shape follows the maintainer classification in #42: every high-volume
 * snapshot type collapses to an **entity** table keyed by its natural
 * identity with first_seen / last_seen, so the row count is bounded by
 * the fixed arrays in sloth.h rather than by uptime. Event tables
 * (append-only, SIEM-relevant) and the telemetry types that are dropped
 * entirely are not part of this commit — see db.h.
 *
 * Every table carries first_seen / last_seen. That pair is what turns a
 * snapshot stream into a queryable history: "who was here between 2 and
 * 4 AM" is a range scan, not a log grep. */

#include "db.h"

static const char SCHEMA_SQL[] =
    /* ── meta ────────────────────────────────────────────── */
    "CREATE TABLE IF NOT EXISTS meta ("
    "  key   TEXT PRIMARY KEY,"
    "  value TEXT NOT NULL"
    ");\n"

    /* ── survey sessions (#56) ───────────────────────────── *
     * One row per run. "New since last survey" is a comparison against
     * the previous session's end, and without this the operator would
     * have to remember when they last visited. */
    "CREATE TABLE IF NOT EXISTS sessions ("
    "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  started    INTEGER NOT NULL,"
    "  ended      INTEGER,"
    "  site_label TEXT"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started);\n"

    /* ── devices — synthesised profiles keyed by MAC ──────── */
    "CREATE TABLE IF NOT EXISTS devices ("
    "  mac           TEXT PRIMARY KEY,"
    "  ip            TEXT,"
    "  hostname      TEXT,"
    "  vendor        TEXT,"
    "  last_ssid     TEXT,"
    "  is_ap         INTEGER NOT NULL DEFAULT 0,"
    "  signal_dbm    INTEGER,"
    "  probe_count   INTEGER NOT NULL DEFAULT 0,"
    "  sources       INTEGER NOT NULL DEFAULT 0,"
    "  risk_signals  INTEGER NOT NULL DEFAULT 0,"
    "  risk_level    INTEGER NOT NULL DEFAULT 0,"
    "  first_seen    INTEGER NOT NULL,"
    "  last_seen     INTEGER NOT NULL"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);\n"

    /* ── PNL — the 15%-of-volume type, as <=2048 rows ─────── *
     * Split client/SSID so the SSID set is queryable: "which devices
     * remember network X" is the deanonymisation question, and it is a
     * join here rather than a scan of repeated JSON arrays. */
    "CREATE TABLE IF NOT EXISTS pnl_clients ("
    "  mac         TEXT PRIMARY KEY,"
    "  mac_random  INTEGER NOT NULL DEFAULT 0,"
    "  probe_count INTEGER NOT NULL DEFAULT 0,"
    "  os_fp       TEXT,"
    "  phy         TEXT,"
    "  first_seen  INTEGER NOT NULL,"
    "  last_seen   INTEGER NOT NULL"
    ");\n"
    "CREATE TABLE IF NOT EXISTS pnl_ssids ("
    "  mac        TEXT NOT NULL,"
    "  ssid       TEXT NOT NULL,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (mac, ssid)"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_pnl_ssids_ssid ON pnl_ssids(ssid);\n"

    /* ── probe clients — unassociated 802.11 devices ──────── */
    "CREATE TABLE IF NOT EXISTS probe_clients ("
    "  mac         TEXT PRIMARY KEY,"
    "  ssid        TEXT,"
    "  signal_dbm  INTEGER,"
    "  channel     INTEGER,"
    "  frame_count INTEGER NOT NULL DEFAULT 0,"
    /* presence_class_t (#53) — 0 unknown, 1 passing, 2 visitor,
     * 3 resident. Persisted as the strongest verdict ever reached, so a
     * device that demonstrably drove past stays "passing" in the record
     * even after the trajectory has aged out of the live ring. */
    "  presence    INTEGER NOT NULL DEFAULT 0,"
    "  first_seen  INTEGER NOT NULL,"
    "  last_seen   INTEGER NOT NULL"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_probe_presence ON probe_clients(presence);\n"

    /* ── APs ──────────────────────────────────────────────── *
     * beacon_aps is the passive monitor-mode inventory; wifi_aps is
     * the nl80211 scan list. Kept apart because they are different
     * observations with different trust: one is what we heard on the
     * air, the other is what the kernel reports. */
    "CREATE TABLE IF NOT EXISTS beacon_aps ("
    "  bssid       TEXT PRIMARY KEY,"
    "  ssid        TEXT,"
    "  signal_dbm  INTEGER,"
    "  channel     INTEGER,"
    "  enc         TEXT,"
    "  beacon_ms   INTEGER,"
    "  pairwise    TEXT,"
    "  group_ciph  TEXT,"
    "  akm         TEXT,"
    "  mfp         INTEGER,"
    "  vendor      TEXT,"
    "  has_wps     INTEGER NOT NULL DEFAULT 0,"
    "  wps_state   INTEGER,"
    "  wps_locked  INTEGER,"
    "  phy         TEXT,"
    "  revealed    INTEGER NOT NULL DEFAULT 0,"
    "  frame_count INTEGER NOT NULL DEFAULT 0,"
    "  has_qbss    INTEGER NOT NULL DEFAULT 0,"
    "  qbss_stations  INTEGER,"
    "  qbss_chan_util INTEGER,"
    "  first_seen  INTEGER NOT NULL,"
    "  last_seen   INTEGER NOT NULL"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_beacon_aps_ssid ON beacon_aps(ssid);\n"
    /* Distinct SSIDs per BSSID — the KARMA/PineAP signal, and the
     * multi-VAP topology record. */
    "CREATE TABLE IF NOT EXISTS beacon_ap_ssids ("
    "  bssid      TEXT NOT NULL,"
    "  ssid       TEXT NOT NULL,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (bssid, ssid)"
    ");\n"
    "CREATE TABLE IF NOT EXISTS wifi_aps ("
    "  bssid      TEXT PRIMARY KEY,"
    "  ssid       TEXT,"
    "  signal_dbm INTEGER,"
    "  channel    INTEGER,"
    "  enc        TEXT,"
    "  status     INTEGER,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"

    /* ── stations and associations ───────────────────────── */
    "CREATE TABLE IF NOT EXISTS wifi_stas ("
    "  mac            TEXT PRIMARY KEY,"
    "  signal_dbm     INTEGER,"
    "  tx_rate_kbps   INTEGER,"
    "  rx_rate_kbps   INTEGER,"
    "  connected_secs INTEGER,"
    "  inactive_ms    INTEGER,"
    "  tx_bytes       INTEGER,"
    "  rx_bytes       INTEGER,"
    "  first_seen     INTEGER NOT NULL,"
    "  last_seen      INTEGER NOT NULL"
    ");\n"
    "CREATE TABLE IF NOT EXISTS assocs ("
    "  bssid       TEXT NOT NULL,"
    "  sta_mac     TEXT NOT NULL,"
    "  ssid        TEXT,"
    "  sta_random  INTEGER NOT NULL DEFAULT 0,"
    "  source      INTEGER NOT NULL DEFAULT 0,"
    "  channel     INTEGER,"
    "  signal_dbm  INTEGER,"
    "  frame_count INTEGER NOT NULL DEFAULT 0,"
    "  first_seen  INTEGER NOT NULL,"
    "  last_seen   INTEGER NOT NULL,"
    "  PRIMARY KEY (bssid, sta_mac)"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_assocs_sta ON assocs(sta_mac);\n"

    /* ── multi-radio merge (#21) ──────────────────────────── */
    "CREATE TABLE IF NOT EXISTS wifi_merged ("
    "  entity       TEXT PRIMARY KEY,"
    "  sensor_mask  INTEGER NOT NULL DEFAULT 0,"
    "  seen_by      INTEGER NOT NULL DEFAULT 0,"
    "  best_rssi    INTEGER,"
    "  best_sensor  INTEGER,"
    "  channel      INTEGER,"
    "  freq_mhz     INTEGER,"
    "  observations INTEGER NOT NULL DEFAULT 0,"
    "  first_seen   INTEGER NOT NULL,"
    "  last_seen    INTEGER NOT NULL"
    ");\n"

    /* ── IP-layer entities ───────────────────────────────── */
    "CREATE TABLE IF NOT EXISTS arp ("
    "  ip         TEXT NOT NULL,"
    "  mac        TEXT NOT NULL,"
    "  iface      TEXT,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (ip, mac)"
    ");\n"
    "CREATE TABLE IF NOT EXISTS dhcp_leases ("
    "  ip         TEXT PRIMARY KEY,"
    "  hostname   TEXT,"
    "  expire     INTEGER,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"
    "CREATE TABLE IF NOT EXISTS top_hosts ("
    "  ip         TEXT PRIMARY KEY,"
    "  hostname   TEXT,"
    "  owner      TEXT,"
    "  conn_count INTEGER NOT NULL DEFAULT 0,"
    "  rx_bytes   INTEGER NOT NULL DEFAULT 0,"
    "  tx_bytes   INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"

    /* ── service discovery ───────────────────────────────── */
    "CREATE TABLE IF NOT EXISTS mdns_services ("
    "  instance   TEXT PRIMARY KEY,"
    "  service    TEXT,"
    "  host       TEXT,"
    "  ip         TEXT,"
    "  port       INTEGER,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"
    "CREATE TABLE IF NOT EXISTS nbns_names ("
    "  name       TEXT NOT NULL,"
    "  suffix     INTEGER NOT NULL,"
    "  ip         TEXT,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (name, suffix)"
    ");\n"
    "CREATE TABLE IF NOT EXISTS ssdp_devices ("
    "  usn        TEXT PRIMARY KEY,"
    "  ip         TEXT,"
    "  type       TEXT,"
    "  location   TEXT,"
    "  nts        TEXT,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"

    /* ── IPv6 router advertisements ──────────────────────── */
    "CREATE TABLE IF NOT EXISTS ndp_ras ("
    "  src_ip          TEXT PRIMARY KEY,"
    "  src_mac         TEXT,"
    "  cur_hop_limit   INTEGER,"
    "  flags           INTEGER,"
    "  router_lifetime INTEGER,"
    "  ra_count        INTEGER NOT NULL DEFAULT 0,"
    "  first_seen      INTEGER NOT NULL,"
    "  last_seen       INTEGER NOT NULL"
    ");\n"
    "CREATE TABLE IF NOT EXISTS ndp_ra_prefixes ("
    "  src_ip     TEXT NOT NULL,"
    "  prefix     TEXT NOT NULL,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (src_ip, prefix)"
    ");\n"


    /* ── protocol flows ──────────────────────────────────── *
     * Aggregates per endpoint pair, not per packet: the row is "what
     * has this pair done", which is what the brute-force and burst
     * rules key on. Counters keep a high-water mark on upsert because
     * the in-memory rings reset a flow's counts when it is evicted.
     *
     * MISSION §2 note: identifiers that were exposed in the clear
     * (RDP mstshash usernames, MQTT usernames, SSH server banners) are
     * kept — they are the exposure *fact*, the same call cleartext_cred
     * makes. SNMP community strings are NOT kept, in either the v1/v2c
     * or "last seen" form: a community string is a shared secret, so
     * persisting it in a long-lived general-purpose DB is the same
     * blast-radius trade the schema refuses for PMKIDs. The distinct
     * community *count* is retained, which is what the brute-force
     * detector actually keys on. */
    "CREATE TABLE IF NOT EXISTS bgp_sessions ("
    "  peer_a             TEXT NOT NULL,"
    "  peer_b             TEXT NOT NULL,"
    "  open_count         INTEGER NOT NULL DEFAULT 0,"
    "  update_count       INTEGER NOT NULL DEFAULT 0,"
    "  notification_count INTEGER NOT NULL DEFAULT 0,"
    "  keepalive_count    INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (peer_a, peer_b)"
    ");\n"
    "CREATE TABLE IF NOT EXISTS ssh_flows ("
    "  src_ip        TEXT NOT NULL,"
    "  dst_ip        TEXT NOT NULL,"
    "  banner_count  INTEGER NOT NULL DEFAULT 0,"
    "  server_banner TEXT,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (src_ip, dst_ip)"
    ");\n"
    "CREATE TABLE IF NOT EXISTS rdp_flows ("
    "  src_ip            TEXT NOT NULL,"
    "  dst_ip            TEXT NOT NULL,"
    "  connect_req_count INTEGER NOT NULL DEFAULT 0,"
    "  last_cookie       TEXT,"
    "  proto_mask        INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (src_ip, dst_ip)"
    ");\n"
    "CREATE TABLE IF NOT EXISTS snmp_flows ("
    "  src_ip          TEXT NOT NULL,"
    "  dst_ip          TEXT NOT NULL,"
    "  get_count       INTEGER NOT NULL DEFAULT 0,"
    "  getnext_count   INTEGER NOT NULL DEFAULT 0,"
    "  getbulk_count   INTEGER NOT NULL DEFAULT 0,"
    "  set_count       INTEGER NOT NULL DEFAULT 0,"
    "  response_count  INTEGER NOT NULL DEFAULT 0,"
    "  trap_count      INTEGER NOT NULL DEFAULT 0,"
    "  version         INTEGER,"
    /* count only — see the MISSION §2 note above */
    "  community_count INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (src_ip, dst_ip)"
    ");\n"
    "CREATE TABLE IF NOT EXISTS mqtt_flows ("
    "  src_ip             TEXT NOT NULL,"
    "  dst_ip             TEXT NOT NULL,"
    "  connect_count      INTEGER NOT NULL DEFAULT 0,"
    "  connack_fail_count INTEGER NOT NULL DEFAULT 0,"
    "  subscribe_count    INTEGER NOT NULL DEFAULT 0,"
    "  publish_count      INTEGER NOT NULL DEFAULT 0,"
    "  proto_level        INTEGER,"
    "  last_username      TEXT,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (src_ip, dst_ip)"
    ");\n"
    "CREATE TABLE IF NOT EXISTS ldap_events ("
    "  src_ip           TEXT PRIMARY KEY,"
    "  bind_count       INTEGER NOT NULL DEFAULT 0,"
    "  bind_anon_count  INTEGER NOT NULL DEFAULT 0,"
    "  search_count     INTEGER NOT NULL DEFAULT 0,"
    "  search_ref_count INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"
    "CREATE TABLE IF NOT EXISTS kerb_events ("
    "  src_ip                 TEXT PRIMARY KEY,"
    "  as_req_count           INTEGER NOT NULL DEFAULT 0,"
    "  as_rep_count           INTEGER NOT NULL DEFAULT 0,"
    "  tgs_req_count          INTEGER NOT NULL DEFAULT 0,"
    "  tgs_rep_count          INTEGER NOT NULL DEFAULT 0,"
    "  preauth_required_count INTEGER NOT NULL DEFAULT 0,"
    "  preauth_failed_count   INTEGER NOT NULL DEFAULT 0,"
    "  principal_unknown_count INTEGER NOT NULL DEFAULT 0,"
    "  error_other_count      INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"
    "CREATE TABLE IF NOT EXISTS smb_sessions ("
    "  client_ip   TEXT NOT NULL,"
    "  server_ip   TEXT NOT NULL,"
    "  server_port INTEGER NOT NULL,"
    "  dialect     TEXT,"
    "  obs_count   INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (client_ip, server_ip, server_port)"
    ");\n"


    /* ── events (append-per-episode, SIEM-relevant) ──────── *
     *
     * Keyed by episode identity rather than by tick: an alert that
     * persists for an hour is one row whose count and last_seen
     * advance, not 3600 rows. Same reasoning as the entity tables —
     * the file has to stay bounded to be useful.
     *
     * MISSION §2, enforced by tests in tests/test_db.c:
     *
     *  - cleartext_creds records the *fact* of exposure and the
     *    username, never the password. `pw_observed` is a 0/1 flag and
     *    is named to match the JSONL field exactly; there is no column
     *    a password could occupy.
     *  - eapol_events records that a handshake or PMKID was observed —
     *    `has_pmkid` is likewise a 0/1 flag. The PMKID, ANonce, SNonce
     *    and MIC themselves have no columns anywhere. Crackable
     *    material stays in the --eapol-dir file the operator explicitly
     *    asked for; a long-lived general-purpose DB is the wrong place
     *    to accumulate it. */
    "CREATE TABLE IF NOT EXISTS alerts ("
    "  key        TEXT NOT NULL,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  type       INTEGER NOT NULL,"
    "  sev        INTEGER NOT NULL,"
    "  title      TEXT,"
    "  detail     TEXT,"
    "  technique  TEXT,"
    "  match_ip   TEXT,"
    "  match_port INTEGER,"
    "  count      INTEGER NOT NULL DEFAULT 0,"
    "  PRIMARY KEY (key, first_seen)"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen);\n"
    "CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(sev);\n"

    "CREATE TABLE IF NOT EXISTS cleartext_creds ("
    "  ts          INTEGER NOT NULL,"
    "  src         TEXT NOT NULL,"
    "  dst         TEXT NOT NULL,"
    "  dst_port    INTEGER NOT NULL,"
    "  protocol    TEXT NOT NULL,"
    "  username    TEXT,"
    /* the exposure fact, never the secret */
    "  pw_observed INTEGER NOT NULL DEFAULT 0,"
    "  first_seen  INTEGER NOT NULL,"
    "  last_seen   INTEGER NOT NULL,"
    "  PRIMARY KEY (ts, src, dst, dst_port, protocol)"
    ");\n"

    "CREATE TABLE IF NOT EXISTS eapol_events ("
    "  bssid              TEXT NOT NULL,"
    "  sta_mac            TEXT NOT NULL,"
    "  ts                 INTEGER NOT NULL,"
    "  msg_num            INTEGER NOT NULL,"
    "  ssid               TEXT,"
    /* the observation fact; the material itself has no column */
    "  has_pmkid          INTEGER NOT NULL DEFAULT 0,"
    "  handshake_complete INTEGER NOT NULL DEFAULT 0,"
    "  signal_dbm         INTEGER,"
    "  channel            INTEGER,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (bssid, sta_mac, ts, msg_num)"
    ");\n"

    "CREATE TABLE IF NOT EXISTS deauth_events ("
    "  src        TEXT NOT NULL,"
    "  dst        TEXT NOT NULL,"
    "  bssid      TEXT NOT NULL,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  reason     INTEGER,"
    "  subtype    INTEGER,"
    "  obs_count  INTEGER NOT NULL DEFAULT 0,"
    "  flood      INTEGER NOT NULL DEFAULT 0,"
    "  PRIMARY KEY (src, dst, bssid, first_seen)"
    ");\n"

    "CREATE TABLE IF NOT EXISTS seqnum_correlations ("
    "  mac_a        TEXT NOT NULL,"
    "  mac_b        TEXT NOT NULL,"
    "  mac_a_random INTEGER NOT NULL DEFAULT 0,"
    "  mac_b_random INTEGER NOT NULL DEFAULT 0,"
    "  gap          INTEGER,"
    "  dt_ms        INTEGER,"
    "  a_count      INTEGER NOT NULL DEFAULT 0,"
    "  b_count      INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (mac_a, mac_b)"
    ");\n"

    "CREATE TABLE IF NOT EXISTS twin_episodes ("
    "  ssid               TEXT NOT NULL,"
    "  real_bssid         TEXT NOT NULL,"
    "  twin_bssid         TEXT NOT NULL,"
    "  enc                TEXT,"
    "  real_rssi          INTEGER,"
    "  twin_rssi          INTEGER,"
    "  rssi_swing_dbm     INTEGER,"
    "  attack_in_progress INTEGER NOT NULL DEFAULT 0,"
    "  attacker_oui       INTEGER NOT NULL DEFAULT 0,"
    "  hash_mismatch      INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (ssid, real_bssid, twin_bssid)"
    ");\n"

    /* Flagged entries only (#41): an unflagged scan_entry is one host
     * touching a couple of ports, which is ordinary traffic, and
     * persisting it would put the CDN false positives #41 removed
     * straight back into the durable record. */
    "CREATE TABLE IF NOT EXISTS scan_entries ("
    "  ip         TEXT PRIMARY KEY,"
    "  port_count INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"
    "CREATE TABLE IF NOT EXISTS scan_entry_ports ("
    "  ip         TEXT NOT NULL,"
    "  port       INTEGER NOT NULL,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (ip, port)"
    ");\n"


    /* ── detector evidence (#30 / #31) ───────────────────── *
     *
     * karma_ap_t and rogue_radius_ap_t have no jsonl_emit_* at all —
     * they are TUI-only and vanish on exit. Their alerts fire, so the
     * *fact* that something was detected survives in `alerts`, but the
     * evidence that justified it (SSID/PNL overlap, IE uniformity, the
     * deauth chain, which EAP methods were offered, how many identities
     * leaked) does not. That is the difference between "sloth said this
     * AP was a Pineapple" and being able to show why.
     *
     * Both are bounded tiny — 64 + 32 rows — so this is close to free.
     *
     * MISSION §2: last_identity is a leaked EAP username, not a
     * secret. Same call cleartext_creds makes — the exposure fact and
     * the identifier, never the credential. */
    "CREATE TABLE IF NOT EXISTS karma_candidates ("
    "  bssid           TEXT PRIMARY KEY,"
    "  ssid_count      INTEGER NOT NULL DEFAULT 0,"
    "  pnl_overlap     INTEGER NOT NULL DEFAULT 0,"
    "  pnl_jaccard_ppm INTEGER NOT NULL DEFAULT 0,"
    "  ie_uniform      INTEGER NOT NULL DEFAULT 0,"
    "  deauth_chain    INTEGER NOT NULL DEFAULT 0,"
    "  score           INTEGER NOT NULL DEFAULT 0,"
    "  top_ssid        TEXT,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"
    "CREATE TABLE IF NOT EXISTS rogue_radius ("
    "  bssid          TEXT PRIMARY KEY,"
    "  eap_types_seen INTEGER NOT NULL DEFAULT 0,"
    "  weak_method    INTEGER NOT NULL DEFAULT 0,"
    "  identity_leaks INTEGER NOT NULL DEFAULT 0,"
    "  last_identity  TEXT,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL"
    ");\n"

    /* ── passive sensor registry (#28) ───────────────────── */
    "CREATE TABLE IF NOT EXISTS sensors ("
    "  kind       INTEGER NOT NULL,"
    "  iface      TEXT NOT NULL,"
    "  name       TEXT,"
    "  state      INTEGER NOT NULL DEFAULT 0,"
    "  observed   INTEGER NOT NULL DEFAULT 0,"
    "  first_seen INTEGER NOT NULL,"
    "  last_seen  INTEGER NOT NULL,"
    "  PRIMARY KEY (kind, iface)"
    ");\n";

/* Applied before the version check — see db.h. */
static const char META_SQL[] =
    "CREATE TABLE IF NOT EXISTS meta ("
    "  key   TEXT PRIMARY KEY,"
    "  value TEXT NOT NULL"
    ");\n";

const char *db_schema_sql(void)      { return SCHEMA_SQL; }
const char *db_schema_meta_sql(void) { return META_SQL; }
