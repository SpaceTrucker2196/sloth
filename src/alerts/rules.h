#ifndef SLOTH_ALERTS_RULES_H
#define SLOTH_ALERTS_RULES_H

#include <time.h>
#include "sloth.h"
#include "alert_quality.h"

/* The ordered rule table (#118).
 *
 * alerts_update() was a hand-written sequence of 68 calls; it is now a
 * loop over g_alert_rules[], defined in src/alerts/rules_table.c and
 * nowhere else. Each row carries the rule's own name so a test can pin
 * the order dependencies by name rather than by position
 * (tests/test_alert_rules.c), and so a row that is missing or doubled
 * is caught against the rule definitions themselves.
 *
 * Not a registry: no constructor attributes, no self-registration. A
 * rule that is defined and not listed in the table is a red suite, not
 * a silently dead detector. */
typedef void (*alert_rule_fn)(const sloth_state_t *, time_t);

typedef struct {
    const char   *name;
    alert_rule_fn fn;
} alert_rule_t;

/* The per-alert pcap exporters, as the engine calls them (#213). Both
 * write captured frames: src/alert_pcap.c the IP packets of a match_ip
 * (--pcap-dir), src/evidence_export.c the 802.11 frames an alert cites
 * (--collect-handshakes and --eapol-dir). They belong to the table and
 * not to the engine so that a daemon with no capture links neither. */
struct loc_stamp;
typedef struct {
    int (*ip_enabled)(void);
    int (*ip_dump)(const sloth_state_t *s, const alert_t *a,
                   char *out_path, int out_sz);
    int (*ev_enabled)(void);
    int (*ev_alert_name)(const char *incident_id, uint64_t event_id,
                         const char *rule, char *out, size_t outsz);
    int (*ev_pcap_unique)(const char *name, const uint64_t *ids, int n,
                          int *skipped,
                          const char *incident_id, const char *rule,
                          const struct loc_stamp *loc,
                          char *name_out, size_t name_outsz,
                          char *err, size_t errsz);
    int (*ev_path)(const char *name, char *out, size_t outsz);
    /* SHA-256 of a file each wrote, by bare name, through the directory
     * descriptor it wrote through (#251's pcap_sha256). */
    int (*ip_sha256)(const char *name, char hex[65]);
    int (*ev_sha256)(const char *name, char hex[65]);
} alert_exporter_t;

/* A rule table is data the application selects (#213), as its poll
 * stage table is (src/poll.h): the rows in run order, the functions
 * that drop the history those rows keep between ticks (alerts_clear()
 * calls each), and the exporters, NULL for none.
 *
 *   g_alert_table_wifi   the capture's, the monitor radio's and
 *                        BLE's rules, SENSOR_UNDERVOLT and
 *                        SENSOR_SOURCE_DOWN - sloth-wifi    rules_table.c
 *   g_alert_table_rf     the GNSS rules, ADSB_EMERGENCY and
 *                        SENSOR_SOURCE_DOWN - sloth-rf      rules_table_rf.c
 *
 * They share one row, rule_sensor_source_down, which judges whichever
 * source rows its daemon reports; tests/test_rf_rules.c holds that, and
 * that the GNSS rules and ADSB_EMERGENCY are in the second only (#216).
 * SENSOR_UNDERVOLT is in the first only: the host has one supply, and
 * on a host running both daemons only the one with the capture reports
 * it (owner ruling 2026-11-15, ADR 0010). */
typedef struct {
    const alert_rule_t        *rules;
    int                        count;
    void               (*const *forget)(void);
    int                        forget_count;
    const alert_exporter_t    *exporter;
    /* What an incident's cited frames say, for its quality fields
     * (#246, src/alert_quality.h): the table's for the reason the
     * exporters are, the evidence ring being capture code. NULL for
     * none, and a finding then carries no latency or corroboration. */
    aq_evidence_fn             evidence;
} alert_rule_table_t;

extern const alert_rule_table_t g_alert_table_wifi;
extern const alert_rule_table_t g_alert_table_rf;

/* Select the table alerts_update() runs. Once, at start, before the
 * first tick and on the thread that ticks; NULL selects none. */
void alerts_set_table(const alert_rule_table_t *t);
const alert_rule_table_t *alerts_table(void);

/* The selected table's rows (src/alerts/engine.c): NULL and 0 until a
 * table is selected. */
extern const alert_rule_t *g_alert_rules;
extern int                 g_alert_rule_count;

/* src/alerts/rules_wired.c */
void rule_port_scan(const sloth_state_t *s, time_t now);
void rule_nxdomain_burst(const sloth_state_t *s, time_t now);
void rule_arp_spoof(const sloth_state_t *s, time_t now);
void rule_cleartext_cred(const sloth_state_t *s, time_t now);
void rule_weak_tls(const sloth_state_t *s, time_t now);
void rule_attack_path(const sloth_state_t *s, time_t now);
void rule_attack_tool_ua(const sloth_state_t *s, time_t now);
void rule_dns_tunnel(const sloth_state_t *s, time_t now);
void rule_icmp_tunnel(const sloth_state_t *s, time_t now);
void rule_cam_ws_discovery(const sloth_state_t *s, time_t now);
void rule_surv_cloud_sni(const sloth_state_t *s, time_t now);
void rule_surv_dns(const sloth_state_t *s, time_t now);
void rule_cam_rtsp_unauth(const sloth_state_t *s, time_t now);
void rule_rogue_dhcp(const sloth_state_t *s, time_t now);
void rule_rogue_ra(const sloth_state_t *s, time_t now);
void rule_smb1_use(const sloth_state_t *s, time_t now);
void rule_kerb_preauth_burst(const sloth_state_t *s, time_t now);
void rule_ldap_search_flood(const sloth_state_t *s, time_t now);
void rule_bgp_notification_burst(const sloth_state_t *s, time_t now);
void rule_ssh_brute_force(const sloth_state_t *s, time_t now);
void rule_rdp_brute_force(const sloth_state_t *s, time_t now);
void rule_snmp_community_brute(const sloth_state_t *s, time_t now);
void rule_mqtt_broker_brute(const sloth_state_t *s, time_t now);
void rule_dga_domain(const sloth_state_t *s, time_t now);
void rule_threat_domain(const sloth_state_t *s, time_t now);
void rule_threat_ip(const sloth_state_t *s, time_t now);
void rule_beaconing(const sloth_state_t *s, time_t now);

/* src/alerts/rules_twin.c. The open-hotspot guardrail OPEN_SETUP_AP and
 * CAM_SETUP_SSID both check before their pattern tables; exported so
 * src/camera_join.c applies it in the same place and the Devices view
 * never marks a setup SSID the rule itself stays quiet on. */
int ssid_is_public_hotspot(const char *ssid);

/* src/alerts/rules_camera.c (#106 slice A) */
void rule_cam_mdns_service(const sloth_state_t *s, time_t now);
void rule_cam_ssdp_device(const sloth_state_t *s, time_t now);
void rule_cam_setup_oui(const sloth_state_t *s, time_t now);

/* src/alerts/rules_wifi_mgmt.c */
void rule_deauth_flood(const sloth_state_t *s, time_t now);
void rule_beacon_flood(const sloth_state_t *s, time_t now);
void rule_auth_flood(const sloth_state_t *s, time_t now);
void rule_assoc_flood(const sloth_state_t *s, time_t now);
void rule_btm_abuse(const sloth_state_t *s, time_t now);
void rule_blockack_attack(const sloth_state_t *s, time_t now);
void rule_sa_query_flood(const sloth_state_t *s, time_t now);
void rule_mfp_unprotected(const sloth_state_t *s, time_t now);
void rule_rts_flood(const sloth_state_t *s, time_t now);
void rule_rrm_survey_abuse(const sloth_state_t *s, time_t now);
void rule_csa_abuse(const sloth_state_t *s, time_t now);
void rule_tpc_absent_high_band(const sloth_state_t *s, time_t now);
void rule_country_absent(const sloth_state_t *s, time_t now);   /* rules_regulatory.c */
void rule_dfs_masking(const sloth_state_t *s, time_t now);      /* rules_regulatory.c */
void rule_no_monitor_mode(const sloth_state_t *s, time_t now);
void rule_bt_own_transmit(const sloth_state_t *s, time_t now);   /* rules_ble.c (#144) */
void rule_ble_adv_flood(const sloth_state_t *s, time_t now);     /* rules_ble.c (#144 slice 4) */
void rule_ble_hid_unexpected(const sloth_state_t *s, time_t now);/* rules_ble.c (#144 slice 4) */
void rule_ble_watchlist(const sloth_state_t *s, time_t now);     /* rules_ble.c (#144 slice 4) */
void rule_probe_flood(const sloth_state_t *s, time_t now);
void rule_my_network_recon(const sloth_state_t *s, time_t now);
void rule_recurring_transit(const sloth_state_t *s, time_t now);
void rule_unknown_device(const sloth_state_t *s, time_t now);
void rule_rf_degraded(const sloth_state_t *s, time_t now);
void rule_pm_forge(const sloth_state_t *s, time_t now);
void rule_queue_evict(const sloth_state_t *s, time_t now);
void rule_mgmt_fuzz(const sloth_state_t *s, time_t now);

/* src/alerts/rules_twin.c */
void rule_captive_portal(const sloth_state_t *s, time_t now);
void rule_fragattack(const sloth_state_t *s, time_t now);
void rule_sae_psk_split(const sloth_state_t *s, time_t now);
void rule_sae_psk_regression(const sloth_state_t *s, time_t now);
void rule_wpa_downgrade(const sloth_state_t *s, time_t now);
void rule_karma_ap(const sloth_state_t *s, time_t now);
void rule_karma_probe_forge(const sloth_state_t *s, time_t now);
/* src/alerts/rules_harvest.c (#172) */
void rule_pmkid_harvest(const sloth_state_t *s, time_t now);
void rule_handshake_harvest(const sloth_state_t *s, time_t now);
void rule_open_setup_ap(const sloth_state_t *s, time_t now);
void rule_cam_setup_ssid(const sloth_state_t *s, time_t now);
void rule_evil_twin(const sloth_state_t *s, time_t now);
void rule_ssid_confusion(const sloth_state_t *s, time_t now);
void rule_evil_twin_proximity(const sloth_state_t *s, time_t now);
void rule_evil_twin_attack_chain(const sloth_state_t *s, time_t now);

/* src/alerts/rules_enterprise.c */
void rule_wps_pin_brute(const sloth_state_t *s, time_t now);
void rule_wps_lockout_cycling(const sloth_state_t *s, time_t now);
void rule_wps_pbc_race(const sloth_state_t *s, time_t now);
void rule_wps_pixie_probe(const sloth_state_t *s, time_t now);
void rule_wps_pixie_likely_success(const sloth_state_t *s, time_t now);
void rule_rogue_radius(const sloth_state_t *s, time_t now);
void rule_peap_no_server_cert(const sloth_state_t *s, time_t now);

/* src/alerts/rules_mle.c */
void rule_mle_invalid_link_id(const sloth_state_t *s, time_t now);
void rule_mle_common_info_len_bad(const sloth_state_t *s, time_t now);
void rule_mle_subelem_overrun(const sloth_state_t *s, time_t now);
void rule_mld_mac_collision(const sloth_state_t *s, time_t now);
void rule_mle_cross_link_cipher_downgrade(const sloth_state_t *s, time_t now);
void rule_mle_reconfig_no_mlo(const sloth_state_t *s, time_t now);
void rule_mle_pr_beacon_diff(const sloth_state_t *s, time_t now);

/* src/alerts/rules_gnss.c (2026-11-03): the --gps receiver's own inputs */
void rule_gnss_jamming(const sloth_state_t *s, time_t now);
void rule_gnss_spoof_suspect(const sloth_state_t *s, time_t now);
void rule_gnss_time_jump(const sloth_state_t *s, time_t now);
void rule_gnss_position_jump(const sloth_state_t *s, time_t now);

/* src/alerts/rules_adsb.c (#186): the --adsb decoder's aircraft table */
void rule_adsb_emergency(const sloth_state_t *s, time_t now);

/* src/alerts/rules_sensor.c (2026-11-11): the sensor's own state, read
 * off sys_status_get(). The spans are the rule file's to justify. */
#define SENSOR_RECOVER_S        120   /* clear this long before `recovered` */
#define SENSOR_SRC_DOWN_HOLD_S  10    /* `down` this long opens */
#define SENSOR_SRC_STALE_S      300   /* not `ok` this long opens */
void rule_sensor_undervolt(const sloth_state_t *s, time_t now);
void rule_sensor_source_down(const sloth_state_t *s, time_t now);
/* SENSOR_SUPPRESSED (#242 item 4): sloth-wifi's table only - it reads
 * the capture handles' counters, the synthesis tables' eviction tally
 * and the per-interval coverage record, none of which sloth-rf has. */
void rule_sensor_suppressed(const sloth_state_t *s, time_t now);
/* What its open incidents say the sensor is losing, for the coverage
 * environment (src/rule_coverage_capture.c): `inputs` gets
 * 1u << cov_input_t of each input a signal suppresses, `frames` the
 * COV_F_* classes of an evicting 802.11 table. 0 and 0 with none open. */
void rules_sensor_suppressed(unsigned *inputs, unsigned *frames);
/* Everything rules_sensor.c keeps, the channels SENSOR_SUPPRESSED has
 * heard this run included, which alerts_clear() keeps (the test
 * registry's, src/reset_all.h: a new run starts from nothing). */
void rules_sensor_reset(void);
#endif
