#ifndef SLOTH_ALERTS_RULES_H
#define SLOTH_ALERTS_RULES_H

#include <time.h>
#include "sloth.h"

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

extern const alert_rule_t g_alert_rules[];
extern const int          g_alert_rule_count;

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
#endif
