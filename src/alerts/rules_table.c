/* THE rule order (#118). A verbatim copy of the hand-written sequence
 * alerts_update() carried before the split, and nothing else lives here.
 *
 * The order is load-bearing, which is why it is one list in one file:
 *
 *   1. JSONL event order within a tick is what a consumer sees. Two
 *      findings raised in the same poll reach the stream in this order.
 *   2. rule_evil_twin_attack_chain taints the rogue half of a pair, and
 *      twin_choose_sides() reads that taint when rule_evil_twin
 *      attributes the pair. Running rule_evil_twin first means the taint
 *      is read on the NEXT tick, as it always has been. The chain's
 *      finding cites a deauth flood, and rule_deauth_flood runs before
 *      it so the DEAUTH_FLOOD it cites reaches the stream first.
 *   3. wifi_downgrade_update() derives the posture rule_wpa_downgrade
 *      reads. It is not a rule and is not in this table: alerts_update()
 *      calls it before the loop.
 *
 * tests/test_alert_rules.c pins (2) and (3) by name and holds the table
 * to the rule definitions under src/alerts/. A new rule goes in once,
 * here, at the position its dependencies need; the end is the right
 * answer when it has none. */
#include "rules.h"

#define R(fn) { #fn, fn }

const alert_rule_t g_alert_rules[] = {
    R(rule_port_scan),
    R(rule_deauth_flood),
    R(rule_nxdomain_burst),
    R(rule_threat_domain),
    R(rule_dga_domain),
    R(rule_arp_spoof),
    R(rule_rogue_dhcp),
    R(rule_rogue_ra),
    R(rule_smb1_use),
    R(rule_kerb_preauth_burst),
    R(rule_ldap_search_flood),
    R(rule_bgp_notification_burst),
    R(rule_ssh_brute_force),
    R(rule_rdp_brute_force),
    R(rule_icmp_tunnel),
    R(rule_snmp_community_brute),
    R(rule_mqtt_broker_brute),
    R(rule_evil_twin),
    R(rule_evil_twin_proximity),
    R(rule_evil_twin_attack_chain),
    R(rule_karma_ap),
    R(rule_open_setup_ap),
    R(rule_cam_setup_ssid),
    R(rule_cam_ws_discovery),
    R(rule_surv_cloud_sni),
    R(rule_surv_dns),
    R(rule_wps_pin_brute),
    R(rule_wps_lockout_cycling),
    R(rule_wps_pbc_race),
    R(rule_wps_pixie_probe),
    R(rule_wps_pixie_likely_success),
    R(rule_pm_forge),
    R(rule_queue_evict),
    R(rule_mle_invalid_link_id),
    R(rule_mle_common_info_len_bad),
    R(rule_mle_subelem_overrun),
    R(rule_mld_mac_collision),
    R(rule_mle_cross_link_cipher_downgrade),
    R(rule_mle_reconfig_no_mlo),
    R(rule_mle_pr_beacon_diff),
    R(rule_ssid_confusion),
    R(rule_mgmt_fuzz),
    R(rule_rogue_radius),
    R(rule_peap_no_server_cert),
    R(rule_beacon_flood),
    R(rule_auth_flood),
    R(rule_assoc_flood),
    R(rule_btm_abuse),
    R(rule_wpa_downgrade),
    R(rule_tpc_absent_high_band),
    R(rule_csa_abuse),
    R(rule_rrm_survey_abuse),
    R(rule_rts_flood),
    R(rule_captive_portal),
    R(rule_fragattack),
    R(rule_sae_psk_split),
    R(rule_sae_psk_regression),
    R(rule_sa_query_flood),
    R(rule_mfp_unprotected),
    R(rule_blockack_attack),
    R(rule_dns_tunnel),
    R(rule_probe_flood),
    R(rule_my_network_recon),
    R(rule_recurring_transit),
    R(rule_unknown_device),
    R(rule_rf_degraded),
    R(rule_attack_tool_ua),
    R(rule_attack_path),
    R(rule_weak_tls),
    R(rule_no_monitor_mode),
    R(rule_cleartext_cred),
    R(rule_threat_ip),
    R(rule_beaconing),
};

#undef R

const int g_alert_rule_count =
    (int)(sizeof(g_alert_rules) / sizeof(g_alert_rules[0]));
