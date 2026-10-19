#include <stdio.h>
#include "runner.h"
#include "reset_all.h"
#include "sloth_clock.h"
#include "tui.h"

/* Shared counters — all test files reference these via extern */
int g_pass      = 0;
int g_fail      = 0;
int g_test_fail  = 0;
int g_test_total = 0;

/* Default setUp (#114): every test starts from the same clean slate —
 * every module table sloth_reset_all() knows about, plus the real
 * clock restored — whether or not the test remembers to ask for it.
 * A test with its own extra setup still runs it after this. */
static void default_test_setup(void) {
    sloth_reset_all();
    sloth_clock_test_set(NULL, NULL);
    tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS);
    tui_test_erase();
}

void (*g_test_setup)(void) = default_test_setup;

/* LeakSanitizer reads this hook at exit when the suite is built with
 * -fsanitize=address; in any other build it is an unused function.
 * The offscreen screen (#116) is torn down with endwin() + delscreen(),
 * and libncursesw still keeps one 3.5 KB calloc() from newterm() that
 * no public call frees. Suppressed by module, so only allocations made
 * inside the ncurses libraries match — an allocation sloth makes and
 * leaks has a sloth frame on top of the stack and is still reported.
 * Kept here rather than in an LSAN_OPTIONS file so `make test` under
 * the sanitizer is self-contained and CI needs no change to pick it up. */
const char *__lsan_default_suppressions(void);
const char *__lsan_default_suppressions(void) {
    return "leak:libncursesw.so\n"
           "leak:libtinfo.so\n";
}

void run_parse_tests(void);
void run_rate_tests(void);
void run_state_tests(void);
void run_scenario_tests(void);
void run_conns_tests(void);
void run_wifi_tests(void);
void run_packets_tests(void);
void run_procs_tests(void);
void run_bw_tests(void);
void run_dns_tests(void);
void run_stats_tests(void);
void run_probe_tests(void);
void run_oui_tests(void);
void run_services_tests(void);
void run_arp_tests(void);
void run_pcap_write_tests(void);
void run_iface_graph_tests(void);
void run_geo_tests(void);
void run_dhcp_tests(void);
void run_rtt_tests(void);
void run_tree_tests(void);
void run_scan_tests(void);
void run_dns_snoop_tests(void);
void run_sni_snoop_tests(void);
void run_mdns_snoop_tests(void);
void run_http_snoop_tests(void);
void run_nbns_snoop_tests(void);
void run_dhcp_snoop_tests(void);
void run_quic_snoop_tests(void);
void run_ssdp_snoop_tests(void);
void run_onvif_discovery_tests(void);
void run_beacon_snoop_tests(void);
void run_reg_ie_tests(void);
void run_deauth_snoop_tests(void);
void run_flood_window_tests(void);
void run_clock_seam_tests(void);
void run_poll_tests(void);
void run_http_log_tests(void);
void run_tls_log_tests(void);
void run_quic_log_tests(void);
void run_dns_log_tests(void);
void run_ntp_log_tests(void);
void run_icmp_log_tests(void);
void run_threat_intel_tests(void);
void run_vendor_watchlist_tests(void);
void run_alerts_tests(void);
void run_cleartext_creds_tests(void);
void run_pop3_snoop_tests(void);
void run_imap_snoop_tests(void);
void run_smtp_snoop_tests(void);
void run_device_risk_tests(void);
void run_posture_tests(void);
void run_version_tests(void);
void run_updater_tests(void);
void run_md5_tests(void);
void run_tune_tests(void);
void run_fs_capacity_tests(void);
void run_pcap_format_tests(void);
void run_evidence_export_tests(void);
void run_sha256_tests(void);
void run_devices_tests(void);
void run_beacon_detect_tests(void);
void run_jsonl_tests(void);
void run_filter_tests(void);
void run_alert_pcap_tests(void);
void run_alert_key_tests(void);
void run_alert_rules_tests(void);
void run_ip_owner_tests(void);
void run_dashboard_tests(void);
void run_ip_color_tests(void);
void run_top_hosts_tests(void);
void run_host_cache_tests(void);
void run_probe_pnl_tests(void);
void run_eapol_log_tests(void);
void run_seqnum_track_tests(void);
void run_assoc_track_tests(void);
void run_channel_tests(void);
void run_dga_tests(void);
void run_wifi_oui_attacker_tests(void);
void run_data_socket_tests(void);
void run_osi_tests(void);
void run_chanhop_tests(void);
void run_auth_track_tests(void);
void run_action_snoop_tests(void);
void run_ctrl_frames_tests(void);
void run_dot11_data_tests(void);
void run_dot11_frame_tests(void);
void run_mle_tests(void);
void run_tool_fingerprint_tests(void);
void run_captive_portal_tests(void);
void run_fragattack_tests(void);
void run_research_ingest_tests(void);
void run_research_corpus_tests(void);
void run_docs_consistency_tests(void);
void run_build_recipe_tests(void);
void run_unit_file_tests(void);
void run_ci_pin_tests(void);
void run_libver_tests(void);
void run_research_query_tests(void);
void run_research_mcp_tests(void);
void run_research_view_tests(void);
void run_fragattack_view_tests(void);
void run_wifi_snapshot_tests(void);
void run_wifi_assess_tests(void);
void run_wifi_baseline_tests(void);
void run_sensors_tests(void);
void run_sensor_health_tests(void);
void run_bytes_tests(void);
void run_dot11_ie_tests(void);
void run_rsn_ie_tests(void);
void run_stab_tests(void);
void run_evidence_ring_tests(void);
void run_persist_health_tests(void);
void run_wps_track_tests(void);
void run_pm_forge_tests(void);
void run_queue_evict_tests(void);
void run_wifi_merge_tests(void);
void run_twins_tests(void);
void run_karma_tests(void);
void run_rogue_radius_tests(void);
void run_help_tests(void);
void run_discovery_tests(void);
void run_secure_file_tests(void);
void run_observe_tests(void);
void run_privdrop_tests(void);
void run_wifi_scan_trigger_tests(void);
void run_eap_parse_tests(void);
void run_eap_track_tests(void);
void run_formatter_tests(void);
void run_ndp_snoop_tests(void);
void run_smb_snoop_tests(void);
void run_kerb_snoop_tests(void);
void run_ldap_snoop_tests(void);
void run_bgp_snoop_tests(void);
void run_ssh_snoop_tests(void);
void run_rdp_snoop_tests(void);
void run_snmp_snoop_tests(void);
void run_mqtt_snoop_tests(void);
void run_capture_tests(void);
void run_tui_palette_tests(void);
void run_ownership_tests(void);
void run_inventory_tests(void);
void run_wired_attach_tests(void);
void run_db_tests(void);
void run_presence_tests(void);
void run_transit_tests(void);
void run_radiotap_tests(void);
void run_rf_quality_tests(void);
void run_reset_registry_tests(void);
void run_views_render_tests(void);
void run_capture_path_tests(void);        /* tests/test_capture_path.c (#95) */
void run_poll_capture_path_tests(void);   /* tests/test_poll.c (#113) */

int main(void) {
    printf("sloth test suite\n");
    printf("===============\n");

    /* Views draw through the shipped renderer (#116): an ncurses SCREEN
     * whose output goes to /dev/null, read back with tui_test_line().
     * Without it every TPRINT is printw onto no window, so a failure
     * here fails the run rather than letting each view test pass on an
     * empty screen. */
    if (tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS) != 0) {
        fprintf(stderr, "sloth_test: no offscreen ncurses screen "
                        "(is a terminfo entry for xterm-256color, xterm, "
                        "vt100 or dumb installed?)\n");
        return 2;
    }

    run_parse_tests();
    run_rate_tests();
    run_state_tests();
    run_scenario_tests();
    run_conns_tests();
    run_wifi_tests();
    run_packets_tests();
    run_procs_tests();
    run_bw_tests();
    run_dns_tests();
    run_stats_tests();
    run_probe_tests();
    run_oui_tests();
    run_services_tests();
    run_arp_tests();
    run_pcap_write_tests();
    run_iface_graph_tests();
    run_geo_tests();
    run_dhcp_tests();
    run_rtt_tests();
    run_tree_tests();
    run_scan_tests();
    run_dns_snoop_tests();
    run_sni_snoop_tests();
    run_mdns_snoop_tests();
    run_http_snoop_tests();
    run_nbns_snoop_tests();
    run_dhcp_snoop_tests();
    run_quic_snoop_tests();
    run_ssdp_snoop_tests();
    run_onvif_discovery_tests();
    run_beacon_snoop_tests();
    run_reg_ie_tests();
    run_deauth_snoop_tests();
    run_flood_window_tests();
    run_clock_seam_tests();
    run_poll_tests();
    run_http_log_tests();
    run_tls_log_tests();
    run_quic_log_tests();
    run_dns_log_tests();
    run_ntp_log_tests();
    run_icmp_log_tests();
    run_threat_intel_tests();
    run_vendor_watchlist_tests();
    run_alerts_tests();
    run_cleartext_creds_tests();
    run_pop3_snoop_tests();
    run_imap_snoop_tests();
    run_smtp_snoop_tests();
    run_device_risk_tests();
    run_posture_tests();
    run_version_tests();
    run_updater_tests();
    run_md5_tests();
    run_tune_tests();
    run_fs_capacity_tests();
    run_pcap_format_tests();
    run_evidence_export_tests();
    run_sha256_tests();
    run_devices_tests();
    run_beacon_detect_tests();
    run_jsonl_tests();
    run_filter_tests();
    run_alert_pcap_tests();
    run_alert_key_tests();
    run_alert_rules_tests();
    run_ip_owner_tests();
    run_dashboard_tests();
    run_ip_color_tests();
    run_top_hosts_tests();
    run_host_cache_tests();
    run_probe_pnl_tests();
    run_eapol_log_tests();
    run_seqnum_track_tests();
    run_assoc_track_tests();
    run_channel_tests();
    run_dga_tests();
    run_wifi_oui_attacker_tests();
    run_data_socket_tests();
    run_osi_tests();
    run_chanhop_tests();
    run_auth_track_tests();
    run_action_snoop_tests();
    run_ctrl_frames_tests();
    run_dot11_data_tests();
    run_dot11_frame_tests();
    run_mle_tests();
    run_tool_fingerprint_tests();
    run_captive_portal_tests();
    run_fragattack_tests();
    run_research_ingest_tests();
    run_research_corpus_tests();
    run_docs_consistency_tests();
    run_build_recipe_tests();
    run_unit_file_tests();
    run_ci_pin_tests();
    run_libver_tests();
    run_research_query_tests();
    run_research_mcp_tests();
    run_research_view_tests();
    run_fragattack_view_tests();
    run_wifi_snapshot_tests();
    run_wifi_assess_tests();
    run_wifi_baseline_tests();
    run_sensors_tests();
    run_sensor_health_tests();
    run_bytes_tests();
    run_dot11_ie_tests();
    run_rsn_ie_tests();
    run_stab_tests();
    run_evidence_ring_tests();
    run_persist_health_tests();
    run_wps_track_tests();
    run_pm_forge_tests();
    run_queue_evict_tests();
    run_wifi_merge_tests();
    run_twins_tests();
    run_karma_tests();
    run_rogue_radius_tests();
    run_help_tests();
    run_discovery_tests();
    run_secure_file_tests();
    run_observe_tests();
    run_privdrop_tests();
    run_wifi_scan_trigger_tests();
    run_eap_parse_tests();
    run_eap_track_tests();
    run_formatter_tests();
    run_ndp_snoop_tests();
    run_smb_snoop_tests();
    run_kerb_snoop_tests();
    run_ldap_snoop_tests();
    run_bgp_snoop_tests();
    run_ssh_snoop_tests();
    run_rdp_snoop_tests();
    run_snmp_snoop_tests();
    run_mqtt_snoop_tests();
    run_capture_tests();
    run_tui_palette_tests();
    run_ownership_tests();
    run_inventory_tests();
    run_wired_attach_tests();
    run_db_tests();
    run_presence_tests();
    run_transit_tests();
    run_radiotap_tests();
    run_rf_quality_tests();
    run_reset_registry_tests();
    run_views_render_tests();
    run_capture_path_tests();
    run_poll_capture_path_tests();

    tui_offscreen_end();
    RUNNER_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
