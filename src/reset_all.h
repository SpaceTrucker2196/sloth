#ifndef RESET_ALL_H
#define RESET_ALL_H

/* Test-only registry of every module-level static table's full-reset
 * function (#114). The point: a test author no longer has to remember
 * which of 70+ module clears their test's state touches — forgetting
 * one used to leak state silently into the next test, with nothing
 * to catch it. tests/main_test.c points RUN_TEST's setUp hook at
 * sloth_reset_all() so every test starts from the same clean slate
 * whether its author asked for that or not.
 *
 * Never resets `g_incident_seq` (src/alerts/engine.c) — that counter is
 * monotonic for the whole process lifetime by design (an incident ID
 * must never repeat within a run), so a blanket reset would silently
 * defeat any test that proves IDs never collide.
 *
 * SLOTH_RESETS is also the completeness list tests/test_reset_registry.c
 * checks against every `_clear(void)` / `_reset(void)` declared under
 * src (recursively) and include's headers. A declared reset deliberately
 * NOT here belongs in that test's own exclusion list, with a reason —
 * not silently dropped. Today there are none: `probe_clear` was the
 * one, while src/capture/probe.c was linked only into the separate
 * capture-path binary, and since #116 sloth_test links it. */
#define SLOTH_RESETS(X) \
    X(action_clear) \
    X(action_mfp_clear) \
    X(alerts_clear) \
    X(assoc_clear) \
    X(assoc_flood_clear) \
    X(assoc_request_clear) \
    X(auth_clear) \
    X(bd_clear) \
    X(beacon_clear) \
    X(bgp_snoop_clear) \
    X(ble_clear) \
    X(ble_flood_clear) \
    X(ble_rot_reset) \
    X(ble_watchlist_reset) \
    X(bt_stream_clear) \
    X(btm_clear) \
    X(bw_reset) \
    X(capture_ifname_cache_reset) \
    X(capture_out_of_scope_dropped_reset) \
    X(cleartext_creds_reset) \
    X(cp_clear) \
    X(csa_clear) \
    X(ctrl_clear) \
    X(dashboard_info_clear) \
    X(data_socket_cleanup) \
    X(db_close) \
    X(deauth_clear) \
    X(dhcp_snoop_clear) \
    X(dns_log_clear) \
    X(dns_reset) \
    X(dns_resolver_stats_reset) \
    X(eap_track_clear) \
    X(eapol_clear) \
    X(evidence_ring_reset) \
    X(evidence_manifest_reset) \
    X(evil_twin_taint_clear) \
    X(frag_clear) \
    X(host_cache_clear) \
    X(http_log_clear) \
    X(icmp_log_clear) \
    X(inventory_clear) \
    X(ip_index_clear) \
    X(jsonl_dedup_reset) \
    X(lan_role_clear) \
    X(kerb_snoop_clear) \
    X(ldap_snoop_clear) \
    X(linux_wifi_scan_trigger_reset) \
    X(mdns_clear) \
    X(mle_clear) \
    X(mqtt_snoop_clear) \
    X(nbns_clear) \
    X(ndp_snoop_clear) \
    X(ntp_log_clear) \
    X(onvif_clear) \
    X(ownership_clear) \
    X(pm_forge_clear) \
    X(probe_clear) \
    X(probe_pnl_clear) \
    X(queue_evict_clear) \
    X(quic_log_clear) \
    X(rdp_snoop_clear) \
    X(rf_quality_clear) \
    X(rrm_clear) \
    X(rtsp_snoop_clear) \
    X(saq_clear) \
    X(seqnum_clear) \
    X(sh_evict_reset) \
    X(sh_parse_fault_reset) \
    X(smb_snoop_clear) \
    X(smtp_snoop_reset) \
    X(snmp_snoop_clear) \
    X(ssdp_clear) \
    X(ssh_snoop_clear) \
    X(tls_log_clear) \
    X(top_hosts_clear) \
    X(transit_clear) \
    X(tui_alert_hot_clear) \
    X(tui_reset) \
    X(tune_reset) \
    X(twins_clear) \
    X(wifi_baseline_clear) \
    X(wired_attach_clear) \
    X(view_procs_fold_clear) \
    X(wps_track_clear)

void sloth_reset_all(void);

#endif /* RESET_ALL_H */
