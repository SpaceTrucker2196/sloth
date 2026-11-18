#include "web_fleetshare.h"

#include <string.h>

#include "web_metrics.h"
#include "web_scope.h"

/* ── the alert types ───────────────────────────────────────────────── */

/* Each by its capture provenance, the rule's input and not the file the
 * rule sits in (web_scope.c tags the same inputs for the scope switch):
 * the monitor radio's 802.11 frames, the BLE receivers, the ADS-B SDR
 * and the GNSS receiver are passive reception over the air; nothing here
 * read the host's own interfaces. */
const char *const web_fleet_share_alerts[] = {
    /* 802.11 management and control frames off the monitor radio */
    "DEAUTH_FLOOD", "PROBE_FLOOD", "BEACON_FLOOD", "AUTH_FLOOD", "MGMT_FUZZ",
    "ASSOC_FLOOD", "BTM_ABUSE", "CSA_ABUSE", "RRM_SURVEY_ABUSE", "RTS_FLOOD",
    "BLOCKACK_ATTACK", "SA_QUERY_FLOOD", "MFP_UNPROTECTED", "PM_FORGE", "QUEUE_EVICT",
    "RF_DEGRADED", "RECURRING_TRANSIT",
    /* probes and associations heard on the air, judged against the
     * operator's own networks and roster (configuration, which travels
     * as own_net): the frames are the radio's */
    "MY_NETWORK_RECON", "UNKNOWN_DEVICE",
    /* beacons and probe responses: impersonation and posture */
    "EVIL_TWIN", "EVIL_TWIN_PROXIMITY", "KARMA_AP", "KARMA_PROBE_FORGE", "SSID_CONFUSION",
    "WPA_DOWNGRADE", "SAE_PSK_SPLIT", "SAE_PSK_REGRESSION", "OPEN_SETUP_AP",
    "TPC_ABSENT_HIGH_BAND", "COUNTRY_ABSENT", "DFS_MASKING", "CAM_SETUP_SSID",
    "CAM_SETUP_OUI",
    /* EAP, EAPOL and WPS frames heard on the air */
    "ROGUE_RADIUS", "PEAP_NO_SERVER_CERT", "WPS_PIN_BRUTE", "WPS_LOCKOUT_CYCLING",
    "WPS_PBC_RACE", "WPS_PIXIE_PROBE", "WPS_PIXIE_LIKELY_SUCCESS", "PMKID_HARVEST",
    "HANDSHAKE_HARVEST",
    /* FragAttacks: data frames heard on the air */
    "FRAG_PLAINTEXT", "FRAG_BCAST", "FRAG_CACHE", "FRAG_MIXED", "FRAG_AMSDU",
    "FRAG_AMSDU_EAPOL", "FRAG_MIXKEY", "FRAG_PN_GAP", "FRAG_EAPOL_RELAY",
    /* Multi-Link elements */
    "MLE_INVALID_LINK_ID", "MLE_COMMON_INFO_LEN_BAD", "MLE_SUBELEM_OVERRUN",
    "MLD_MAC_COLLISION", "MLE_CROSS_LINK_CIPHER_DOWNGRADE", "MLE_RECONFIG_NO_MLO",
    "MLE_PR_BEACON_DIFF",
    /* the BLE receivers */
    "BLE_ADV_FLOOD", "BLE_HID_UNEXPECTED", "BLE_WATCHLIST",
    /* the ADS-B SDR and the GNSS receiver: passive radio, no network */
    "ADSB_EMERGENCY", "GNSS_JAMMING", "GNSS_SPOOF_SUSPECT", "GNSS_TIME_JUMP",
    "GNSS_POSITION_JUMP",
    NULL
};

const char *const web_fleet_withheld_alerts[] = {
    /* the host's own interfaces: the socket table, ARP, the IP capture
     * (DNS, DHCP, RA, HTTP, TLS, the flows), LAN discovery */
    "PORT_SCAN", "NXDOMAIN_BURST", "THREAT_DOMAIN", "THREAT_IP", "BEACONING",
    "DGA_DOMAIN", "ARP_SPOOF", "ROGUE_DHCP", "ROGUE_RA", "SMB1_USE",
    "KERB_PREAUTH_BURST", "LDAP_SEARCH_FLOOD", "BGP_NOTIFICATION_BURST",
    "SSH_BRUTE_FORCE", "RDP_BRUTE_FORCE", "SNMP_COMMUNITY_BRUTE", "MQTT_BROKER_BRUTE",
    "DNS_TUNNEL", "ATTACK_TOOL_UA", "ATTACK_PATH", "WEAK_TLS", "CLEARTEXT_CRED",
    "ICMP_TUNNEL", "CAPTIVE_PORTAL", "CAM_WS_DISCOVERY", "SURV_CLOUD_SNI", "SURV_DNS",
    "CAM_MDNS_SERVICE", "CAM_SSDP_DEVICE", "CAM_RTSP_UNAUTH",
    /* the sensor's own state, not a datum the radio heard */
    "NO_MONITOR_MODE", "BT_OWN_TRANSMIT", "SENSOR_UNDERVOLT", "SENSOR_SOURCE_DOWN",
    NULL
};

int web_fleet_alert_shareable(const char *name) {
    if (!name || !name[0]) return 0;
    for (int i = 0; web_fleet_share_alerts[i]; i++)
        if (!strcmp(web_fleet_share_alerts[i], name)) return 1;
    return 0;
}

int web_fleet_share_rule_ok(const char *rule) {
    return rule && (!strcmp(rule, WEB_FLEET_SHARE_RULE) || !strcmp(rule, WEB_FLEET_SHARE_RULE_V1));
}

/* ── the devices ───────────────────────────────────────────────────── */

int web_fleet_share_dev(const web_sdb_dev_t *d, const char (*self)[WEB_FLEET_MAC_SZ],
                        int nself) {
    /* Heard on the air: a beacon, a probe, or a camera's setup SSID or
     * OUI on a beacon (web_scope.h's Monitor bits). A row the LAN or the
     * station dump alone knows has none of them. */
    if (!(d->sources & (WEB_SRC_MONITOR | WEB_SRC_CAMERA))) return 0;
    /* The Monitor scope reads no address and no name; one here means the
     * row was not read in it, and its provenance is not the radio's. */
    if (d->ip[0] || d->hostname[0] || d->dhcp_name[0] || d->mdns_name[0] ||
        d->nbns_name[0] || d->dhcp_vci[0])
        return 0;
    /* The host's own interfaces and the operator's roster: sloth's
     * knowledge of the device, not the radio's. */
    if (d->risk_signals & WEB_RISK_SELF) return 0;
    char k[WEB_KEY_MAX + 1];
    if (web_key_mac(d->mac, k) != 0) return 0;
    for (int i = 0; i < nself; i++)
        if (!strcmp(self[i], k)) return 0;
    return 1;
}

/* ── the importer ──────────────────────────────────────────────────── */

const char *web_fleet_share_refuses(const char *type, const web_jrec_t *r, int attested) {
    if (!type) return "unknown";
    if (!strcmp(type, "wifi") || !strcmp(type, "ap") || !strcmp(type, "probe"))
        return attested ? NULL : "unattested";
    if (!strcmp(type, "alert")) {
        if (!web_fleet_alert_shareable(web_jl_str(r, "alert_type"))) return "alert_type";
        const char *ip = web_jl_str(r, "ip");
        if (ip && ip[0]) return "alert_ip";
        return NULL;
    }
    if (!strcmp(type, "verdict")) {
        if (!web_fleet_alert_shareable(web_jl_str(r, "alert_type"))) return "verdict_type";
        const char *a = web_jl_str(r, "addr");
        char k[WEB_KEY_MAX + 1];
        if (a && a[0] && web_key_mac(a, k) != 0) return "verdict_addr";
        return NULL;
    }
    return NULL;
}
