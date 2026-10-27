#include "web_scope.h"

#include <stdio.h>
#include <string.h>

#include "web_rollup.h"

static const char *const WORDS[WEB_SCOPE_COUNT] = { "hybrid", "monitor", "local" };

int web_scope_find(const char *word) {
    for (int i = 0; word && i < WEB_SCOPE_COUNT; i++)
        if (!strcmp(WORDS[i], word)) return i;
    return -1;
}

const char *web_scope_word(int scope) {
    return scope >= 0 && scope < WEB_SCOPE_COUNT ? WORDS[scope] : "hybrid";
}

int web_scope_eff(int tag, int radio) {
    if ((tag & WEB_SC_IPCAP) && radio) return WEB_SC_M;
    return tag & WEB_SC_META;
}

int web_scope_pass(int scope, int tag) {
    if (scope == WEB_SCOPE_HYBRID) return 1;
    int want = scope == WEB_SCOPE_MONITOR ? WEB_SC_M : WEB_SC_L;
    return (tag & want) != 0;
}

/* ── record types ────────────────────────────────────────────────────── */

#define M  WEB_SC_M
#define L  WEB_SC_L
#define LI (WEB_SC_L | WEB_SC_IPCAP)
#define MT WEB_SC_META
#define BK WEB_SC_BYKEY

static const struct { const char *t; int tag; } RTYPES[] = {
    /* the 802.11 monitor stream (src/capture/probe.c and its trackers) */
    { "beacon", M }, { "wifi_regulatory", M }, { "deauth", M },
    { "probe_client", M }, { "pnl_client", M }, { "seqnum_client", M },
    { "seqnum_correlation", M }, { "channel_summary", M }, { "assoc", M },
    { "wifi_assoc_req", M }, { "btm_request", M }, { "wifi_csa_event", M },
    { "rrm_beacon_request", M }, { "wifi_mld", M }, { "eapol", M },
    { "twin_episode", M }, { "wifi_merged", M },
    /* the BLE receivers: passive radio */
    { "ble_device", M }, { "ble_alert", M },
    /* the IP capture (src/capture/capture.c) */
    { "dns", LI }, { "tls", LI }, { "quic", LI }, { "http", LI }, { "ntp", LI },
    { "icmp", LI }, { "packet", LI }, { "arp", LI }, { "dhcp_lease", LI },
    { "top_host", LI }, { "mdns_service", LI }, { "nbns_name", LI },
    { "ssdp_device", LI }, { "onvif_device", LI }, { "scan_entry", LI },
    { "ndp_ra", LI }, { "smb_session", LI }, { "kerb_event", LI },
    { "ldap_event", LI }, { "bgp_session", LI }, { "ssh_flow", LI },
    { "rdp_flow", LI }, { "snmp_flow", LI }, { "mqtt_flow", LI },
    { "captive_portal_event", LI }, { "cleartext_cred", LI },
    /* the host itself: /proc and the managed Wi-Fi card's nl80211 */
    { "connections", L }, { "process", L }, { "wifi_sta", L }, { "wifi_ap", L },
    /* by the record */
    { "iface", BK }, { "device", BK },
    /* sloth's own state */
    { "sensor", MT }, { "sensor_health", MT }, { "socket_gap", MT },
};

int web_scope_record(const char *type) {
    if (!type) return 0;
    for (size_t i = 0; i < sizeof(RTYPES) / sizeof(RTYPES[0]); i++)
        if (!strcmp(RTYPES[i].t, type)) return RTYPES[i].tag;
    return 0;
}

/* ── alert types, in include/sloth_alerts.def's order ────────────────── */

const web_scope_alert_t web_scope_alerts[] = {
    { "PORT_SCAN", LI }, { "DEAUTH_FLOOD", M }, { "NXDOMAIN_BURST", LI },
    { "THREAT_DOMAIN", LI }, { "THREAT_IP", LI },
    { "BEACONING", LI },            /* C2 beaconing over IP, not 802.11 */
    { "DGA_DOMAIN", LI }, { "ARP_SPOOF", LI }, { "ROGUE_DHCP", LI },
    { "ROGUE_RA", LI }, { "SMB1_USE", LI }, { "KERB_PREAUTH_BURST", LI },
    { "LDAP_SEARCH_FLOOD", LI }, { "BGP_NOTIFICATION_BURST", LI },
    { "SSH_BRUTE_FORCE", LI }, { "RDP_BRUTE_FORCE", LI },
    { "SNMP_COMMUNITY_BRUTE", LI }, { "MQTT_BROKER_BRUTE", LI },
    { "EVIL_TWIN", M }, { "EVIL_TWIN_PROXIMITY", M }, { "KARMA_AP", M },
    { "DNS_TUNNEL", LI }, { "PROBE_FLOOD", M }, { "ATTACK_TOOL_UA", LI },
    { "ATTACK_PATH", LI },          /* reads http_log */
    { "WEAK_TLS", LI },             /* reads tls_log */
    { "NO_MONITOR_MODE", MT },      /* sloth's own state */
    { "CLEARTEXT_CRED", LI }, { "BEACON_FLOOD", M }, { "AUTH_FLOOD", M },
    { "SSID_CONFUSION", M }, { "MGMT_FUZZ", M },
    { "ROGUE_RADIUS", M },          /* EAP frames heard on the air */
    { "ICMP_TUNNEL", LI },
    { "MY_NETWORK_RECON", M },      /* PNLs; --my-ssid is config */
    { "RECURRING_TRANSIT", M }, { "UNKNOWN_DEVICE", M }, { "RF_DEGRADED", M },
    { "ASSOC_FLOOD", M }, { "BTM_ABUSE", M }, { "WPA_DOWNGRADE", M },
    { "PEAP_NO_SERVER_CERT", M }, { "CSA_ABUSE", M }, { "RRM_SURVEY_ABUSE", M },
    { "RTS_FLOOD", M },
    { "CAPTIVE_PORTAL", LI },       /* rules_twin.c, but DNS/HTTP/TLS */
    { "BLOCKACK_ATTACK", M }, { "FRAG_PLAINTEXT", M }, { "FRAG_BCAST", M },
    { "FRAG_CACHE", M }, { "FRAG_MIXED", M }, { "SAE_PSK_SPLIT", M },
    { "SAE_PSK_REGRESSION", M }, { "FRAG_AMSDU", M }, { "FRAG_AMSDU_EAPOL", M },
    { "FRAG_MIXKEY", M }, { "FRAG_PN_GAP", M }, { "FRAG_EAPOL_RELAY", M },
    { "SA_QUERY_FLOOD", M }, { "MFP_UNPROTECTED", M }, { "OPEN_SETUP_AP", M },
    { "WPS_PIN_BRUTE", M }, { "WPS_LOCKOUT_CYCLING", M }, { "WPS_PBC_RACE", M },
    { "MLE_INVALID_LINK_ID", M }, { "MLE_COMMON_INFO_LEN_BAD", M },
    { "MLE_SUBELEM_OVERRUN", M }, { "MLD_MAC_COLLISION", M },
    { "MLE_CROSS_LINK_CIPHER_DOWNGRADE", M },
    { "CAM_WS_DISCOVERY", LI },     /* ONVIF WS-Discovery over IP */
    { "PM_FORGE", M },
    { "SURV_CLOUD_SNI", LI },       /* TLS SNI */
    { "TPC_ABSENT_HIGH_BAND", M }, { "CAM_SETUP_SSID", M }, { "QUEUE_EVICT", M },
    { "MLE_RECONFIG_NO_MLO", M }, { "MLE_PR_BEACON_DIFF", M },
    { "SURV_DNS", LI }, { "WPS_PIXIE_PROBE", M }, { "WPS_PIXIE_LIKELY_SUCCESS", M },
    { "COUNTRY_ABSENT", M }, { "DFS_MASKING", M },
    { "CAM_MDNS_SERVICE", LI }, { "CAM_SSDP_DEVICE", LI },
    { "CAM_SETUP_OUI", M },         /* rules_camera.c, but beacon BSSIDs */
    { "CAM_RTSP_UNAUTH", LI },
    { "BT_OWN_TRANSMIT", MT },      /* sloth's own state */
    { "BLE_ADV_FLOOD", M }, { "BLE_HID_UNEXPECTED", M }, { "BLE_WATCHLIST", M },
};
const int web_scope_alerts_n = (int)(sizeof(web_scope_alerts) / sizeof(web_scope_alerts[0]));

int web_scope_alert(int ty) {
    return ty >= 0 && ty < web_scope_alerts_n ? web_scope_alerts[ty].tag : 0;
}

int web_scope_alert_types(int scope, int radio, int *out, int max) {
    int n = 0;
    for (int ty = 0; ty < web_scope_alerts_n && n < max; ty++)
        if (web_scope_pass(scope, web_scope_eff(web_scope_alerts[ty].tag, radio)))
            out[n++] = ty;
    return n;
}

/* ── metrics ─────────────────────────────────────────────────────────── */

int web_scope_metric(int metric) {
    switch (metric) {
    case WM_IFACE_RX: case WM_IFACE_TX:          return BK;
    case WM_ALERTS_FIRED:                        return BK;
    case WM_HOST_RX: case WM_HOST_TX: case WM_HOST_CONNS:
    case WM_DNS_QUERIES: case WM_DNS_NXDOMAIN:
    case WM_TLS_HANDSHAKES: case WM_HTTP_REQUESTS:
    case WM_FLOW_SSH: case WM_FLOW_RDP: case WM_FLOW_SMB: case WM_FLOW_SNMP:
    case WM_FLOW_MQTT:                           return LI;
    case WM_CONNS_TOTAL:                         return L;
    case WM_DEV_FRAMES:
    case WM_WIFI_AP_COUNT: case WM_WIFI_CTRL_TOTAL: case WM_WIFI_DEAUTH:
    case WM_WIFI_PROBE_CLIENTS:                  return M;
    case WM_DEV_PRESENT_MON:                     return M;
    case WM_DEV_PRESENT_LOC:                     return L;
    /* dev.present is every source's: Hybrid's series. The scopes have
     * their own two. */
    default:                                     return 0;
    }
}

int web_scope_ok(const web_scope_ctx_t *c, int tag) {
    if (!c || c->scope == WEB_SCOPE_HYBRID) return 1;
    return web_scope_pass(c->scope, web_scope_eff(tag, c->radio));
}

int web_scope_iface(const char *name, const web_scope_ctx_t *c) {
    for (int i = 0; name && c && i < c->nmon; i++)
        if (c->mon[i][0] && !strcmp(c->mon[i], name)) return M;
    return L;
}

void web_scope_note_mon(web_scope_ctx_t *c, const char *name) {
    if (!name || !name[0] || strlen(name) > WEB_SCOPE_IFNAME) return;
    for (int i = 0; i < c->nmon; i++)
        if (!strcmp(c->mon[i], name)) return;
    if (c->nmon >= WEB_SCOPE_MON_MAX) return;
    snprintf(c->mon[c->nmon++], WEB_SCOPE_IFNAME + 1, "%s", name);
}

int web_scope_metric_key(int metric, const char *key, const web_scope_ctx_t *c) {
    int radio = c ? c->radio : 0;
    int tag = web_scope_metric(metric);
    if (tag != BK) return web_scope_eff(tag, radio);
    if (metric == WM_ALERTS_FIRED) {
        int ty = -1;
        if (key && key[0]) {
            ty = 0;
            for (const char *p = key; *p; p++) {
                if (*p < '0' || *p > '9' || ty > 9999) { ty = -1; break; }
                ty = ty * 10 + (*p - '0');
            }
        }
        return web_scope_eff(web_scope_alert(ty), radio);
    }
    return web_scope_iface(key, c);
}


/* ── devices ─────────────────────────────────────────────────────────── */

int web_scope_device(long long sources, long long cam, const char *ip) {
    int tag = 0;
    if (sources & WEB_SRC_LOCAL) tag |= L;
    if (sources & WEB_SRC_MONITOR) tag |= M;
    if (cam > 0) {
        if (cam & WEB_CAM_LOCAL) tag |= L;
        if (cam & WEB_CAM_MONITOR) tag |= M;
    }
    if (ip && ip[0]) tag |= L;
    return tag;
}

long long web_scope_risk_mask(int scope) {
    switch (scope) {
    case WEB_SCOPE_MONITOR: return WEB_RISK_BOTH | WEB_RISK_MONITOR;
    case WEB_SCOPE_LOCAL:   return WEB_RISK_BOTH | WEB_RISK_LOCAL;
    default:                return 0x3f;
    }
}

int web_scope_risk_level(long long sig) {
    static const int W[6] = { 1, 1, 1, 1, 3, 3 };
    int score = 0;
    for (int b = 0; b < 6; b++) if (sig & (1LL << b)) score += W[b];
    return score >= 5 ? 3 : score >= 3 ? 2 : score >= 1 ? 1 : 0;
}

int web_scope_ip_on_radio(long long lt, const char *cap, const char *mon) {
    if (lt >= 0) return lt == 105 || lt == 119 || lt == 127 || lt == 163;
    return cap && mon && cap[0] && !strcmp(cap, mon);
}

#undef M
#undef L
#undef LI
#undef MT
#undef BK
