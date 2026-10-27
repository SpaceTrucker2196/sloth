#include "web_alertfmt.h"

#include <string.h>

#include "web_alertkb.h"

/* The audited types (web_alertfmt.h). A type is added here only after
 * reading every fire() site's detail format in src/alerts/; the test
 * re-reads them on every run. Types left off are withheld, which is the
 * safe answer for one nobody audited. */
const web_adf_t web_alert_detail_audited[] = {
    { "PORT_SCAN", "", "" },
    { "DEAUTH_FLOOD", "rsn",
      "rsn is snprintf'd from the reason code (%u) or one of the literals"
      " \"encrypted\" / \"unknown\" just above the detail" },
    { "NXDOMAIN_BURST", "", "" },
    { "BEACONING", "d sep",
      "d is beacon_dest()'s address:port of one track, sep the literal"
      " \", \" or \" \"" },
    { "ARP_SPOOF", "", "" },
    { "ROGUE_DHCP", "", "" },
    { "ROGUE_RA", "", "" },
    { "SMB1_USE", "", "" },
    { "KERB_PREAUTH_BURST", "", "" },
    { "LDAP_SEARCH_FLOOD", "", "" },
    { "BGP_NOTIFICATION_BURST", "", "" },
    { "EVIL_TWIN_PROXIMITY", "", "" },
    { "PROBE_FLOOD", "", "" },
    { "NO_MONITOR_MODE", "", "" },
    { "BEACON_FLOOD", "", "" },
    { "AUTH_FLOOD", "", "" },
    { "MGMT_FUZZ", "", "" },
    { "ICMP_TUNNEL", "", "" },
    { "RECURRING_TRANSIT", "", "" },
    { "UNKNOWN_DEVICE", "", "" },
    { "RF_DEGRADED", "", "" },
    { "ASSOC_FLOOD", "", "" },
    { "PEAP_NO_SERVER_CERT", "", "" },
    { "CSA_ABUSE", "", "" },
    { "RRM_SURVEY_ABUSE", "", "" },
    { "RTS_FLOOD", "", "" },
    { "BLOCKACK_ATTACK", "", "" },
    { "FRAG_PLAINTEXT", "", "" },
    { "FRAG_BCAST", "", "" },
    { "FRAG_CACHE", "", "" },
    { "FRAG_MIXED", "", "" },
    { "SAE_PSK_SPLIT", "", "" },
    { "SAE_PSK_REGRESSION", "", "" },
    { "FRAG_AMSDU", "", "" },
    { "FRAG_AMSDU_EAPOL", "", "" },
    { "FRAG_MIXKEY", "", "" },
    { "FRAG_PN_GAP", "", "" },
    { "FRAG_EAPOL_RELAY", "", "" },
    { "SA_QUERY_FLOOD", "", "" },
    { "MFP_UNPROTECTED", "", "" },
    { "WPS_LOCKOUT_CYCLING", "", "" },
    { "WPS_PBC_RACE", "", "" },
    { "MLE_INVALID_LINK_ID", "", "" },
    { "MLE_COMMON_INFO_LEN_BAD", "", "" },
    { "MLE_SUBELEM_OVERRUN", "", "" },
    { "MLD_MAC_COLLISION", "", "" },
    { "PM_FORGE", "", "" },
    { "MLE_RECONFIG_NO_MLO", "", "" },
    { "WPS_PIXIE_PROBE", "", "" },
    { "WPS_PIXIE_LIKELY_SUCCESS", "", "" },
};
const size_t web_alert_detail_audited_n =
    sizeof(web_alert_detail_audited) / sizeof(web_alert_detail_audited[0]);

const char *const web_alert_fmt_names[] = {
    /* addresses */
    "ip", "src", "dst", "src_ip", "dst_ip", "client_ip", "server_ip",
    "peer_a", "peer_b", "remote_ip", "servers", "routers",
    /* MACs and BSSIDs, as mac_to_str() writes them */
    "mac", "mac_buf", "new_mac", "old_mac", "coll", "bssid", "bssid_str",
    "bss", "a_bssid", "b_bssid", "w_bssid", "s_bssid", "sta", "stastr",
    "psta", "tgt", "tx", "rx", "sa", "da", "ta",
    /* network names */
    "ssid", "last_ssid",
    NULL
};

const char *const web_alert_fmt_banned[] = {
    "user", "cred", "communit", "cookie", "pass", "identit", "secret",
    "token", "banner", "host", "qname", "path", "agent", "url", "uri",
    "sni", "query", "xaddr", "vendor", "label", "note", NULL
};

int web_alert_detail_ok(long long type) {
    const web_akb_t *k = web_akb_get(type);
    if (!k) return 0;
    for (size_t i = 0; i < web_alert_detail_audited_n; i++)
        if (!strcmp(web_alert_detail_audited[i].type, k->name)) return 1;
    return 0;
}
