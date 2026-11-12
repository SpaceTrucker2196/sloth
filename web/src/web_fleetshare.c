#include "web_fleetshare.h"

#include <stdio.h>
#include <stdlib.h>
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
    /* heard on the air, but about the operator's own networks: the probes
     * naming them, the stations on them */
    "MY_NETWORK_RECON", "UNKNOWN_DEVICE",
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

/* ── the local network ─────────────────────────────────────────────── */

static int by_str(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static int add_mac(char (*set)[WEB_FLEET_MAC_SZ], int *n, int cap, const char *mac, int *ok) {
    char k[WEB_KEY_MAX + 1];
    if (!mac || web_key_mac(mac, k) != 0) return 0;      /* not an address: names nothing */
    if (strlen(k) >= WEB_FLEET_MAC_SZ) return 0;          /* canonical: never */
    if (*n >= cap) { *ok = 0; return -1; }
    memcpy(set[(*n)++], k, strlen(k) + 1);
    return 0;
}

static int add_ssid(web_fleet_local_t *l, const char *s) {
    if (!s || !s[0] || strlen(s) > WEB_FLEET_SSID_MAX) return 0;
    for (int i = 0; i < l->nssid; i++)
        if (!strcmp(l->ssid[i], s)) return 0;
    if (l->nssid >= WEB_FLEET_LOCAL_SSIDS) { l->ok = 0; return -1; }
    snprintf(l->ssid[l->nssid++], WEB_FLEET_SSID_MAX + 1, "%s", s);
    return 0;
}

typedef struct {
    web_fleet_local_t *l;
    int                what;
} ln_t;

static int ln_row(void *ctx, const web_sdb_item_t *it) {
    ln_t *x = ctx;
    web_fleet_local_t *l = x->l;
    if (x->what == WEB_SDB_LN_JOINED) {
        add_mac(l->bssid, &l->nbssid, WEB_FLEET_LOCAL_BSSIDS, it->a, &l->ok);
        add_ssid(l, it->b);
    } else if (x->what == WEB_SDB_LN_SSID) {
        add_mac(l->bssid, &l->nbssid, WEB_FLEET_LOCAL_BSSIDS, it->a, &l->ok);
    } else {
        add_mac(l->mac, &l->nmac, WEB_FLEET_LOCAL_MACS, it->a, &l->ok);
    }
    return !l->ok;
}

static void ln_read(web_fleet_local_t *l, web_sdb_conn_t *c, int what, const char *arg,
                    int max) {
    ln_t x = { l, what };
    int n = web_sdb_local_net(c, what, arg, max + 1, ln_row, &x);
    if (n < 0 || n > max || c->timed_out) l->ok = 0;
}

static void dedup(char (*set)[WEB_FLEET_MAC_SZ], int *n) {
    qsort(set, (size_t)*n, sizeof(set[0]), by_str);
    int o = 0;
    for (int i = 0; i < *n; i++)
        if (!o || strcmp(set[o - 1], set[i])) memmove(set[o++], set[i], sizeof(set[0]));
    *n = o;
}

int web_fleet_local_build(web_fleet_local_t *l, web_sdb_conn_t *c,
                          const web_fleet_mine_t *mine, const char *own_csv) {
    memset(l, 0, sizeof(*l));
    l->bssid = malloc(sizeof(l->bssid[0]) * WEB_FLEET_LOCAL_BSSIDS);
    l->ssid = malloc(sizeof(l->ssid[0]) * WEB_FLEET_LOCAL_SSIDS);
    l->mac = malloc(sizeof(l->mac[0]) * WEB_FLEET_LOCAL_MACS);
    if (!l->bssid || !l->ssid || !l->mac) return -1;
    l->ok = 1;
    /* The operator's own networks, as slothweb is told them. */
    for (int i = 0; mine && i < mine->nssid; i++) add_ssid(l, mine->ssid[i]);
    for (int i = 0; mine && i < mine->nbssid; i++)
        add_mac(l->bssid, &l->nbssid, WEB_FLEET_LOCAL_BSSIDS, mine->bssid[i], &l->ok);
    /* This host's own radios: the managed card is a station of the
     * local network, and its address says which one. */
    char own[WEB_FLEET_OWN_MAX][WEB_FLEET_MAC_SZ];
    int nown = 0;
    if (own_csv && own_csv[0] && web_fleet_own_parse(own_csv, own, &nown) != 0) l->ok = 0;
    for (int i = 0; i < nown; i++)
        add_mac(l->mac, &l->nmac, WEB_FLEET_LOCAL_MACS, own[i], &l->ok);
    if (c && l->ok) {
        ln_read(l, c, WEB_SDB_LN_JOINED, NULL, WEB_FLEET_LOCAL_BSSIDS);
        ln_read(l, c, WEB_SDB_LN_LINK, NULL, WEB_FLEET_LOCAL_MACS);
        ln_read(l, c, WEB_SDB_LN_ARP, NULL, WEB_FLEET_LOCAL_MACS);
        /* Every BSSID that carried a joined SSID: the network's other
         * APs and bands, which the managed card never scanned. */
        for (int i = 0; l->ok && i < l->nssid; i++)
            ln_read(l, c, WEB_SDB_LN_SSID, l->ssid[i], WEB_FLEET_LOCAL_BSSIDS);
    }
    dedup(l->bssid, &l->nbssid);
    dedup(l->mac, &l->nmac);
    return l->ok ? 0 : -1;
}

void web_fleet_local_free(web_fleet_local_t *l) {
    free(l->bssid);
    free(l->ssid);
    free(l->mac);
    memset(l, 0, sizeof(*l));
}

static int in_set(char (*set)[WEB_FLEET_MAC_SZ], int n, const char *k) {
    return n > 0 && bsearch(k, set, (size_t)n, sizeof(set[0]), by_str) != NULL;
}

int web_fleet_local_addr(const web_fleet_local_t *l, const char *mac) {
    char k[WEB_KEY_MAX + 1];
    if (!mac || web_key_mac(mac, k) != 0) return 0;
    return in_set(l->bssid, l->nbssid, k) || in_set(l->mac, l->nmac, k);
}

int web_fleet_local_ssid(const web_fleet_local_t *l, const char *ssid) {
    for (int i = 0; ssid && ssid[0] && i < l->nssid; i++)
        if (!strcmp(l->ssid[i], ssid)) return 1;
    return 0;
}

int web_fleet_local_names(const web_fleet_local_t *l, const char *text) {
    for (int i = 0; text && text[0] && i < l->nssid; i++)
        if (strstr(text, l->ssid[i])) return 1;
    return 0;
}

int web_fleet_local_needles(const web_fleet_local_t *l, const char **out, int max) {
    int n = 0;
    for (int i = 0; i < l->nbssid && n < max; i++) out[n++] = l->bssid[i];
    for (int i = 0; i < l->nmac && n < max; i++) out[n++] = l->mac[i];
    return n;
}

int web_fleet_share_dev(const web_fleet_local_t *l, const web_sdb_dev_t *d) {
    if (!l->ok) return 0;
    /* Heard on the air: a beacon, a probe, or a camera's setup SSID or
     * OUI on a beacon (web_scope.h's Monitor bits). */
    if (!(d->sources & (WEB_SRC_MONITOR | WEB_SRC_CAMERA))) return 0;
    /* The Monitor scope reads no address and no name; one here means the
     * row was not read in it, and its provenance is not the radio's. */
    if (d->ip[0] || d->hostname[0] || d->dhcp_name[0] || d->mdns_name[0] ||
        d->nbns_name[0] || d->dhcp_vci[0])
        return 0;
    /* The host's own interfaces and the operator's roster. */
    if (d->risk_signals & WEB_RISK_SELF) return 0;
    return !web_fleet_local_addr(l, d->mac);
}

/* ── the importer ──────────────────────────────────────────────────── */

const char *web_fleet_share_refuses(const char *type, const web_jrec_t *r, int attested) {
    if (!type) return "unknown";
    if (!strcmp(type, "own_net")) return "own_net";
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
