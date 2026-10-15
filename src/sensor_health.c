#include <pthread.h>
#include <string.h>
#include "sensor_health.h"

/* Table-overflow tally — contract and rationale in sensor_health.h.
 *
 * Written from the capture threads (probe_pnl, dhcp_snoop, eap_track,
 * beacon_snoop, seqnum_track, assoc_track, evidence_ring, rf_quality,
 * wps_track, pm_forge, src/capture/probe.c's client table, the HTTP
 * pairing table, the six per-protocol flow rings, and — through
 * src/stab.c since #110 — the BGP/LDAP/Kerberos/SMB/SSH/RDP/SNMP/MQTT
 * snoopers plus mDNS and NBNS) and from the poll loop (alerts, including
 * its ARP-spoof baseline, top_hosts, devices), so the tally takes a
 * mutex rather than relying on unsynchronised increments.
 *
 * That list is the current set and is maintained by hand, so treat it
 * as a guide and `grep sh_evict_note` for the authority — three writers
 * were missing from it until 2026-10-13. What is NOT hand-maintained is
 * the kind enum itself, which sensor_health.h enumerates and the JSONL
 * emitter loops over, so a new kind reaches every consumer without an
 * edit here. The
 * lock is cold by construction: it is only reached when a bounded table
 * is already full. */

static uint64_t        g_evict[SH_EVICT_KIND_COUNT];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static int in_range(sh_evict_t kind) {
    return (int)kind >= 0 && (int)kind < SH_EVICT_KIND_COUNT;
}

void sh_evict_note(sh_evict_t kind) {
    if (!in_range(kind)) return;
    pthread_mutex_lock(&g_mu);
    g_evict[kind]++;
    pthread_mutex_unlock(&g_mu);
}

uint64_t sh_evict_count(sh_evict_t kind) {
    if (!in_range(kind)) return 0;
    pthread_mutex_lock(&g_mu);
    uint64_t n = g_evict[kind];
    pthread_mutex_unlock(&g_mu);
    return n;
}

uint64_t sh_evict_total(void) {
    uint64_t n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < SH_EVICT_KIND_COUNT; i++) n += g_evict[i];
    pthread_mutex_unlock(&g_mu);
    return n;
}

int sh_evict_is_flow_ring(sh_evict_t kind) {
    switch (kind) {
    case SH_EVICT_DNS_LOG:
    case SH_EVICT_TLS_LOG:
    case SH_EVICT_QUIC_LOG:
    case SH_EVICT_HTTP_LOG:
    case SH_EVICT_NTP_LOG:
    case SH_EVICT_ICMP_LOG:
        return 1;
    default:
        return 0;
    }
}

uint64_t sh_evict_total_tables(void) {
    uint64_t n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < SH_EVICT_KIND_COUNT; i++)
        if (!sh_evict_is_flow_ring((sh_evict_t)i)) n += g_evict[i];
    pthread_mutex_unlock(&g_mu);
    return n;
}

const char *sh_evict_name(sh_evict_t kind) {
    switch (kind) {
    case SH_EVICT_ALERT:       return "alert";
    case SH_EVICT_TOP_HOST:    return "top_host";
    case SH_EVICT_PNL_CLIENT:  return "pnl_client";
    case SH_EVICT_PNL_SSID:    return "pnl_ssid";
    case SH_EVICT_DHCP_EVENT:  return "dhcp_event";
    case SH_EVICT_EAP_SESSION: return "eap_session";
    case SH_EVICT_DEVICE:      return "device";
    case SH_EVICT_BEACON_AP:     return "beacon_ap";
    case SH_EVICT_SEQNUM_CLIENT: return "seqnum_client";
    case SH_EVICT_ASSOC_PAIR:    return "assoc_pair";
    case SH_EVICT_ASSOC_REQ:     return "assoc_req";
    case SH_EVICT_WPS_SESSION:   return "wps_session";
    case SH_EVICT_EVIDENCE_FRAME: return "evidence_frame";
    case SH_EVICT_PROBE_CLIENT: return "probe_client";
    case SH_EVICT_PM_FORGE:    return "pm_forge";
    case SH_EVICT_QUEUE_EVICT: return "queue_evict";
    case SH_EVICT_PCAP_COOLDOWN: return "pcap_cooldown";
    case SH_EVICT_DNS_LOG:     return "dns_log";
    case SH_EVICT_TLS_LOG:     return "tls_log";
    case SH_EVICT_QUIC_LOG:    return "quic_log";
    case SH_EVICT_HTTP_LOG:    return "http_log";
    case SH_EVICT_NTP_LOG:     return "ntp_log";
    case SH_EVICT_ICMP_LOG:    return "icmp_log";
    case SH_EVICT_RF_CHANNEL:  return "rf_channel";
    case SH_EVICT_HTTP_FLOW:   return "http_flow";
    case SH_EVICT_BGP_SESSION: return "bgp_session";
    case SH_EVICT_LDAP_EVENT:  return "ldap_event";
    case SH_EVICT_KERB_EVENT:  return "kerb_event";
    case SH_EVICT_SMB_SESSION: return "smb_session";
    case SH_EVICT_SSH_FLOW:    return "ssh_flow";
    case SH_EVICT_RDP_FLOW:    return "rdp_flow";
    case SH_EVICT_SNMP_FLOW:   return "snmp_flow";
    case SH_EVICT_MQTT_FLOW:   return "mqtt_flow";
    case SH_EVICT_MDNS_SERVICE: return "mdns_service";
    case SH_EVICT_NBNS_NAME:   return "nbns_name";
    case SH_EVICT_ARP_HIST:    return "arp_hist";
    case SH_EVICT_KIND_COUNT:  break;
    }
    return "";
}

void sh_evict_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_evict, 0, sizeof(g_evict));
    pthread_mutex_unlock(&g_mu);
}

/* ── Parse-fault tally (#126) — contract in sensor_health.h ───── */

static uint64_t        g_pf[SH_PF_KIND_COUNT];
static pthread_mutex_t g_pf_mu = PTHREAD_MUTEX_INITIALIZER;

static int pf_in_range(sh_parse_fault_t kind) {
    return (int)kind >= 0 && (int)kind < SH_PF_KIND_COUNT;
}

void sh_parse_fault_note(sh_parse_fault_t kind) {
    if (!pf_in_range(kind)) return;
    pthread_mutex_lock(&g_pf_mu);
    g_pf[kind]++;
    pthread_mutex_unlock(&g_pf_mu);
}

uint64_t sh_parse_fault_count(sh_parse_fault_t kind) {
    if (!pf_in_range(kind)) return 0;
    pthread_mutex_lock(&g_pf_mu);
    uint64_t n = g_pf[kind];
    pthread_mutex_unlock(&g_pf_mu);
    return n;
}

uint64_t sh_parse_fault_total(void) {
    uint64_t n = 0;
    pthread_mutex_lock(&g_pf_mu);
    for (int i = 0; i < SH_PF_KIND_COUNT; i++) n += g_pf[i];
    pthread_mutex_unlock(&g_pf_mu);
    return n;
}

const char *sh_parse_fault_name(sh_parse_fault_t kind) {
    switch (kind) {
    case SH_PF_RADIOTAP_BAD:  return "radiotap_bad";
    case SH_PF_DOT11_RUNT:    return "dot11_runt";
    case SH_PF_IE_OVERRUN:    return "ie_overrun";
    case SH_PF_RSN_MALFORMED: return "rsn_malformed";
    case SH_PF_MLE_MALFORMED: return "mle_malformed";
    case SH_PF_IP_TRUNCATED:  return "ip_truncated";
    case SH_PF_IP_FRAGMENT:   return "ip_fragment";
    case SH_PF_DNS_NAME_BAD:  return "dns_name_bad";
    case SH_PF_TLS_MALFORMED: return "tls_malformed";
    case SH_PF_KIND_COUNT:    break;
    }
    return "";
}

int sh_parse_fault_is_wired(sh_parse_fault_t kind) {
    switch (kind) {
    case SH_PF_RADIOTAP_BAD:
    case SH_PF_DOT11_RUNT:
    case SH_PF_IE_OVERRUN:
    case SH_PF_MLE_MALFORMED:
        return 1;
    default:
        return 0;
    }
}

void sh_parse_fault_reset(void) {
    pthread_mutex_lock(&g_pf_mu);
    memset(g_pf, 0, sizeof(g_pf));
    pthread_mutex_unlock(&g_pf_mu);
}
