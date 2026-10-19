#include <pthread.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif
#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif
#include "sensor_health.h"
#include "dns.h"

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
    case SH_EVICT_FRAG_BSS:     return "frag_bss";
    case SH_EVICT_FRAG_STA:     return "frag_sta";
    case SH_EVICT_FRAG_SESSION: return "frag_session";
    case SH_EVICT_FRAG_ASSOC:   return "frag_assoc";
    case SH_EVICT_FRAG_MPDU:    return "frag_mpdu";
    case SH_EVICT_NDP_RA:       return "ndp_ra";
    case SH_EVICT_ROGUE_RADIUS: return "rogue_radius";
    case SH_EVICT_SSDP_DEVICE:  return "ssdp_device";
    case SH_EVICT_ONVIF_DEVICE: return "onvif_device";
    case SH_EVICT_SMTP_FLOW:    return "smtp_flow";
    case SH_EVICT_EAPOL_PENDING: return "eapol_pending";
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
    case SH_PF_FRAME_EDGE:    return "frame_edge";
    case SH_PF_KIND_COUNT:    break;
    }
    return "";
}

int sh_parse_fault_is_wired(sh_parse_fault_t kind) {
    switch (kind) {
    case SH_PF_RADIOTAP_BAD:
    case SH_PF_DOT11_RUNT:
    case SH_PF_IE_OVERRUN:
    case SH_PF_RSN_MALFORMED:
    case SH_PF_MLE_MALFORMED:
    case SH_PF_IP_TRUNCATED:
    case SH_PF_IP_FRAGMENT:
    case SH_PF_FRAME_EDGE:
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

/* ── Process memory sample (#121) — contract in sensor_health.h ── */

/* Value of one "Key:   1234 kB" line, or -1. Digits only: the kernel
 * prints a non-negative decimal, and anything else is not a figure. */
static long long status_value(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p >= end || *p < '0' || *p > '9') return -1;
    long long v = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        if (v > (0x7fffffffffffffffLL - 9) / 10) return -1;
        v = v * 10 + (*p - '0');
        p++;
    }
    return v;
}

void sh_mem_parse_status(const char *text, int len,
                         long long *rss_kb, long long *hwm_kb) {
    *rss_kb = -1;
    *hwm_kb = -1;
    if (!text || len <= 0) return;
    const char *p = text, *end = text + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *eol = nl ? nl : end;
        size_t n = (size_t)(eol - p);
        if (n > 6 && memcmp(p, "VmRSS:", 6) == 0)
            *rss_kb = status_value(p + 6, eol);
        else if (n > 6 && memcmp(p, "VmHWM:", 6) == 0)
            *hwm_kb = status_value(p + 6, eol);
        p = nl ? nl + 1 : end;
    }
}

static void sample_status(sh_mem_t *out) {
    out->rss_kb = out->rss_hwm_kb = -1;
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    /* VmRSS and VmHWM sit in the first few hundred bytes; a status page
     * longer than this buffer loses only fields that come after them. */
    char buf[8192];
    int len = 0;
    for (;;) {
        ssize_t r = read(fd, buf + len, sizeof(buf) - (size_t)len);
        if (r <= 0) break;
        len += (int)r;
        if (len == (int)sizeof(buf)) break;
    }
    close(fd);
    sh_mem_parse_status(buf, len, &out->rss_kb, &out->rss_hwm_kb);
}

static long long count_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    long long n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (e->d_name[0] >= '0' && e->d_name[0] <= '9') n++;
    closedir(d);
    /* The directory stream holds one descriptor of its own while it is
     * being read, and it is not the process's. */
    return n > 0 ? n - 1 : 0;
}

void sh_mem_sample(sh_mem_t *out) {
    memset(out, 0, sizeof(*out));
    sample_status(out);
#ifdef WITH_SQLITE
    out->sqlite_mem_kb     = (long long)(sqlite3_memory_used() / 1024);
    out->sqlite_mem_hwm_kb = (long long)(sqlite3_memory_highwater(0) / 1024);
#else
    out->sqlite_mem_kb = out->sqlite_mem_hwm_kb = -1;
#endif
    /* mallinfo2() arrived in glibc 2.33; the older mallinfo() truncates
     * to int and wraps past 2 GiB — the very size this field is for. In
     * use = arena chunks handed out (uordblks) plus direct mmap chunks
     * (hblkhd); free-but-retained arena memory is the gap between this
     * and rss. Under ASan the sanitiser owns malloc and this reports
     * only what glibc itself still serves. */
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
    struct mallinfo2 mi = mallinfo2();
    out->malloc_kb = (long long)((mi.uordblks + mi.hblkhd) / 1024);
#else
    out->malloc_kb = -1;
#endif
    out->fd_count = count_fds();
    dns_resolver_stats_t ds;
    dns_resolver_stats(&ds);
    out->resolver_calls = (long long)ds.getnameinfo_calls;
}
