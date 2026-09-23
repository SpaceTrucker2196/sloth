#include <pthread.h>
#include <string.h>
#include "sensor_health.h"

/* Table-overflow tally — contract and rationale in sensor_health.h.
 *
 * Written from the capture threads (probe_pnl, dhcp_snoop, eap_track)
 * and from the poll loop (alerts, top_hosts, devices), so the tally
 * takes a mutex rather than relying on unsynchronised increments. The
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

const char *sh_evict_name(sh_evict_t kind) {
    switch (kind) {
    case SH_EVICT_ALERT:       return "alert";
    case SH_EVICT_TOP_HOST:    return "top_host";
    case SH_EVICT_PNL_CLIENT:  return "pnl_client";
    case SH_EVICT_PNL_SSID:    return "pnl_ssid";
    case SH_EVICT_DHCP_EVENT:  return "dhcp_event";
    case SH_EVICT_EAP_SESSION: return "eap_session";
    case SH_EVICT_DEVICE:      return "device";
    case SH_EVICT_KIND_COUNT:  break;
    }
    return "";
}

void sh_evict_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_evict, 0, sizeof(g_evict));
    pthread_mutex_unlock(&g_mu);
}
