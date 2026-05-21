#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "probe_pnl.h"

static pnl_client_t    g_tbl[MAX_PNL_CLIENTS];
static int             g_n   = 0;
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

void probe_pnl_observe(const uint8_t mac[6], const char *ssid)
{
    if (!ssid || !ssid[0]) return;   /* wildcard probes carry no PNL info */
    time_t now = time(NULL);

    pthread_mutex_lock(&g_mu);

    /* Find or insert the client. */
    int idx = -1;
    for (int i = 0; i < g_n; i++) {
        if (mac_eq(g_tbl[i].mac, mac)) { idx = i; break; }
    }
    if (idx < 0) {
        if (g_n >= MAX_PNL_CLIENTS) {
            /* Evict the entry with the lowest last_seen — keeps the most
             * recently active devices. */
            idx = 0;
            for (int i = 1; i < g_n; i++)
                if (g_tbl[i].last_seen < g_tbl[idx].last_seen) idx = i;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        } else {
            idx = g_n++;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        }
        memcpy(g_tbl[idx].mac, mac, 6);
        g_tbl[idx].mac_random = (mac[0] & 0x02) ? 1 : 0;
        g_tbl[idx].first_seen = now;
    }
    g_tbl[idx].last_seen = now;
    g_tbl[idx].probe_count++;

    /* Dedupe — skip if this SSID is already in this client's list. */
    for (int j = 0; j < g_tbl[idx].ssid_count; j++) {
        if (strncmp(g_tbl[idx].ssids[j], ssid, 32) == 0) {
            pthread_mutex_unlock(&g_mu);
            return;
        }
    }
    /* Append. When the per-client list is full, evict the first entry
     * (oldest in insertion order) and shift down. Bounded at 16. */
    if (g_tbl[idx].ssid_count >= MAX_PNL_SSIDS_PER_CLI) {
        for (int j = 1; j < MAX_PNL_SSIDS_PER_CLI; j++)
            memcpy(g_tbl[idx].ssids[j - 1], g_tbl[idx].ssids[j], 33);
        g_tbl[idx].ssid_count = MAX_PNL_SSIDS_PER_CLI - 1;
    }
    int s = g_tbl[idx].ssid_count++;
    snprintf(g_tbl[idx].ssids[s], 33, "%s", ssid);

    pthread_mutex_unlock(&g_mu);
}

void probe_pnl_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_PNL_CLIENTS ? g_n : MAX_PNL_CLIENTS;
    /* Copy sorted by last_seen DESC so newest activity is at top. */
    int order[MAX_PNL_CLIENTS];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (g_tbl[order[j]].last_seen > g_tbl[order[best]].last_seen)
                best = j;
        if (best != i) { int t = order[i]; order[i] = order[best]; order[best] = t; }
    }
    for (int i = 0; i < n; i++) s->pnl_clients[i] = g_tbl[order[i]];
    s->pnl_count = n;
    if (s->pnl_sel >= n && n > 0) s->pnl_sel = n - 1;
    pthread_mutex_unlock(&g_mu);
}

void probe_pnl_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}

int probe_pnl_count(void)
{
    pthread_mutex_lock(&g_mu);
    int n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int probe_pnl_ssid_count(const uint8_t mac[6])
{
    pthread_mutex_lock(&g_mu);
    int out = 0;
    for (int i = 0; i < g_n; i++) {
        if (mac_eq(g_tbl[i].mac, mac)) { out = g_tbl[i].ssid_count; break; }
    }
    pthread_mutex_unlock(&g_mu);
    return out;
}
