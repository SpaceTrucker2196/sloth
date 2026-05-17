#ifndef FAKE_PLATFORM_H
#define FAKE_PLATFORM_H

#include "sloth.h"

/* The fake network state. Tests and scenarios read/write this directly. */
typedef struct {
    iface_stat_t   ifaces[MAX_IFACES];
    int            iface_count;

    conn_t         conns[MAX_CONNS];
    int            conn_count;

    wifi_ap_t      aps[MAX_WIFI_APS];
    int            ap_count;

    wifi_sta_t     wifi_stas[MAX_WIFI_STAS];
    int            wifi_sta_count;

    probe_client_t probe_clients[MAX_PROBE_CLIENTS];
    int            probe_count;
    char           probe_iface[16]; /* monitor interface name, "" = none */

    int            tick;   /* incremented by scenario_simulate_step() */
} fake_net_t;

extern fake_net_t g_fake_net;

/* Zero out g_fake_net and tick */
void fake_net_reset(void);

/* Copy probe state from g_fake_net into s — test-only equivalent of
   probe_snapshot(): sets s->probe_clients, probe_count, probe_iface. */
void fake_net_apply_probe(sloth_state_t *s);

/* platform_ops_t backed by g_fake_net.
   Assigned to g_platform in fake_platform.c so the test binary links. */
extern platform_ops_t g_platform;

#endif /* FAKE_PLATFORM_H */
