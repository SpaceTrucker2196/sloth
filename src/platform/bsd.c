#ifdef PLATFORM_BSD

#include "ntop.h"

/* Week 2: sysctl(NET_RT_IFLIST) for interface stats    */
/* Week 3: sysctl(KERN_FILE) for connection table        */
/* Week 4: CoreWLAN (macOS) / net80211 (FreeBSD) WiFi   */

int bsd_get_ifaces(iface_stat_t *out, int max) { (void)out; (void)max; return 0; }
int bsd_get_conns(conn_t *out, int max)         { (void)out; (void)max; return 0; }
int bsd_wifi_scan(wifi_ap_t *out, int max)      { (void)out; (void)max; return 0; }

static void bsd_init(void)    {}
static void bsd_cleanup(void) {}

platform_ops_t g_platform = {
    bsd_get_ifaces,
    bsd_get_conns,
    bsd_wifi_scan,
    bsd_init,
    bsd_cleanup,
};

#endif /* PLATFORM_BSD */
