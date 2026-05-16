#ifdef PLATFORM_WIN32

#include "ntop.h"

/* Week 2: GetIfTable2 for interface stats               */
/* Week 3: GetExtendedTcpTable for connection table      */
/* Week 4: wlanapi for WiFi scanning                     */

int win32_get_ifaces(iface_stat_t *out, int max) { (void)out; (void)max; return 0; }
int win32_get_conns(conn_t *out, int max)         { (void)out; (void)max; return 0; }
int win32_wifi_scan(wifi_ap_t *out, int max)      { (void)out; (void)max; return 0; }

static void win32_init(void)    {}
static void win32_cleanup(void) {}

platform_ops_t g_platform = {
    win32_get_ifaces,
    win32_get_conns,
    win32_wifi_scan,
    win32_init,
    win32_cleanup,
};

#endif /* PLATFORM_WIN32 */
