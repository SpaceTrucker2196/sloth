#ifdef PLATFORM_STUB

#include "ntop.h"

/* No-op fallback for unsupported or embedded platforms.
   Implement get_ifaces / get_conns / wifi_scan using
   whatever RTOS or bare-metal APIs are available. */

int stub_get_ifaces(iface_stat_t *out, int max) { (void)out; (void)max; return 0; }
int stub_get_conns(conn_t *out, int max)         { (void)out; (void)max; return 0; }
int stub_wifi_scan(wifi_ap_t *out, int max)      { (void)out; (void)max; return 0; }
int stub_get_arp(arp_entry_t *out, int max)      { (void)out; (void)max; return 0; }

static void stub_init(void)    {}
static void stub_cleanup(void) {}

platform_ops_t g_platform = {
    stub_get_ifaces,
    stub_get_conns,
    stub_wifi_scan,
    stub_get_arp,
    stub_init,
    stub_cleanup,
};

#endif /* PLATFORM_STUB */
