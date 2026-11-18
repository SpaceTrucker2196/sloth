#include "sloth.h"
#include "sys_status.h"

/* sloth-rf's platform (#213).
 *
 * The vtable is the seam to the kernel (include/sloth.h), and this
 * daemon's side of it is two functions: read a regular file, list a
 * directory. src/sys_status.c calls them for /proc and /sys - the
 * host's load, memory, temperatures, supply alarm and the receivers
 * sysfs lists - and it calls them through g_platform so the test
 * binary can stand a fake host in.
 *
 * Every other slot is NULL, and that is the content of this file:
 * no interface or socket enumeration (rtnetlink, INET_DIAG), no Wi-Fi
 * scan, station dump or channel set (nl80211), no ARP or DHCP read, no
 * self-MAC roster. `sloth`'s vtable (src/platform/linux.c) names all of
 * those, so linking it would link the nl80211 backend; the Makefile's
 * check_rf_no_capture holds linux_wifi_* and linux_get_* out of this
 * binary. Nothing sloth-rf runs calls a NULL slot: its poll table
 * (g_poll_rf) has no platform stage. */
platform_ops_t g_platform = {
    .sys_read = sys_io_read_file,
    .sys_list = sys_io_list_dir,
};
