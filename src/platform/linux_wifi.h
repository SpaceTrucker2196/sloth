#ifndef LINUX_WIFI_H
#define LINUX_WIFI_H

#include "ntop.h"

/* Read cached scan results via nl80211 (NL80211_CMD_GET_SCAN dump).
   No root required for reading cached results.
   Returns 0 when WITH_WIFI is not defined, no wireless interfaces are
   found, or the kernel netlink call fails. APs are sorted by signal
   strength (strongest first). */
int linux_wifi_scan(wifi_ap_t *out, int max);

#endif /* LINUX_WIFI_H */
