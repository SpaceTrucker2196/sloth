#ifndef LINUX_WIFI_H
#define LINUX_WIFI_H

#include "sloth.h"

/* Read cached scan results via nl80211 (NL80211_CMD_GET_SCAN dump).
   No root required for reading cached results.
   Returns 0 when WITH_WIFI is not defined, no wireless interfaces are
   found, or the kernel netlink call fails. APs are sorted by signal
   strength (strongest first). */
int linux_wifi_scan(wifi_ap_t *out, int max);

/* Query station info via nl80211 (NL80211_CMD_GET_STATION dump).
   In managed mode returns one entry (the AP we're linked to).
   In AP mode returns all associated clients.
   Returns 0 when not associated, no wlan interfaces found, or kernel
   call fails. */
int linux_wifi_get_stations(wifi_sta_t *out, int max);

/* Retune `iface` (a monitor-mode interface) to freq_mhz via nl80211
   (NL80211_CMD_SET_CHANNEL). Requires CAP_NET_ADMIN. Returns 0 on an
   ACKed retune, -1 on any error (bad iface, EPERM, kernel refusal).
   The only kernel-state write sloth performs; gated behind --hop.
   See issue #22 and MISSION §2. */
int linux_wifi_set_channel(const char *iface, int freq_mhz);

#endif /* LINUX_WIFI_H */
