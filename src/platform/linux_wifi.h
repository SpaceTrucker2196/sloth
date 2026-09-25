#ifndef LINUX_WIFI_H
#define LINUX_WIFI_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

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

/* ── Scan-trigger policy, limiter and instrumentation (#84) ──
 *
 * linux_wifi_scan() reads cached results, but it also used to kick a
 * background NL80211_CMD_TRIGGER_SCAN from the ordinary poll loop. That
 * is a kernel-state change, so #84 puts it behind the same observation
 * policy as the resolver: no request is built unless the operator passed
 * --allow-active, and --strict refuses it for the whole run.
 *
 * The decision, the rate limiter and the message construction are split
 * out of the sending path so a test can assert "zero TRIGGER_SCAN
 * requests were built" without a radio, a socket, or root. Counting at
 * the builder rather than at sendto(2) is deliberate: a request that was
 * built and then dropped is still a request the code was willing to
 * make.
 *
 * Not thread-safe — the limiter table and the counters carry no lock,
 * because linux_wifi_scan() is only ever called from the poll loop (the
 * same assumption the existing static receive buffers already make). */

/* find_wlan_ifaces() enumerates at most this many interfaces, so a table
   of this size gives every enumerated radio its own limiter slot. */
#define WIFI_SCAN_TRIGGER_MAX_IFACES        8

/* Minimum seconds between triggers on the same interface. */
#define WIFI_SCAN_TRIGGER_MIN_INTERVAL_SEC  5

typedef struct {
    uint64_t considered;        /* prepare calls that got past arg checks */
    uint64_t suppressed_policy; /* refused: active behaviour not permitted */
    uint64_t suppressed_rate;   /* refused: per-interface rate limiter     */
    uint64_t requests_built;    /* TRIGGER_SCAN requests actually built    */
} wifi_scan_trigger_stats_t;

/* Decide whether a scan trigger for `ifidx` is permitted right now and,
   if so, build the netlink request into `buf`. Returns the request
   length in bytes, or 0 when nothing was built — policy refusal, rate
   limit, or a buffer too small. `now` is passed in rather than read from
   the clock so the limiter is testable. */
size_t linux_wifi_prepare_scan_trigger(uint8_t *buf, size_t sz, int family,
                                       unsigned ifidx, time_t now);

void linux_wifi_scan_trigger_stats(wifi_scan_trigger_stats_t *out);

/* Clear the counters and the per-interface limiter state (for testing). */
void linux_wifi_scan_trigger_reset(void);

#endif /* LINUX_WIFI_H */
