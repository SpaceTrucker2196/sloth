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
   ACKed retune, or a negative errno (#91): the kernel's refusal from
   the ack (-EPERM, -EBUSY, -EINVAL ...), -ENODEV for an unknown
   iface, -EOPNOTSUPP with no nl80211 (or without WITH_WIFI), and
   -ETIMEDOUT when no ack arrived inside the 200 ms receive timeout.
   A kernel-state write, gated behind --hop, and the narrowest one
   sloth makes: it retunes sloth's own receiver, changing only what
   sloth hears.

   Deliberately given no total. This comment has twice claimed a count
   and been wrong both times — first a sole claim (#84 found the
   NL80211_CMD_TRIGGER_SCAN built below, behind --allow-active),
   then a count of two, which missed that opening a capture handle sets
   promiscuous mode (pcap_set_promisc in src/capture/capture.c, and
   promisc=1 on every pcap_open_live). That one touches whatever
   interface libpcap opened and sits behind no opt-in at all. Three
   known writes is not a guarantee of three; counting them here is what
   keeps going stale, so this comment names them and asserts no total.
   See MISSION.md §2 for the governing rule, and issues #22 and #84. */
int linux_wifi_set_channel(const char *iface, int freq_mhz);

/* Decode the reply to an NLM_F_ACK request: 0 for an ACK, the kernel's
   negative errno for a refusal, -EIO for anything that is not a
   well-formed NLMSG_ERROR. Pure, so the errno plumbing is testable with
   hand-built bytes and no socket (#91). */
int linux_wifi_ack_result(const void *buf, long len);

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

/* ── Cached-scan read (#84) ──
 *
 * Build the NL80211_CMD_GET_SCAN dump request for `ifidx` into `buf`.
 * Returns its length, or 0 for bad arguments only. Not policy-gated, by
 * design: the dump reads the kernel's cached BSS table, and --strict
 * stops sloth asking for a scan, not reading what is already cached. */
size_t linux_wifi_prepare_get_scan(uint8_t *buf, size_t sz, int family,
                                   unsigned ifidx);

/* One interface's turn in linux_wifi_scan(): offer the (policy-gated,
 * rate-limited) scan trigger, then build the GET_SCAN read into
 * `get_buf`. Returns the read's length. This is the exact composition
 * linux_wifi_scan() sends, split out so a test can prove a strict run
 * still reads the cache while building no trigger. The trigger, if one
 * is built, is sent on its own disposable socket inside this call. */
size_t linux_wifi_prepare_scan_pass(uint8_t *get_buf, size_t get_sz,
                                    int family, unsigned ifidx);

#endif /* LINUX_WIFI_H */
