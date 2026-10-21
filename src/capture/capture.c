#include <string.h>
#include <stdint.h>
#include "capture/capture.h"
#include "bytes.h"
#include "sloth_clock.h"    /* injectable wall clock for freshness (#91) */
#include "captive_portal.h"
#include "dns.h"
#include "dot11_frame.h"
#include "radiotap.h"
#include "capture/frame_edge.h"
#include "pcap_format.h"
#include "ble_hci.h"        /* bt_dev_is_bluetooth (#144 slice 2) */

/* DLT_LINUX_SLL  (113) — Linux cooked capture v1 used by "any"
 * DLT_LINUX_SLL2 (276) — Linux cooked capture v2, carries the ingress
 * interface index as sll2_if_index (offset 4). Selectable via
 * pcap_set_datalink() after activate on libpcap ≥ 1.10; default for
 * "any" on ≥ 1.11. Enables per-iface data-stream filtering (#17).
 *
 * Above the WITH_PCAP guard because capture_dlt_has_ifindex() below is
 * compiled into the test build, which links no libpcap. */
#define MY_DLT_LINUX_SLL  113
#define MY_DLT_LINUX_SLL2 276

/* Kept outside the WITH_PCAP guard: it is pure arithmetic on libpcap's
   documented return contract, so the test build (which links no libpcap)
   can still assert it. See capture.h for the contract and issue #46. */
int capture_activate_failed(int rc) {
    return rc < 0;
}

/* Also outside the guard, and for the same reason. See capture.h. */
int capture_dlt_has_ifindex(int dlt) {
    return dlt == MY_DLT_LINUX_SLL2;
}

/* Outside the guard as well; contract in capture.h. */
const char *capture_fallback_device(const char *const *names, int n) {
    if (!names) return NULL;
    for (int i = 0; i < n; i++)
        if (names[i] && names[i][0] && !bt_dev_is_bluetooth(names[i]))
            return names[i];
    return NULL;
}

/* Outside the guard again so the test build can pin it (#84 slice 2).
   Rationale and the defect it removes are in capture.h. */
const char *capture_quic_hostname(const char *remote_ip,
                                  char *buf, size_t sz) {
    return dns_lookup_cached(remote_ip, buf, sz);
}

/* ── Fail-closed capture scope (#85) ───────────────────────────
 * Outside the guard for the same reason again: the test build drives
 * these with hand-built SLL2 headers and a seeded resolver. Contract in
 * capture.h. */
#define SLL2_HDRLEN 20

#define IFINDEX_CACHE_MAX 16
typedef struct { uint32_t idx; char name[16]; } ifname_cache_t;
static ifname_cache_t g_ifname_cache[IFINDEX_CACHE_MAX];
static int            g_ifname_cache_n;
static int            g_ifname_cache_next;   /* round-robin victim */

void capture_ifname_cache_reset(void) {
    g_ifname_cache_n    = 0;
    g_ifname_cache_next = 0;
}

const char *capture_ifname_lookup(uint32_t idx, capture_ifname_fn resolve) {
    for (int i = 0; i < g_ifname_cache_n; i++)
        if (g_ifname_cache[i].idx == idx) return g_ifname_cache[i].name;
    char name[16];
    memset(name, 0, sizeof(name));
    /* A miss is not an answer: an index that failed to resolve now is
     * asked again next packet, and never lands in the cache. The old
     * cache stored "" and every later frame on that index bypassed the
     * allow-list. */
    if (!resolve || !resolve(idx, name)) return NULL;
    name[sizeof(name) - 1] = '\0';
    if (!name[0]) return NULL;
    ifname_cache_t *e;
    if (g_ifname_cache_n < IFINDEX_CACHE_MAX) {
        e = &g_ifname_cache[g_ifname_cache_n++];
    } else {
        e = &g_ifname_cache[g_ifname_cache_next];
        g_ifname_cache_next = (g_ifname_cache_next + 1) % IFINDEX_CACHE_MAX;
    }
    e->idx = idx;
    memcpy(e->name, name, sizeof(e->name));
    return e->name;
}

int capture_policy_pin(capture_policy_t *p, const sloth_state_t *s,
                       capture_ifindex_fn resolve, pthread_mutex_t *mu) {
    if (!p) return 0;
    memset(p, 0, sizeof(*p));
    p->mu = mu;
    if (!s || !resolve) return 0;
    for (int i = 0; i < s->iface_allowed_count && p->count < MAX_IFACES; i++) {
        uint32_t idx = resolve(s->iface_allowed[i]);
        /* Absent at start: not pinned, so never admitted. The scope then
         * reads DEGRADED, which is what makes this visible. */
        if (idx == 0) continue;
        capture_pin_t *pin = &p->pins[p->count++];
        pin->ifindex = idx;
        memcpy(pin->name, s->iface_allowed[i], sizeof(pin->name));
        pin->name[sizeof(pin->name) - 1] = '\0';
        pin->valid = 1;
    }
    return p->count;
}

const capture_pin_t *capture_policy_match(const capture_policy_t *p,
                                          uint32_t ifindex) {
    if (!p) return NULL;
    for (int i = 0; i < p->count; i++) {
        if (p->pins[i].ifindex != ifindex) continue;
        int ok;
        if (p->mu) pthread_mutex_lock(p->mu);
        ok = p->pins[i].valid;
        if (p->mu) pthread_mutex_unlock(p->mu);
        return ok ? &p->pins[i] : NULL;
    }
    return NULL;
}

int capture_policy_revalidate(capture_policy_t *p, capture_ifname_fn resolve) {
    if (!p) return 0;
    int failed = 0;
    for (int i = 0; i < p->count; i++) {
        /* Unlocked read: this thread is the only writer of `valid`. */
        if (!p->pins[i].valid) continue;   /* sticky until restart */
        char name[16];
        memset(name, 0, sizeof(name));
        /* The resolver runs outside the lock — the callback takes it per
         * packet and should never wait on an ioctl. */
        int same = resolve && resolve(p->pins[i].ifindex, name);
        name[sizeof(name) - 1] = '\0';
        if (same) same = strcmp(name, p->pins[i].name) == 0;
        if (same) continue;
        if (p->mu) pthread_mutex_lock(p->mu);
        p->pins[i].valid = 0;
        p->generation++;
        if (p->mu) pthread_mutex_unlock(p->mu);
        failed++;
    }
    return failed;
}

int capture_policy_valid_count(const capture_policy_t *p) {
    if (!p) return 0;
    int n = 0;
    for (int i = 0; i < p->count; i++) n += p->pins[i].valid != 0;
    return n;
}

/* Allow-listed names with no valid pin, for the launch notice (#85).
 * Matched by name rather than by pin index so the operator reads back
 * what they typed, and recomputed from the live `valid` bits so the
 * answer stays honest after a mid-run fail-closed instead of describing
 * only the state at launch.
 *
 * Unlocked read of `valid`, on the same argument as
 * capture_policy_valid_count(): the main thread is its only writer. */
int capture_policy_unpinned(const capture_policy_t *p, const sloth_state_t *s,
                            char *buf, int sz) {
    int off = 0, count = 0;
    if (buf && sz > 0) buf[0] = '\0';
    if (!s) return 0;
    int n = s->iface_allowed_count;
    if (n < 0) n = 0;
    if (n > MAX_IFACES) n = MAX_IFACES;
    for (int i = 0; i < n; i++) {
        const char *name = s->iface_allowed[i];
        int pinned = 0;
        for (int j = 0; p && j < p->count && !pinned; j++)
            pinned = p->pins[j].valid && strcmp(p->pins[j].name, name) == 0;
        if (pinned) continue;
        count++;
        /* The return counts unpinned names, never the names that fitted:
         * a short buffer must not understate the problem. */
        if (!buf || sz <= 0) continue;
        if (off > 0 && off < sz - 1) buf[off++] = ',';
        for (const char *c = name; *c && off < sz - 1; c++) buf[off++] = *c;
        buf[off] = '\0';
    }
    return count;
}

/* Which launch notice the unpinned set earns, if any (#85).
 *
 * Pure, and above the WITH_PCAP guard, so the test build can drive it
 * without libpcap -- the same split capture_scope_verdict() already
 * uses, which leaves main.c nothing to decide and only a line to print.
 *
 * `capture_open == 0` is silent unconditionally, and that gate is why
 * this function exists rather than main.c comparing the two counts
 * itself. With no pcap handle capture_run() returns before
 * capture_policy_pin(), so the policy is still zeroed and every
 * requested name reads unpinned -- which would announce "none of the
 * requested interfaces could be resolved" underneath the truthful
 * "capture unavailable" line main already printed for the NO_CAPTURE
 * verdict, blaming the resolver for the handle's absence. */
capture_scope_notice_t capture_scope_notice(int capture_open, int requested,
                                            int unpinned) {
    if (!capture_open || requested <= 0 || unpinned <= 0)
        return CAPTURE_SCOPE_NOTICE_NONE;
    if (unpinned >= requested) return CAPTURE_SCOPE_NOTICE_ALL;
    return CAPTURE_SCOPE_NOTICE_SOME;
}

void capture_policy_sync_deselect(capture_policy_t *p,
                                  const sloth_state_t *s) {
    if (!p || !s) return;
    int n = s->iface_deselected_count;
    if (n < 0) n = 0;
    if (n > MAX_IFACES) n = MAX_IFACES;
    if (p->mu) pthread_mutex_lock(p->mu);
    /* The whole list goes in one critical section so the callback never
     * sees a count from one toggle and names from another. */
    memcpy(p->desel, s->iface_deselected, (size_t)n * 16);
    p->desel_count = n;
    if (p->mu) pthread_mutex_unlock(p->mu);
}

/* Locked count read for the callback's fast path: TSan-clean, and a
 * mutex acquisition per packet is the price capture_policy_match()
 * already pays in restricted mode. */
static int policy_desel_count(const capture_policy_t *p) {
    if (!p) return 0;
    int n;
    if (p->mu) pthread_mutex_lock(p->mu);
    n = p->desel_count;
    if (p->mu) pthread_mutex_unlock(p->mu);
    return n;
}

int capture_policy_deselected(const capture_policy_t *p, const char *name) {
    if (!p || !name) return 0;
    int hit = 0;
    if (p->mu) pthread_mutex_lock(p->mu);
    for (int i = 0; i < p->desel_count; i++) {
        if (strncmp(p->desel[i], name, 16) == 0) { hit = 1; break; }
    }
    if (p->mu) pthread_mutex_unlock(p->mu);
    return hit;
}

/* Lifetime count of frames refused specifically by the launch-time
 * --iface/--monitor-only allow-list (#85's authorization boundary) — not
 * the unrelated runtime [y] deselect, which is an operator toggle that
 * predates #85 and isn't an authorization failure, with or without an
 * allow-list in force. Bumped inside
 * capture_frame_in_scope() itself, below, so it's testable with
 * hand-built frames and needs no live capture. Read by jsonl.c's
 * sensor_health emitter (#85 wave 8). */
static uint64_t g_out_of_scope_dropped;

uint64_t capture_out_of_scope_dropped(void) { return g_out_of_scope_dropped; }
void capture_out_of_scope_dropped_reset(void) { g_out_of_scope_dropped = 0; }

int capture_frame_in_scope(const sloth_state_t *s, const capture_policy_t *p,
                           int dlt, const uint8_t *frame, int caplen,
                           capture_ifname_fn resolve) {
    if (!s) return 0;
    int restricted = s->iface_allowed_count > 0;
    if (!capture_dlt_has_ifindex(dlt) || !frame || caplen < SLL2_HDRLEN) {
        if (restricted) g_out_of_scope_dropped++;
        return !restricted;
    }
    /* Nothing filters: skip the name lookup so the hot path stays
     * syscall-free. The count comes from the policy snapshot, not the
     * live state — a toggle lands on the next synced tick (#95). */
    if (!restricted && policy_desel_count(p) == 0) return 1;
    uint32_t ifi = ((uint32_t)frame[4] << 24) | ((uint32_t)frame[5] << 16)
                 | ((uint32_t)frame[6] <<  8) |  (uint32_t)frame[7];
    if (restricted) {
        /* The pinned set is the authority, not whatever name the index
         * resolves to today. */
        const capture_pin_t *pin = capture_policy_match(p, ifi);
        /* Only an attribution failure is counted. A pinned, still-valid
         * interface the operator switched off with [y] is refused too,
         * but that is the operator's own toggle on an authorised
         * interface, not traffic from outside the scope -- counting it
         * made an idle deselect read as an authorization violation on
         * an `enforced` scope (#85; owner ruling 2026-10-19: the code
         * follows the documented contract). */
        if (!pin) {
            g_out_of_scope_dropped++;
            return 0;
        }
        return !capture_policy_deselected(p, pin->name);
    }
    const char *name = capture_ifname_lookup(ifi, resolve);
    if (!name) return 1;
    return !capture_policy_deselected(p, name);
}

capture_scope_state_t capture_scope_state(int requested, int capture_live,
                                          int enforced) {
    if (requested <= 0)        return CAPTURE_SCOPE_STATE_NONE;
    if (!capture_live)         return CAPTURE_SCOPE_STATE_NO_CAPTURE;
    if (enforced < requested)  return CAPTURE_SCOPE_STATE_DEGRADED;
    return CAPTURE_SCOPE_STATE_ENFORCED;
}

const char *capture_scope_state_name(capture_scope_state_t st) {
    switch (st) {
    case CAPTURE_SCOPE_STATE_NONE:       return "none";
    case CAPTURE_SCOPE_STATE_ENFORCED:   return "enforced";
    case CAPTURE_SCOPE_STATE_NO_CAPTURE: return "no_capture";
    case CAPTURE_SCOPE_STATE_DEGRADED:   break;
    }
    return "degraded";
}

int capture_scope_not_enforced(capture_scope_state_t st) {
    return st != CAPTURE_SCOPE_STATE_NONE && st != CAPTURE_SCOPE_STATE_ENFORCED;
}

capture_scope_t capture_scope_verdict(int iface_args, int monitor_only,
                                      const char *monitor_iface,
                                      int allowed_count, int capture_open,
                                      int linktype) {
    if (iface_args <= 0 && !monitor_only) return CAPTURE_SCOPE_NONE;
    if (monitor_only && (!monitor_iface || !monitor_iface[0]))
        return CAPTURE_SCOPE_REFUSE_NO_MONITOR;
    /* An empty list reads as "unrestricted" everywhere downstream. */
    if (allowed_count <= 0)          return CAPTURE_SCOPE_REFUSE_EMPTY;
    if (!capture_open)               return CAPTURE_SCOPE_NO_CAPTURE;
    if (!capture_dlt_has_ifindex(linktype))
        return CAPTURE_SCOPE_REFUSE_DATALINK;
    return CAPTURE_SCOPE_ENFORCED;
}

int capture_scope_refuses(capture_scope_t v) {
    return v == CAPTURE_SCOPE_REFUSE_NO_MONITOR
        || v == CAPTURE_SCOPE_REFUSE_EMPTY
        || v == CAPTURE_SCOPE_REFUSE_DATALINK;
}

/* ── Capture-worker exit classification (#91 slice 2) ──────────
 * Contract and rationale in capture.h. Kept above the WITH_PCAP guard
 * for the same reason capture_activate_failed() is: it is pure logic
 * over libpcap's documented return contract, so the test build can pin
 * it without linking libpcap or touching a radio. */

/* pcap_dispatch()'s error codes, written out rather than #included:
 * this half of the file compiles in every configuration, including the
 * no-pcap ones that have no <pcap.h>, and these have been stable since
 * libpcap 1.0. */
#define CAP_PCAP_ERROR               (-1)
#define CAP_PCAP_ERROR_BREAK         (-2)
#define CAP_PCAP_ERROR_NOT_ACTIVATED (-3)

/* Case-insensitive substring search. strcasestr() is a GNU extension and
 * this file is C99 with no gating, so it is spelled out. */
static int err_has(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return 0;
    for (const char *h = hay; *h; h++) {
        const char *a = h, *b = needle;
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
            if (ca != cb) break;
            a++; b++;
        }
        if (!*b) return 1;
    }
    return 0;
}

capture_exit_t capture_classify_exit(int dispatch_rc, int stop_requested,
                                     const char *err) {
    /* A requested stop wins over everything else: pcap_breakloop() makes
     * the pending dispatch fail, so reporting an error here would flag a
     * fault on every clean shutdown. */
    if (stop_requested)                       return CAPTURE_EXIT_STOPPED;
    if (dispatch_rc >= 0)                     return CAPTURE_EXIT_NONE;
    /* breakloop() is only ever called from the stop paths, which clear
     * the run flag first; a -2 without the flag is a lost race on it,
     * not a fault. */
    if (dispatch_rc == CAP_PCAP_ERROR_BREAK)  return CAPTURE_EXIT_STOPPED;
    if (dispatch_rc == CAP_PCAP_ERROR_NOT_ACTIVATED)
        return CAPTURE_EXIT_NOT_ACTIVATED;
    if (dispatch_rc != CAP_PCAP_ERROR)        return CAPTURE_EXIT_ERROR;

    /* PCAP_ERROR only: the code cannot separate a revoked capability
     * from a vanished adapter, and those need different responses. The
     * text is libpcap's wording, not a kernel contract, so an unmatched
     * message degrades to ERROR rather than being guessed at — the raw
     * string travels alongside in exit_detail either way. */
    if (err_has(err, "no such device")     ||
        err_has(err, "device is not up")   ||
        err_has(err, "went down")          ||
        err_has(err, "disappeared")        ||
        err_has(err, "network is down")    ||
        err_has(err, "not found"))
        return CAPTURE_EXIT_IFACE_GONE;
    if (err_has(err, "permission denied")  ||
        err_has(err, "not permitted"))
        return CAPTURE_EXIT_PERM_LOST;
    return CAPTURE_EXIT_ERROR;
}

const char *capture_exit_name(capture_exit_t r) {
    switch (r) {
    case CAPTURE_EXIT_NONE:          return "none";
    case CAPTURE_EXIT_STOPPED:       return "stopped";
    case CAPTURE_EXIT_IFACE_GONE:    return "iface_gone";
    case CAPTURE_EXIT_PERM_LOST:     return "perm_lost";
    case CAPTURE_EXIT_NOT_ACTIVATED: return "not_activated";
    case CAPTURE_EXIT_ERROR:         break;
    }
    return "error";
}

int capture_worker_live(int handle_open, int run_flag, int exit_reason) {
    return handle_open && run_flag && exit_reason == CAPTURE_EXIT_NONE;
}

void capture_stats_accumulate(capture_health_t *h,
                              uint32_t recv, uint32_t drop, uint32_t ifdrop) {
    if (!h) return;
    uint32_t d_recv, d_drop, d_ifdrop;
    if (!h->stats_valid) {
        /* libpcap's counters start at zero with the handle, so the first
         * sample IS the total so far. Discarding it as a baseline would
         * lose every drop before the first poll — the startup window
         * where an undersized buffer drops hardest. */
        d_recv = recv; d_drop = drop; d_ifdrop = ifdrop;
        h->stats_valid = 1;
    } else {
        /* A sample below the previous one is a counter reset, not a wrap:
         * on Linux libpcap accumulates these in user space per handle, so
         * a decrease means it restarted. Taking the new value keeps the
         * exported lifetime monotonic either way. */
        d_recv   = recv   >= h->last_recv   ? recv   - h->last_recv   : recv;
        d_drop   = drop   >= h->last_drop   ? drop   - h->last_drop   : drop;
        d_ifdrop = ifdrop >= h->last_ifdrop ? ifdrop - h->last_ifdrop : ifdrop;
    }
    h->last_recv   = recv;
    h->last_drop   = drop;
    h->last_ifdrop = ifdrop;
    h->d_recv      = d_recv;
    h->d_drop      = d_drop;
    h->d_ifdrop    = d_ifdrop;
    h->ps_recv    += d_recv;
    h->ps_drop    += d_drop;
    h->ps_ifdrop  += d_ifdrop;
}

const char *capture_scope_reason(capture_scope_t v) {
    switch (v) {
    case CAPTURE_SCOPE_REFUSE_NO_MONITOR:
        return "--monitor-only requested but no monitor-mode interface was "
               "found; refusing to capture an unrestricted stream";
    case CAPTURE_SCOPE_REFUSE_EMPTY:
        return "--iface requested but no usable interface name was given; "
               "refusing to capture an unrestricted stream";
    case CAPTURE_SCOPE_REFUSE_DATALINK:
        return "--iface/--monitor-only requested but the capture datalink "
               "carries no ingress interface (needs SLL2/276); refusing to "
               "capture an unrestricted stream";
    case CAPTURE_SCOPE_NO_CAPTURE:
        return "--iface/--monitor-only requested but packet capture is "
               "disabled; no data stream is collected";
    case CAPTURE_SCOPE_NONE:
    case CAPTURE_SCOPE_ENFORCED:
        break;
    }
    return "";
}

/* Run flag (#95). Contract in capture.h. */
int capture_run_flag_get(capture_run_flag_t *f) {
    pthread_mutex_lock(&f->mu);
    int v = f->v;
    pthread_mutex_unlock(&f->mu);
    return v;
}

void capture_run_flag_set(capture_run_flag_t *f, int v) {
    pthread_mutex_lock(&f->mu);
    f->v = v;
    pthread_mutex_unlock(&f->mu);
}

int capture_run_flag_take(capture_run_flag_t *f) {
    pthread_mutex_lock(&f->mu);
    int v = f->v;
    f->v = 0;
    pthread_mutex_unlock(&f->mu);
    return v;
}

#ifdef WITH_PCAP

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>       /* if_indextoname — issue #17 SLL2 lookup */

#include "sloth.h"
#include "worker_thread.h"     /* signal-blocked worker creation (#95) */
#include "dns_snoop.h"
#include "sni_snoop.h"
#include "mdns_snoop.h"
#include "nbns_snoop.h"
#include "dhcp_snoop.h"
#include "lan_role.h"
#include "ndp_snoop.h"
#include "smb_snoop.h"
#include "kerb_snoop.h"
#include "ldap_snoop.h"
#include "bgp_snoop.h"
#include "ssh_snoop.h"
#include "rdp_snoop.h"
#include "snmp_snoop.h"
#include "mqtt_snoop.h"
#include "quic_log.h"
#include "dns_log.h"
#include "ntp_log.h"
#include "icmp_log.h"
#include "ssdp_snoop.h"
#include "onvif_discovery.h"
#include "rtsp_snoop.h"
#include "sensor_health.h"     /* SH_PF_FRAME_EDGE (#141), SH_PF_IP_* (#132) */
#include "http_snoop.h"
#include "ftp_snoop.h"
#include "pop3_snoop.h"
#include "imap_snoop.h"
#include "smtp_snoop.h"
#include "cleartext_creds.h"
#include "http_log.h"
#include "tls_log.h"

/* ── Thread state ─────────────────────────────────────────── */

static capture_run_flag_t g_running = CAPTURE_RUN_FLAG_INIT;
static pthread_t       g_thread;
static pthread_mutex_t g_mu      = PTHREAD_MUTEX_INITIALIZER;
static sloth_state_t   *g_state;
static pcap_t         *g_handle;
/* Pinned allow-list (#85 slice 2). Identities fixed before the worker
 * exists; valid bits and generation written under g_mu thereafter. */
static capture_policy_t g_policy;
/* Per-stream freshness (#91). Written by on_packet() under g_mu, read
 * by capture_health_poll() on the main thread. */
static time_t g_last_frame_ts   = 0;   /* the frame's own clock */
static time_t g_last_frame_wall = 0;   /* host clock at arrival, 0 = never */

/* The wired packet ring (#111). on_packet() used to write
 * g_state->packets[] directly under g_mu, which protected the writer
 * from nothing: every reader -- views/packets.c, bandwidth.c,
 * pcap_write.c, ip_color.c, alerts/, jsonl.c, alert_pcap.c -- is on
 * main and never took the lock, because the lock was this module's
 * private static. The ring now lives here and main gets a copy once per
 * poll through capture_ring_snapshot(), the same copy pattern
 * mon_frame_snapshot() has used for the 802.11 stream since #21.
 * Head / count / total keep their meanings exactly (bandwidth.c's
 * cursor arithmetic depends on them), so s->packets reads unchanged. */
static packet_info_t g_ring[MAX_PACKETS];
static int           g_ring_head;
static int           g_ring_count;
static uint64_t      g_ring_total;

/* ── Protocol decoders ────────────────────────────────────── */

/* The try_* observers below take the TCP payload, never the segment:
 * the data offset is read and bounded once, in decode_tcp() (#132),
 * instead of once per observer — thirteen copies of one bounds check
 * is thirteen places for it to differ. Each keeps only its own
 * protocol's minimum length. */

/* HTTP request Host header, or a response (#71). */
static void try_http(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 16) return;
    http_log_entry_t entry;

    /* Responses first (#71): a response and a request cannot be
     * confused — one starts "HTTP/1.x", the other a method — and trying
     * the request parser on a response wastes the pass. */
    if (http_log_parse_response(pay, pay_len, pkt->src, &entry)) {
        snprintf(entry.dst, sizeof(entry.dst), "%s", pkt->dst);
        entry.src_port = pkt->src_port;
        entry.dst_port = pkt->dst_port;
        http_log_pair_response(&entry);
        /* A connectivity-check probe answered by something other than
         * the real endpoint (#69). Only fires on a complete body — see
         * cp_check_response. */
        int cp = cp_check_response(&entry);
        if (cp) {
            char ev[80];
            snprintf(ev, sizeof(ev), "HTTP %u, %d body bytes",
                     entry.status, entry.resp_body_len);
            cp_record((uint8_t)cp, entry.host, pkt->dst, ev, sloth_wall());
        }
        snprintf(pkt->info, sizeof(pkt->info), "HTTP %u %.40s",
                 entry.status, entry.host[0] ? entry.host : "");
        http_log_record(&entry);
        return;
    }

    if (!http_log_parse(pay, pay_len, pkt->src, &entry)) return;
    snprintf(entry.dst, sizeof(entry.dst), "%s", pkt->dst);
    entry.src_port = pkt->src_port;
    entry.dst_port = pkt->dst_port;
    if (entry.host[0]) dns_set_resolved(pkt->dst, entry.host);
    snprintf(pkt->info, sizeof(pkt->info), "HTTP %.54s", entry.host[0] ? entry.host : "?");
    http_log_record(&entry);
    /* Same payload pass: look for Authorization: Basic and record any
     * cleartext credential exposure. Username only — see #16 phase 3. */
    http_snoop_scan_creds(pay, pay_len, pkt->src, pkt->dst, pkt->dst_port);
}

/* FTP command-channel observer on TCP/21. Records USER<->PASS
 * exposures via the cleartext_creds ring. #16 phase 3. */
static void try_ftp(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 5) return;
    if (ftp_snoop(pay, pay_len, pkt->src, pkt->dst, pkt->dst_port))
        snprintf(pkt->info, sizeof(pkt->info), "FTP");
}

/* POP3 on TCP/110 — same shape as FTP (USER/PASS lines). */
static void try_pop3(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 5) return;
    if (pop3_snoop(pay, pay_len, pkt->src, pkt->dst, pkt->dst_port))
        snprintf(pkt->info, sizeof(pkt->info), "POP3");
}

/* IMAP on TCP/143 — tagged LOGIN with optional quoting. */
static void try_imap(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 8) return;
    if (imap_snoop(pay, pay_len, pkt->src, pkt->dst, pkt->dst_port))
        snprintf(pkt->info, sizeof(pkt->info), "IMAP");
}

/* SMTP on TCP/25/587 — AUTH PLAIN in one shot. */
static void try_smtp(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 5) return;
    if (smtp_snoop(pay, pay_len, pkt->src, pkt->dst, pkt->dst_port))
        snprintf(pkt->info, sizeof(pkt->info), "SMTP");
}

/* TLS ClientHello SNI, on any port. Updates pkt->info and calls
 * dns_set_resolved if an SNI hostname is found. */
static void try_sni(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 9) return;
    tls_log_entry_t entry;
    if (!tls_log_parse(pay, pay_len, pkt->src, pkt->dst, &entry)) return;
    if (entry.host[0]) dns_set_resolved(pkt->dst, entry.host);
    /* A sentinel host reached over TLS at a private address is a portal
     * terminating the connection (#69). Independent of the body check —
     * a rogue that chunks its HTTP answer still has to do this. */
    {
        int cp = cp_check_tls(entry.host, pkt->dst);
        if (cp) cp_record((uint8_t)cp, entry.host, pkt->src, pkt->dst,
                          sloth_wall());
    }
    snprintf(pkt->info, sizeof(pkt->info), "%s %.46s",
             entry.tls_ver, entry.host[0] ? entry.host : pkt->dst);
    tls_log_record(&entry);
}

static void try_smb(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 4) return;
    if (smb_snoop_observe(pkt->src, pkt->src_port,
                          pkt->dst, pkt->dst_port, pay, pay_len))
        snprintf(pkt->info, sizeof(pkt->info), "SMB");
}

/* Kerberos over TCP/88 — payload starts with a 4-byte length prefix
 * then the ASN.1 message. The UDP path is decode_udp()'s. */
static void try_kerb_tcp(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 1) return;
    if (kerb_snoop_observe(pkt->src, pkt->src_port,
                           pkt->dst, pkt->dst_port, pay, pay_len))
        snprintf(pkt->info, sizeof(pkt->info), "Kerberos");
}

/* LDAP over TCP/389 (default) or TCP/3268 (Global Catalog). TLS
 * variants 636 / 3269 are opaque past the handshake and not
 * observed. */
static void try_ldap(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 2) return;
    if (ldap_snoop_observe(pkt->src, pkt->src_port,
                           pkt->dst, pkt->dst_port, pay, pay_len))
        snprintf(pkt->info, sizeof(pkt->info), "LDAP");
}

/* BGP over TCP/179. The 19-byte marker + length + type header is
 * distinctive enough that we can match on it directly. */
static void try_bgp(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 19) return;
    if (bgp_snoop_observe(pkt->src, pkt->src_port,
                          pkt->dst, pkt->dst_port, pay, pay_len))
        snprintf(pkt->info, sizeof(pkt->info), "BGP");
}

/* RDP X.224 Connection Request on TCP/3389 — TPKT envelope
 * (version 0x03) wrapping a Class 0 CR TPDU (code 0xE0). */
static void try_rdp(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 11) return;
    if (rdp_snoop_observe(pkt->src, pkt->src_port,
                          pkt->dst, pkt->dst_port, pay, pay_len))
        snprintf(pkt->info, sizeof(pkt->info), "RDP");
}

/* MQTT on TCP/1883. Fixed header is one type byte + 1-4 byte
 * Remaining Length varint, so the protocol is tag-recognisable. */
static void try_mqtt(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 2) return;
    if (mqtt_snoop_observe(pkt->src, pkt->src_port,
                           pkt->dst, pkt->dst_port, pay, pay_len))
        snprintf(pkt->info, sizeof(pkt->info), "MQTT");
}

/* RTSP on TCP/554 or the registered alternative 8554 (RFC 7826 §10.2).
 * Requests and responses both: the observer pairs them by CSeq. The
 * shortest message it reads is a 12-byte status line. */
static void try_rtsp(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 12) return;
    rtsp_snoop_observe(pkt->src, pkt->src_port, pkt->dst, pkt->dst_port,
                       pay, pay_len, pkt->info, (int)sizeof(pkt->info));
}

/* SSH banner on TCP/22. Matches the cleartext "SSH-protoversion-..."
 * exchange that precedes the encrypted key exchange. */
static void try_ssh(const uint8_t *pay, int pay_len, packet_info_t *pkt) {
    if (pay_len < 6) return;
    if (ssh_snoop_observe(pkt->src, pkt->src_port,
                          pkt->dst, pkt->dst_port, pay, pay_len))
        snprintf(pkt->info, sizeof(pkt->info), "SSH");
}

static void decode_tcp_flags(uint8_t flags, char *buf, int sz) {
    snprintf(buf, sz, "TCP%s%s%s%s%s%s",
             (flags & 0x02) ? " SYN" : "",
             (flags & 0x10) ? " ACK" : "",
             (flags & 0x08) ? " PSH" : "",
             (flags & 0x01) ? " FIN" : "",
             (flags & 0x04) ? " RST" : "",
             (flags & 0x20) ? " URG" : "");
}

static void decode_icmp(uint8_t type, uint8_t code, char *buf, int sz) {
    switch (type) {
    case 0:  snprintf(buf, sz, "ICMP Echo Reply");             break;
    case 3:  snprintf(buf, sz, "ICMP Unreachable c=%u", code); break;
    case 8:  snprintf(buf, sz, "ICMP Echo Request");           break;
    case 11: snprintf(buf, sz, "ICMP TTL Exceeded");           break;
    default: snprintf(buf, sz, "ICMP type=%u code=%u", type, code); break;
    }
}

static int port_is(const packet_info_t *pkt, uint16_t port) {
    return pkt->src_port == port || pkt->dst_port == port;
}

/* TCP (RFC 9293 §3.1). Ports and flags from the fixed header; the data
 * offset is read here once and the observers get the payload. A data
 * offset below 5 words or past the segment leaves the row as ports and
 * flags only — there is no payload to hand anyone. */
static void decode_tcp(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    pkt->src_port = be16(tp + 0);
    pkt->dst_port = be16(tp + 2);
    decode_tcp_flags(tp[13], pkt->info, sizeof(pkt->info));

    const int doff = (tp[12] >> 4) * 4;
    if (doff < 20 || doff > tlen) return;
    const uint8_t *pay     = tp + doff;
    const int      pay_len = tlen - doff;

    try_sni(pay, pay_len, pkt);
    if (port_is(pkt, 80) || port_is(pkt, 8080) || port_is(pkt, 8000))
        try_http(pay, pay_len, pkt);
    if (port_is(pkt, 21))                        try_ftp(pay, pay_len, pkt);
    if (port_is(pkt, 110))                       try_pop3(pay, pay_len, pkt);
    if (port_is(pkt, 143))                       try_imap(pay, pay_len, pkt);
    if (port_is(pkt, 25) || port_is(pkt, 587))   try_smtp(pay, pay_len, pkt);
    if (port_is(pkt, 445) || port_is(pkt, 139))  try_smb(pay, pay_len, pkt);
    if (port_is(pkt, 88))                        try_kerb_tcp(pay, pay_len, pkt);
    if (port_is(pkt, 389) || port_is(pkt, 3268)) try_ldap(pay, pay_len, pkt);
    if (port_is(pkt, 179))                       try_bgp(pay, pay_len, pkt);
    if (port_is(pkt, 22))                        try_ssh(pay, pay_len, pkt);
    if (port_is(pkt, 3389))                      try_rdp(pay, pay_len, pkt);
    if (port_is(pkt, 1883))                      try_mqtt(pay, pay_len, pkt);
    if (port_is(pkt, 554) || port_is(pkt, 8554)) try_rtsp(pay, pay_len, pkt);
}

/* UDP (RFC 768). The one UDP dispatch for both IP versions: until #132
 * the v4 and v6 decoders each carried a copy, and the v6 copy had
 * already lost the Kerberos and SNMP arms. */
static void decode_udp(const uint8_t *tp, int tlen, packet_info_t *pkt) {
    pkt->src_port = be16(tp + 0);
    pkt->dst_port = be16(tp + 2);
    const uint8_t *pay     = tp + 8;
    const int      pay_len = tlen - 8;

    if (pay_len <= 0) {
        snprintf(pkt->info, sizeof(pkt->info), "UDP %u", be16(tp + 4));
    } else if (port_is(pkt, 53)) {
        /* A LAN host answering other LAN hosts' DNS (#155 router role). */
        lan_role_dns_observe(pkt->src, pkt->src_port, pkt->dst, pay, pay_len);
        if (!dns_snoop(pay, pay_len, pkt->info, sizeof(pkt->info)))
            snprintf(pkt->info, sizeof(pkt->info), "UDP %u", be16(tp + 4));
        dns_log_entry_t dqe;
        if (dns_log_parse(pay, pay_len, pkt->src, &dqe)) {
            dns_log_record(&dqe);
            /* A connectivity-check host resolving into private or
             * CGNAT space is a portal answering for it (#69). */
            int cp = cp_check_dns(dqe.qname, dqe.answer);
            if (cp) cp_record((uint8_t)cp, dqe.qname, pkt->dst,
                              dqe.answer, sloth_wall());
        }
    } else if (port_is(pkt, 5353)) {
        mdns_snoop(pay, pay_len);
        snprintf(pkt->info, sizeof(pkt->info), "mDNS");
    } else if (port_is(pkt, 137)) {
        if (!nbns_snoop(pay, pay_len, pkt->info, sizeof(pkt->info)))
            snprintf(pkt->info, sizeof(pkt->info), "NBNS");
    } else if (port_is(pkt, 67) || port_is(pkt, 68)) {
        if (!dhcp_snoop(pkt->src, pkt->src_port, pay, pay_len,
                        pkt->info, sizeof(pkt->info)))
            snprintf(pkt->info, sizeof(pkt->info), "DHCP");
    } else if (port_is(pkt, 443)) {
        const char *remote = (pkt->dst_port == 443) ? pkt->dst : pkt->src;
        char        hbuf[DNS_NAME_MAX];
        const char *host   = capture_quic_hostname(remote, hbuf, sizeof(hbuf));
        quic_log_entry_t qe;
        if (quic_log_parse(pay, pay_len, pkt->src, pkt->dst,
                           host && host[0] ? host : NULL, &qe)) {
            snprintf(pkt->info, sizeof(pkt->info), "QUIC %.58s",
                     qe.host[0] ? qe.host : qe.ver);
            quic_log_record(&qe);
        } else {
            snprintf(pkt->info, sizeof(pkt->info), "UDP 443");
        }
    } else if (port_is(pkt, 1900)) {
        if (!ssdp_snoop(pkt->src, pay, pay_len, pkt->info, sizeof(pkt->info)))
            snprintf(pkt->info, sizeof(pkt->info), "SSDP");
    } else if (port_is(pkt, 3702)) {
        if (!onvif_ws_discovery_snoop(pkt->src, pay, pay_len,
                                      pkt->info, sizeof(pkt->info)))
            snprintf(pkt->info, sizeof(pkt->info), "WSD");
    } else if (port_is(pkt, 123)) {
        ntp_log_entry_t ne;
        if (ntp_log_parse(pay, pay_len, pkt->src, pkt->dst, &ne)) {
            snprintf(pkt->info, sizeof(pkt->info),
                     "NTP v%u %.6s str=%u", ne.version, ne.mode, ne.stratum);
            ntp_log_record(&ne);
        } else {
            snprintf(pkt->info, sizeof(pkt->info), "NTP");
        }
    } else if (port_is(pkt, 88)) {
        if (kerb_snoop_observe(pkt->src, pkt->src_port,
                               pkt->dst, pkt->dst_port, pay, pay_len))
            snprintf(pkt->info, sizeof(pkt->info), "Kerberos");
        else
            snprintf(pkt->info, sizeof(pkt->info), "UDP 88");
    } else if (port_is(pkt, 161) || port_is(pkt, 162)) {
        if (snmp_snoop_observe(pkt->src, pkt->src_port,
                               pkt->dst, pkt->dst_port, pay, pay_len))
            snprintf(pkt->info, sizeof(pkt->info), "SNMP");
        else
            snprintf(pkt->info, sizeof(pkt->info), "UDP %u",
                     pkt->dst_port == 161 || pkt->dst_port == 162
                     ? pkt->dst_port : pkt->src_port);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "UDP %u", be16(tp + 4));
    }
}

/* THE transport dispatch (#132). `proto` is the upper-layer protocol
 * after any IPv6 extension headers; `tp` is bounded by the IP length
 * field, not by the frame, so link-layer padding never reaches it. */
static void decode_l4(int proto, int is_v6, const uint8_t *tp, int tlen,
                      packet_info_t *pkt) {
    if (proto == 6 && tlen >= 20) {
        decode_tcp(tp, tlen, pkt);
    } else if (proto == 17 && tlen >= 8) {
        decode_udp(tp, tlen, pkt);
    } else if (!is_v6 && proto == 1 && tlen >= 2) {
        decode_icmp(tp[0], tp[1], pkt->info, sizeof(pkt->info));
        icmp_log_entry_t ie;
        if (icmp_log_parse(tp, tlen, pkt->src, pkt->dst, 0, &ie))
            icmp_log_record(&ie);
    } else if (is_v6 && proto == 58 && tlen >= 2) {
        snprintf(pkt->info, sizeof(pkt->info), "ICMPv6 type=%u", tp[0]);
        icmp_log_entry_t ie;
        if (icmp_log_parse(tp, tlen, pkt->src, pkt->dst, 1, &ie))
            icmp_log_record(&ie);
        /* NDP Router Advertisement (type 134) — feeds the rogue-RA
         * tracker. Other NDP types (RS, NS, NA, Redirect) are not yet
         * snooped; see docs/wiki/ipv6-ndp.md for the scope decision. */
        if (tp[0] == 134) {
            ndp_snoop_ra(pkt->src, tp, tlen);
            snprintf(pkt->info, sizeof(pkt->info), "NDP RA");
        }
    } else if (is_v6) {
        snprintf(pkt->info, sizeof(pkt->info), "IPv6 nh=%d", proto);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "IP proto %d", proto);
    }
}

/* IPv4 (RFC 791 §3.1) down to its transport segment. Returns 1 with
 * *tp / *tlen set, 0 when there is no segment to parse.
 *
 * Total Length bounds the packet, not the frame (#132): Ethernet pads
 * a short packet to 46 octets of payload, and before this the padding
 * was handed to the payload parsers as if it were the datagram's tail.
 * The clamp only ever shortens — a Total Length past the captured bytes
 * widens nothing — and that case is tallied as ip_truncated unless the
 * capture itself was snapped (`snapped`: caplen < wire length), where a
 * short packet is expected rather than malformed.
 *
 * A Total Length of 0 is read as "not stated", not as malformed: Linux
 * BIG TCP puts 0 there for a GSO packet over 64 KiB, which a passive
 * tap on the sending host does see. Such a packet is parsed to the
 * captured length, as every packet was before.
 *
 * A non-first fragment (offset != 0) carries no transport header — its
 * first octets are payload at an arbitrary offset into the datagram —
 * so parsing it as TCP or UDP invented ports and produced bogus
 * records. It is labelled and tallied, not parsed: sloth does not
 * reassemble. The first fragment (offset 0, MF set) is parsed, because
 * its transport header is real and the observers bound their reads. */
static int l4_from_ipv4(const uint8_t *p, int len, int snapped,
                        packet_info_t *pkt, const uint8_t **tp, int *tlen) {
    if (len < 20) return 0;
    int ihl = (p[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len) return 0;

    pkt->proto = p[9];
    inet_ntop(AF_INET, p + 12, pkt->src, sizeof(pkt->src));
    inet_ntop(AF_INET, p + 16, pkt->dst, sizeof(pkt->dst));

    const int total = be16(p + 2);
    if (total != 0) {
        if (total < ihl) {
            sh_parse_fault_note(SH_PF_IP_TRUNCATED);
            snprintf(pkt->info, sizeof(pkt->info), "IPv4 bad len");
            return 0;
        }
        if (total < len)
            len = total;
        else if (total > len && !snapped)
            sh_parse_fault_note(SH_PF_IP_TRUNCATED);
    }

    if ((be16(p + 6) & 0x1fff) != 0) {
        sh_parse_fault_note(SH_PF_IP_FRAGMENT);
        snprintf(pkt->info, sizeof(pkt->info), "IPv4 frag");
        return 0;
    }

    *tp   = p + ihl;
    *tlen = len - ihl;
    return 1;
}

/* IPv6 (RFC 8200 §3) down to its transport segment, walking the
 * extension headers (§4). Same contract and length policy as
 * l4_from_ipv4(), with Payload Length in place of Total Length; a
 * Payload Length of 0 is a jumbogram (RFC 2675) or BIG TCP and is
 * parsed to the captured length.
 *
 * Walked: Hop-by-Hop (0), Routing (43) and Destination Options (60),
 * 8 * (Hdr Ext Len + 1) octets (§4.3, §4.4, §4.6); AH (51, RFC 4302
 * §2.2), 4 * (Payload Len + 2); Fragment (44, §4.5), 8 octets, where a
 * non-zero Fragment Offset ends the walk exactly as an IPv4 non-first
 * fragment does. Anything else — No Next Header (59), ESP (50),
 * Mobility (135), an unknown value — ends the walk and decode_l4()
 * labels it "IPv6 nh=N". Before #132 there was no walk: an MLD report
 * behind its Hop-by-Hop Router Alert never reached the ICMPv6 arm, and
 * the bytes after any extension header were parsed as whatever p[6]
 * named.
 *
 * pkt->proto is the protocol the walk ended on, not p[6]: the field
 * means "what this packet carries", and an extension header is not
 * that. Every header advances the walk by at least 8 octets inside a
 * length below 64 KiB, so the loop terminates. */
static int l4_from_ipv6(const uint8_t *p, int len, int snapped,
                        packet_info_t *pkt, const uint8_t **tp, int *tlen) {
    if (len < 40) return 0;
    inet_ntop(AF_INET6, p + 8,  pkt->src, sizeof(pkt->src));
    inet_ntop(AF_INET6, p + 24, pkt->dst, sizeof(pkt->dst));

    const int plen = be16(p + 4);
    if (plen != 0) {
        if (40 + plen < len)
            len = 40 + plen;
        else if (40 + plen > len && !snapped)
            sh_parse_fault_note(SH_PF_IP_TRUNCATED);
    }

    int nh  = p[6];
    int off = 40;
    for (;;) {
        int hlen;
        if (nh == 0 || nh == 43 || nh == 60) {
            if (off + 2 > len) break;
            hlen = 8 * (p[off + 1] + 1);
        } else if (nh == 51) {
            if (off + 2 > len) break;
            hlen = 4 * (p[off + 1] + 2);
        } else if (nh == 44) {
            hlen = 8;
            if (off + hlen > len) break;
            if ((be16(p + off + 2) >> 3) != 0) {
                pkt->proto = p[off];
                sh_parse_fault_note(SH_PF_IP_FRAGMENT);
                snprintf(pkt->info, sizeof(pkt->info), "IPv6 frag");
                return 0;
            }
        } else {
            pkt->proto = (uint8_t)nh;
            *tp   = p + off;
            *tlen = len - off;
            return 1;
        }
        if (off + hlen > len) break;
        nh   = p[off];
        off += hlen;
    }

    /* An extension header that runs past the packet's own end. */
    pkt->proto = (uint8_t)nh;
    if (!snapped) sh_parse_fault_note(SH_PF_IP_TRUNCATED);
    snprintf(pkt->info, sizeof(pkt->info), "IPv6 nh=%d", nh);
    return 0;
}

static void decode_ipv4(const uint8_t *p, int len, int snapped,
                        packet_info_t *pkt) {
    const uint8_t *tp   = NULL;
    int            tlen = 0;
    if (l4_from_ipv4(p, len, snapped, pkt, &tp, &tlen))
        decode_l4(pkt->proto, 0, tp, tlen, pkt);
}

static void decode_ipv6(const uint8_t *p, int len, int snapped,
                        packet_info_t *pkt) {
    const uint8_t *tp   = NULL;
    int            tlen = 0;
    if (l4_from_ipv6(p, len, snapped, pkt, &tp, &tlen))
        decode_l4(pkt->proto, 1, tp, tlen, pkt);
}

/* SLL2 header layout (per pcap-linktype(7)):
 *   0  protocol   (2)  big-endian ethertype
 *   2  reserved   (2)
 *   4  ifindex    (4)  big-endian
 *   8  hatype     (2)
 *   10 pkttype    (1)
 *   11 halen      (1)
 *   12 addr       (8)
 *   20 payload
 * Payload starts at offset 20; ethertype lives at offset 0.
 * SLL2_HDRLEN is defined above the WITH_PCAP guard (#85). */

/* Takes the gated view (#141), never a raw pcap header: caplen here has
 * already been bounded and checked against the wire length. */
static int decode_frame(const frame_view_t *f, packet_info_t *pkt) {
    const uint8_t *data   = f->data;
    int            caplen = f->caplen;
    const int      dlt    = f->dlt;
    int       offset    = 0;
    uint16_t  ethertype = 0;
    /* Read before the radiotap arm shortens caplen by the FCS: a frame
     * the capture cut short is allowed an IP length past its end (#132). */
    const int snapped   = (uint32_t)f->caplen < f->origlen;

    if (dlt == DLT_EN10MB) {
        if (caplen < 14) return 0;
        ethertype = be16(data + 12);
        offset    = 14;
    } else if (dlt == MY_DLT_LINUX_SLL) {
        if (caplen < 16) return 0;
        ethertype = be16(data + 14);
        offset    = 16;
    } else if (dlt == MY_DLT_LINUX_SLL2) {
        if (caplen < SLL2_HDRLEN) return 0;
        ethertype = be16(data + 0);
        offset    = SLL2_HDRLEN;
    } else if (dlt == DLT_IEEE802_11_RADIO) {
        /* The monitor radio (#72). Until this existed the two capture
         * paths saw disjoint worlds — 802.11 metadata on one side, IP
         * on the other — with no bridge even on an open network where
         * the payload is in the clear.
         *
         * Radiotap first, then the variable 802.11 header, then
         * LLC/SNAP. The arithmetic lives in dot11_frame.c because that
         * is where the risk is and this file is not in TEST_SRCS.
         *
         * One decode (#122): radiotap's FCS / DATAPAD / BADFCS flags
         * become hints, the FCS trailer is taken off the length so it
         * is not handed to the IP decoder as payload, and the body
         * offset honours the driver's 4-octet padding.
         *
         * The radiotap gate, the FCS strip and the 802.11 minimum are
         * frame_view_radiotap()'s (#141) — the same call on_probe_frame()
         * makes, so the two monitor entry points cannot drift apart on
         * what a valid header is. Not tallied here: the monitor stream
         * owns the radiotap_bad / dot11_runt counts. */
        radiotap_info_t rti;
        const uint8_t  *dot11     = NULL;
        int             dot11_len = 0;
        if (frame_view_radiotap(f, &rti, &dot11, &dot11_len) != FRAME_RT_OK)
            return 0;
        const int rt = (int)(dot11 - data);
        caplen = rt + dot11_len;              /* the FCS trailer is gone */
        const dot11_rt_hints_t hints = { rti.fcs_present, rti.datapad,
                                         rti.bad_fcs };
        dot11_frame_t fr;
        dot11_frame_decode(dot11, dot11_len, &hints, &fr);
        int poff = 0;
        if (dot11_frame_payload(&fr, &poff, &ethertype) != DOT11_DATA_OK)
            return 0;
        offset = rt + poff;
    } else {
        return 0;
    }

    /* strip 802.1Q VLAN tag */
    if (ethertype == 0x8100 && offset + 4 <= caplen) {
        ethertype = be16(data + offset + 2);
        offset   += 4;
    }

    /* IEEE 802.3 / LLC frames put a length value (< 0x0600) where ethernet II
     * puts an ethertype. We don't decode them — drop. */
    if (ethertype < 0x0600) return 0;

    const uint8_t *payload = data + offset;
    int            plen    = caplen - offset;

    if      (ethertype == 0x0800) { decode_ipv4(payload, plen, snapped, pkt); return 1; }
    else if (ethertype == 0x86DD) { decode_ipv6(payload, plen, snapped, pkt); return 1; }
    /* ARP and the rest are dropped on purpose. */
    return 0;
}

/* ── pcap callback ────────────────────────────────────────── */

/* if_indextoname() adapter for capture_ifname_lookup(), whose cache
 * keeps the hot path free of per-packet syscalls (#17, #85). */
static int sys_ifname(uint32_t idx, char name[16]) {
    return if_indextoname(idx, name) != NULL;
}

/* if_nametoindex() adapter for capture_policy_pin(); 0 = no such iface. */
static uint32_t sys_ifindex(const char *name) {
    return (uint32_t)if_nametoindex(name);
}

static void on_packet(u_char *user, const struct pcap_pkthdr *hdr,
                      const u_char *data) {
    (void)user;
    int dlt = pcap_datalink(g_handle);

    /* The pcap-edge gate (#141), before anything reads `data`: caplen
     * bounded and checked against the wire length, the timestamp's
     * microseconds in range. Everything below reads the view, never
     * hdr. A refusal is tallied — a stream of lying headers otherwise
     * reads as a quiet segment. */
    frame_view_t f;
    if (!frame_view_init(&f, data, hdr->caplen, hdr->len,
                         (long)hdr->ts.tv_sec, (long)hdr->ts.tv_usec, dlt)) {
        sh_parse_fault_note(SH_PF_FRAME_EDGE);
        return;
    }

    /* Data-stream election (#17 + #35), fail-closed since #85: drop
     * before decode when the runtime deselect ([y]) or the launch-time
     * allow-list (--iface / --monitor-only) rejects the ingress iface,
     * and — whenever an allow-list is active — when the frame cannot be
     * attributed to a pinned, still-valid iface at all. The pins were
     * fixed before this thread was created; the main thread only ever
     * clears their valid bits, under g_mu (#85 slice 2). */
    if (!capture_frame_in_scope(g_state, &g_policy, dlt, f.data,
                                f.caplen, sys_ifname))
        return;

    packet_info_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.ts_sec  = (uint32_t)f.ts_sec;
    pkt.ts_usec = f.ts_usec;
    pkt.len     = f.origlen;
    if (!decode_frame(&f, &pkt))
        return;  /* drop ARP / LLC / unknown — see decode_frame() comment */

    int rl = f.caplen < 64 ? f.caplen : 64;
    memcpy(pkt.raw, f.data, (size_t)rl);
    pkt.raw_len = (uint16_t)rl;

    pthread_mutex_lock(&g_mu);
    /* Freshness, recorded where the frame is accepted rather than where
     * it is dispatched: a frame the decoder rejected is not evidence
     * this stream is delivering anything usable (#91). */
    g_last_frame_ts   = f.ts_sec;
    g_last_frame_wall = sloth_wall();
    g_ring[g_ring_head] = pkt;
    g_ring_head = (g_ring_head + 1) % MAX_PACKETS;
    if (g_ring_count < MAX_PACKETS) g_ring_count++;
    g_ring_total++;   /* monotonic; drives once-only jsonl emit (issue #20) */
    pthread_mutex_unlock(&g_mu);
}

void capture_ring_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    /* Slots [0, count) are the populated ones in both regimes: before
     * the first wrap head == count, after it count == MAX_PACKETS. */
    memcpy(s->packets, g_ring, (size_t)g_ring_count * sizeof(g_ring[0]));
    s->pkt_head  = g_ring_head;
    s->pkt_count = g_ring_count;
    s->pkt_total = g_ring_total;
    pthread_mutex_unlock(&g_mu);
}

/* ── Capture-path test seam (#95) ─────────────────────────── */

/* The savefile layout comes from src/pcap_format.h, the same writer the
 * four production sinks use. This block used to carry its own fifth
 * copy of the format in native byte order; sharing it means a change to
 * the layout cannot leave the test harness building a file the
 * production writer would no longer produce. */

/* Install a policy snapshot for the dispatches that follow, NULL to
 * clear it. A setter rather than a capture_test_dispatch() parameter
 * because on_packet() reads the module-static g_policy, and because
 * that is the shape the other test seams here already take
 * (data_socket_test_set_*_fn, sloth_clock_test_set).
 *
 * `mu` is taken from the caller's snapshot: NULL means single-threaded,
 * which is what this harness is. */
void capture_test_set_policy(const capture_policy_t *p) {
    if (p) g_policy = *p;
    else   memset(&g_policy, 0, sizeof(g_policy));
}

/* Build an in-memory libpcap savefile image. Shared by both test
 * dispatch seams rather than copied into each — the monitor seam
 * (#92) needs the identical header layout, and two copies of a
 * byte-exact format is two places to get it wrong.
 *
 * ts_secs is optional: NULL gives each frame a synthetic increasing
 * timestamp, which is what the IP-path tests have always seen. Passing
 * real values is what lets a caller assert which clock a record was
 * stamped from. orig_lens is likewise optional (defaults to lens).
 *
 * Returns a malloc'd image with *out_size set, or NULL. */
uint8_t *capture_test_savefile(int dlt, const uint8_t *const *frames,
                               const int *lens, const int *orig_lens,
                               const uint32_t *ts_secs, int n,
                               size_t *out_size) {
    if (n < 0 || !out_size) return NULL;
    if (n > 0 && (!frames || !lens)) return NULL;

    size_t total = PCAP_FILE_HDR_LEN;
    for (int i = 0; i < n; i++) {
        if (lens[i] < 0) return NULL;
        total += PCAP_REC_HDR_LEN + (size_t)lens[i];
    }
    uint8_t *img = malloc(total);
    if (!img) return NULL;

    pcap_fmt_file_hdr(img, (uint32_t)dlt, PCAP_SNAPLEN_LARGE);

    size_t off = PCAP_FILE_HDR_LEN;
    for (int i = 0; i < n; i++) {
        uint32_t orig = orig_lens ? (uint32_t)orig_lens[i] : (uint32_t)lens[i];
        uint32_t ts   = ts_secs ? ts_secs[i] : (uint32_t)(1700000000 + i);
        pcap_fmt_rec_hdr(img + off, ts, (uint32_t)(i * 1000),
                         (uint32_t)lens[i], orig);
        off += PCAP_REC_HDR_LEN;
        if (lens[i] > 0) memcpy(img + off, frames[i], (size_t)lens[i]);
        off += (size_t)lens[i];
    }
    *out_size = total;
    return img;
}

int capture_test_dispatch(sloth_state_t *s, int dlt,
                          const uint8_t *const *frames, const int *lens,
                          const int *orig_lens, int n) {
    return capture_dispatch_frames(s, dlt, frames, lens, orig_lens, NULL, n);
}

/* The body capture_test_dispatch() always had, with the timestamps
 * exposed: --replay (#119) carries each record's own ts_sec through,
 * where the test seam lets them default to synthetic ones. */
int capture_dispatch_frames(sloth_state_t *s, int dlt,
                            const uint8_t *const *frames, const int *lens,
                            const int *orig_lens, const uint32_t *ts_secs,
                            int n) {
    if (!s) return -1;
    size_t total = 0;
    uint8_t *img = capture_test_savefile(dlt, frames, lens, orig_lens,
                                         ts_secs, n, &total);
    if (!img) return -1;

    FILE *fp = fmemopen(img, total, "rb");
    if (!fp) { free(img); return -1; }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_fopen_offline(fp, errbuf);
    if (!pc) { fclose(fp); free(img); return -1; }

    /* on_packet() reads both of these; no worker thread exists here, so
     * swapping them is safe and the dispatch is synchronous. */
    pcap_t        *saved_handle = g_handle;
    sloth_state_t *saved_state  = g_state;
    g_handle = pc;
    g_state  = s;
    /* The ring is module-private since #111, so `s` is seeded into it
     * before the dispatch and copied back out after: the caller's state
     * stays the whole premise and the whole result, exactly as when
     * on_packet() wrote s->packets directly. A zeroed `s` therefore
     * means an empty ring, and a second dispatch on the same `s`
     * continues where the first left off. Under g_mu for the one caller
     * that dispatches on a worker thread while main snapshots
     * (test_ring_snapshot_is_stable_under_writer). */
    pthread_mutex_lock(&g_mu);
    memcpy(g_ring, s->packets, sizeof(g_ring));
    g_ring_head  = s->pkt_head;
    g_ring_count = s->pkt_count;
    g_ring_total = s->pkt_total;
    pthread_mutex_unlock(&g_mu);
    int got = pcap_dispatch(pc, n > 0 ? n : -1, on_packet, NULL);
    capture_ring_snapshot(s);
    g_handle = saved_handle;
    g_state  = saved_state;

    pcap_close(pc);          /* closes the FILE* it took ownership of */
    free(img);
    return got;
}

/* decode_frame() alone, for the libFuzzer target (#125). Contract in
 * capture.h. No on_packet(), no scope election, no ring: those are what
 * capture_test_dispatch() is for, and they cost the fuzzer the one
 * property it needs — the bytes decode_frame() walks are the fuzzer's
 * own redzoned buffer, not a record inside libpcap's oversized
 * offline-read buffer. */
int capture_test_decode_frame(const uint8_t *data, int caplen, int origlen,
                              int dlt, packet_info_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!data || caplen < 0 || origlen < 0) return 0;
    /* Through the same gate on_packet() uses (#141), so the fuzzer
     * reaches decode_frame() only with a view production could hand it. */
    frame_view_t f;
    if (!frame_view_init(&f, data, (uint32_t)caplen, (uint32_t)origlen,
                         0, 0, dlt))
        return 0;
    return decode_frame(&f, out);
}

/* ── Capture thread ───────────────────────────────────────── */

/* Why the worker left its loop, published for the poll loop to read
 * (#91 slice 2). Written once by the dying thread, read once per tick by
 * main(). The pair goes under the module's existing g_mu rather than
 * being bare volatiles: exit_detail is a string, and a torn read would
 * hand the operator a truncated or interleaved error message at exactly
 * the moment they need it. The lock is cold — once at thread death,
 * once per poll. */
static int  g_exit_reason = CAPTURE_EXIT_NONE;
static char g_exit_detail[80];

static void *capture_thread(void *arg) {
    (void)arg;
    int r = 0;
    while (capture_run_flag_get(&g_running)) {
        r = pcap_dispatch(g_handle, 32, on_packet, NULL);
        if (r < 0) break;   /* PCAP_ERROR or PCAP_ERROR_BREAK */
    }
    /* The gap #91 opens with: this used to `return NULL` and leave an
     * open handle with no packets behind it, which reads exactly like a
     * quiet segment. */
    const char *err = (r < 0 && g_handle) ? pcap_geterr(g_handle) : "";
    /* Read before g_mu: the run-flag mutex is a leaf and is never taken
     * under another lock. */
    int stop_requested = !capture_run_flag_get(&g_running);
    pthread_mutex_lock(&g_mu);
    snprintf(g_exit_detail, sizeof(g_exit_detail), "%s", err ? err : "");
    g_exit_reason = (int)capture_classify_exit(r, stop_requested, g_exit_detail);
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

void capture_health_poll(capture_health_t *h) {
    if (!h) return;
    h->open = g_handle != NULL;
    pthread_mutex_lock(&g_mu);
    h->exit_reason = g_exit_reason;
    snprintf(h->exit_detail, sizeof(h->exit_detail), "%s", g_exit_detail);
    int reason = g_exit_reason;
    pthread_mutex_unlock(&g_mu);
    /* A dead worker leaves g_running set — it broke out of the loop
     * rather than being asked to stop — so liveness is the run flag AND
     * the absence of a terminal reason. That conjunction is the whole
     * point: the handle staying open is what made the failure invisible.
     * capture_scope_poll() reads the same helper. */
    h->running = capture_worker_live(g_handle != NULL,
                                     capture_run_flag_get(&g_running), reason);
    pthread_mutex_lock(&g_mu);
    time_t fts = g_last_frame_ts, fwall = g_last_frame_wall;
    pthread_mutex_unlock(&g_mu);
    h->last_frame_ts = fts;
    /* -1 while nothing has arrived: "never delivered" is a different
     * claim from "delivered just now", and a stream that never started
     * must not read as fresh. */
    h->stale_secs = fwall ? (int)(sloth_wall() - fwall) : -1;
    if (!g_handle) return;
    struct pcap_stat ps;
    memset(&ps, 0, sizeof(ps));
    if (pcap_stats(g_handle, &ps) == 0)
        capture_stats_accumulate(h, (uint32_t)ps.ps_recv, (uint32_t)ps.ps_drop,
                                 (uint32_t)ps.ps_ifdrop);
}

/* Accessor, not logic: g_policy is module-static, and main.c needs the
 * unpinned set for the launch notice. Deliberately does not revalidate
 * or sync the deselect snapshot -- that is capture_scope_poll()'s job on
 * the poll thread, and doing it here would bump `generation` for a
 * rename landing in this window (#85). */
int capture_scope_unpinned(const sloth_state_t *s, char *buf, int sz) {
    return capture_policy_unpinned(&g_policy, s, buf, sz);
}

void capture_scope_poll(sloth_state_t *s) {
    if (!s) return;
    capture_policy_revalidate(&g_policy, sys_ifname);
    /* Copy the runtime [y] list into the callback's snapshot — the
     * callback never reads s->iface_deselected itself (#95). */
    capture_policy_sync_deselect(&g_policy, s);
    capture_scope_health_t *h = &s->scope_health;
    h->requested = s->iface_allowed_count;
    h->enforced  = capture_policy_valid_count(&g_policy);
    /* Main thread is the only writer of generation; no lock to read. */
    h->generation = g_policy.generation;
    /* Liveness, not the handle: a worker that died (PERM_LOST,
     * IFACE_GONE, ...) keeps g_handle until capture_stop(), and keying on
     * the handle read that run as `enforced` while nothing was being
     * collected at all (#85). The run flag is read outside g_mu -- its
     * mutex is a leaf and is never taken under another lock. */
    pthread_mutex_lock(&g_mu);
    int reason = g_exit_reason;
    pthread_mutex_unlock(&g_mu);
    int live = capture_worker_live(g_handle != NULL,
                                   capture_run_flag_get(&g_running), reason);
    h->state = (int)capture_scope_state(h->requested, live, h->enforced);
}

/* Test seam, contract in capture.h. Here rather than beside
 * capture_test_set_policy() because it writes the worker's exit
 * bookkeeping, which is declared just above capture_thread(). */
void capture_test_set_worker(int open, int running, int exit_reason) {
    if (open && !g_handle)
        g_handle = pcap_open_dead(MY_DLT_LINUX_SLL2, 65535);
    else if (!open && g_handle) {
        pcap_close(g_handle);
        g_handle = NULL;
    }
    capture_run_flag_set(&g_running, running ? 1 : 0);
    pthread_mutex_lock(&g_mu);
    g_exit_reason    = exit_reason;
    g_exit_detail[0] = '\0';
    pthread_mutex_unlock(&g_mu);
}

/* ── Public API ───────────────────────────────────────────── */

void capture_open(sloth_state_t *s) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_state  = s;
    /* Reset the ifindex cache — a re-start on the same handle would
     * otherwise carry stale ifindex → name mappings. */
    capture_ifname_cache_reset();

    /* Prefer pcap_create + activate so we can request DLT_LINUX_SLL2
     * (276) as the datalink. SLL2 is what gives the pcap callback
     * access to the ingress interface index, which the data-stream
     * election needs to filter by iface name (#17). Anything short of
     * SLL2 — SLL v1, EN10MB — still captures; the per-iface filter
     * just becomes a no-op on those datalinks. */
    g_handle = pcap_create("any", errbuf);
    if (g_handle) {
        pcap_set_snaplen(g_handle, 65535);
        pcap_set_promisc(g_handle, 1);
        pcap_set_timeout(g_handle, 100);
        if (capture_activate_failed(pcap_activate(g_handle))) {
            pcap_close(g_handle);
            g_handle = NULL;
        } else {
            /* Try to switch to SLL2; ignore errors (older libpcap
             * doesn't know the DLT, some kernels reject it). */
            (void)pcap_set_datalink(g_handle, MY_DLT_LINUX_SLL2);
            snprintf(s->pkt_iface, sizeof(s->pkt_iface), "any");
        }
    }

    if (!g_handle) {
        /* pcap_create("any") failed or activation rejected — try the
         * simpler open_live path, then fall back to first device. */
        g_handle = pcap_open_live("any", 65535, 1, 100, errbuf);
        if (g_handle) {
            snprintf(s->pkt_iface, sizeof(s->pkt_iface), "any");
        } else {
            /* Not the head of the list: that can be a raw HCI device
             * (#144 slice 2). The names go through the same pure picker
             * the tests pin, so the walk and the refusal are one. */
            pcap_if_t *devs = NULL;
            if (pcap_findalldevs(&devs, errbuf) == 0 && devs) {
                enum { FALLBACK_MAX = 64 };
                const char *names[FALLBACK_MAX];
                int nn = 0;
                for (pcap_if_t *d = devs; d && nn < FALLBACK_MAX; d = d->next)
                    names[nn++] = d->name;
                const char *pick = capture_fallback_device(names, nn);
                if (pick) {
                    snprintf(s->pkt_iface, sizeof(s->pkt_iface), "%s", pick);
                    g_handle = pcap_open_live(pick, 65535, 1, 100, errbuf);
                }
                pcap_freealldevs(devs);
            }
        }
    }
    if (!g_handle) return;  /* silently disabled — show live hint in view */

    s->pkt_linktype = pcap_datalink(g_handle);
}

int capture_is_open(void) {
    return g_handle != NULL;
}

void capture_run(void) {
    if (!g_handle || capture_run_flag_get(&g_running)) return;
    /* Pin the allow-list to (ifindex, name) pairs now, while no worker
     * exists. pthread_create() synchronises memory with the new thread
     * (POSIX XBD 4.12), so the pins are visible to on_packet() from its
     * first frame; after this only their valid bits change (#85). */
    capture_policy_pin(&g_policy, g_state, sys_ifindex, &g_mu);
    /* Seed the deselect snapshot before the worker exists, same
     * visibility argument as the pins (#95). */
    capture_policy_sync_deselect(&g_policy, g_state);
    /* A restart clears the previous run's verdict — otherwise a fresh
     * worker would report the reason the last one died (#91 slice 2). */
    pthread_mutex_lock(&g_mu);
    g_exit_reason    = CAPTURE_EXIT_NONE;
    g_exit_detail[0] = '\0';
    pthread_mutex_unlock(&g_mu);
    capture_run_flag_set(&g_running, 1);
    if (worker_thread_create(&g_thread, capture_thread, NULL) != 0)
        capture_run_flag_set(&g_running, 0);
}

void capture_start(sloth_state_t *s) {
    capture_open(s);
    capture_run();
}

void capture_stop(void) {
    /* Clear-then-break: the worker re-checks the flag when breakloop
     * forces pcap_dispatch() to return, so it must already read 0. */
    if (capture_run_flag_take(&g_running)) {
        if (g_handle) pcap_breakloop(g_handle);
        pthread_join(g_thread, NULL);
    }
    if (g_handle) { pcap_close(g_handle); g_handle = NULL; }
}

int capture_set_filter(const char *expr, char *errbuf, int errsz) {
    if (!g_handle) return 0;
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        if (errbuf && errsz > 0)
            snprintf(errbuf, errsz, "%s", pcap_geterr(g_handle));
        return -1;
    }
    pcap_setfilter(g_handle, &fp);
    pcap_freecode(&fp);
    return 0;
}

#endif /* WITH_PCAP */
