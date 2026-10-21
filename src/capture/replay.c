#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capture/replay.h"

/* Link types by number, so the pure half below compiles without pcap.h
 * (WITH_PCAP=0, embedded). Same values capture.c switches on. */
#define RP_DLT_EN10MB     1
#define RP_DLT_LINUX_SLL  113
#define RP_DLT_RADIOTAP   127
#define RP_DLT_BT_MONITOR 254
#define RP_DLT_LINUX_SLL2 276

replay_route_t replay_route(int dlt) {
    switch (dlt) {
    case RP_DLT_EN10MB:
    case RP_DLT_LINUX_SLL:
    case RP_DLT_LINUX_SLL2: return REPLAY_ROUTE_WIRED;
    case RP_DLT_RADIOTAP:   return REPLAY_ROUTE_MONITOR;
    case RP_DLT_BT_MONITOR: return REPLAY_ROUTE_BT;
    default:                return REPLAY_ROUTE_NONE;
    }
}

int replay_split_list(const char *arg, char out[][REPLAY_PATH_MAX], int max) {
    if (!arg || !out || max <= 0) return -1;
    int n = 0;
    const char *p = arg;
    for (;;) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len == 0 || len >= REPLAY_PATH_MAX || n >= max) return -1;
        memcpy(out[n], p, len);
        out[n][len] = '\0';
        n++;
        if (!comma) return n;
        p = comma + 1;
    }
}

static int  rp_zero_ifaces(iface_stat_t *o, int m)   { (void)o; (void)m; return 0; }
static int  rp_zero_conns(conn_t *o, int m)          { (void)o; (void)m; return 0; }
static int  rp_zero_aps(wifi_ap_t *o, int m)         { (void)o; (void)m; return 0; }
static int  rp_zero_stas(wifi_sta_t *o, int m)       { (void)o; (void)m; return 0; }
static int  rp_zero_arp(arp_entry_t *o, int m)       { (void)o; (void)m; return 0; }
static int  rp_zero_dhcp(dhcp_lease_t *o, int m)     { (void)o; (void)m; return 0; }
static void rp_nop(void)                             {}
/* The vtable's "unsupported" (#91): there is no radio to retune. */
static int  rp_no_channel(const char *i, int f)      { (void)i; (void)f; return -EOPNOTSUPP; }

void replay_platform_install(void) {
    g_platform.get_ifaces        = rp_zero_ifaces;
    g_platform.get_conns         = rp_zero_conns;
    g_platform.wifi_scan         = rp_zero_aps;
    g_platform.get_wifi_stations = rp_zero_stas;
    g_platform.get_arp           = rp_zero_arp;
    g_platform.get_dhcp          = rp_zero_dhcp;
    g_platform.init              = rp_nop;
    g_platform.cleanup           = rp_nop;
    g_platform.set_channel       = rp_no_channel;
}

#ifdef WITH_PCAP

#include <pcap.h>
#include "capture/capture.h"
#include "capture/probe.h"
#include "capture/bt_monitor.h"

/* Frames per dispatch. Each batch is re-serialised into an in-memory
 * savefile by the dispatch seam, so this bounds the copy, not the file. */
#define REPLAY_BATCH 512

/* libpcap names the path in some open errors ("x: No such file or
 * directory") and not in others ("unknown file format"); the operator
 * needs it in every one, and with eight files on the line, once. */
static void rp_open_err(char *err, int errsz, const char *path,
                        const char *ebuf) {
    if (strncmp(ebuf, path, strlen(path)) == 0)
        snprintf(err, (size_t)errsz, "%s", ebuf);
    else
        snprintf(err, (size_t)errsz, "%s: %s", path, ebuf);
}

int replay_check(const char *path, replay_src_t *src, char *err, int errsz) {
    if (!path || !src) return -1;
    memset(src, 0, sizeof(*src));
    snprintf(src->path, sizeof(src->path), "%s", path);
    char ebuf[PCAP_ERRBUF_SIZE];
    ebuf[0] = '\0';
    pcap_t *pc = pcap_open_offline(path, ebuf);
    if (!pc) {
        rp_open_err(err, errsz, path, ebuf);
        return -1;
    }
    src->dlt   = pcap_datalink(pc);
    src->route = replay_route(src->dlt);
    pcap_close(pc);
    if (src->route == REPLAY_ROUTE_NONE) {
        snprintf(err, (size_t)errsz,
                 "%s: datalink %d is not Ethernet, Linux cooked, radiotap "
                 "or Bluetooth Linux monitor",
                 path, src->dlt);
        return -1;
    }
    return 0;
}

typedef struct {
    uint8_t *frames[REPLAY_BATCH];
    int      lens[REPLAY_BATCH];
    int      orig[REPLAY_BATCH];
    uint32_t ts[REPLAY_BATCH];
    int      n;
} rp_batch_t;

static void rp_batch_free(rp_batch_t *b) {
    for (int i = 0; i < b->n; i++) free(b->frames[i]);
    b->n = 0;
}

static int rp_batch_flush(sloth_state_t *s, const replay_src_t *src,
                          rp_batch_t *b) {
    if (b->n == 0) return 0;
    const uint8_t *const *fr = (const uint8_t *const *)b->frames;
    int got;
    switch (src->route) {
    case REPLAY_ROUTE_MONITOR:
        got = probe_test_dispatch(s, fr, b->lens, b->orig, b->ts, b->n);
        break;
    case REPLAY_ROUTE_BT:
        got = bt_monitor_dispatch_frames(fr, b->lens, b->orig, b->ts, b->n);
        break;
    default:
        got = capture_dispatch_frames(s, src->dlt, fr, b->lens, b->orig,
                                      b->ts, b->n);
        break;
    }
    rp_batch_free(b);
    return got;
}

long replay_run(sloth_state_t *s, const replay_src_t *src,
                char *err, int errsz) {
    if (!s || !src) return -1;
    char ebuf[PCAP_ERRBUF_SIZE];
    ebuf[0] = '\0';
    pcap_t *pc = pcap_open_offline(src->path, ebuf);
    if (!pc) {
        rp_open_err(err, errsz, src->path, ebuf);
        return -1;
    }
    static rp_batch_t b;   /* ~8 KiB of arrays; not on the stack */
    b.n = 0;
    long total = 0;
    struct pcap_pkthdr *h;
    const u_char *data;
    int r;
    while ((r = pcap_next_ex(pc, &h, &data)) == 1) {
        uint8_t *copy = malloc(h->caplen ? h->caplen : 1);
        if (!copy) {
            snprintf(err, (size_t)errsz, "%s: out of memory", src->path);
            rp_batch_free(&b);
            pcap_close(pc);
            return -1;
        }
        if (h->caplen) memcpy(copy, data, h->caplen);
        b.frames[b.n] = copy;
        b.lens[b.n]   = (int)h->caplen;
        b.orig[b.n]   = (int)h->len;
        b.ts[b.n]     = (uint32_t)h->ts.tv_sec;
        b.n++;
        if (b.n == REPLAY_BATCH) {
            int got = rp_batch_flush(s, src, &b);
            if (got < 0) {
                snprintf(err, (size_t)errsz, "%s: dispatch failed", src->path);
                pcap_close(pc);
                return -1;
            }
            total += got;
        }
    }
    /* PCAP_ERROR (-1) is a damaged file; -2 is the normal end. Frames
     * read before the damage are still dispatched, and the error is
     * still reported: a replay that stopped early must not read as a
     * replay of the whole file. */
    if (r == PCAP_ERROR)
        snprintf(err, (size_t)errsz, "%s: %s", src->path, pcap_geterr(pc));
    int got = rp_batch_flush(s, src, &b);
    pcap_close(pc);
    if (r == PCAP_ERROR) return -1;
    if (got < 0) {
        snprintf(err, (size_t)errsz, "%s: dispatch failed", src->path);
        return -1;
    }
    return total + got;
}

#endif /* WITH_PCAP */
