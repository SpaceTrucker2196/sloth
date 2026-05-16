#ifndef NTOP_H
#define NTOP_H

#include <stdint.h>

#define NTOP_VERSION "0.1.0"

#define MAX_IFACES   32
#define MAX_CONNS    1024
#define MAX_WIFI_APS 64
#define MAX_PACKETS  256
#define POLL_MS      1000

/* ── Views ──────────────────────────────────────────────── */
typedef enum {
    VIEW_IFACE   = 0,
    VIEW_CONNS   = 1,
    VIEW_WIFI    = 2,
    VIEW_PACKETS = 3,
    VIEW_COUNT
} view_t;

/* ── Interface stats ────────────────────────────────────── */
typedef struct {
    char     name[16];
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    double   rx_rate;   /* bytes/sec since last poll */
    double   tx_rate;
} iface_stat_t;

/* ── Connections ────────────────────────────────────────── */
#define PROTO_TCP 6
#define PROTO_UDP 17

typedef struct {
    char     local_addr[46];
    char     remote_addr[46];
    uint16_t local_port;
    uint16_t remote_port;
    int      proto;
    int      state;
    int      pid;
    char     proc[16];
} conn_t;

/* ── WiFi APs ───────────────────────────────────────────── */
typedef struct {
    char ssid[33];
    char bssid[18];
    int  signal_dbm;
    int  channel;
    char enc[16];
} wifi_ap_t;

/* ── Packets ────────────────────────────────────────────── */
typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    char     src[46];
    char     dst[46];
    uint16_t src_port;
    uint16_t dst_port;
    int      proto;
    uint32_t len;
    char     info[64];
} packet_info_t;

/* ── App state ──────────────────────────────────────────── */
typedef struct {
    view_t        active_view;
    int           poll_ms;

    iface_stat_t  ifaces[MAX_IFACES];
    int           iface_count;

    conn_t        conns[MAX_CONNS];
    int           conn_count;

    wifi_ap_t     aps[MAX_WIFI_APS];
    int           ap_count;

    packet_info_t packets[MAX_PACKETS]; /* ring buffer */
    int           pkt_head;             /* next write slot */
    int           pkt_count;            /* total written (capped at MAX_PACKETS) */
} ntop_state_t;

/* ── Platform ops vtable ────────────────────────────────── */
typedef struct {
    int  (*get_ifaces)(iface_stat_t *out, int max);
    int  (*get_conns)(conn_t *out, int max);
    int  (*wifi_scan)(wifi_ap_t *out, int max);
    void (*init)(void);
    void (*cleanup)(void);
} platform_ops_t;

extern platform_ops_t g_platform;

#endif /* NTOP_H */
