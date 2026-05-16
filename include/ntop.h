#ifndef NTOP_H
#define NTOP_H

#include <stdint.h>
#include <time.h>

#define NTOP_VERSION "0.2.0"

#define MAX_IFACES   32
#define MAX_CONNS    1024
#define MAX_WIFI_APS 64
#define MAX_PACKETS  256
#define POLL_MS      1000
#define HIST_LEN     30    /* rate history samples per interface (sparkline) */

/* Cross-platform key codes — outside ASCII range, returned by tui_poll_key() */
#define NTOP_KEY_UP        0x101
#define NTOP_KEY_DOWN      0x102
#define NTOP_KEY_BACKSPACE 0x103

/* ── Views ──────────────────────────────────────────────── */
typedef enum {
    VIEW_IFACE   = 0,
    VIEW_CONNS   = 1,
    VIEW_WIFI    = 2,
    VIEW_PACKETS = 3,
    VIEW_PROCS   = 4,
    VIEW_STATS   = 5,
    VIEW_PROBE   = 6,
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

/* ── Interface rate history (sparkline data) ────────────── */
typedef struct {
    char   name[16];
    double rx[HIST_LEN];
    double tx[HIST_LEN];
    int    head;    /* next write slot */
    int    count;   /* entries populated (≤ HIST_LEN) */
} iface_hist_t;

/* ── Connections ────────────────────────────────────────── */
#define PROTO_TCP 6
#define PROTO_UDP 17

typedef struct {
    char          local_addr[46];
    char          remote_addr[46];
    uint16_t      local_port;
    uint16_t      remote_port;
    int           proto;
    int           state;
    int           pid;
    char          proc[16];
    unsigned long inode;   /* socket inode for PID resolution */
} conn_t;

/* ── Per-connection bandwidth snapshot ──────────────────── */
#define CONN_BW_HIST 20

typedef struct {
    char     local_addr[46];
    uint16_t local_port;
    char     remote_addr[46];
    uint16_t remote_port;
    int      proto;
    double   rx_rate;              /* bytes/sec */
    double   tx_rate;
    float    rx_hist[CONN_BW_HIST];
    float    tx_hist[CONN_BW_HIST];
    int      hist_head;
    int      hist_count;
} conn_bw_t;

/* ── Connection view state ──────────────────────────────── */
typedef enum {
    CONN_SORT_STATE = 0,
    CONN_SORT_PROTO = 1,
    CONN_SORT_LPORT = 2,
    CONN_SORT_PID   = 3,
    CONN_SORT_BW    = 4,
    CONN_SORT_COUNT
} conn_sort_t;

typedef enum {
    CONN_FILTER_ALL = 0,
    CONN_FILTER_TCP = 1,
    CONN_FILTER_UDP = 2,
    CONN_FILTER_COUNT
} conn_filter_t;

/* ── WiFi APs ───────────────────────────────────────────── */
typedef struct {
    char ssid[33];
    char bssid[18];
    int  signal_dbm;
    int  channel;
    char enc[16];
} wifi_ap_t;

/* ── Probe clients (802.11 unassociated devices) ────────── */
#define MAX_PROBE_CLIENTS 128
#define PROBE_AGE_SECS    120

typedef struct {
    uint8_t mac[6];       /* source MAC */
    char    ssid[33];     /* last-probed SSID, "" = wildcard */
    int8_t  signal_dbm;
    int     channel;
    time_t  last_seen;
    int     frame_count;
} probe_client_t;

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
    uint8_t  raw[64];
    uint16_t raw_len;
} packet_info_t;

/* ── App state ──────────────────────────────────────────── */
typedef struct {
    view_t        active_view;
    int           poll_ms;

    iface_stat_t  ifaces[MAX_IFACES];
    int           iface_count;
    iface_hist_t  iface_hist[MAX_IFACES];  /* rate history, keyed by name */
    int           iface_sel;               /* selected row in iface view */
    char          iface_hidden[MAX_IFACES][16]; /* hidden interface names */
    int           iface_hidden_count;

    conn_t        conns[MAX_CONNS];
    int           conn_count;
    int           conn_sel;
    conn_sort_t   conn_sort;
    conn_filter_t conn_filter;
    int           conn_idx[MAX_CONNS]; /* sorted+filtered indices into conns[] */
    int           conn_idx_count;

    wifi_ap_t     aps[MAX_WIFI_APS];
    int           ap_count;
    int           wifi_sel;  /* selected row in wifi view */

    packet_info_t packets[MAX_PACKETS]; /* ring buffer */
    int           pkt_head;             /* next write slot */
    int           pkt_count;            /* total written (capped at MAX_PACKETS) */
    int           pkt_sel;             /* selected row in packets view */
    int           pkt_paused;          /* non-zero = freeze auto-scroll */

    char pkt_filter[256];      /* active BPF expression ("" = none) */
    char pkt_filter_buf[256];  /* working buffer while user is typing */
    int  pkt_filter_len;       /* length of pkt_filter_buf */
    int  pkt_filter_mode;      /* non-zero = filter input prompt is open */
    char pkt_filter_err[128];  /* last compile/apply error, "" = ok */
    int  pkt_detail;           /* non-zero = detail panel open */

    int           proc_sel;    /* selected row in procs view */
    int           proc_detail; /* non-zero = detail panel open */
    int           dns_enabled; /* non-zero = show hostnames instead of IPs */

    conn_bw_t     conn_bw[MAX_CONNS];
    int           conn_bw_count;
    int           pkt_bw_cursor;  /* pkt_head at last bandwidth attribution */

    /* ── Probe clients ──────────────────────────────────── */
    probe_client_t probe_clients[MAX_PROBE_CLIENTS];
    int            probe_count;
    int            probe_sel;
    char           probe_iface[16]; /* monitor iface name, "" = none found */

    /* ── Session stats baseline ─────────────────────────── */
    time_t   stats_start;                    /* time of last reset */
    int      stats_init;                     /* 0 = baseline not yet taken */
    uint64_t stats_base_rx[MAX_IFACES];      /* rx_bytes at baseline */
    uint64_t stats_base_tx[MAX_IFACES];      /* tx_bytes at baseline */
    uint64_t stats_base_rxp[MAX_IFACES];     /* rx_packets at baseline */
    uint64_t stats_base_txp[MAX_IFACES];     /* tx_packets at baseline */
    char     stats_base_name[MAX_IFACES][16];/* iface name for each slot */
    int      stats_base_count;               /* number of baseline slots */
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
