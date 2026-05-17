#ifndef SLOTH_H
#define SLOTH_H

#include <stdint.h>
#include <time.h>

#define SLOTH_VERSION "0.2.0"

#define MAX_IFACES   32
#define MAX_CONNS    1024
#define MAX_WIFI_APS 64
#define MAX_PACKETS  256
#define POLL_MS      1000
#define HIST_LEN     30    /* rate history samples per interface (sparkline) */

/* Cross-platform key codes — outside ASCII range, returned by tui_poll_key() */
#define SLOTH_KEY_UP        0x101
#define SLOTH_KEY_DOWN      0x102
#define SLOTH_KEY_BACKSPACE 0x103

/* ── Views ──────────────────────────────────────────────── */
typedef enum {
    VIEW_IFACE   = 0,
    VIEW_CONNS   = 1,
    VIEW_WIFI    = 2,
    VIEW_PACKETS = 3,
    VIEW_PROCS   = 4,
    VIEW_STATS   = 5,
    VIEW_PROBE   = 6,
    VIEW_ARP     = 7,
    VIEW_MDNS    = 8,
    VIEW_NBNS    = 9,
    VIEW_DHCP    = 10,
    VIEW_SSDP    = 11,
    VIEW_BEACON  = 12,
    VIEW_COUNT
} view_t;

/* ── Interface stats ────────────────────────────────────── */
typedef struct {
    char     name[16];
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_errors;
    uint64_t rx_drops;
    uint64_t tx_errors;
    uint64_t tx_drops;
    double   rx_rate;      /* bytes/sec since last poll */
    double   tx_rate;
    uint32_t mtu;          /* 0 = unknown */
    int32_t  speed_mbps;   /* -1 = unknown */
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
    unsigned long inode;    /* socket inode for PID resolution */
    uint32_t      rtt_us;   /* smoothed RTT in microseconds (TCP only, 0=unknown) */
    uint32_t      retrans;  /* total retransmissions (TCP only) */
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
    CONN_SORT_RTT   = 5,
    CONN_SORT_COUNT
} conn_sort_t;

typedef enum {
    CONN_FILTER_ALL = 0,
    CONN_FILTER_TCP = 1,
    CONN_FILTER_UDP = 2,
    CONN_FILTER_COUNT
} conn_filter_t;

/* ── Port scan detection ────────────────────────────────── */
#define MAX_SCAN_ENTRIES  32
#define MAX_SCAN_PORTS    64
#define SCAN_PORT_THRESH   8   /* distinct local ports from one IP to flag */
#define SCAN_TTL_SECS     60   /* seconds to keep entry after last activity */

typedef struct {
    char     ip[46];
    uint16_t ports[MAX_SCAN_PORTS]; /* distinct local ports seen from this IP */
    int      port_count;
    time_t   first_seen;
    time_t   last_seen;
    int      flagged;               /* port_count >= SCAN_PORT_THRESH */
} scan_entry_t;

/* ── NetBIOS Name Service entries ───────────────────────── */
#define MAX_NBNS_NAMES 64

typedef struct {
    char    name[16];   /* decoded NetBIOS name, NUL-terminated  */
    char    ip[46];     /* resolved IP, "" = not yet known       */
    uint8_t suffix;     /* service type: 0x00=workstation 0x20=SMB … */
    time_t  last_seen;
} nbns_name_t;

/* ── mDNS local services ────────────────────────────────── */
#define MAX_MDNS_SERVICES 64

typedef struct {
    char     instance[64];   /* "My Printer._ipp._tcp.local" */
    char     service[32];    /* "_ipp._tcp"                  */
    char     host[64];       /* SRV target hostname          */
    char     ip[46];         /* resolved IP, "" = unknown    */
    uint16_t port;           /* SRV port, 0 = unknown        */
    time_t   last_seen;
} mdns_service_t;

/* ── SSDP/UPnP devices ──────────────────────────────────── */
#define MAX_SSDP_DEVICES 64

typedef struct {
    char   ip[46];         /* source IP of the announcing device    */
    char   type[80];       /* NT (notify) or ST (search target)     */
    char   usn[96];        /* Unique Service Name                   */
    char   location[96];   /* LOCATION: URL, "" = unknown           */
    char   nts[16];        /* "alive", "byebye", "search"          */
    time_t last_seen;
} ssdp_device_t;

/* ── Live DHCP snoop events ─────────────────────────────── */
#define MAX_DHCP_EVENTS 128

typedef struct {
    char    mac[18];       /* "aa:bb:cc:dd:ee:ff"              */
    char    ip[46];        /* assigned IP, "" = not yet known  */
    char    hostname[64];  /* option 12, "" = unknown          */
    uint8_t msg_type;      /* 1=DISCOVER 3=REQUEST 5=ACK …     */
    time_t  last_seen;
} dhcp_event_t;

/* ── ARP neighbors ──────────────────────────────────────── */
#define MAX_ARP_ENTRIES  256
#define MAX_DHCP_LEASES   64

typedef struct {
    char    ip[46];
    uint8_t mac[6];
    char    iface[16];
} arp_entry_t;

typedef struct {
    char   ip[46];
    char   hostname[64];
    time_t expire;   /* 0 = unknown; >0 = absolute expiry epoch */
} dhcp_lease_t;

/* ── WiFi APs ───────────────────────────────────────────── */
/* BSS status values (mirror of NL80211_BSS_STATUS_* enum) */
#define WIFI_STATUS_NONE        (-1)
#define WIFI_STATUS_AUTH        0
#define WIFI_STATUS_ASSOC       1
#define WIFI_STATUS_IBSS_JOINED 2

typedef struct {
    char ssid[33];
    char bssid[18];
    int  signal_dbm;
    int  channel;
    char enc[16];
    int  status;   /* NL80211_BSS_STATUS_* value, or -1 if not current */
} wifi_ap_t;

/* ── WiFi stations (our link to AP in managed mode, or clients in AP mode) ── */
#define MAX_WIFI_STAS 16

typedef struct {
    char     mac[18];          /* station MAC (= AP bssid when we are a client) */
    int8_t   signal_dbm;
    uint32_t tx_rate_kbps;     /* TX link rate in kbps */
    uint32_t rx_rate_kbps;
    uint32_t connected_secs;
    uint32_t inactive_ms;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
} wifi_sta_t;

/* ── Beacon APs (passively observed 802.11 access points) ── */
#define MAX_BEACON_APS  256
#define BEACON_AGE_SECS 300

typedef struct {
    char     ssid[33];      /* "" = hidden/broadcast network */
    uint8_t  bssid[6];
    int8_t   signal_dbm;
    int      channel;
    char     enc[10];       /* OPEN WEP WPA WPA2 WPA3 */
    uint16_t beacon_ms;     /* beacon interval in ms */
    time_t   last_seen;
    int      frame_count;
} beacon_ap_t;

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
    int           iface_graph;             /* non-zero = rx/tx graph panel open */
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
    int           wifi_sel;    /* selected row in wifi view */
    int           wifi_detail; /* non-zero = detail panel open for selected AP */

    wifi_sta_t    wifi_stas[MAX_WIFI_STAS];
    int           wifi_sta_count;

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
    int  pkt_linktype;         /* pcap DLT link type (set by capture_start) */
    char pkt_export_msg[80];   /* last pcap export result shown in status */
    char pkt_iface[32];        /* pcap capture interface, "" if none */

    int           proc_sel;    /* selected row in procs view */
    int           proc_detail; /* non-zero = detail panel open */
    int           dns_enabled; /* non-zero = show hostnames instead of IPs */

    conn_bw_t     conn_bw[MAX_CONNS];
    int           conn_bw_count;
    int           pkt_bw_cursor;  /* pkt_head at last bandwidth attribution */

    /* ── ARP neighbor table ────────────────────────────── */
    arp_entry_t  arp_entries[MAX_ARP_ENTRIES];
    int          arp_count;
    int          arp_sel;

    /* ── DHCP leases (hostname lookup for ARP view) ─────── */
    dhcp_lease_t dhcp_leases[MAX_DHCP_LEASES];
    int          dhcp_count;

    /* ── Port scan detection ─────────────────────────────── */
    scan_entry_t scan_entries[MAX_SCAN_ENTRIES];
    int          scan_count;

    /* ── Beacon APs (passive 802.11 beacon sniff) ──────────── */
    beacon_ap_t beacon_aps[MAX_BEACON_APS];
    int         beacon_count;
    int         beacon_sel;

    /* ── Probe clients ──────────────────────────────────── */
    probe_client_t probe_clients[MAX_PROBE_CLIENTS];
    int            probe_count;
    int            probe_sel;
    char           probe_iface[16]; /* monitor iface name, "" = none found */
    char           probe_err[80];   /* last probe open/set error, "" = ok */

    /* ── mDNS services ────────────────────────────────────── */
    mdns_service_t mdns_services[MAX_MDNS_SERVICES];
    int            mdns_count;
    int            mdns_sel;

    /* ── NetBIOS names ─────────────────────────────────────── */
    nbns_name_t    nbns_names[MAX_NBNS_NAMES];
    int            nbns_count;
    int            nbns_sel;

    /* ── Live DHCP events ──────────────────────────────────── */
    dhcp_event_t   dhcp_events[MAX_DHCP_EVENTS];
    int            dhcp_event_count;
    int            dhcp_event_sel;

    /* ── SSDP/UPnP devices ─────────────────────────────────── */
    ssdp_device_t  ssdp_devices[MAX_SSDP_DEVICES];
    int            ssdp_count;
    int            ssdp_sel;

    /* ── Session stats baseline ─────────────────────────── */
    time_t   stats_start;                    /* time of last reset */
    int      stats_init;                     /* 0 = baseline not yet taken */
    uint64_t stats_base_rx[MAX_IFACES];      /* rx_bytes at baseline */
    uint64_t stats_base_tx[MAX_IFACES];      /* tx_bytes at baseline */
    uint64_t stats_base_rxp[MAX_IFACES];     /* rx_packets at baseline */
    uint64_t stats_base_txp[MAX_IFACES];     /* tx_packets at baseline */
    char     stats_base_name[MAX_IFACES][16];/* iface name for each slot */
    int      stats_base_count;               /* number of baseline slots */
} sloth_state_t;

/* ── Platform ops vtable ────────────────────────────────── */
typedef struct {
    int  (*get_ifaces)(iface_stat_t *out, int max);
    int  (*get_conns)(conn_t *out, int max);
    int  (*wifi_scan)(wifi_ap_t *out, int max);
    int  (*get_wifi_stations)(wifi_sta_t *out, int max);
    int  (*get_arp)(arp_entry_t *out, int max);
    int  (*get_dhcp)(dhcp_lease_t *out, int max);
    void (*init)(void);
    void (*cleanup)(void);
} platform_ops_t;

extern platform_ops_t g_platform;

#endif /* SLOTH_H */
