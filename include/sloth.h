#ifndef SLOTH_H
#define SLOTH_H

#include <stdint.h>
#include <time.h>

#define SLOTH_VERSION "1.7.0"

#define MAX_IFACES   32
#define MAX_CONNS    1024
#define MAX_WIFI_APS 64
#define MAX_PACKETS  256
#define POLL_MS      250   /* dashboard refresh interval default. Overridable via --refresh-ms. The TUI loop also wakes early on alert fires (see src/event_wake.h), so this is an upper bound on stale-render time, not a fixed cadence. */
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
    VIEW_DEAUTH  = 13,
    VIEW_HTTP    = 14,
    VIEW_TLS     = 15,
    VIEW_QUIC    = 16,
    VIEW_DNS     = 17,
    VIEW_NTP     = 18,
    VIEW_ICMP    = 19,
    VIEW_ALERTS  = 20,
    VIEW_DEVICES = 21,
    VIEW_HELP    = 22,
    VIEW_DASH    = 23,
    VIEW_PNL     = 24,   /* per-MAC Preferred Network List */
    VIEW_EAPOL   = 25,   /* PMKID / 4-way handshake capture */
    VIEW_SEQNUM  = 26,   /* per-MAC seqnum + cross-MAC correlation */
    VIEW_ASSOC   = 27,   /* STA <-> AP association tracker */
    VIEW_CHANNEL = 28,   /* per-channel activity histogram */
    VIEW_OSI     = 29,   /* OSI / TCP-IP stack synthesis (one row per layer) */
    VIEW_TWINS   = 30,   /* Evil-twin episode table (Phase 5) */
    VIEW_KARMA   = 31,   /* KARMA / PineAP candidate table (#30) */
    VIEW_ROGUE_RADIUS = 32, /* 802.1X EAP method / identity-leak table (#38) */
    VIEW_COUNT
} view_t;

/* ── Interface stats ────────────────────────────────────── */

/* Link-layer / mode label. IFACE_MODE_MONITOR is what the "any WiFi
 * radio in monitor mode?" check keys on — see rule_no_monitor_mode(). */
typedef enum {
    IFACE_MODE_UNKNOWN = 0,
    IFACE_MODE_ETHER,      /* ARPHRD_ETHER, loopback, virtuals */
    IFACE_MODE_WIFI,       /* ARPHRD_IEEE80211 (managed / station) */
    IFACE_MODE_MONITOR,    /* ARPHRD_IEEE80211_RADIOTAP / PRISM */
} iface_mode_t;

typedef struct {
    char     name[16];
    uint8_t  mac[6];       /* hardware address; all-zero = unknown */
    iface_mode_t mode;     /* IFACE_MODE_* — WIFI vs MONITOR matters */
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

/* TCP socket state (conn_t.state), mirroring the kernel TCP_* enum as
   reported by /proc/net/tcp. Only LISTEN is consulted outside jsonl's
   pretty-printer: scan detection uses it to tell an inbound connection
   (remote reached a port we listen on) from an outbound one whose local
   port is just an ephemeral source port. See src/scan.c / issue #41. */
#define TCP_STATE_LISTEN 0x0A

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
    /* Cumulative bytes since the bw entry was created (since the flow
     * was first observed by the pcap thread). 0 if WITH_PCAP=0. */
    uint64_t rx_bytes;
    uint64_t tx_bytes;
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
    /* DHCP option 54 (Server Identifier) — set on server replies
     * (OFFER / ACK / NAK). Multiple distinct values across events
     * signal a rogue DHCP server on the segment. "" on client
     * requests (DISCOVER / REQUEST / DECLINE / RELEASE / INFORM). */
    char    server_ip[46];
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

/* ── BGP observation tracking ─────────────────────────── */
/* BGP lives on TCP/179. The 19-byte common header (RFC 4271 §4.1)
 * is unmistakable: 16 bytes of all-0xFF marker + 2-byte length +
 * 1-byte type code. Tier 1 counts the four message types per
 * peer-pair; that's enough for the NOTIFICATION-burst alert which
 * catches session-instability / route-hijack-precursor patterns
 * without needing to parse AS numbers or prefix announcements. */
#define MAX_BGP_SESSIONS 32

typedef struct {
    char     peer_a[46];           /* lexically smaller endpoint */
    char     peer_b[46];           /* lexically greater endpoint */
    int      open_count;           /* type 1 — session start  */
    int      update_count;         /* type 2 — routes         */
    int      notification_count;   /* type 3 — session teardown */
    int      keepalive_count;      /* type 4 — heartbeat      */
    time_t   first_seen;
    time_t   last_seen;
} bgp_session_t;

/* ── SSH observation tracking ────────────────────────── */
/* SSH lives on TCP/22. The protocol begins with a cleartext
 * banner exchange ("SSH-protoversion-softwareversion\r\n") before
 * any key exchange happens — that's the only field we can read
 * passively. Per RFC 4253 §4.2 the banner starts with the literal
 * bytes "SSH-" followed by "1.99" or "2.0", a hyphen, then
 * implementation text and CR/LF.
 *
 * Each completed banner exchange = one TCP connection that reached
 * the SSH handshake. SSH brute-force tools (hydra, medusa, ncrack)
 * open many connections per second; legitimate users open one and
 * stay connected. Tier 1 counts banners observed per (src_ip,
 * dst_ip) and fires SSH_BRUTE_FORCE when the count crosses the
 * threshold — without ever decrypting anything, because brute-force
 * is a TCP-shape signal, not a payload signal. */
#define MAX_SSH_FLOWS 64

typedef struct {
    char     src_ip[46];           /* client (initiator of TCP) */
    char     dst_ip[46];           /* server (the SSHd target)  */
    int      banner_count;         /* TCP flows that reached banner */
    char     server_banner[80];    /* last banner string seen   */
    time_t   first_seen;
    time_t   last_seen;
} ssh_flow_t;

/* ── RDP observation tracking ────────────────────────── */
/* RDP lives on TCP/3389. The connection setup is TPKT (RFC 1006)
 * carrying an X.224 Class 0 Connection Request TPDU, optionally
 * followed by a cookie ("Cookie: mstshash=USERNAME\r\n") and an
 * RDP Negotiation Request (MS-RDPBCGR §2.2.1.1) that announces
 * which security protocols the client wants — vanilla RDP, SSL,
 * CredSSP/NLA, or HYBRID_EX. Everything after the negotiation
 * response is wrapped in TLS (or CredSSP-over-TLS) and opaque.
 *
 * Tier 1 counts X.224 CR TPDUs per (client_ip, server_ip), keeps
 * the latest mstshash cookie value (the username the attacker is
 * guessing against), and bitmasks the requested protocols. That's
 * enough for the brute-force alert which catches xfreerdp-loop /
 * NLBrute / Crowbar without seeing the encrypted auth. */
#define MAX_RDP_FLOWS 64

#define RDP_PROTO_RDP        0x01u   /* vanilla legacy RDP   */
#define RDP_PROTO_SSL        0x02u   /* TLS-only             */
#define RDP_PROTO_HYBRID     0x04u   /* CredSSP / NLA        */
#define RDP_PROTO_HYBRID_EX  0x08u   /* CredSSP early-user   */

typedef struct {
    char     src_ip[46];           /* client (TCP initiator) */
    char     dst_ip[46];           /* server (the RDP target) */
    int      connect_req_count;    /* X.224 CR TPDUs observed */
    char     last_cookie[64];      /* last mstshash username seen */
    uint8_t  proto_mask;           /* OR of RDP_PROTO_* observed  */
    time_t   first_seen;
    time_t   last_seen;
} rdp_flow_t;

/* ── SNMP observation tracking ───────────────────────── */
/* SNMP lives on UDP/161 (agent) and UDP/162 (traps). v1 (RFC 1157)
 * and v2c (RFC 1901-1908) carry the community string in cleartext
 * ASN.1 BER. v3 (RFC 3411+) authenticates but still exposes the
 * security name. We track v1/v2c here — v3 is rare on the LAN and
 * the brute-force shape would be different.
 *
 * Tier 1 counts PDU types per (src_ip, dst_ip) and tracks up to 8
 * distinct community strings seen — community-guessing is the
 * unmistakable signature of snmpwalk -v2c -c <wordlist> sweeps and
 * the metasploit `auxiliary/scanner/snmp/snmp_login` module.
 *
 * Set requests are tracked separately because they're rare in
 * monitoring traffic — almost every legitimate SNMP query is a
 * Get/GetNext/GetBulk. A Set with a guessed community is the
 * post-exploitation config-rewrite step. */
#define MAX_SNMP_FLOWS         48
#define MAX_SNMP_COMMUNITIES    8
#define SNMP_COMMUNITY_LEN     32

typedef struct {
    char     src_ip[46];
    char     dst_ip[46];
    int      get_count;            /* GetRequest               */
    int      getnext_count;        /* GetNextRequest           */
    int      getbulk_count;        /* GetBulkRequest (v2+)     */
    int      set_count;            /* SetRequest               */
    int      response_count;       /* GetResponse              */
    int      trap_count;           /* Trap (v1) / SNMPv2-Trap  */
    int      version;              /* 0=v1, 1=v2c, 3=v3        */
    int      community_count;      /* unique communities seen  */
    char     communities[MAX_SNMP_COMMUNITIES][SNMP_COMMUNITY_LEN];
    char     last_community[SNMP_COMMUNITY_LEN];
    time_t   first_seen;
    time_t   last_seen;
} snmp_flow_t;

/* ── MQTT observation tracking ───────────────────────── */
/* MQTT (v3.1.1 RFC-equivalent OASIS spec / v5 OASIS spec) is the
 * dominant IoT pub/sub protocol. Brokers default to TCP/1883
 * cleartext; TLS variant is TCP/8883 and is opaque past the
 * handshake. Sloth tracks the cleartext path.
 *
 * Tier 1 detects:
 *   - CONNECT packets per (client_ip, broker_ip) — high count
 *     means credential brute-force or a malformed-client
 *     reconnect storm.
 *   - The username field from the CONNECT payload (when the
 *     User Name Flag is set) — same role as the SNMP community
 *     or the mstshash cookie: tells operators which account the
 *     attacker is guessing.
 *   - CONNACK reason codes — code 4 in v3 / 0x86 in v5 = bad
 *     credentials. A high failure count is the explicit signal,
 *     even quieter than the connect-count threshold.
 *   - Protocol-level (3 / 4 / 5) for asset inventory. */
#define MAX_MQTT_FLOWS   32
#define MQTT_USERNAME_LEN 32

typedef struct {
    char     src_ip[46];           /* MQTT client                    */
    char     dst_ip[46];           /* MQTT broker                    */
    int      connect_count;        /* CONNECT packets observed       */
    int      connack_fail_count;   /* bad-auth CONNACK responses     */
    int      subscribe_count;      /* SUBSCRIBE packets              */
    int      publish_count;        /* PUBLISH packets                */
    int      proto_level;          /* last seen: 3 / 4 / 5           */
    char     last_username[MQTT_USERNAME_LEN];
    time_t   first_seen;
    time_t   last_seen;
} mqtt_flow_t;

/* ── LDAP observation tracking ───────────────────────── */
/* LDAP lives on TCP/389 (cleartext) and TCP/3268 (Global Catalog
 * cleartext). TLS variants (636 / 3269) are opaque past the
 * handshake and not observed here.
 *
 * Tier 1 detects BindRequest, SearchRequest, and SearchResult
 * Reference messages via the outer ASN.1 [APPLICATION n] tag and
 * counts them per-source. The aggregate feeds the
 * LDAP_SEARCH_FLOOD alert — BloodHound, ldapdomaindump, and the
 * impacket family produce 100+ search requests in seconds from a
 * single workstation, which a normal AD client never does. */
#define MAX_LDAP_EVENTS 64

typedef struct {
    char   src_ip[46];
    int    bind_count;          /* LDAP BindRequest                  */
    int    bind_anon_count;     /* BindRequest with empty DN         */
    int    search_count;        /* LDAP SearchRequest                */
    int    search_ref_count;    /* SearchResultReference (referral)  */
    time_t first_seen;
    time_t last_seen;
} ldap_event_t;

/* ── Kerberos observation tracking ────────────────────── */
/* Kerberos lives on TCP / UDP port 88. v1 of sloth's Kerberos
 * snooper does message-type detection (via the outer ASN.1
 * [APPLICATION] tag byte) and KRB-ERROR error-code extraction
 * (via a minimal ASN.1 walk for the [6] error-code field). Per-
 * source aggregate counts feed the KERB_PREAUTH_BURST alert
 * (password spray detection).
 *
 * Deeper Kerberos visibility — username/principal extraction,
 * AS-REP roasting detection, kerberoasting service-ticket
 * tracking — is documented out of scope; see
 * docs/wiki/kerberos-snoop.md. */
#define MAX_KERB_EVENTS  64

typedef struct {
    char   src_ip[46];
    int    as_req_count;             /* AS-REQ messages seen      */
    int    as_rep_count;             /* AS-REP messages seen      */
    int    tgs_req_count;            /* TGS-REQ messages seen     */
    int    tgs_rep_count;            /* TGS-REP messages seen     */
    int    preauth_required_count;   /* KRB-ERROR 25              */
    int    preauth_failed_count;     /* KRB-ERROR 24 (spray)      */
    int    principal_unknown_count;  /* KRB-ERROR 6 (enumeration) */
    int    error_other_count;        /* any other error code      */
    time_t first_seen;
    time_t last_seen;
} kerb_event_t;

/* ── SMB observation tracking ──────────────────────────── */
/* SMB lives on TCP/445 (direct) and TCP/139 (NetBIOS Session
 * Service framing). v1 has been deprecated since 2017 (EternalBlue
 * / WannaCry) — any observed SMB1 use is itself a finding. We
 * track flows by (client, server, server_port) and record the
 * highest-risk dialect ever seen on the flow.
 *
 * dialect values are short strings ("SMB1", "SMB2") — SMB2 / SMB3
 * are merged into "SMB2" because distinguishing them requires
 * parsing past the negotiate response, and the rogue-SMB1 trigger
 * doesn't need the distinction. */
#define MAX_SMB_SESSIONS 64

typedef struct {
    char     client_ip[46];
    char     server_ip[46];
    uint16_t server_port;        /* 445 or 139 */
    char     dialect[8];         /* "SMB1" or "SMB2" — sticky to SMB1 */
    time_t   first_seen;
    time_t   last_seen;
    int      count;
} smb_session_t;

/* ── IPv6 NDP Router Advertisement tracking ─────────────── */
/* RFC 4861 §4.2 Router Advertisement (ICMPv6 type 134).
 *
 * For SOC visibility we only need to know *who* is acting as a
 * default router on the segment — multiple distinct router IPs
 * with non-zero lifetime is the rogue-RA condition (the IPv6
 * analogue of rogue DHCP). NS/NA neighbor cache tracking is a
 * future addition; today this struct is RA-only. */
#define MAX_NDP_RAS         16   /* distinct RA-emitting routers */
#define NDP_RA_MAX_PREFIXES  4   /* prefixes captured per router */

typedef struct {
    char     src_ip[46];                         /* router's IPv6 source addr */
    uint8_t  src_mac[6];                         /* SLLA option (option type 1) */
    uint8_t  has_src_mac;                        /* 1 if SLLA was present */
    uint8_t  cur_hop_limit;
    uint8_t  flags;                              /* M/O/H bits + reserved */
    uint16_t router_lifetime;                    /* seconds; 0 = NOT a router */
    char     prefixes[NDP_RA_MAX_PREFIXES][50];  /* "2001:db8::/64" */
    int      prefix_count;
    time_t   first_seen;
    time_t   last_seen;
    int      count;
} ndp_ra_event_t;

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
    /* ── Security / capability posture (roadmap B3b) ──────
     * Filled by the shared beacon IE parser. Before B3b the nl80211
     * scan path had its own parser yielding SSID plus three booleans,
     * so the same AP reported far less detail in managed mode than in
     * monitor mode. Empty string / 0 means the IE was absent.
     *
     * 802.11k neighbour reports are deliberately NOT mirrored here:
     * they are an AP-topology record that belongs with the monitor
     * table's beacon_ap_t, and copying the array into every scan
     * result would cost 7 KB of state for a view that has nowhere to
     * show it. */
    char pairwise[12];
    char group[12];
    char akm[24];
    int  mfp;            /* 0=off 1=capable 2=required */
    char vendor[24];
    int  has_wps;
    int  wps_state;
    int  wps_locked;
    char phy[10];        /* "Wi-Fi 7" / "6" / "5" / "4" / "legacy" */
    int  has_qbss;
    int  qbss_stations;
    int  qbss_chan_util;
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

/* ── DNS query log ──────────────────────────────────────── */
#define MAX_DNS_LOG  256
#define DNS_NAME_LEN  64

typedef struct {
    char   src[46];             /* source IP of the DNS packet */
    char   qname[DNS_NAME_LEN]; /* query name (truncated at 63 chars) */
    char   qtype[8];            /* "A", "AAAA", "PTR", "MX", "NS", "CNAME", "TXT", "SRV", "?" */
    char   answer[46];          /* first A/AAAA IP, "NXDOMAIN", or "" */
    int    is_resp;             /* 0 = query, 1 = response */
    time_t ts;
} dns_log_entry_t;

/* ── NTP log ────────────────────────────────────────────── */
#define MAX_NTP_LOG 256

typedef struct {
    char   src[46];
    char   dst[46];
    char   mode[10];   /* "client", "server", "sym-act", "sym-pas", "bcast", "ctrl", "?" */
    char   ref[16];    /* reference ID (server name like "GPS", "DCF", or IP) */
    uint8_t version;   /* NTP version 1..4 */
    uint8_t stratum;   /* 0=unspec, 1=primary, 2..15=secondary, 16=unsync */
    time_t ts;
} ntp_log_entry_t;

/* ── Top hosts (aggregated remote IPs across all conns) ── */
#define MAX_TOP_HOSTS   32
#define TOP_HOST_STALE_S 600   /* drop a host not seen for this long */

typedef struct {
    char     ip[46];
    char     hostname[64];   /* DNS-resolved name, "" if unresolved/pending */
    char     owner[32];      /* hosting org from embedded IP_OWNER table */
    time_t   first_seen;
    time_t   last_seen;
    int      conn_count;     /* distinct flows to this IP this poll */
    double   rx_rate;        /* B/s summed across all flows */
    double   tx_rate;
    /* Cumulative bytes since first_seen, integrated from rx_rate /
     * tx_rate * poll-interval each tick. Approximate (1 Hz integration)
     * but monotonic and accurate to within the poll period. */
    uint64_t rx_bytes;
    uint64_t tx_bytes;
} top_host_t;

/* ── Devices (synthesized device profiles, keyed by MAC) ─ */
#define MAX_DEVICES  256

#define DEV_SRC_ARP     (1 << 0)
#define DEV_SRC_DHCP    (1 << 1)
#define DEV_SRC_MDNS    (1 << 2)
#define DEV_SRC_BEACON  (1 << 3)
#define DEV_SRC_PROBE   (1 << 4)
#define DEV_SRC_STA     (1 << 5)

/* ── Device risk signals (roadmap #16 phase 4) ─────
 * A bitmask of signals contributing to a device's risk bucket.
 * Each signal is either "observed / not observed"; the score is
 * derived from a weighted sum in device_risk_score(). */
#define DEV_RISK_RANDOM_MAC      (1 << 0)  /* locally-administered MAC */
#define DEV_RISK_UNKNOWN_VENDOR  (1 << 1)  /* OUI not in the embedded table */
#define DEV_RISK_NO_HOSTNAME     (1 << 2)  /* no DHCP/mDNS/NBNS resolution */
#define DEV_RISK_PROBE_ONLY      (1 << 3)  /* probe frames, no association */
#define DEV_RISK_CLEARTEXT_CRED  (1 << 4)  /* cred exposure attributed to us */
#define DEV_RISK_ALERT_TAGGED    (1 << 5)  /* an alert's match_ip == our ip */

typedef enum {
    DEV_RISK_LOW  = 0,
    DEV_RISK_MED  = 1,
    DEV_RISK_HIGH = 2,
    DEV_RISK_CRIT = 3,
} device_risk_level_t;

typedef struct {
    uint8_t mac[6];
    char    ip[46];          /* best-known IP, "" if unknown */
    char    hostname[64];    /* DHCP/mDNS hostname, "" if unknown */
    char    vendor[32];      /* OUI vendor short name, "" if unknown */
    char    last_ssid[33];   /* most recent probed SSID, "" if none */
    int     is_ap;           /* seen emitting beacons */
    int8_t  signal_dbm;      /* most recent WiFi signal, 0 if none */
    int     probe_count;     /* total probe frames */
    int     sources;         /* bitmask of DEV_SRC_* */
    /* Risk scoring: derived once per poll from the observed signals
     * below and the alert / cleartext-cred state. See src/device_risk.c
     * and roadmap #16 phase 4. */
    int                risk_signals;   /* bitmask of DEV_RISK_* */
    device_risk_level_t risk_level;
    time_t  last_seen;
} device_t;

/* Human-readable bucket name for the alerts view / JSONL. */
const char *device_risk_label(device_risk_level_t l);

/* device_risk_score() is declared alongside iface_is_hidden() below,
 * after sloth_state_t is defined. */

/* ── Alerts ─────────────────────────────────────────────── */
#define MAX_ALERTS         128
#define ALERT_TITLE_LEN     20
#define ALERT_DETAIL_LEN   256   /* holds the longest rule detail incl. two IPv6 addrs */
#define ALERT_KEY_LEN       96   /* dedup id: "<rule>:%.39s->%.39s:%u" worst case */
#define ALERT_NXDOMAIN_WINDOW_S  60   /* sliding window for NXDOMAIN-burst rule */
#define ALERT_NXDOMAIN_THRESH    10   /* NXDOMAINs from one src to trigger */

/* Three-tier alert severity. Numeric values are stable and consumed by
 * the JSONL `sev` field — never change them. Render colour:
 *   LOW  → yellow  — reconnaissance / suspicious-but-passive
 *   WARN → orange  — clearly malicious, not yet an active exploit
 *   CRIT → red     — active attack or IOC hit
 * Cross-panel IP coloring follows the highest severity an IP has
 * been associated with within ALERT_HOT_TTL_S. */
typedef enum {
    ALERT_SEV_LOW  = 0,
    ALERT_SEV_WARN = 1,
    ALERT_SEV_CRIT = 2,
} alert_sev_t;

typedef enum {
    ALERT_TYPE_PORT_SCAN = 0,
    ALERT_TYPE_DEAUTH_FLOOD,
    ALERT_TYPE_NXDOMAIN_BURST,
    ALERT_TYPE_THREAT_DOMAIN,
    ALERT_TYPE_THREAT_IP,
    ALERT_TYPE_BEACONING,
    ALERT_TYPE_DGA_DOMAIN,
    ALERT_TYPE_ARP_SPOOF,
    ALERT_TYPE_ROGUE_DHCP,
    ALERT_TYPE_ROGUE_RA,
    ALERT_TYPE_SMB1_USE,
    ALERT_TYPE_KERB_PREAUTH_BURST,
    ALERT_TYPE_LDAP_SEARCH_FLOOD,
    ALERT_TYPE_BGP_NOTIFICATION_BURST,
    ALERT_TYPE_SSH_BRUTE_FORCE,
    ALERT_TYPE_RDP_BRUTE_FORCE,
    ALERT_TYPE_SNMP_COMMUNITY_BRUTE,
    ALERT_TYPE_MQTT_BROKER_BRUTE,
    ALERT_TYPE_EVIL_TWIN,
    ALERT_TYPE_EVIL_TWIN_PROXIMITY,
    ALERT_TYPE_KARMA_AP,
    ALERT_TYPE_DNS_TUNNEL,
    ALERT_TYPE_PROBE_FLOOD,
    ALERT_TYPE_ATTACK_TOOL_UA,
    ALERT_TYPE_ATTACK_PATH,
    ALERT_TYPE_WEAK_TLS,
    ALERT_TYPE_NO_MONITOR_MODE,     /* startup: no WiFi radio in monitor mode */
    ALERT_TYPE_CLEARTEXT_CRED,      /* username observed in the clear (#16 phase 3) */
    ALERT_TYPE_BEACON_FLOOD,        /* mdk-style flood of fake APs (roadmap B4) */
    ALERT_TYPE_AUTH_FLOOD,          /* 802.11 auth-request flood at an AP (roadmap B1) */
    ALERT_TYPE_SSID_CONFUSION,      /* same SSID advertised with downgraded RSN (CVE-2023-52424, #32) */
    ALERT_TYPE_MGMT_FUZZ,           /* malformed-IE / fuzzed 802.11 mgmt frames (mdk4 mode m, #33) */
    ALERT_TYPE_ROGUE_RADIUS,        /* weak EAP method / identity leak — eaphammer/hostapd-wpe (#31) */
    ALERT_TYPE_ICMP_TUNNEL,         /* oversized Echo payloads — ptunnel/icmptunnel/Loki (#40) */
    ALERT_TYPE_MY_NETWORK_RECON,    /* unassociated client remembers an operator-designated SSID (#52) */
    ALERT_TYPE_RECURRING_TRANSIT,   /* same device seen passing repeatedly — circling (#54) */
    ALERT_TYPE_UNKNOWN_DEVICE,      /* device on a designated network, absent from the roster (#55) */
    ALERT_TYPE_RF_DEGRADED,         /* sustained retry ratio on a channel — interference/jamming (B3) */
    ALERT_TYPE_COUNT,
} alert_type_t;

typedef struct {
    alert_type_t type;
    alert_sev_t  sev;
    char         title[ALERT_TITLE_LEN];
    char         detail[ALERT_DETAIL_LEN];
    char         key[ALERT_KEY_LEN];      /* dedup id (type:identifier) */
    int          count;                   /* observations under this key */
    time_t       first_seen;
    time_t       last_seen;
    /* Optional pcap export criteria — set by rules that have a concrete
     * (ip[, port]) the alert is *about*. Empty for rules where the alert
     * is broader than a single flow. */
    char         match_ip[46];
    uint16_t     match_port;              /* 0 = any port */
    int          pcap_dumped;             /* engine-internal flag */
    /* MITRE ATT&CK technique ID (e.g. "T1110.001") — populated from a
     * fixed lookup on alert_type by fire(). Empty for alerts that
     * describe operator/host posture rather than an adversary
     * technique (e.g. NO_MONITOR_MODE). */
    char         technique[16];
} alert_t;

/* Canonical MITRE ATT&CK technique for a given alert type. Returns
 * an empty string ("") for alert types that describe host posture
 * rather than adversary behaviour. Defined in src/alerts.c so tests
 * can compile against the table directly. */
const char *alert_technique(alert_type_t type);

/* ── ICMP log ───────────────────────────────────────────── */
#define MAX_ICMP_LOG 256

typedef struct {
    char     src[46];
    char     dst[46];
    char     desc[24];  /* "Echo Req", "Echo Reply", "Unreachable", "TTL Exceeded", ... */
    uint16_t seq;       /* sequence (echo) or 0 */
    uint16_t payload_len; /* bytes after the 8-byte ICMP header (tunnel signal) */
    uint8_t  type;
    uint8_t  code;
    uint8_t  is_v6;     /* 0=ICMPv4, 1=ICMPv6 */
    time_t   ts;
} icmp_log_entry_t;

/* ── QUIC session log ───────────────────────────────────── */
#define MAX_QUIC_LOG 256

typedef struct {
    char   src[46];
    char   dst[46];
    char   host[64];  /* hostname from DNS cache, "" if unknown */
    char   ver[8];    /* "v1", "v2", "draft" */
    time_t ts;
} quic_log_entry_t;

/* ── TLS connection log ─────────────────────────────────── */
#define MAX_TLS_LOG 256

typedef struct {
    char   src[46];
    char   dst[46];
    char   host[64];    /* SNI hostname, "" if absent */
    char   tls_ver[8];  /* "TLS 1.3" "TLS 1.2" "TLS 1.1" "TLS 1.0" "TLS" */
    char   ja3[33];     /* MD5 of JA3 string, lowercase hex; "" if not computed */
    /* JA4 client fingerprint (FoxIO spec): a(10) + '_' + b(12) + '_' + c(12) = 37
     * chars, + NUL. Section a encodes protocol/version/SNI/counts/ALPN;
     * sections b + c are sha256-truncated over sorted cipher / ext lists
     * so extension reordering doesn't change the value (unlike JA3). "" if
     * not computed. Roadmap #16 phase 2. */
    char   ja4[48];
    time_t ts;
} tls_log_entry_t;

/* ── HTTP request log ───────────────────────────────────── */
#define MAX_HTTP_LOG 256

typedef struct {
    char   src[46];        /* source IP */
    char   method[10];     /* GET POST PUT etc */
    char   host[64];       /* Host header value */
    char   path[128];      /* request URI */
    char   user_agent[64]; /* User-Agent header, truncated */
    /* JA4H client fingerprint (FoxIO spec): a(10) _ b(12) _ c(12) _ d(12)
     * = 49 chars + NUL. Section a encodes method/version/cookie flag/
     * referer flag/numheaders/lang; b hashes observed header names; c
     * hashes sorted cookie names; d hashes sorted cookie name=value
     * pairs. "" if not computed. Roadmap follow-up to #16 phase 2. */
    char   ja4h[50];
    time_t ts;
} http_log_entry_t;

/* ── Cleartext credential exposures (roadmap #16 phase 3) ──
 * Passive observation of authentication material sent in the clear.
 * Records the *fact* of exposure and the username, never the password
 * or its hash. Guardrail lives in src/cleartext_creds.c — see
 * docs/wiki/jsonl-schema.md for the schema policy. */
#define MAX_CLEARTEXT_CREDS 64

typedef struct {
    char     src[46];       /* client IP */
    char     dst[46];       /* server IP */
    uint16_t dst_port;      /* 80 for HTTP Basic, 21 for FTP, etc. */
    char     protocol[16];  /* "HTTP-Basic", "FTP", "POP3", ... */
    char     username[64];  /* observed username, sanitized */
    int      password_observed;  /* 1 if a password token was seen */
    time_t   ts;
} cleartext_cred_t;

/* ── Deauth / Disassoc events ───────────────────────────── */
#define MAX_DEAUTH_ENTRIES    128
#define DEAUTH_AGE_SECS        60   /* drop events older than this */
#define DEAUTH_FLOOD_THRESH     5   /* frames per burst to raise flood flag */
#define DEAUTH_FLOOD_WIN_SECS   5   /* burst window in seconds */
/* Beacon-flood (mdk3/mdk4): a legit RF neighbourhood gains new APs slowly;
 * a flood injects dozens of brand-new BSSIDs in seconds. */
#define BEACON_FLOOD_THRESH    40   /* distinct new BSSIDs in the window */
#define BEACON_FLOOD_WIN_SECS  10
/* Auth-request flood: a legit AP fields the odd auth frame (roam,
 * reconnect); an mdk-style flood sprays dozens per second at one BSSID. */
#define AUTH_FLOOD_THRESH      30   /* auth frames to one BSSID in the window */
#define AUTH_FLOOD_WIN_SECS     5

typedef struct {
    uint8_t  src[6];
    uint8_t  dst[6];     /* ff:ff:ff:ff:ff:ff = broadcast deauth */
    uint8_t  bssid[6];
    uint16_t reason;     /* 802.11 reason code */
    uint8_t  subtype;    /* 10=disassoc 12=deauth */
    time_t   first_seen;
    time_t   last_seen;
    int      count;
    int      flood;      /* count exceeded DEAUTH_FLOOD_THRESH in window */
} deauth_event_t;

/* ── Beacon APs (passively observed 802.11 access points) ── */
#define MAX_BEACON_APS  256
#define BEACON_AGE_SECS 300

/* AP fingerprint — auxiliary fields harvested from beacon frames that
 * help distinguish a legit AP from a same-SSID twin. Carried inside
 * beacon_ap_t (below). Phase 1 only defines the carrier and the OUI
 * bytes (which equal bssid[0..2]); Phase 2 populates vendor_ies_hash
 * and the capability flags from beacon parsing. */
#define AP_FP_FLAG_WPS_UUID_ZERO        0x01u
#define AP_FP_FLAG_HT_PRESENT           0x02u
#define AP_FP_FLAG_VHT_PRESENT          0x04u
#define AP_FP_FLAG_HE_PRESENT           0x08u
#define AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS 0x10u
#define AP_FP_FLAG_HAK5_OUI             0x20u
#define AP_FP_FLAG_ESPRESSIF_OUI        0x40u

typedef struct {
    uint8_t  oui[3];               /* equals bssid[0..2]; cached for readability */
    uint16_t beacon_interval_ms;   /* parsed once at first observation */
    uint32_t vendor_ies_hash;      /* hash of concatenated tag-221 IEs (Phase 2) */
    uint8_t  flags;                /* AP_FP_FLAG_* bitset (Phase 2) */
} ap_fingerprint_t;

/* RSSI sliding-window ring — Phase 3. 16 slots ≈ 1.6 s of typical
 * (100 ms TBTT) beacon traffic per AP, but the window is bounded by
 * timestamps, not count. Powers the proximity detector that fires
 * when an AP's signal jumps ≥15 dBm inside 60 s (no roam). */
#define RSSI_WIN_SAMPLES 16
#define RSSI_WIN_SECS    60

typedef struct {
    int8_t  dbm[RSSI_WIN_SAMPLES];
    time_t  ts [RSSI_WIN_SAMPLES];
    int     head;                  /* next write slot */
    int     count;                 /* entries populated (≤ SAMPLES) */
} rssi_ring_t;

/* 802.11k Neighbor Report entry — one neighbor AP advertised by the
 * subject AP's beacon (tag 52). Used to map enterprise WiFi topology
 * and to discover BSSIDs on other channels we haven't tuned to. */
#define MAX_AP_NEIGHBORS 8

typedef struct {
    uint8_t bssid[6];
    int     channel;
    int     phy_type;     /* IEEE 802.11 PHY type code */
} ap_neighbor_t;

typedef struct {
    char     ssid[33];        /* "" = hidden/broadcast network */
    uint8_t  bssid[6];
    int8_t   signal_dbm;
    int      channel;
    char     enc[10];         /* OPEN WEP WPA WPA2 WPA3 */
    uint16_t beacon_ms;       /* beacon interval in ms */
    /* RSN inventory — parsed from beacon's RSN IE (tag 48). The
     * cipher / AKM fields show empty strings for OPEN/WEP/WPA(v1).
     * mfp 0=off (no RSN capabilities or both bits clear),
     *      1=capable but not required,
     *      2=required. */
    char     pairwise[12];    /* "CCMP" / "TKIP" / "GCMP" / "GCMP-256" */
    char     group[12];
    char     akm[24];          /* "PSK" / "SAE" / "PSK,FT-PSK" / "802.1X" */
    int      mfp;
    /* Vendor-IE fingerprint — best-guess AP vendor from tag-221 OUIs
     * (Apple AirPort, Cisco, Mikrotik, Ubiquiti, etc.) and a WPS flag.
     * WPS-enabled APs are operationally interesting because PixieDust
     * and online PIN attacks are still a thing on many SOHO routers. */
    char     vendor[24];
    int      has_wps;
    /* WPS state from the WPS IE attributes (when has_wps).
     *   wps_state:  0=unknown 1=NotConfigured 2=Configured
     *   wps_locked: 0=unknown 1=unlocked       2=locked
     * Unlocked + NotConfigured -> classic PixieDust / PIN-attack
     * candidate; locked -> attempts will be refused. */
    int      wps_state;
    int      wps_locked;
    /* Max PHY tier advertised by the AP — same scheme as pnl_client_t.phy. */
    char     phy[10];
    /* 1 if this beacon was originally hidden (empty SSID in the beacon
     * frame) and we revealed it via an out-of-band probe-response /
     * (re)association-response carrying the real SSID. */
    int      revealed;
    /* 802.11k Neighbor Reports — APs this AP advertises as neighbors. */
    ap_neighbor_t neighbors[MAX_AP_NEIGHBORS];
    int      neighbor_count;
    /* Distinct SSIDs ever emitted by this BSSID. Legitimate APs
     * pick one and stick to it; pineapple-style rogue APs spoof
     * many SSIDs from a single radio (>=3 = strong KARMA signal). */
#define MAX_AP_SSID_HISTORY 8
    char     ssid_history[MAX_AP_SSID_HISTORY][33];
    /* Per-SSID IE fingerprint (enc/cipher/akm/mfp + vendor-IE hash) at the
     * time each SSID was first seen. A legit multi-VAP AP varies these
     * across its VAPs; a PineAP/KARMA radio spoofs many SSIDs with one
     * identical IE tuple — the ie_uniformity signal (#30). 0 = unknown. */
    uint32_t ssid_history_fp[MAX_AP_SSID_HISTORY];
    int      ssid_history_n;
    time_t   last_seen;
    int      frame_count;
    /* Evil-twin fingerprint surface. Populated incrementally:
     *   Phase 1 — fp.oui (mirrors bssid[0..2]) used by rule_evil_twin.
     *   Phase 2 — fp.flags + fp.vendor_ies_hash from beacon parsing.
     *   Phase 3 — rssi_{min,max}_60s feed the proximity detector. */
    ap_fingerprint_t fp;
    int8_t   rssi_min_60s;     /* lowest signal seen in last 60s (dBm, 0 = unseen) */
    int8_t   rssi_max_60s;     /* highest signal seen in last 60s (dBm, 0 = unseen) */
    rssi_ring_t rssi_ring;     /* raw samples feeding rssi_min/max_60s */
    /* QBSS Load IE (tag 11) — AP self-reported occupancy. A free
     * congestion metric: no math, just what the AP advertises.
     * has_qbss=0 = IE absent. */
    int      has_qbss;
    int      qbss_stations;    /* associated station count */
    int      qbss_chan_util;   /* channel utilisation, 0..255 (fraction of 255) */
    /* Malformed-IE counters accumulated across this BSSID's frames —
     * the mgmt-frame fuzz detector (#33). mdk4 mode m / crafted
     * aireplay frames drive these up; well-formed APs leave them 0. */
    uint16_t fuzz_ie_overruns;
    uint16_t fuzz_oversize_ssid;
    uint16_t fuzz_truncated_rsn;
} beacon_ap_t;

/* True when `ap` names `bssid` in its 802.11k Neighbor Report list. */
int ap_advertises_neighbor(const beacon_ap_t *ap, const uint8_t bssid[6]);

/* True when two APs are co-operating infrastructure rather than
 * strangers sharing an SSID: either advertises the other as an 802.11k
 * neighbor (tag 52).
 *
 * Neighbor Reports are how an AP tells clients where else to roam, so
 * membership is asserted by the deployment itself. An impostor spoofing
 * an SSID does not appear in the real AP's list and cannot make the
 * real AP appear in its own — it would have to guess a BSSID that its
 * target already advertises. One-directional is enough: in mixed
 * deployments only the controller-managed side may emit tag 52.
 *
 * Used to keep same-SSID rules from calling a range extender a rogue
 * AP (#51). Note the converse does not hold — plenty of legitimate
 * consumer gear emits no Neighbor Reports at all, so a 0 here means
 * "no evidence of a relationship", never "proven unrelated". */
int ap_infrastructure_peers(const beacon_ap_t *a, const beacon_ap_t *b);

/* ── Evil-twin episodes (Phase 5 — materialised view) ──── */
#define MAX_TWIN_EPISODES 64

/* One detected same-SSID + same-cipher + diff-OUI twin pair. The
 * "real" / "twin" assignment defaults to the lower-RSSI BSSID being
 * the real one (background, far) and the higher being the twin
 * (closer, often the attacker). When rule_evil_twin_attack_chain
 * has tainted a BSSID, that override pins the assignment. */
typedef struct {
    char     ssid[33];
    uint8_t  real_bssid[6];
    uint8_t  twin_bssid[6];
    char     enc[10];                /* shared encryption mode */
    int8_t   real_rssi;              /* last observed signal (0 = unseen) */
    int8_t   twin_rssi;
    uint8_t  rssi_swing_dbm;         /* max swing of twin in 60s (0 = unseen) */
    uint8_t  attack_in_progress;     /* set when chain rule tainted twin BSSID */
    uint8_t  attacker_oui;           /* twin OUI in Hak5 / Espressif tables */
    uint8_t  hash_mismatch;          /* vendor-IE hashes differ */
    time_t   last_seen;
} twin_episode_t;

/* ── KARMA / PineAP candidates (#30) ─────────────────────────
 * One row per BSSID that beacons an abnormal number of distinct SSIDs
 * — the PineAP / mdk4 / airbase-ng "answer every probed network" lure.
 * Synthesised each poll by karma_update() from the beacon table, the
 * client PNLs, and the deauth ring; the view reads only this table. */
#define MAX_KARMA_APS 64
typedef struct {
    uint8_t  bssid[6];
    int      ssid_count;    /* distinct SSIDs beaconed (beacon ssid_history_n) */
    int      pnl_overlap;   /* advertised SSIDs matching nearby client PNLs */
    int      pnl_jaccard_ppm; /* Jaccard(advertised, PNL-union) in parts-per-million */
    int      ie_uniform;    /* 1 = identical IE fingerprint across all SSIDs (PineAP tell) */
    int      deauth_chain;  /* 1 = concurrent deauth flood (deauth-then-lure) */
    int      score;         /* composite: 1 + (overlap?2:0) + (deauth?3:0) */
    char     top_ssid[33];  /* most recently advertised SSID */
    time_t   last_seen;
} karma_ap_t;

/* ── Rogue-RADIUS / EAP method tracking (#31) ────────────────
 * One row per BSSID seen running an 802.1X EAP conversation. Records
 * which inner EAP method types it offered (bitmap; the methods we
 * classify all have type codes < 32) and how many Response/Identity
 * frames leaked a real username. Synthesised from the EAP inner-frame
 * parser via eap_track. */
#define MAX_ROGUE_RADIUS 32
typedef struct {
    uint8_t  bssid[6];
    uint32_t eap_types_seen;   /* bit T set = EAP method type T observed */
    int      weak_method;      /* 1 = a weak method (MD5/GTC) was offered */
    int      identity_leaks;   /* Response/Identity frames with a real username */
    char     last_identity[64];/* most recent leaked identity (printable) */
    time_t   first_seen;
    time_t   last_seen;
} rogue_radius_ap_t;

/* ── Probe clients (802.11 unassociated devices) ────────── */
#define MAX_PROBE_CLIENTS 128
#define PROBE_AGE_SECS    120

typedef struct {
    uint8_t mac[6];       /* source MAC */
    char    ssid[33];     /* last-probed SSID, "" = wildcard */
    int8_t  signal_dbm;
    int     channel;
    time_t  first_seen;   /* set when the MAC is first observed */
    time_t  last_seen;
    int     frame_count;
    /* RSSI history for presence classification (#53). Dwell alone
     * cannot separate a resident device from one driving past — the
     * trajectory shape can. See src/presence.h. */
    rssi_ring_t rssi_ring;
} probe_client_t;

/* ── PNL: per-MAC Preferred Network List ─────────────────── *
 * Aggregated probe-request targets. Each unique MAC carries the
 * unique set of directed SSIDs it has probed for since launch —
 * a device's PNL leaks where it has connected before, and across
 * MAC-randomization boundaries the set itself often fingerprints
 * the owner. */
#define MAX_PNL_CLIENTS         128
#define MAX_PNL_SSIDS_PER_CLI   16

typedef struct {
    uint8_t mac[6];
    int     mac_random;                       /* 1 if MAC[0] & 0x02 */
    int     ssid_count;
    char    ssids[MAX_PNL_SSIDS_PER_CLI][33];
    int     probe_count;                       /* total directed probes */
    /* OS fingerprint derived from the vendor-specific IEs the client
     * leaks in probe requests. Empty when we don't have a confident
     * label. Sticky: once a strong vendor IE pins the OS, weaker
     * later probes don't overwrite. */
    char    os_fp[16];
    /* Max PHY tier — "Wi-Fi 7" / "Wi-Fi 6" / "Wi-Fi 5" / "Wi-Fi 4" /
     * "legacy" — derived from HT (45), VHT (191), HE / EHT (255 ext).
     * Pins the device generation across MAC rotations. */
    char    phy[10];
    time_t  first_seen;
    time_t  last_seen;
} pnl_client_t;

/* ── Recurring transits (#54) ─────────────────────────────── *
 * Devices seen passing more than once. Bounded like everything else:
 * the interesting population is small, and an unbounded table would be
 * the one place a passive monitor could be made to allocate without
 * limit by an attacker spraying randomised MACs. */
#define MAX_TRANSIT_DEVICES 64
#define MAX_TRANSIT_PASSES  16

typedef struct {
    uint8_t mac[6];                        /* canonical identity */
    time_t  pass_ts[MAX_TRANSIT_PASSES];   /* start of each pass, oldest first */
    int     pass_n;
    int8_t  best_rssi;                     /* closest approach across passes */
    time_t  first_seen;
    time_t  last_seen;
} transit_device_t;

/* ── Sequence-number tracking ──────────────────────────────── *
 * 12-bit per-station seqnum is the deanonymisation primitive —
 * randomised MACs that share a monotonic seqnum trail are the same
 * physical radio. */
#define MAX_SEQNUM_CLIENTS        256
#define SEQNUM_HISTORY_LEN        8
#define MAX_SEQNUM_CORRELATIONS   32

typedef struct {
    uint8_t  mac[6];
    int      mac_random;
    time_t   last_seen;
    int      frame_count;
    uint16_t hist[SEQNUM_HISTORY_LEN];
    time_t   hist_ts[SEQNUM_HISTORY_LEN];
    int      hist_n;
} seqnum_client_t;

typedef struct {
    uint8_t  mac_a[6];
    uint8_t  mac_b[6];
    int      mac_a_random;
    int      mac_b_random;
    int      gap;
    long     dt_ms;
    int      a_count;
    int      b_count;
} seqnum_correlation_t;

/* ── Channel activity summary (derived from beacons + assoc) ─ */
#define MAX_CHAN_ENTRIES   64

typedef struct {
    int     channel;        /* 1..177 across 2.4/5/6 GHz */
    int     ap_count;       /* APs with a beacon on this channel */
    int     assoc_count;    /* associated STAs on this channel  */
    int8_t  best_signal;    /* strongest signal among APs here  */
    char    top_ssid[33];   /* SSID of the strongest AP         */
    time_t  last_seen;
    /* RF quality over the last window (roadmap B3). Retries and FCS
     * failures are the passive signature of interference, a hidden
     * node, or a jammer. -1 means "not enough frames to say", which is
     * a different answer from 0% — a quiet channel is not a clean one. */
    uint32_t frames;
    int      retry_pct;
    int      badfcs_pct;
} channel_summary_t;

/* ── Client ↔ AP association tracker ─────────────────────── */
#define MAX_ASSOC_ENTRIES   128

/* Evidence source — strongest (definitive) first. */
enum {
    ASSOC_SRC_UNKNOWN = 0,
    ASSOC_SRC_EAPOL   = 1,   /* completed 4-way handshake */
    ASSOC_SRC_ASSOC   = 2,   /* assoc-response status=0    */
    ASSOC_SRC_REASSOC = 3,   /* reassoc-response status=0  */
};

typedef struct {
    uint8_t bssid[6];
    uint8_t sta_mac[6];
    char    ssid[33];
    int     sta_random;
    int     source;
    int     channel;
    int8_t  signal_dbm;
    time_t  first_seen;
    time_t  last_seen;
    int     frame_count;
} assoc_t;

/* ── EAPOL handshake event (WPA 4-way / PMKID) ────────────── *
 * One per observed EAPOL-Key frame. M2 events carry the M1+M2
 * combined info (handshake_complete=1) when their M1 was seen. */
#define MAX_EAPOL_EVENTS  256

typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta_mac[6];
    char     ssid[33];
    time_t   ts;
    int      msg_num;
    int      has_pmkid;
    uint8_t  pmkid[16];
    uint8_t  anonce[32];
    uint8_t  snonce[32];
    uint8_t  mic[16];
    int      handshake_complete;
    int8_t   signal_dbm;
    int      channel;
} eapol_event_t;

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

/* One captured 802.11 frame, for the monitor-mode packets band. Populated
 * from the probe/monitor pcap (radiotap + dot11) rather than the IP capture.
 * Addresses are raw MACs; label is a human subtype ("Beacon","Auth",…). */
#define MAX_MON_FRAMES 256
typedef struct {
    time_t   ts;
    int8_t   signal_dbm;
    uint16_t len;
    uint8_t  type;        /* 0=mgmt 1=ctrl 2=data 3=ext */
    uint8_t  subtype;
    uint8_t  addr1[6];    /* DA / RA */
    uint8_t  addr2[6];    /* SA / TA */
    char     label[12];
} mon_frame_t;

/* Passive sensor abstraction (issue #28). A sensor is a typed producer of
 * observations copied into sloth_state_t — the Wi-Fi monitor today, BLE /
 * Zigbee / SDR / GPS / ADS-B / Meshtastic / CAN tomorrow (see
 * docs/wiki/non-ip-sensors.md). Deliberately small: it normalises metadata
 * about passive sources, it is NOT a plugin ABI or a control surface. */
#define MAX_SENSORS 16
typedef enum {
    SENSOR_WIFI = 0, SENSOR_BLE, SENSOR_ZIGBEE, SENSOR_SDR,
    SENSOR_GPS, SENSOR_ADSB, SENSOR_MESHTASTIC, SENSOR_CAN,
    SENSOR_KIND_COUNT
} sensor_kind_t;
typedef enum {
    SENSOR_STATE_PRESENT = 0, /* detected, not yet producing */
    SENSOR_STATE_ACTIVE,      /* producing observations */
    SENSOR_STATE_HIDDEN,      /* present but suppressed by the operator */
    SENSOR_STATE_ERROR        /* failed to read */
} sensor_state_e;
typedef struct {
    int      kind;            /* sensor_kind_t */
    int      state;          /* sensor_state_e */
    char     name[32];       /* human-readable ("Wi-Fi monitor") */
    char     iface[32];      /* interface / source id */
    uint64_t observed;       /* cumulative observation count */
    time_t   first_seen;
    time_t   last_seen;
} sensor_t;

/* Multi-radio Wi-Fi merge (issue #21). Several monitor-mode adapters can
 * listen at once — each a SENSOR_WIFI sensor with its own id (0..15). A
 * single adapter only hears one channel at a time, so short management
 * frames slip past while it is tuned elsewhere; a second radio parked on
 * another channel closes that gap. This layer merges per-radio 802.11
 * observations into ONE world model keyed by the observed entity (AP
 * BSSID / STA MAC), while retaining enough observer metadata to answer
 * "which radio saw this, on what channel, at what signal, when?".
 *
 * Existing Wi-Fi tables still aggregate by entity, not by adapter; this
 * runs alongside them and is the seam a future N-thread capture path
 * feeds. Purely additive — with one radio it is an identity map. */
#define MAX_WIFI_MERGED 512
typedef struct {
    uint8_t  key[6];          /* observed entity: AP BSSID or STA MAC */
    uint16_t sensor_mask;     /* bit i set = sensor id i observed this entity */
    int      seen_by;         /* popcount(sensor_mask): distinct radios */
    int      best_rssi;       /* strongest RSSI across radios (dBm, closest to 0) */
    int      best_sensor;     /* sensor id that heard it strongest */
    int      channel;         /* channel of the most recent observation */
    int      freq_mhz;        /* frequency of the most recent observation */
    time_t   first_seen;
    time_t   last_seen;
    uint64_t observations;    /* total merged observations across all radios */
} wifi_merged_t;
typedef struct {
    wifi_merged_t ents[MAX_WIFI_MERGED];
    int           count;
    uint64_t      dropped;    /* observations discarded (table full / bad sensor id) */
} wifi_merge_t;

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
    /* Data-stream election: names in this list are excluded from the
     * capture pipeline (packets/DNS/HTTP/TLS/alerts/JSONL). This is
     * distinct from iface_hidden, which is display-only. See issue #17
     * and rule_no_monitor_mode() for how it composes with capture. */
    char          iface_deselected[MAX_IFACES][16];
    int           iface_deselected_count;
    /* Launch-time data-stream allow-list (#35): when non-empty, only
     * these interfaces feed the capture pipeline — the headless
     * complement to the interactive deselect election above. Filled
     * once at startup (--iface / --monitor-only), never mutated at
     * runtime. Empty list = unrestricted. */
    char          iface_allowed[MAX_IFACES][16];
    int           iface_allowed_count;

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

    mon_frame_t   mon_frames[MAX_MON_FRAMES]; /* 802.11 frames, newest first */
    int           mon_frame_count;
    int           mon_frame_sel;              /* selected row in the frames view */

    sensor_t      sensors[MAX_SENSORS];       /* passive sensor registry (#28) */
    int           sensor_count;

    wifi_merge_t  wifi_merged;                /* multi-radio merged 802.11 view (#21) */

    packet_info_t packets[MAX_PACKETS]; /* ring buffer */
    int           pkt_head;             /* next write slot */
    int           pkt_count;            /* total written (capped at MAX_PACKETS) */
    uint64_t      pkt_total;            /* monotonic total ever written (never wraps) */
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
    uint64_t      pkt_jsonl_emitted; /* pkt_total value at last jsonl emit (issue #20) */

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

    /* ── DNS query log ──────────────────────────────────────── */
    dns_log_entry_t dns_log[MAX_DNS_LOG];
    int             dns_log_head;
    int             dns_log_count;
    int             dns_log_sel;

    /* ── NTP log ────────────────────────────────────────────── */
    ntp_log_entry_t ntp_log[MAX_NTP_LOG];
    int             ntp_log_head;
    int             ntp_log_count;
    int             ntp_log_sel;

    /* ── ICMP log ───────────────────────────────────────────── */
    icmp_log_entry_t icmp_log[MAX_ICMP_LOG];
    int              icmp_log_head;
    int              icmp_log_count;
    int              icmp_log_sel;

    /* ── Alerts ─────────────────────────────────────────────── */
    alert_t alerts[MAX_ALERTS];
    int     alert_count;
    int     alert_sel;
    int     alert_detail;   /* 1 = drill-down detail panel shown */

    /* ── Devices ────────────────────────────────────────────── */
    device_t devices[MAX_DEVICES];
    int      device_count;
    int      device_sel;

    /* ── Top hosts (aggregated remote IPs from conns + bw) ─── */
    top_host_t top_hosts[MAX_TOP_HOSTS];
    int        top_host_count;

    /* ── Filter (case-insensitive substring, applied to log views) ── */
    char     filter[48];
    int      filter_editing;   /* 1 while user is typing the filter */

    /* ── Dashboard panel focus (tab navigation) ──────────────── */
    int      dash_focus;       /* dash_panel_t index — see views/dashboard.c */

    /* ── QUIC session log ───────────────────────────────────── */
    quic_log_entry_t quic_log[MAX_QUIC_LOG];
    int              quic_log_head;
    int              quic_log_count;
    int              quic_log_sel;

    /* ── TLS connection log ──────────────────────────────────── */
    tls_log_entry_t tls_log[MAX_TLS_LOG];
    int             tls_log_head;
    int             tls_log_count;
    int             tls_log_sel;

    /* ── HTTP request log ────────────────────────────────────── */
    http_log_entry_t http_log[MAX_HTTP_LOG];  /* ring buffer */

    cleartext_cred_t cleartext_creds[MAX_CLEARTEXT_CREDS];
    int              cleartext_cred_count;
    int              http_log_head;           /* next write slot */
    int              http_log_count;          /* entries written (capped at MAX_HTTP_LOG) */
    int              http_log_sel;

    /* ── Deauth / Disassoc events ────────────────────────────── */
    deauth_event_t deauth_events[MAX_DEAUTH_ENTRIES];
    int            deauth_count;
    int            deauth_sel;
    int            deauth_flood_active;  /* any entry currently flooded */

    /* ── Beacon APs (passive 802.11 beacon sniff) ──────────── */
    beacon_ap_t beacon_aps[MAX_BEACON_APS];
    int         beacon_count;
    int         beacon_sel;
    int         beacon_detail;  /* 1 = AP drill-down detail panel shown */

    /* ── Evil-twin episodes (Phase 5 — materialised view) ───
     *
     * One entry per detected same-cipher diff-OUI twin pair, with
     * the Phase 2/3/4 signal sources merged in. Refreshed once per
     * poll by twins_snapshot(). Consumed by VIEW_TWINS and the
     * jsonl twin-episode emitter. */
    twin_episode_t twin_episodes[MAX_TWIN_EPISODES];
    int            twin_episode_count;
    int            twin_episode_sel;

    karma_ap_t     karma_aps[MAX_KARMA_APS];   /* KARMA/PineAP candidates (#30) */
    int            karma_count;
    int            karma_sel;

    rogue_radius_ap_t rogue_radius[MAX_ROGUE_RADIUS]; /* 802.1X EAP tracking (#31) */
    int               rogue_radius_count;
    int               rogue_radius_sel;               /* VIEW_ROGUE_RADIUS row (#38) */

    /* ── Probe clients ──────────────────────────────────── */
    probe_client_t probe_clients[MAX_PROBE_CLIENTS];
    int            probe_count;
    int            probe_sel;
    char           probe_iface[16]; /* monitor iface name, "" = none found */
    /* Channel scan bar (#22 --hop): the channel list the monitor radio is
     * cycling through and the one it's currently parked on. Populated from
     * the hop scheduler each poll; scan_chan_count==0 when not hopping. */
    int            scan_chans[32];
    int            scan_chan_count;
    int            scan_cur_idx;    /* index of the current channel, -1 = none */
    char           probe_err[80];   /* last probe open/set error, "" = ok */

    /* ── PNL snapshot (Preferred Network Lists per client) ── */
    pnl_client_t   pnl_clients[MAX_PNL_CLIENTS];
    int            pnl_count;
    int            pnl_sel;

    /* ── EAPOL / PMKID / 4-way handshake snapshot ─────────── */
    eapol_event_t  eapol_events[MAX_EAPOL_EVENTS];
    int            eapol_count;
    int            eapol_sel;

    /* ── Sequence-number tracking snapshot ────────────────── */
    seqnum_client_t      seqnum_clients[MAX_SEQNUM_CLIENTS];
    int                  seqnum_count;
    seqnum_correlation_t seqnum_correlations[MAX_SEQNUM_CORRELATIONS];
    int                  seqnum_correlation_count;
    int                  seqnum_corr_sel;

    /* ── Association tracker snapshot ─────────────────────── */
    transit_device_t     transits[MAX_TRANSIT_DEVICES];  /* #54 */
    int                  transit_count;
    assoc_t              assocs[MAX_ASSOC_ENTRIES];
    int                  assoc_count;
    int                  assoc_sel;

    /* ── Channel activity summary ─────────────────────────── */
    channel_summary_t    channels[MAX_CHAN_ENTRIES];
    int                  channel_count;
    int                  channel_sel;

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

    /* ── IPv6 NDP — Router Advertisement events ──────────── */
    ndp_ra_event_t ndp_ras[MAX_NDP_RAS];
    int            ndp_ra_count;

    /* ── SMB observation table ───────────────────────────── */
    smb_session_t  smb_sessions[MAX_SMB_SESSIONS];
    int            smb_session_count;

    /* ── Kerberos observation table ──────────────────────── */
    kerb_event_t   kerb_events[MAX_KERB_EVENTS];
    int            kerb_event_count;

    /* ── LDAP observation table ──────────────────────────── */
    ldap_event_t   ldap_events[MAX_LDAP_EVENTS];
    int            ldap_event_count;

    /* ── BGP observation table ───────────────────────────── */
    bgp_session_t  bgp_sessions[MAX_BGP_SESSIONS];
    int            bgp_session_count;

    /* ── SSH observation table ───────────────────────────── */
    ssh_flow_t     ssh_flows[MAX_SSH_FLOWS];
    int            ssh_flow_count;

    /* ── RDP observation table ───────────────────────────── */
    rdp_flow_t     rdp_flows[MAX_RDP_FLOWS];
    int            rdp_flow_count;

    /* ── SNMP observation table ──────────────────────────── */
    snmp_flow_t    snmp_flows[MAX_SNMP_FLOWS];
    int            snmp_flow_count;

    /* ── MQTT observation table ──────────────────────────── */
    mqtt_flow_t    mqtt_flows[MAX_MQTT_FLOWS];
    int            mqtt_flow_count;

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

    /* Version check-in (notify-only). Populated by updater_snapshot()
     * each poll. `enabled` is 0 until --check-manifest is set on the
     * CLI. See src/updater.c and docs/wiki/version-checkin.md. */
    struct {
        int    enabled;
        int    has_update;                    /* 1 iff latest > current */
        int    err;                           /* 1 iff manifest missing / malformed */
        char   current[16];                   /* baked SLOTH_VERSION */
        char   latest[16];                    /* from the manifest, "" if unknown */
        char   url[128];                      /* release URL, "" if not published */
        char   err_msg[64];                   /* short human message when err=1 */
        time_t last_checked;                  /* 0 iff never read successfully */
    } updater;
} sloth_state_t;

/* ── Iface hide election (shared by iface view + dashboard band) ── */
int iface_is_hidden(const sloth_state_t *s, const char *name);
void iface_hide_non_monitor(sloth_state_t *s);

/* ── Iface data-stream election (shared by iface view + capture) ──
 * A deselected iface's packets are dropped in the pcap callback before
 * any decode / log / alert runs. Purely logical — the OS state of the
 * interface (up/down, monitor, addresses) is never touched. Issue #17. */
int iface_is_deselected(const sloth_state_t *s, const char *name);

/* ── Launch-time allow-list (--iface / --monitor-only, issue #35) ──
 * Empty list = unrestricted (everything passes). Non-empty = whitelist.
 * The capture callback drops a frame when EITHER election rejects its
 * ingress iface: deselected, or absent from a non-empty allow-list.
 * Purely logical — OS interface state is never touched.
 * iface_allow_add() dedupes, ignores NULL/empty names, and is bounded
 * at MAX_IFACES; returns 1 iff the name is in the list afterwards. */
int iface_is_allowed(const sloth_state_t *s, const char *name);
int iface_allow_add(sloth_state_t *s, const char *name);

/* ── Allow-list exclusion marker (issue #37) ──
 * Excluded = rejected by a NON-EMPTY allow-list; an empty list excludes
 * nothing. Display predicate only — the capture callback composes the
 * elections directly. iface_row_prefix() is the shared row-prefix
 * election for both iface render paths:
 * hidden 'h' > deselected 'd' > excluded 'x' > scanning 's' > ' '. */
int iface_is_excluded(const sloth_state_t *s, const char *name);
char iface_row_prefix(const sloth_state_t *s, const char *name, int is_scan);

/* ── Key routing: does the active view claim this key over the global
 * view-switch letters? Kept in main.c as a small, centralized table;
 * exposed for direct unit-test coverage of the routing decision. */
int view_claims_key(view_t v, int key);

/* "[key] Name" label for a view — the tab bar and the [?] help card
 * both read this so their key lists can't drift apart. */
const char *view_label(view_t v);

/* ── Device risk scoring — declared here (post-state) so we can name
 * sloth_state_t without a forward decl dance. See src/device_risk.c
 * and roadmap #16 phase 4. */
device_risk_level_t device_risk_score(const device_t *d,
                                      const sloth_state_t *s,
                                      int *signals);

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
    /* Retune sloth's own monitor-mode capture interface to freq_mhz
     * (issue #22, gated behind --hop; see MISSION §2). Returns 0 on
     * success, -1 if unsupported on this platform / build or the retune
     * failed. The ONLY kernel-state write in the vtable. */
    int  (*set_channel)(const char *iface, int freq_mhz);
} platform_ops_t;

extern platform_ops_t g_platform;

#endif /* SLOTH_H */
