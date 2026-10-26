#ifndef SLOTH_H
#define SLOTH_H

#include <stdint.h>
#include <time.h>

/* beacon_ap_t embeds a reg_ie_t (#101). Every header
 * sloth.h pulls in depends on nothing in sloth.h itself; this one
 * needs only <stdint.h>, and the alternative was a second copy of
 * the type. */
#include "reg_ie.h"
#include "reg_6g.h"   /* beacon_ap_t embeds reg_6g_t too (#101 slice B) */
#include "rf_track.h" /* the distance data point rows embed (2026-10-26) */

/* The view and alert-type lists, each generated from its own .def
 * (#117). Re-included here so every file that took view_t or
 * alert_type_t from sloth.h still does; neither depends on anything
 * below. */
#include "sloth_view.h"
#include "sloth_alert.h"

#define SLOTH_VERSION "1.8.5"

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
/* view_t, VIEW_COUNT, view_label() and view_for_key() live in
 * sloth_view.h, generated from sloth_views.def (#117). */

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
    /* SERVER: header, "" = never seen (#106 slice A). UDA 1.0 §1.1.2
     * puts the product name here; CAM_SSDP_DEVICE reads it to tell a
     * camera's Basic:1 root from anything else's. Sticky: a byebye
     * carries no SERVER and must not erase what an alive said. */
    char   server[96];
    /* Per-family source address of the same row (#106 round 2): a USN
     * announced over both 239.255.255.250 and ff02::c (UDA 2.0 §1, Discovery)
     * keeps one address per family, so a join by IP does not follow
     * whichever family spoke last. ip[] stays the latest source. */
    char   ip4[46];
    time_t ip4_seen;
    char   ip6[46];
    time_t ip6_seen;
} ssdp_device_t;

/* ── WS-Discovery / ONVIF devices (#106 slice 1) ──────────
 * Passive observation of UDP/3702 multicast discovery traffic.
 * sloth sends nothing here: it only reads the Hello / Bye /
 * ProbeMatches / ResolveMatches a device already broadcasts to
 * announce itself (OASIS WS-Discovery 1.1, 2009-07-01). */
#define MAX_ONVIF_DEVICES 32

typedef struct {
    char   ip[46];         /* source IP of the announcing device    */
    char   uuid[48];       /* EndpointReference, "urn:uuid:..." or ""*/
    char   types[96];      /* d:Types content, e.g. "dn:NetworkVideoTransmitter" */
    char   scopes[192];    /* d:Scopes content, space-separated onvif:// URIs */
    char   xaddrs[160];    /* d:XAddrs content, device service URL  */
    char   kind[16];       /* "Hello", "Bye", "ProbeMatch", "ResolveMatch" */
    int    is_camera;      /* 1 if Types names a NetworkVideoTransmitter */
    time_t last_seen;
    /* Per-family source address (#106 round 2). WS-Discovery runs on
     * 239.255.255.250 and ff02::c (WS-Discovery 1.1 §2.4), and a row is
     * keyed by EndpointReference, so one camera's Hellos arrive from
     * both an IPv4 and an IPv6 source. ip[] is the latest; these keep
     * one per family so the device join does not flap between them. */
    char   ip4[46];
    time_t ip4_seen;
    char   ip6[46];
    time_t ip6_seen;
} onvif_device_t;

/* ── RTSP stream exposure (#106 slice B) ─────────────────
 * One row per (server IP, server port, Request-URI path) whose
 * DESCRIBE sloth saw answered (RFC 2326 §10.2, RFC 7826 §13.2).
 * Counts only: no Authorization value, no URL userinfo and no
 * credential-shaped query is ever copied into a row — a request
 * carrying any of those is either counted as authenticated (header
 * present) or not tracked at all (credential in the URL). The
 * cleartext_creds.h guardrail applies here unchanged. */
#define MAX_RTSP_STREAMS 32
#define RTSP_PATH_LEN    128

typedef struct {
    char     server[46];       /* responder IP                           */
    uint16_t port;             /* responder TCP port (554, 8554)         */
    char     path[RTSP_PATH_LEN]; /* abs_path, query/fragment stripped   */
    char     client[46];       /* last requester whose DESCRIBE was answered */
    uint32_t anon_ok;          /* 200 to a DESCRIBE with no Authorization,
                                * on a connection that had no 401 before */
    uint32_t auth_ok;          /* 200 to a DESCRIBE that carried one, or
                                * followed a 401 on the same connection  */
    uint32_t challenged;       /* 401 to a DESCRIBE                      */
    char     auth_scheme[16];  /* first token of the last WWW-Authenticate */
    uint8_t  sdp;              /* a 200 named Content-Type application/sdp */
    time_t   first_seen;
    time_t   last_seen;
} rtsp_stream_t;

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
    /* Option 55 Parameter Request List and option 60 Vendor Class
     * Identifier (RFC 2132 §9.8, §9.13) from this client's last message
     * that carried them (#155). Display-only evidence: no table maps
     * either to a device class, because no licence-clean source cites
     * one per row. prl is the option codes in wire order, "1,3,6,15";
     * vci is netstr-filtered (#138), the client chose every byte. */
    char    prl[96];
    char    vci[64];
    time_t  last_seen;
} dhcp_event_t;

/* ── LAN service roles (#155) ───────────────────────────────
 * Addresses seen acting as a DHCP server or a DNS responder, keyed by
 * IP. Router-role evidence for the device class: a camera does neither.
 *
 *   LAN_ROLE_DHCP_REPLY  a BOOTREPLY (op 2) from UDP 67 with this source
 *                        (RFC 2131 §4.1: the server port)
 *   LAN_ROLE_DHCP_SID    this address named in option 54 Server
 *                        Identifier (RFC 2132 §9.7)
 *   LAN_ROLE_DNS         a DNS response (QR 1, RFC 1035 §4.1.1) from
 *                        UDP 53 with this source to a LAN client
 *
 * dns_clients counts distinct LAN destinations, saturating at
 * LAN_ROLE_DNS_CLIENTS: the veto asks "two or more", never "how many". */
#define MAX_LAN_ROLES         32
#define LAN_ROLE_DNS_CLIENTS   4

#define LAN_ROLE_DHCP_REPLY (1 << 0)
#define LAN_ROLE_DHCP_SID   (1 << 1)
#define LAN_ROLE_DNS        (1 << 2)

typedef struct {
    char    ip[46];
    int     roles;                                 /* LAN_ROLE_* */
    char    dns_client[LAN_ROLE_DNS_CLIENTS][46];  /* first distinct ones */
    int     dns_clients;
    time_t  dhcp_seen;        /* newest DHCP evidence, 0 = none */
    time_t  dns_seen;         /* newest DNS response to a LAN client */
    time_t  first_seen;
    time_t  last_seen;
} lan_role_t;

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
    /* First A/AAAA IP, "NXDOMAIN", or "" — or, for a PTR question
     * (#165), the PTR target name. Sized to qname's 63 bytes: a
     * 45-byte cut would clip common provider PTR names
     * ("ec2-203-0-113-25.us-west-2.compute.amazonaws.com" is 48), and
     * a target that does not fit is refused, not cut. */
    char   answer[DNS_NAME_LEN];
    int    is_resp;             /* 0 = query, 1 = response */
    /* 1 when qname holds less than the wire name: cut at 63 bytes, or
     * stopped at a NUL octet inside a label. The stored text is then a
     * PREFIX, and a prefix can end on any suffix: the first 63 bytes of
     * "<43 x a>.control.verkada.com.evil.example" read as a Verkada
     * hostname. A suffix-matching consumer must skip these rows. */
    uint8_t qname_trunc;
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
/* A camera-discovery row (WS-Discovery, mDNS, SSDP, RTSP) joined to
 * this record by IP (#106 round 2). A record with only this bit and an
 * all-zero MAC is a camera sloth heard announce itself but never saw a
 * link-layer address for: the IP is then its only key. */
#define DEV_SRC_CAMERA  (1 << 6)

/* ── Camera identity on the device record (#106 round 2) ──
 *
 * Which of the camera rules' inputs were seen for this device, joined
 * only on a key sloth actually observes: the same IP for the LAN-side
 * signals, the same MAC (BSSID) for the beacon-side ones. A setup
 * SoftAP's BSSID is never joined to a LAN IP — nothing on the air ties
 * the two, so the camera behind a setup AP and the same camera on the
 * LAN are two records. One bit per rule, named after it. */
#define CAM_SIG_WS_DISCOVERY  (1 << 0)  /* CAM_WS_DISCOVERY: ONVIF NVT */
#define CAM_SIG_SETUP_SSID    (1 << 1)  /* CAM_SETUP_SSID: beacon SSID  */
#define CAM_SIG_MDNS_SERVICE  (1 << 2)  /* CAM_MDNS_SERVICE             */
#define CAM_SIG_SSDP_DEVICE   (1 << 3)  /* CAM_SSDP_DEVICE              */
#define CAM_SIG_SETUP_OUI     (1 << 4)  /* CAM_SETUP_OUI: beacon BSSID  */
#define CAM_SIG_RTSP_UNAUTH   (1 << 5)  /* CAM_RTSP_UNAUTH              */
#define CAM_SIG_COUNT         6

/* What the device class rests on. CAMERA: the device named its own
 * class — an ONVIF NetworkVideoTransmitter, UPnP DigitalSecurityCamera:1,
 * a camera DNS-SD service type, a camera vendor's documented setup SSID.
 * CAMERA_VENDOR: only an address block or a SERVER product token ties it
 * to a camera maker, and the class itself was not observed. Either one
 * corroborates; neither confirms (#145 ruling 2). RTSP alone sets no
 * class: it is a protocol, served by NVRs and media servers too. */
typedef enum {
    DEV_CLASS_UNKNOWN       = 0,
    DEV_CLASS_CAMERA_VENDOR = 1,
    DEV_CLASS_CAMERA        = 2,
    /* #155: a mixed-vendor OUI (Ubiquiti, TP-Link, Wyze) on a record
     * seen in a router role (CAM_VETO_*) with no camera evidence. Last
     * and not ordered with the two above: it is a verdict against, not
     * a stronger "for", so nothing may MAX() it against them. */
    DEV_CLASS_NOT_CAMERA    = 3,
} device_class_t;

/* ── Behavioural evidence and router-role vetoes (#155) ──
 *
 * What camera_join.c's classifier scored for a record, and the
 * router-role observations that veto a mixed-vendor OUI. Weights are in
 * camera_join.c beside their sources; only RTSP_SDP decides a class
 * (RFC 2326 §10.2), the rest are shown. Nothing here was solicited:
 * every bit is a frame some other host sent. */
#define CAM_EV_MIXED_OUI    (1 << 0)  /* +1: Ubiquiti / TP-Link / Wyze MA-L */
#define CAM_EV_RTSP_SDP     (1 << 1)  /* +2: DESCRIBE 200, application/sdp  */
#define CAM_EV_RTSP_SERVER  (1 << 2)  /* +1: answered DESCRIBE, no SDP seen */
#define CAM_EV_MDNS_RTSP    (1 << 3)  /* +1: advertises _rtsp (a protocol)  */
#define CAM_EV_COUNT        4

#define CAM_VETO_DHCP_SERVER   (1 << 0)  /* RFC 2131 §4.1 / RFC 2132 §9.7 */
#define CAM_VETO_SENDS_RA      (1 << 1)  /* RFC 4861 §4.2, lifetime > 0   */
#define CAM_VETO_DNS_RESPONDER (1 << 2)  /* answers >= 2 LAN clients      */
#define CAM_VETO_COUNT         3

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
    /* Camera identity (#106 round 2), from src/camera_join.c. Vendor
     * and model are what the device or its address block said, filtered
     * to printable ASCII: model comes from the ONVIF name / hardware
     * scopes, which the camera chooses. setup_mode is 1 only on a
     * BSSID record whose SSID is a camera vendor's documented setup
     * SSID — the advertisement, not the provisioning state. */
    device_class_t device_class;
    char    camera_vendor[32];
    char    camera_model[48];
    int     setup_mode;
    int     cam_signal_mask;            /* CAM_SIG_* */
    time_t  cam_seen[CAM_SIG_COUNT];    /* newest source row per signal */
    /* #155 classifier output. cam_conflict is 1 when camera evidence
     * (a self-declaration, or the RTSP_SDP score) met a router-role
     * veto: shown, never resolved - a scored-only record then stays
     * DEV_CLASS_UNKNOWN, a self-declared one keeps its class. dhcp_prl
     * and dhcp_vci are the client's DHCP options 55 / 60 (dhcp_event_t),
     * display-only. */
    int     cam_score;
    int     cam_evidence;               /* CAM_EV_*   */
    int     cam_vetoes;                 /* CAM_VETO_* */
    int     cam_conflict;
    char    dhcp_prl[96];
    char    dhcp_vci[64];
    /* Copied from the beacon or probe row signal_dbm came from, the same
     * last-writer rule; invalid for a record with no monitor-mode row. */
    rf_track_t dist;
} device_t;

/* Human-readable bucket name for the alerts view / JSONL. */
const char *device_risk_label(device_risk_level_t l);

/* device_risk_score() is declared alongside iface_is_hidden() below,
 * after sloth_state_t is defined. */

/* ── Alerts ─────────────────────────────────────────────── */
#define MAX_ALERTS         128
#define ALERT_TITLE_LEN     20
/* Holds the longest rule detail incl. two IPv6 addrs. Raised 256 → 320
 * in #89 slice 3: the same-security evil-twin detail was calibrated to
 * land at exactly 255 bytes worst case (SSID + two BSSIDs + cipher +
 * confidence + the longest `reason` + all three evidence notes + a BTM
 * steer note), so adding the ` [class=… wired=…]` axes pushed it over
 * and gcc's -Wformat-truncation caught it.
 *
 * Grown rather than trading a field away, because the field that would
 * have been dropped is the one slice 3 exists to add — and truncating
 * the tail of a twin detail silently removes `wired=?`, which is the
 * single statement that stops a reader assuming sloth checked the wire.
 * Cost is 64 bytes × MAX_ALERTS in the engine and the same again in the
 * snapshot, ~16 KB. `detail` is a variable-length string everywhere it
 * is exported (JSONL, the `--db` TEXT column), so no consumer contract
 * moves with it. */
#define ALERT_DETAIL_LEN   320
#define ALERT_KEY_LEN      192   /* dedup id; worst case is rule_cleartext_cred:
                                  * two 45-char IPv6 + port + proto + 63-char user = 184 */
#define ALERT_NXDOMAIN_WINDOW_S  60   /* sliding window for NXDOMAIN-burst rule */
#define ALERT_NXDOMAIN_THRESH    10   /* NXDOMAINs from one src to trigger */

/* Evidence-ring event IDs an alert may cite (#92). The ring is keyed by
 * ID and nothing else, so an alert that carries IDs can have its own
 * frames pulled back out byte-exact — the retrieval path a wireless
 * detection with no IP match otherwise has no way to reach.
 *
 * Eight because the field is a sample a reader can judge the finding
 * from, not an archive of it: a deauth flood is thousands of frames and
 * the ring holds as many as its budget allows regardless. */
#define ALERT_EVIDENCE_IDS   8

/* ── Incident lifecycle (#98) ────────────────────────────────
 * Both durations run on CLOCK_MONOTONIC (the #88 seam in
 * flood_window.h); an NTP step must not resolve a live incident or
 * hold a dead one open. Wall clock is evidence only. */
#define ALERT_RESOLVE_AFTER_S   300
/* Quiet period after which a key that no rule re-asserted is declared
 * resolved. 300 s because every rule re-evaluates from retained state
 * once per poll (~1 Hz), so five minutes of silence means the evidence
 * itself aged out of the source ring — and it matches
 * JSONL_HEARTBEAT_SECS, so "is this incident still live?" has the same
 * horizon as every other entity in the stream. */
#define ALERT_UPDATE_MIN_S       60
/* Floor between two `alert.update` events on one incident. A rule whose
 * detail carries a live counter re-renders it every poll; without a
 * floor that is one event per tick, which is the thing #98 exists to
 * stop. Severity transitions are never throttled — that is what
 * consumers page on. */
#define ALERT_RESOLVE_AFTER_MS  ((uint64_t)ALERT_RESOLVE_AFTER_S * 1000u)
#define ALERT_UPDATE_MIN_MS     ((uint64_t)ALERT_UPDATE_MIN_S    * 1000u)
#define ALERT_INCIDENT_ID_LEN    17   /* 16 hex chars + NUL */
#define ALERT_EVENT_ID_LEN       23   /* "<incident>-<4-digit seq>" + NUL */
#define ALERT_PCAP_PATH_LEN     256   /* see alert_t.pcap_path */

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

/* alert_type_t, ALERT_TYPE_COUNT, alert_technique() and alert_type_name()
 * live in sloth_alert.h, generated from sloth_alerts.def (#117). */

typedef struct {
    alert_type_t type;
    alert_sev_t  sev;
    char         title[ALERT_TITLE_LEN];
    char         detail[ALERT_DETAIL_LEN];
    char         key[ALERT_KEY_LEN];      /* dedup id (type:identifier) */
    int          count;                   /* alias of `evaluations` (#98) —
                                           * rule ticks, not incidents. Kept
                                           * because the TUI, the --db `alerts`
                                           * table and JSONL consumers read it. */
    /* The *finding's* first sighting: the key's earliest incident the
     * engine's side table remembers (#112, every reopen since #170).
     * The incident's own start is first_detected. */
    time_t       first_seen;
    time_t       last_seen;               /* == last_evaluated */
    /* Optional pcap export criteria — set by rules that have a concrete
     * (ip[, port]) the alert is *about*. Empty for rules where the alert
     * is broader than a single flow. */
    char         match_ip[46];
    uint16_t     match_port;              /* 0 = any port */
    /* pcap_dumped is set only once export has nothing left to do for
     * this incident — it wrote evidence, or genuinely no packet in the
     * ring ever matched. It is deliberately NOT set on a failed write
     * (#92): a disk-full or permission error is transient the same way
     * jsonl.c's is, so dump_new_alert_pcaps() retries next tick instead
     * of losing the evidence for good. pcap_write_failures counts those
     * attempts; pcap_path is the exported file once one exists.
     *
     * Two exporters fill these, chosen per incident (#92 slice 1): an
     * alert citing evidence-ring frames (evidence_id_count > 0) goes to
     * evidence_export_pcap() under --collect-handshakes + --eapol-dir;
     * otherwise one with a match_ip goes to alert_pcap_dump() under
     * --pcap-dir. Same fields, same severity floor, same per-key
     * cooldown — one "where are this incident's frames" answer.
     *
     * ALERT_PCAP_PATH_LEN holds either export directory (both pinned as
     * 256-byte strings) plus a realistic name. It was 80 until the
     * evidence names (incident + event ID + kind, ~60 bytes) arrived:
     * at 80, any directory over ~20 characters truncated the path into
     * one that names nothing. A path that still does not fit is
     * recorded as the bare file name, never as a truncated path. */
    int          pcap_dumped;
    int          pcap_write_failures;
    char         pcap_path[ALERT_PCAP_PATH_LEN];
    /* MITRE ATT&CK technique ID (e.g. "T1110.001") — populated from a
     * fixed lookup on alert_type by fire(). Empty for alerts that
     * describe operator/host posture rather than an adversary
     * technique (e.g. NO_MONITOR_MODE). */
    char         technique[16];
    /* Evidence-ring event IDs this incident cites, oldest first (#92).
     * Empty for every rule that has no frames to cite. Filled by the
     * no-IP wireless rules whose triggering frames are monitor frames;
     * docs/wiki/pcap-export.md § Which alerts cite frames is the list,
     * kept there rather than here so this comment cannot go stale the
     * way its "only the deauth-flood family" predecessor did.
     *
     * Stamped on the alert rather than looked up at read time so the
     * citations exist at the moment the incident opens, inside
     * fire_inv(), rather than being bolted on after.
     *
     * Exported as `evidence_count` + `evidence_id_N` on both the legacy
     * `alert` record and the `alert.*` lifecycle events (jsonl.c's
     * emit_evidence(), additive, omitted whenever evidence_id_count is
     * 0). Two earlier versions of this comment each overclaimed what
     * reached a consumer — one said the lifecycle events "carry the
     * citations" when no emitter did, the next said "no emitter does"
     * after that was fixed — so this one names the function rather than
     * describing it, to make the next overclaim a one-grep check.
     *
     * Refreshed on each evaluation so a running incident
     * cites IDs the ring still holds: the ring evicts oldest-first, so
     * the IDs an hours-old flood opened with have long since stopped
     * resolving. An ID whose record is gone reads as absent from
     * evidence_ring_get(), never as a different frame, so a stale
     * citation misleads nobody — it just retrieves nothing. */
    uint64_t     evidence_ids[ALERT_EVIDENCE_IDS];
    uint8_t      evidence_id_count;

    /* How sure sloth is that the finding is real, in percent. Zero
     * means the rule reported no confidence — most rules assert a
     * condition they observed directly and have nothing to qualify.
     *
     * This is a *separate axis from `sev`* (#89). Severity is how bad
     * the finding would be if it were true; confidence is how likely it
     * is to be true. Collapsing them is what let an evil-twin rule
     * report an uncorroborated RF coincidence at the same volume as an
     * observed attack. An operator triaging needs both numbers. */
    uint8_t      confidence;

    /* Content hash of the approved inventory this finding consulted,
     * or empty (#89 slice 2). 16 hex characters; the width is
     * INV_HASH_LEN in src/inventory.h, and
     * tests/test_alerts.c :: test_inventory_hash_stamped_on_consulting_alerts
     * pins the two together — sloth.h is the shared header and does not
     * include module headers from src/.
     *
     * Set only by the rules that actually read the inventory. Stamping
     * every alert would claim the anchor backed findings it never
     * touched, which is the opposite of the traceability this field
     * exists for: a finding in an archive must name the exact file that
     * produced it, and the human-readable `version` label cannot do
     * that because two files may both claim one. */
    char         inventory[17];

    /* What kind of AP a paired finding is about, and whether it is
     * attached to the wired network (#89 slice 3). Zero on every rule
     * that is not about an AP pair — the `EVIL_TWIN` family is the only
     * producer today, and both fields are omitted from the exports when
     * zero, the same way `confidence` and `inventory` are.
     *
     * `ap_class` is a twin_class_t (src/alerts.h). `wired_attach` is a
     * wired_attach_t (src/wired_attach.h) and stays UNKNOWN unless a
     * correlator that can see the wire is registered: RF cannot
     * establish wired attachment, so it gets its own axis rather than a
     * fourth class value, and no rule in src/alerts/ can set it.
     *
     * Plain uint8_t for the same reason as `inventory` above — sloth.h
     * does not include module headers from src/. */
    uint8_t      ap_class;
    uint8_t      wired_attach;

    /* Provenance of the tool signature behind this finding (#90) —
     * copied from the winning sloth_tool_sig_t row (src/tool_fingerprint.h)
     * so an export names *which* signature, *which* revision of it, and
     * whether anyone has ever validated it against a capture. A
     * "medium confidence" label alone cannot say the last of those.
     *
     * `sig_id` empty means no tool matched, and all four are then
     * omitted from the exports — present only on findings a signature
     * actually shaped, same rule as `inventory`. `KARMA_AP` is the only
     * producer today. Plain strings because sloth.h does not include
     * module headers from src/; the widths fit every shipped row and
     * tests/test_tool_fingerprint.c pins that. */
    char         sig_id[24];
    char         sig_version[24];
    char         sig_evidence[160];
    uint8_t      sig_validated;    /* 1 only for a capture-backed row */

    /* ── Incident lifecycle (#98) ────────────────────────────
     * One *incident* is one continuous run of a dedup key: it opens on
     * the first fire, carries an `incident_id` through every
     * create/update/escalate event, and closes with exactly one
     * resolve. A key that fires again after its resolve opens a new
     * incident with a new id — the engine slot is reused, the identity
     * is not. */
    char         incident_id[ALERT_INCIDENT_ID_LEN];
    uint32_t     event_seq;        /* events emitted for this incident */
    uint32_t     evaluations;      /* fire() calls — rule ticks */
    uint32_t     observations;     /* fire() calls whose evidence differed
                                    * from the previous one. A retained
                                    * condition re-evaluated unchanged does
                                    * not move this. */
    time_t       first_detected;   /* incident opened (wall) */
    time_t       last_evaluated;   /* most recent rule tick (wall) */
    time_t       first_observed;   /* first counted observation (wall) */
    time_t       last_observed;    /* most recent counted observation (wall) */
    uint64_t     last_eval_ms;     /* CLOCK_MONOTONIC — drives expiry */
    uint64_t     last_event_ms;    /* CLOCK_MONOTONIC — drives the update floor */
    uint64_t     detail_sig;       /* FNV-1a of the last emitted detail */
    int          resolved;         /* 1 once alert.resolve has been emitted */
    /* Earlier incidents on this key, as far as the engine's side table
     * remembers it (#112): 0 for the first, 1 for the first re-open,
     * and so on. Carried in src/alerts/engine.c's g_side, which outlives the
     * engine slot. Exported as `reopen_count` on the `alert.*` events,
     * omitted at 0. A count, not a guarantee: the side table is LRU
     * bounded, so a key quiet for long enough under pressure starts
     * again at 0. */
    uint32_t     reopen_count;
} alert_t;

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
    /* 1 when host holds less than the SNI (cut at 63 bytes, or at a
     * NUL octet) — a prefix, so a suffix match on it proves nothing
     * (see dns_log_entry_t.qname_trunc). */
    uint8_t host_trunc;
    time_t ts;
} tls_log_entry_t;

/* ── HTTP request log ───────────────────────────────────── */
#define MAX_HTTP_LOG 256

/* Bounded response body (#71). 512 bytes covers every connectivity
 * check sentinel with room to spare — Apple's is ~90, Microsoft's 22,
 * Firefox's 8 — while a page large enough to matter is one we are not
 * going to hold anyway. The bound exists so a large download cannot be
 * buffered, not to be generous. */
#define HTTP_RESP_BODY_MAX 512

typedef struct {
    char   src[46];        /* source IP */
    char   dst[46];        /* destination IP — the flow's other end */
    uint16_t src_port;
    uint16_t dst_port;
    char   method[10];     /* GET POST PUT etc */
    char   host[64];       /* Host header value */
    char   path[128];      /* request URI */
    char   user_agent[64]; /* User-Agent header, truncated */
    /* ── Response side (#71) ──────────────────────────────
     *
     * is_response distinguishes a parsed response from a request; the
     * two share this struct because they share a flow and pairing them
     * is the point.
     *
     * body_complete is the field that matters most, and the reason this
     * is not simply "capture the body". sloth does not reassemble TCP,
     * so a body larger than the segment carrying the status line
     * arrives truncated. A consumer doing a byte-exact comparison must
     * be able to tell **"different" from "incomplete"** — a partial body
     * that happens to differ is not evidence of anything. */
    int      is_response;
    uint16_t status;             /* 200, 204, 302 … 0 for a request */
    int      content_length;     /* -1 when the header was absent */
    int      chunked;            /* Transfer-Encoding: chunked */
    int      body_complete;      /* the whole declared body is here */
    int      resp_body_len;
    char     resp_body[HTTP_RESP_BODY_MAX];
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

/* ── Sliding flood window (#88) ─────────────────────────── */
/* The most recent counted frame times, on the monotonic clock. K frames
 * in any W-second window needs only the last K times, so the cap is the
 * largest threshold any detector uses (PROBE_FLOOD_FRAMES = 30). See
 * src/flood_window.h. */
#define FLOOD_WIN_CAP 32
typedef struct {
    uint64_t ts_ms[FLOOD_WIN_CAP];  /* ring, monotonic ms */
    uint8_t  head;                  /* next write slot */
    uint8_t  n;                     /* valid slots */
    uint8_t  tripped;               /* threshold met at least once */
    uint64_t trip_ms;               /* monotonic ms it was last met */
} flood_window_t;

/* ── Deauth / Disassoc events ───────────────────────────── */
#define MAX_DEAUTH_ENTRIES    128
#define MAX_DEAUTH_VICTIMS    128
/* Evidence-ring event IDs kept per (BSSID, victim) aggregate (#92) —
 * the most recent distinct frames, which is what the alert cites.
 * Defined as ALERT_EVIDENCE_IDS rather than its own 8 so the hand-off
 * in rule_deauth_flood() cannot silently truncate. */
#define DEAUTH_EVIDENCE_IDS    ALERT_EVIDENCE_IDS
#define DEAUTH_AGE_SECS        60   /* drop rows idle this long (monotonic) */
/* Flood = at least DEAUTH_FLOOD_THRESH distinct frames inside any
 * DEAUTH_FLOOD_WIN_SECS-second sliding window (#88). Retransmissions
 * (Retry=1 repeating the previous sequence number) are not distinct:
 * the receiver's duplicate filter discards them (IEEE 802.11-2020
 * 10.3.2.14), so they cannot add impact. */
#define DEAUTH_FLOOD_THRESH     5
#define DEAUTH_FLOOD_WIN_SECS   5
/* Flood status decays this long after the threshold was last met,
 * whether or not another frame arrives. Longer than the window so a
 * 1 s poll tick cannot miss a short burst, short enough that a flood
 * which stopped stops being reported as current. */
#define DEAUTH_FLOOD_HOLD_SECS 10
/* Beacon-flood (mdk3/mdk4): a legit RF neighbourhood gains new APs slowly;
 * a flood injects dozens of brand-new BSSIDs in seconds. */
#define BEACON_FLOOD_THRESH    40   /* distinct new BSSIDs in the window */
#define BEACON_FLOOD_WIN_SECS  10
/* Auth-request flood: a legit AP fields the odd auth frame (roam,
 * reconnect); an mdk-style flood sprays dozens per second at one BSSID. */
#define AUTH_FLOOD_THRESH      30   /* auth frames to one BSSID in the window */
#define AUTH_FLOOD_WIN_SECS     5
/* Association-request flood (#60) — the missing member of the flood set.
 * Issue #60 specifies "> 20 per BSSID per 60 s", so 21 is the floor. */
#define ASSOC_FLOOD_THRESH     21
#define ASSOC_FLOOD_WIN_SECS   60
/* BTM-forcing (#59). Not a flood — the rate is low by design, because
 * one BSS Transition Management Request with Disassociation Imminent
 * set is enough to move a client. Issue #59 specifies "> N per (BSSID,
 * STA) per 60 s, default N = 3", so 4 is the floor.
 *
 * The window is per *pair*, not per BSSID: an AP steering many clients
 * is load balancing, and an AP steering one client four times in a
 * minute is not taking no for an answer. */
#define BTM_ABUSE_THRESH        4
#define BTM_ABUSE_WIN_SECS     60

/* One observation stream: frames keyed (BSSID, transmitter address,
 * receiver address, subtype). The addresses are what the frame claims —
 * a transmitter address is trivially spoofed and never establishes who
 * actually sent it. */
typedef struct {
    uint8_t  src[6];     /* Address 2 (TA) as claimed */
    uint8_t  dst[6];     /* Address 1 (RA); ff:ff:ff:ff:ff:ff = broadcast */
    uint8_t  bssid[6];   /* Address 3 */
    uint16_t reason;     /* 802.11 reason code; meaningful only if reason_valid */
    uint8_t  subtype;    /* 10=disassoc 12=deauth */
    time_t   first_seen; /* wall clock, evidence only */
    time_t   last_seen;
    int      count;      /* frames observed, retransmissions included */
    int      flood;      /* this stream alone met the window threshold,
                            within DEAUTH_FLOOD_HOLD_SECS (decays) */
    /* #88 additions */
    uint8_t  fc_flags;       /* Frame Control byte 1 of the latest frame */
    uint8_t  reason_valid;   /* 1 = latest reason decoded from a cleartext body */
    int      retries;        /* of count: Retry=1 repeats of the previous seq */
    int      protected_count;/* of count: Protected Frame bit set (PMF) */
    int      truncated_count;/* of count: body too short to hold a reason */
    int      win_count;      /* distinct frames in the trailing window, at snapshot */
    time_t   flood_last;     /* wall time the threshold was last met; 0 = never */
} deauth_event_t;

/* Impact aggregate (#88): every distinct deauth/disassoc frame naming
 * one victim inside one BSS, whatever transmitter address it claims and
 * whichever direction it travels. A spoofing tool alternates AP→STA and
 * STA→AP; a per-stream count splits that attack in half, this one does
 * not. The victim is Address 1 unless Address 1 is the BSSID (a frame
 * "from" the station to its AP), in which case it is Address 2. A group
 * Address 1 stays as-is: it names every station of the BSS.
 *
 * This is an observed-frame count. Whether any station accepted the
 * frames — a PMF-associated station drops unprotected ones — is not
 * something a passive receiver sees. */
typedef struct {
    uint8_t  bssid[6];
    uint8_t  victim[6];
    time_t   first_seen;
    time_t   last_seen;
    int      frames;         /* distinct frames observed (retransmissions excluded) */
    int      streams;        /* observation rows feeding this aggregate, at snapshot */
    uint16_t reason;         /* latest decoded reason; valid only if reason_valid */
    uint8_t  reason_valid;
    int      protected_count;
    int      win_count;      /* distinct frames in the trailing window, at snapshot */
    int      peak_win;       /* most distinct frames seen inside one window */
    int      flood;          /* threshold met within DEAUTH_FLOOD_HOLD_SECS (decays) */
    time_t   flood_last;     /* wall time the threshold was last met; 0 = never */
    /* Evidence-ring event IDs for this aggregate's most recent distinct
     * frames, oldest first (#92). Retransmissions contribute none —
     * they are not distinct frames and the row does not count them.
     * Written by deauth_snapshot(); see src/deauth_snoop.c for why the
     * newest rather than the first. */
    uint64_t evidence_ids[DEAUTH_EVIDENCE_IDS];
    int      evidence_id_count;
} deauth_victim_t;

/* ── Beacon APs (passively observed 802.11 access points) ── */
#define MAX_BEACON_APS  256
#define WPS_LOCK_RING   8   /* AP-Setup-Locked transitions kept per AP (#82) */
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
    /* IE-ordering fingerprint (#77): FNV-1a over the identity of each
     * element in beacon order — Element ID, plus the extension ID for
     * tag 255 and OUI + OUI type for tag 221 — bodies excluded. Names
     * the IE-emitting stack rather than the network. 0 = not decoded
     * (no elements, or the frame overran). See beacon_snoop.c. */
    uint32_t ie_order_hash;
    uint16_t ie_order_count;       /* elements that entered the hash */
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

/* ── Beacon TBTT jitter accumulator (#77) ────────────────────
 *
 * Rolling variance, per BSSID, of the residual between the TSF delta
 * observed across two beacons and the nearest whole multiple of the
 * beacon interval.
 *
 * An AP schedules its beacons at TBTTs that are exact multiples of the
 * Beacon Interval (IEEE 802.11-2020 §11.1.3; Beacon Interval is in TU,
 * §9.4.1.3, 1 TU = 1024 µs) and stamps each beacon body with its own
 * TSF timer value at transmission (beacon frame body order 1,
 * §9.3.3.2; field §9.4.1.10). The residual is therefore the AP's own
 * medium-access deferral, measured on the *transmitter's* clock — it
 * survives a receiver with no radiotap TSFT, a hopping radio, and lost
 * frames, none of which a receive-timestamp measure does.
 *
 * The sums are signed because the residual is. The baseline beacon
 * carried its own unknown deferral d0, so every later residual is
 * (d_n − d0); that constant offset cancels in the standard deviation,
 * which is why the stddev is the quantity worth publishing and the
 * mean is not.
 *
 * No verdict lives here. This is the measurement only — see
 * docs/views/beacons.md for why no threshold ships with it. */
#define TBTT_JITTER_MIN_SAMPLES 2
#define TBTT_JITTER_MAX_SAMPLES 1024

typedef struct {
    uint64_t last_tsf;     /* baseline the next residual is measured from */
    uint16_t bi_tu;        /* beacon interval the baseline was taken at */
    uint8_t  have_last;    /* baseline on file — last_tsf == 0 is legal */
    uint32_t samples;
    int64_t  sum_us;       /* Σ residual */
    uint64_t sumsq_us;     /* Σ residual²  */
    uint32_t resets;       /* baselines discarded: TSF reset / gap / new BI */
} ap_beacon_timing_t;

/* ── Research-corpus coverage (#73 slice 3) ──────────────────
 *
 * One row per alert kind that has fired this session, with what the
 * corpus has to say about it. The view is a companion to VIEW_ALERTS
 * and answers the question that view raises: *why should I believe
 * this?*
 *
 * Rows with zero documents are the point, not a gap to hide. An
 * operator deciding whether to act on a CRIT needs to know whether the
 * threshold behind it has a cited basis or is a guess — which is the
 * argument agents/AGENTS.md makes for citing sources at all. */
#define MAX_RESEARCH_COV   32
#define MAX_RESEARCH_DOCS   8

typedef struct {
    char title[80];
    char source_url[128];
    char retrieved[16];
} research_doc_t;

typedef struct {
    char kind[48];         /* the ALERT_TYPE_* enum name */
    char label[24];        /* the alert's display title  */
    int  severity;         /* highest severity seen for this kind */
    int  fired;            /* occurrences this session */
    int  doc_count;        /* rows written to docs[] */
    /* This kind cites no external source *by design* — alert_technique()
     * returns "" for it, meaning sloth is reporting its own operational
     * state rather than detecting an adversary. Distinct from an
     * uncited detector, which is a gap. Without the distinction the
     * coverage number can never reach its own target and stops meaning
     * anything. */
    int  no_basis;
    int  docs_truncated;   /* the corpus had more than MAX_RESEARCH_DOCS */
    research_doc_t docs[MAX_RESEARCH_DOCS];
} research_cov_t;

/* ── FragAttacks per-BSS view snapshot (#75 slice 5) ──
 *
 * Mirrors frag_bss_t (src/fragattack.h) rather than reusing it
 * directly — the same decoupling every other WiFi-SIGINT view already
 * has from its detector's internal table, so a change to the
 * detector's bookkeeping can't silently reshape what the view renders.
 * 64 mirrors FRAG_MAX_BSS in fragattack.h. */
#define MAX_FRAG_ROWS 64

typedef struct {
    uint8_t bssid[6];
    uint32_t protected_frames;    /* stations witnessed installing a key */
    uint32_t plaintext_unicast;   /* FRAG_PLAINTEXT  — CVE-2020-26140/-26143 */
    uint32_t plaintext_bcast_frag;/* FRAG_BCAST      — CVE-2020-26145 */
    uint32_t cache_poison;        /* FRAG_CACHE      — CVE-2020-24586 */
    uint32_t mixed_protect;       /* FRAG_MIXED      — CVE-2020-26147 */
    uint32_t amsdu_flip;          /* FRAG_AMSDU      — CVE-2020-24588 */
    uint32_t amsdu_eapol_spoof;   /* FRAG_AMSDU_EAPOL — CVE-2020-26144 */
    uint32_t mixed_key;           /* FRAG_MIXKEY     — CVE-2020-24587 */
    uint32_t pn_gap;              /* FRAG_PN_GAP     — CVE-2020-26146 */
    uint32_t eapol_relay;         /* FRAG_EAPOL_RELAY — CVE-2020-26139 */
    uint8_t  last_sa[6];
    uint8_t  last_da[6];
    time_t   last_hit;
} frag_bss_row_t;

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
    /* Machine-readable form of the same suites (#60, #62). The strings
     * above are display-oriented and cap at three AKMs; these do not,
     * which is what makes "PSK and SAE simultaneously" answerable. */
    uint32_t akm_bits;
    uint32_t pairwise_bits;
    /* WPA1 vendor IE (00:50:F2 type 1) seen alongside the RSN IE, and
     * the Wi-Fi Alliance OWE Transition Mode element (50:6F:9A type
     * 0x1C). Both are downgrade lanes an AP advertises about itself. */
    uint8_t  has_wpa1;
    uint8_t  owe_trans;
    /* WPA_DG_* bits — computed per poll from the fields above plus, for
     * the OWE case, the presence of a paired open BSS. */
    uint8_t  downgrade_flags;
    /* In-flight channel switch announced in this AP's beacons (#63).
     * 0 = none pending. The [b] view shows it as CSA->N. */
    uint8_t  pending_csa_channel;
    uint8_t  pending_csa_count;
    /* Operating geometry from the operation IEs (#66). primary_channel
     * is authoritative where the capability-derived `channel` above is
     * best-effort; channel_source names which IE supplied it so a wrong
     * channel is attributable rather than mysterious. */
    uint8_t  primary_channel;
    uint8_t  channel_source;      /* sloth_ch_source_t */
    uint16_t operating_width;     /* sloth_ch_width_t; 0 = not decoded */
    uint8_t  secondary_offset;    /* HT convention: 0 none, 1 above, 3 below */
    uint8_t  center_seg0;         /* channel centre frequency segment 0 */
    uint8_t  center_seg1;         /* segment 1; non-zero only for 80+80/160 */
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
    /* Config Methods bitmap / Device Password ID (#82) — see
     * beacon_snoop.h::beacon_rsn_t for the attribute IDs and why 0
     * means "not observed" for both. Device Password ID 0x0004 means
     * the AP is advertising an active WPS Push-Button session right
     * now; not sticky, so it clears once the beacon stops carrying it. */
    uint16_t wps_config_methods;
    uint16_t wps_device_pwd_id;
    /* AP Setup Locked transition history (#82, wave-6 measurement).
     * Ring of the last WPS_LOCK_RING transitions between *known* lock
     * states with observation timestamps (wps_lock_to[i] is the state
     * entered: 1=unlocked, 2=locked; ring index = n % WPS_LOCK_RING),
     * plus a lifetime completed locked->unlocked cycle count. A
     * Reaver-style brute force trips AP lockout repeatedly, so the
     * sawtooth is attack evidence even when the PIN attempts
     * themselves were missed.
     *
     * The RING ARRAYS — wps_lock_ts[] and wps_lock_to[] — are read only
     * through beacon_snoop.h's wps_lock_history() /
     * wps_lock_cycles_in_window() / wps_lock_dropped(). The modular
     * indexing is not part of the contract: a second module doing its
     * own arithmetic over wps_lock_n is how the lifetime sequence and
     * the slot order drift apart.
     *
     * The two SCALARS are ordinary fields and are read directly, which
     * is why the rule is scoped to the arrays rather than to the group:
     * src/views/beacon.c reads wps_lock_n to decide whether to draw the
     * block at all and wps_lock_cycles to print the lifetime figure,
     * and no accessor exposes the lifetime count. An earlier version of
     * this comment said "read only through" of all four fields, which
     * the same commit's own view code contradicted — an unimplementable
     * rule is worse than none, because the next reader either breaks it
     * or deletes it. ALERT_TYPE_WPS_LOCKOUT_CYCLING (threshold
     * 2026-09-30, configurable) and the WPS ACTIVITY block both go
     * through the accessors for the ring itself. */
    time_t   wps_lock_ts[WPS_LOCK_RING];
    uint8_t  wps_lock_to[WPS_LOCK_RING];
    int      wps_lock_n;        /* lifetime transitions */
    int      wps_lock_cycles;   /* completed locked->unlocked cycles */
    /* WPS vendor-string leakage (#77) — see beacon_snoop.h::beacon_rsn_t
     * for the rationale. Monitor-mode only: like neighbors[] above, this
     * is not mirrored onto wifi_ap_t (the managed-mode scan struct). */
    char     wps_manufacturer[65];
    char     wps_model_name[33];
    char     wps_model_number[33];
    char     wps_serial[33];
    /* Probe responses whose WSC element was merged into this entry
     * (#82). The WSC IE in a probe response is the full one — WSC 2.0
     * puts Manufacturer, Model, Serial and UUID-E there, where many APs'
     * beacons carry only Version / State / Locked — so a non-zero count
     * says the fields above may have come from the probe-response path
     * rather than from a beacon. See beacon_note_probe_resp_ies(). */
    int      wps_probe_resp_n;
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
    time_t   first_seen;       /* set on insert; the posture debounce reads it */
    /* The channel this BSSID was on when the table first heard it
     * (#101 slice A), set once on insert and never updated — `channel`
     * above follows the AP, this does not. The DFS-masking rule reads
     * it: where an AP *started* is the claim, and a later CSA to
     * somewhere else must not rewrite where it came from. 0 = unknown
     * (an entry created with no channel). */
    int      first_seen_channel;
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
    /* Beacon TBTT jitter (#77) — fed from the beacon body's Timestamp
     * field, so it only ever populates on the monitor-mode path. Read
     * it through beacon_tbtt_jitter(); the raw sums are not a figure. */
    ap_beacon_timing_t tbtt;
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
    /* 6 GHz regulatory claims (#101 slice B): the HE 6 GHz Operation
     * Information's Regulatory Info subfield and the Transmit Power
     * Envelope elements, folded in by reg_6g_merge() beside `reg` below
     * and on the same terms — per element, sticky, *_present / count
     * checked before any value is read. */
    reg_6g_t reg6g;
    /* Regulatory envelope this BSSID claims (#101 slice 2) — Country
     * (tag 7), Power Constraint (32) and TPC Report (35) as
     * src/reg_ie.c read them, folded in per element by reg_ie_merge().
     *
     * It lives here rather than in a table of its own because every
     * other per-AP observation does, and a second BSSID-keyed table
     * would age on its own schedule: an entry this table had already
     * evicted could still have a regulatory claim on file, which is
     * exactly the kind of divergence the shared IE walk exists to
     * prevent. The cost is sizeof(reg_ie_t) on all MAX_BEACON_APS
     * entries, paid whether or not the AP ever sends one.
     *
     * The *_present flags are load-bearing for every reader: all-zero
     * means no regulatory element has ever been parsed from this
     * BSSID, which is not the same claim as "no country" or "no power
     * limit". Check the flag before reading the value. */
    reg_ie_t reg;

    /* Evidence-ring citations (#92 slice 4). Two different questions,
     * so two stores:
     *
     *   ev_ids         the newest BEACON_EVIDENCE_IDS beacons heard
     *                  from this BSSID — what the evil-twin family
     *                  cites for each half of a pair. A small ring
     *                  (src/ev_cite.h; read it through
     *                  beacon_ap_evidence(), the head moves), because
     *                  this table is MAX_BEACON_APS entries and a
     *                  beacon arrives ten times a second: the newest
     *                  few are the ones the evidence ring still holds,
     *                  and more would be the same frame again.
     *   ssid_history_ev  the newest frame carrying each distinct
     *                  SSID, parallel to ssid_history[] — what KARMA_AP
     *                  cites, since the finding IS the set of SSIDs one
     *                  radio has advertised. Newest, not first, for the
     *                  src/ev_cite.h reason: the AP outlives the ring.
     *
     * 0 means the capture retained nothing for that frame, or the
     * record came from a path with no frame (nl80211 scan results). */
#define BEACON_EVIDENCE_IDS 4
    uint64_t ev_ids[BEACON_EVIDENCE_IDS];
    uint8_t  ev_n, ev_head;
    uint64_t ssid_history_ev[MAX_AP_SSID_HISTORY];
    /* Distance from signal strength, a data point (src/rf_distance.h):
     * an estimate, never a location, and no rule reads it. */
    rf_track_t dist;
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
    /* Do we actually know which half is the impostor? (#89)
     *
     * 1 only when something other than radio physics said so: an
     * operator-designated BSSID, a tainted BSSID from the deauth chain,
     * or an attacker-tool OUI. 0 means UNATTRIBUTED — the pair is a
     * candidate and `real_bssid`/`twin_bssid` hold it in canonical
     * BSSID order, which is a stable identity for the pair and not a
     * verdict about either half.
     *
     * Before #89 the fallback was "the stronger signal is the impostor",
     * which reads furniture as ownership and gets it backwards in the
     * common case: the operator's own AP is usually the closest radio in
     * the room. Canonical ordering also stabilises the `twin_episodes`
     * primary key, which used to flip — and so insert a second row —
     * whenever the two RSSIs crossed. */
    uint8_t  attributed;
    uint8_t  confidence;             /* percent, matches the alert's (#89) */
    /* What kind of AP this pair is, and whether it is on the wire —
     * two separate axes, deliberately (#89 slice 3).
     *
     * `ap_class` is a twin_class_t (src/alerts.h): impostor / neighbor /
     * declared / unknown. Decidable from RF plus the approved
     * inventory, and a *label* — it never suppresses an episode or
     * moves a confidence.
     *
     * `wired_attach` is a wired_attach_t (src/wired_attach.h) and is
     * UNKNOWN unless a correlator that can see the wire has been
     * registered. RF cannot establish wired attachment: a Pineapple on
     * an LTE uplink and a rogue bridged onto the access VLAN beacon
     * identically. It is a separate field rather than a fourth
     * `ap_class` value precisely so no RF signal can ever set it.
     *
     * Stored as plain uint8_t because sloth.h is the shared header and
     * does not include module headers from src/; the enum values are
     * pinned by tests/test_wired_attach.c and tests/test_twins.c. */
    uint8_t  ap_class;
    uint8_t  wired_attach;
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
    int      pnl_overlap;   /* advertised SSIDs in the union of nearby client PNLs */
    /* Largest count from any *one* station's PNL (#90). pnl_overlap
     * describes the neighbourhood; this is the input to the score,
     * because only one station asking for several of these names is
     * the PineAP Beacon-Response shape. Not persisted — the DB keeps
     * the union and the score it feeds. */
    int      pnl_best;
    int      pnl_jaccard_ppm; /* Jaccard(advertised, PNL-union) in parts-per-million */
    int      ie_uniform;    /* 1 = identical IE fingerprint across all SSIDs (PineAP tell) */
    int      deauth_chain;  /* 1 = shared-victim deauth-then-lure (#90) */
    /* composite: 1 + (pnl_best >= KARMA_PNL_CORROB_MIN ? 2 : 0)
     *              + (ie_uniform ? 1 : 0) + (deauth_chain ? 3 : 0) */
    int      score;
    char     top_ssid[33];  /* most recently advertised SSID */
    /* Tool attribution as the operator reads it — "ESP32 Marauder/med?
     * provisional" for an UNVERIFIED signature, "" when none matched
     * (#90). Rendered by tool_attribution_format(), the same helper the
     * KARMA_AP alert detail uses, so the two cannot disagree. */
    char     tool[48];
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
    /* CVE-2023-52160 evidence (#65). A TLS-in-EAP method (PEAP / TLS /
     * TTLS) that reached EAP-Success without the AP ever presenting a
     * ServerHello or a Certificate means the client authenticated to an
     * unverified server. The AP-side rule above says "this AP offers a
     * weak method"; this says "a client here accepted no server at all".
     *
     * Counts sessions, not frames: one misconfigured client completing
     * one handshake is the finding, and a chatty AP must not inflate it. */
    int      nocert_sessions;      /* TLS-in-EAP successes with no server cert */
    int      nocert_no_hello;      /* subset where no ServerHello was seen either */
    uint8_t  last_nocert_sta[6];   /* most recent client that did it */
    time_t   last_nocert_ts;
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
    int     frame_count;  /* lifetime total; says nothing about rate */
    /* RSSI history for presence classification (#53). Dwell alone
     * cannot separate a resident device from one driving past — the
     * trajectory shape can. See src/presence.h. */
    rssi_ring_t rssi_ring;
    /* Probe-flood window (#88). burst_* describe the densest window at
     * the moment the threshold was last met: burst_frames probe
     * requests whose first and last were burst_span_ms apart. */
    flood_window_t burst_win;
    int      burst_frames;
    uint32_t burst_span_ms;
    int      flood;       /* threshold met within PROBE_FLOOD_HOLD_SECS (decays) */
    time_t   flood_last;  /* wall time it was last met; 0 = never */
    rf_track_t dist;      /* distance data point, src/rf_distance.h; P_tx always assumed */
} probe_client_t;

/* Probe-request flood (#88): at least PROBE_FLOOD_FRAMES requests from
 * one transmitter address inside any PROBE_FLOOD_WIN_SECS-second sliding
 * window — a rate of >= 6/s held across the whole window. A normal
 * client scans in bursts of a few requests per channel per scan and
 * pauses between scans, and a monitor on one channel hears only its
 * share of each scan. */
#define PROBE_FLOOD_FRAMES     30
#define PROBE_FLOOD_WIN_SECS    5
#define PROBE_FLOOD_HOLD_SECS  10

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
    /* 1 when the tier came from an association request rather than a
     * probe (#60). A probe request advertises what the client is
     * willing to say while scanning, and stripped-down probe variants
     * that omit VHT/HE are common; an association request is what it
     * commits to on joining. Same string, better evidence — so the
     * distinction is a flag rather than a second field. */
    int     phy_confirmed;
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

    /* ── Evidence, not verdict (#94) ──────────────────────────
     * The pre-#94 record carried only `gap` and `dt_ms`, and the view
     * turned a small gap into "LIKELY SAME DEVICE". A shared counter
     * position is circumstantial: two independent radios in a dense
     * room land inside any fixed window often enough that an
     * any-pair match needs a score, not a verdict. These fields are
     * what a consumer needs to judge one, and every one of them is
     * additive — no existing field changed meaning. */

    /* Forward modular distance from the earlier MAC's newest seqnum to
     * the later MAC's oldest one. Unlike `gap` (absolute distance) this
     * has a direction: a counter that went *backwards* across the
     * transition is not one radio's counter. */
    int      fwd_gap;

    /* How likely the same-radio hypothesis is, in percent. Capped below
     * 100 by SEQNUM_CORR_CONF_MAX — sloth never observes identity, only
     * a counter that is consistent with it. Same axis as alert_t.confidence
     * (#89): this is "how likely", never "how bad". */
    int      confidence;

    /* The observation window the pair was decided on: earliest and
     * latest frame timestamp across both histories. A consumer reading
     * a correlation out of an archive needs to know it rests on four
     * frames inside six seconds, not on a day of traffic. */
    time_t   window_start;
    time_t   window_end;

    /* Evidence depth per side — history entries actually compared. */
    int      a_hist_n;
    int      b_hist_n;

    /* 1 when the earlier side of the transition is `mac_a`. The pair
     * itself is unordered (either MAC may be seen first); the
     * *transition* has a direction and the score depends on it. */
    int      a_is_earlier;
} seqnum_correlation_t;

/* ── Channel activity summary (derived from beacons + assoc) ─ */
#define MAX_CHAN_ENTRIES   64

typedef struct {
    int     channel;        /* 1..233 — 2.4, 5 and 6 GHz channel numbers
                             * overlap, so this number alone never says
                             * which band; see channel_source below. */
    int     ap_count;       /* APs with a beacon on this channel */
    int     assoc_count;    /* associated STAs on this channel  */
    int8_t  best_signal;    /* strongest signal among APs here  */
    char    top_ssid[33];   /* SSID of the strongest AP         */
    time_t  last_seen;
    /* Set from any contributing AP's channel_source (sloth_ch_source_t)
     * that is CH_SRC_HE_6GHZ, and never un-set once it is — the 6 GHz
     * signal is rarer and more informative than "unknown", so one
     * beacon that carries it settles the row's band for the pass even
     * if another AP sharing this channel *number* reported no source.
     * ap_band_label() is what turns this plus `channel` into a label;
     * see that contract for the real collision this exists to answer.*/
    uint8_t channel_source;
    /* RF quality over the last window (roadmap B3). Retries and FCS
     * failures are the passive signature of interference, a hidden
     * node, or a jammer. -1 means "not enough frames to say", which is
     * a different answer from 0% — a quiet channel is not a clean one. */
    uint32_t frames;
    int      retry_pct;
    int      badfcs_pct;
    /* Observed control-frame volume on this channel (#64). Control
     * frames dominate real utilisation, so without them the QBSS Load
     * IE is the AP's *self-reported* occupancy rather than the measured
     * one. CTS and ACK carry no transmitter address, so they can be
     * attributed to a channel and to nothing finer. */
    uint32_t ctrl_total;
    uint32_t ctrl_rts;
    uint32_t ctrl_cts;
    uint32_t ctrl_ack;
    uint32_t ctrl_blockack;
} channel_summary_t;

/* ── Client ↔ AP association tracker ─────────────────────── */
#define MAX_ASSOC_ENTRIES   128

/* Evidence source — strongest (definitive) first. */
enum {
    ASSOC_SRC_UNKNOWN = 0,
    ASSOC_SRC_EAPOL   = 1,   /* AP installed a pairwise key (M3) — #97 */
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
    /* Distance data point (src/rf_distance.h). Every source behind this
     * row — (re)association response, EAPOL M3 — is a frame the AP sent,
     * so this is the AP's distance from the sensor, not the client's. */
    rf_track_t dist;
} assoc_t;

/* ── Association / reassociation REQUEST (#60) ─────────────
 *
 * What the client asked for, as distinct from what the AP granted
 * (assoc_t above, built from responses). The pair is the point: a STA
 * that requests WPA3-SAE with MFP required and ends up on WPA2-PSK has
 * been downgraded, and that delta is the runtime signature of
 * CVE-2023-52424. The request is also the richest passive client
 * fingerprint available without touching the radio — rates, PHY tier,
 * RSN choice and capability bits, all volunteered.
 *
 * akm_bits / pairwise_bits use the same 00-0F-AC suite-type encoding
 * as beacon_rsn_t (see RSN_AKM_* in beacon_snoop.h), so requested and
 * granted are directly comparable. */
typedef struct {
    uint8_t  sta[6];              /* addr2 — the requesting client */
    uint8_t  bssid[6];            /* addr3 — the AP asked          */
    uint16_t capability_info;
    uint16_t listen_interval;
    char     requested_ssid[33];
    uint32_t supported_rates;     /* bitmap, see ASSOC_RATE_* below */
    uint32_t akm_bits;
    uint32_t pairwise_bits;
    int      requested_mfp;       /* 0=none 1=capable 2=required */
    char     phy[10];             /* "Wi-Fi 7" / "6" / "5" / "4" / "legacy" */
    uint32_t vendor_ie_hash;
    int      is_reassoc;          /* subtype 2 rather than 0 */
    /* Multi-Link Element from the request, when present (#67). The
     * client's own MLE is the half that matters — a beacon's describes
     * an AP's MLD, this one describes the handset that seqnum
     * correlation would otherwise report as three devices. Points into
     * the caller's frame buffer and is valid only during the parse. */
    const uint8_t *mle_body;
    int      mle_len;
    int      downgrade_flags;     /* ASSOC_DG_* — see below */
    uint32_t prev_akm_bits;       /* the ask this one replaced */
    int      prev_mfp;
    time_t   ts;
    /* Evidence-ring event ID of the request frame (#92 slice 4), copied
     * from the frame view by assoc_request_parse_frame(); 0 = none. */
    uint64_t event_id;
} assoc_req_t;

/* Downgrade observed across successive requests from one STA to one
 * BSSID: the client asked for less than it asked for last time.
 *
 * This is the observable form of the CVE-2023-52424 signature. The
 * issue's framing — compare requested AKM against "granted" AKM from
 * the association response — has no source: an Association Response
 * carries no RSNE outside the FT and OWE cases (IEEE 802.11-2020
 * §9.3.3.7). The AP does not echo the negotiated suite; the client's
 * request *is* the selection, and the AP only accepts or rejects it.
 *
 * So the downgrade is visible as a retry that asks for less — which is
 * what actually happens on the air when a client is forced off its
 * first choice. See the note on issue #60. */
#define ASSOC_DG_AKM       (1 << 0)  /* lost SAE, fell back to PSK      */
#define ASSOC_DG_MFP       (1 << 1)  /* management-frame protection cut */
#define ASSOC_DG_PAIRWISE  (1 << 2)  /* TKIP appeared where CCMP was    */

/* Supported-rate bitmap. Rates are carried in 500 kbit/s units with the
 * top bit marking "basic"; we index the common 802.11a/b/g set and
 * ignore the basic flag, since the question is which rates the client
 * supports at all. Bit positions are stable — appended, never renumbered. */
#define ASSOC_RATE_1M     (1u << 0)
#define ASSOC_RATE_2M     (1u << 1)
#define ASSOC_RATE_5M5    (1u << 2)
#define ASSOC_RATE_6M     (1u << 3)
#define ASSOC_RATE_9M     (1u << 4)
#define ASSOC_RATE_11M    (1u << 5)
#define ASSOC_RATE_12M    (1u << 6)
#define ASSOC_RATE_18M    (1u << 7)
#define ASSOC_RATE_24M    (1u << 8)
#define ASSOC_RATE_36M    (1u << 9)
#define ASSOC_RATE_48M    (1u << 10)
#define ASSOC_RATE_54M    (1u << 11)
/* A client offering only the 802.11b rates (1/2/5.5/11) is a legacy
 * device — useful both as a fingerprint and as a posture signal. */
#define ASSOC_RATES_11B_ONLY \
    (ASSOC_RATE_1M | ASSOC_RATE_2M | ASSOC_RATE_5M5 | ASSOC_RATE_11M)

/* ── Captive-portal interception (#69) ─────────────────────
 *
 * Every modern OS probes a fixed URL to decide whether it is behind a
 * captive portal, and expects a published, byte-exact answer. A rogue
 * AP answers with something else — which is exactly what makes the
 * victim's OS open a browser at the attacker's page.
 *
 * Three independent signals, because a portal evading one still has to
 * pass the others: the body was wrong, the DNS answer was local, or the
 * TLS connection terminated locally. */
typedef enum {
    CP_KIND_HIJACK         = 1 << 0,  /* wrong body on a sentinel URL     */
    CP_KIND_DNS_SPOOF      = 1 << 1,  /* sentinel host -> RFC1918 / CGNAT */
    CP_KIND_DNS_UNEXPECTED = 1 << 2,  /* -> outside the known ranges      */
    CP_KIND_TLS_MITM       = 1 << 3,  /* sentinel SNI -> private address  */
    /* A response on any host whose headers and body prefix match a
     * named attack kit's default portal (#169). Not a sentinel check:
     * the kit serves its page to every URL, so this one is keyed by
     * the server that sent it (alert key `portalkit:`), not by host. */
    CP_KIND_KIT            = 1 << 4,
} cp_kind_t;

#define CP_MAX_EVENTS 64

typedef struct {
    char     host[64];        /* the sentinel that was interfered with */
    char     src[46];         /* the client that probed                */
    char     evidence[80];    /* what was seen instead                 */
    /* The responder (#169): the address that answered the probe or
     * served the kit page, "" for a DNS-sourced event. It is what lets
     * an alert carry match_ip for per-alert pcap export. */
    char     server[46];
    uint16_t server_port;
    uint8_t  kind;            /* cp_kind_t                             */
    uint8_t  kit;             /* cp_kit_t (captive_portal.h), 0 = none */
    time_t   ts;
} cp_event_t;

/* ── Wi-Fi 7 Multi-Link Devices (#67) ──────────────────────
 *
 * MLO defeats sequence-number correlation structurally. seqnum_track
 * links randomised addresses belonging to one radio by their shared
 * monotonic counter; a Multi-Link Device runs several radios at once,
 * each with its own address and its own independent sequence space. So
 * one Wi-Fi 7 handset reads as two or three separate devices, and every
 * count, roster check and UNKNOWN_DEVICE decision made about it is
 * wrong in a way that looks entirely plausible.
 *
 * The Multi-Link Element is the protocol *asserting* the identity
 * rather than sloth inferring it, which is why it takes precedence over
 * the seqnum guess wherever both are available. */
#define SLOTH_MLD_MAX        64
#define SLOTH_MLD_MAX_LINKS   3   /* 2.4 / 5 / 6 GHz simultaneously */

typedef struct {
    uint8_t mld_mac[6];                          /* the stable identity */
    uint8_t link_mac[SLOTH_MLD_MAX_LINKS][6];    /* affiliated per-link */
    uint8_t link_id[SLOTH_MLD_MAX_LINKS];
    int     link_count;
    int     links_truncated;   /* more affiliated links than we can hold */
    time_t  first_seen;
    time_t  last_seen;

    /* CVE-2026-58374 / w1.fi 2026-1 (#104): a Per-STA Profile link_id
     * outside 0-14, or one repeated inside a single MLE, is exactly the
     * shape of the hostapd links[] out-of-bounds write. `malformed_link_id`
     * and `bad_link_id` are this frame's finding, set fresh by mle_parse()
     * on every call; `malformed_link_id_total` / `_last_seen` are the
     * persisted, lifetime signal mle_observe() accumulates onto the
     * stored entry. */
    uint8_t  malformed_link_id;
    uint8_t  bad_link_id;
    uint32_t malformed_link_id_total;
    time_t   malformed_link_id_last_seen;

    /* CVE-2026-58374 / w1.fi 2026-1 (#104 slice 2): a declared Common
     * Info Length that can't cover itself plus the mandatory MLD MAC
     * (minimum 7), or that would push Link Info past the element's own
     * bounds, is the same buffer-overread shape the advisory's other
     * parsing gaps share. `malformed_common_info_len`/
     * `bad_common_info_len` are this frame's finding, set fresh by
     * mle_parse() on every call; `_total`/`_last_seen` are the
     * persisted, lifetime signal mle_observe() accumulates. */
    uint8_t  malformed_common_info_len;
    uint8_t  bad_common_info_len;
    uint32_t malformed_common_info_len_total;
    time_t   malformed_common_info_len_last_seen;

    /* CVE-2026-58374 / w1.fi 2026-1 (#104 slice 3): the Link Info
     * subelement chain must tile the element exactly. A subelement whose
     * declared length reaches past the enclosing element's end, or a
     * trailing fragment too short to hold a subelement header, means the
     * sum of the declared lengths exceeds the container — the overrun
     * itself, not a length merely shaped to cause one, which is why this
     * one is CRIT where its two siblings are WARN.
     * `malformed_subelem_len` / `bad_subelem_len` /
     * `subelem_overrun_bytes` are this frame's finding, set fresh by
     * mle_parse() on every call; `_total`/`_last_seen` are the
     * persisted, lifetime signal mle_observe() accumulates. */
    uint8_t  malformed_subelem_len;
    uint8_t  bad_subelem_len;      /* the declared length that overran */
    uint16_t subelem_overrun_bytes; /* how far past the element it reached */
    uint32_t malformed_subelem_len_total;
    time_t   malformed_subelem_len_last_seen;

    /* MLD MAC collision (#104 slice 4). IEEE 802.11be §9.4.2.312: a
     * Per-STA Profile's link_id names one specific affiliated radio of
     * the MLD, and that radio's address does not change for the life
     * of the association. mle_observe() keeps the first address it
     * sees for a given link_id as authoritative; a later frame naming
     * the same (MLD MAC, link_id) pair with a *different* address is
     * not a new subset of the same device's links (that case is the
     * ordinary merge above) — it is two different radios claiming the
     * same link identity under the same stable MLD MAC, which is
     * either impersonation or an address collision either way worth an
     * operator's attention. The conflicting address is counted and
     * reported, never merged into the roster. */
    uint32_t mac_collision_total;
    time_t   mac_collision_last_seen;
    uint8_t  collision_link_id;
    uint8_t  collision_mac[6];

    /* Cross-link cipher/PMF downgrade (#104 slice 5). Two Per-STA
     * Profiles of ONE Multi-Link element, each carrying its own
     * explicit RSNE, that disagree about whether management-frame
     * protection is required or about pairwise-cipher strength. A
     * benign MLD runs one security posture across its radios; a link
     * advertised weaker than its siblings is the lane an
     * adversary-in-the-middle wants the client to take.
     *
     * Only links with an EXPLICIT RSNE are compared. Under 802.11be
     * profile inheritance a Per-STA Profile that omits an element
     * inherits the reporting AP's, so an absent RSNE means "same as
     * the AP", not "no encryption" — reading absence as weakness is
     * this rule's false-positive trap.
     *
     * The first five fields are this frame's finding, set fresh by
     * mle_parse() on every call; `_total`/`_last_seen` are the
     * persisted, lifetime signal mle_observe() accumulates. */
    uint8_t  cross_link_cipher_downgrade;
    uint8_t  downgrade_link_id;        /* the weaker link */
    uint8_t  downgrade_peer_link_id;   /* the sibling it loses to */
    /* One link MFPR=1, another MFPR=0. RECORDED but not a downgrade on
     * its own (owner ruling 2026-10-13): that pair is what the standard
     * mandates for a tri-band AP where one band requires PMF and the
     * others negotiate it, so firing on it alone would fire on
     * conformant Wi-Fi 7 hardware. Reported as context when the cipher
     * arm fires. Carries its own link pair below, because the two
     * mismatches can involve different links. */
    uint8_t  downgrade_pmf_mismatch;
    uint8_t  pmf_mismatch_link_id;
    uint8_t  pmf_mismatch_peer_link_id;
    uint8_t  downgrade_cipher_mismatch;/* pairwise-cipher strength differs */
    uint32_t cross_link_cipher_downgrade_total;
    time_t   cross_link_cipher_downgrade_last_seen;
} sloth_mld_t;

/* ── Per-BSSID Multi-Link advertisement (#104 slice 6) ─────
 *
 * sloth_mld_t is keyed by MLD MAC, the identity an MLD asserts. Two
 * findings need the other key, the BSSID that sent the frame: whether
 * this BSS has ever advertised that it belongs to an AP MLD at all, and
 * whether the MLD identity in its Probe Responses is the one in its
 * Beacons. A row exists only for a BSSID that has sent a Multi-Link
 * element of some variant, so a legacy AP never takes one.
 *
 * Only what both Beacon and Probe Response carry is kept for the
 * comparison: the Basic MLE's MLD MAC Address (unconditional in that
 * variant) and its Link ID Info (Presence Bitmap bit 4). The link SET
 * is deliberately not kept. A Beacon carries no Per-STA Profiles while
 * a multi-link Probe Response carries complete ones, so comparing link
 * sets would fire on every Wi-Fi 7 AP that answers an ML probe. See
 * research/ieee/802.11be-2024-9.4.2.322-bss-mle-consistency.md. */
#define SLOTH_MLE_BSS_MAX        64
/* How old a Beacon's identity may be and still be compared with a
 * Probe Response. The issue's proposed window (#104), not a cited
 * value. It is a freshness bound, not a detection threshold: it limits
 * how long an AP MLD that was legitimately reconfigured can be held to
 * its previous identity, and one mismatch inside it is the finding. */
#define MLE_PR_BEACON_WIN_SECS   30

typedef struct {
    uint8_t  bssid[6];
    time_t   first_seen;
    time_t   last_seen;
    /* A Basic MLE has been seen from this BSSID, in a Beacon or a Probe
     * Response: the BSS has advertised that it is affiliated with an AP
     * MLD. Never cleared while the row lives. */
    uint8_t  basic_mle_seen;

    /* The newest Beacon's own-MLD identity: its first Basic MLE with no
     * AP MLD ID. One that carries an AP MLD ID describes an AP MLD of a
     * multiple-BSSID set, which need not be this BSS's own. */
    uint8_t  beacon_ident;          /* the fields below are valid */
    uint8_t  beacon_mld_mac[6];
    uint8_t  beacon_has_link_id;
    uint8_t  beacon_link_id;
    time_t   beacon_ident_ts;
    uint64_t beacon_ev;             /* evidence-ring id of that Beacon, 0 if none */

    /* MLE_RECONFIG_NO_MLO: a Reconfiguration MLE from a BSSID that, as
     * of that frame and the frame itself included, had never advertised
     * a Basic MLE. Lifetime count, sticky like the sibling MLE rules. */
    uint32_t reconfig_no_mlo_total;
    uint8_t  reconfig_no_mlo_subtype;  /* 8 Beacon, 5 Probe Response */
    time_t   reconfig_no_mlo_last_seen;
    uint64_t reconfig_no_mlo_ev;

    /* MLE_PR_BEACON_DIFF: a Probe Response whose own-MLD identity
     * disagrees with the Beacon identity above, inside
     * MLE_PR_BEACON_WIN_SECS. What differed, and both sides of it. */
    uint32_t pr_beacon_diff_total;
    uint8_t  diff_mld_mac;          /* the MLD MAC Addresses differ */
    uint8_t  diff_link_id;          /* both carry Link ID Info, and it differs */
    uint8_t  diff_beacon_mld_mac[6];
    uint8_t  diff_beacon_link_id;
    uint8_t  diff_pr_mld_mac[6];
    uint8_t  diff_pr_link_id;
    time_t   pr_beacon_diff_last_seen;
    uint64_t diff_beacon_ev;
    uint64_t diff_pr_ev;
} sloth_mle_bss_t;

/* ── 802.11k Radio Measurement survey (#61) ────────────────
 *
 * An RRM Beacon Request asks a client to scan and report back what it
 * can hear: BSSIDs, channels, RSSIs. The client obliges — that is the
 * protocol working. It is also a way for an AP to enumerate the
 * airspace *through* someone else's radio, from a position where its
 * own antenna cannot reach, and the report it gets back is precisely
 * the input needed to build a convincing evil twin.
 *
 * The frames are protocol-legitimate; the abuse is behavioural. So the
 * detector is a rate with context rather than a signature, and the
 * discriminator is whether the requester is asking about an SSID it has
 * any business asking about. */
#define SLOTH_RRM_MAX_PAIRS   64
#define RRM_SURVEY_WIN_SECS  300
#define RRM_SURVEY_THRESH      6   /* targeted requests per pair per window */

typedef struct {
    uint8_t bssid[6];         /* the AP asking          */
    uint8_t sta[6];           /* the client being asked */
    int     targeted_reqs;    /* requests naming a specific SSID */
    int     broadcast_reqs;   /* requests with no SSID subelement */
    int     reports_seen;     /* the client's replies — evidence, not alert */
    char    last_ssid[33];    /* SSID named by the most recent targeted ask */
    uint8_t last_channel;
    uint8_t last_mode;        /* 0 passive, 1 active, 2 table */
    time_t  first_seen;
    time_t  last_seen;
} sloth_rrm_pair_t;

/* ── Operating channel width and primary channel (#66) ─────
 *
 * The capability IEs say what a radio *can* do; the operation IEs say
 * what this BSS is *doing*. Until they were decoded sloth treated every
 * AP as 20 MHz, which makes any airtime or occupancy answer wrong by up
 * to a factor of sixteen.
 *
 * The other half is the durable 6 GHz fix. The beacon channel has come
 * from the DS Parameter Set (tag 3), which many 6 GHz and HE APs simply
 * omit — HE Operation's 6 GHz Operation Info is the authoritative
 * source, and EHT Operation carries the equivalent for 320 MHz. */
typedef enum {
    CH_WIDTH_UNKNOWN =    0,
    CH_WIDTH_20      =   20,
    CH_WIDTH_40      =   40,
    CH_WIDTH_80      =   80,
    CH_WIDTH_160     =  160,
    CH_WIDTH_320     =  320,
    CH_WIDTH_80P80   = 8080,   /* 80+80 non-contiguous */
} sloth_ch_width_t;

/* Where the primary channel number came from. A wrong channel is
 * otherwise unattributable, and the sources genuinely disagree: DS
 * Param is absent on much 6 GHz gear, and radiotap reports where the
 * *radio* was, not what the AP said. */
typedef enum {
    CH_SRC_UNKNOWN  = 0,
    CH_SRC_DS_PARAM = 1,   /* tag 3 */
    CH_SRC_HT_OPER  = 2,   /* tag 61 */
    CH_SRC_HE_6GHZ  = 3,   /* tag 255 ext 36, 6 GHz Operation Info */
    CH_SRC_EHT_OPER = 4,   /* tag 255 ext 106 */
} sloth_ch_source_t;

/* Band label for a channel number, correctly handling the case a
 * number-only heuristic cannot: a 5 GHz and a 6 GHz channel can share
 * the same number (37, 149 and others are valid in both), so "5 GHz"
 * vs. "6 GHz" is not decidable from the number alone. CH_SRC_HE_6GHZ
 * is: the HE Operation element's 6 GHz Operation Info subfield exists
 * only on a 6 GHz BSS, so that source — whatever number it names —
 * settles the question outright. Any other source, or none, falls back
 * to the ordinary numeric ranges. Returns "?" for channel <= 0 or a
 * number in none of the known ranges. */
const char *ap_band_label(int channel, uint8_t channel_source);

/* ── Channel Switch Announcement (#63) ─────────────────────
 *
 * CSA is how an AP moves its clients to a new channel — radar
 * avoidance under DFS, load balancing, a firmware reconfiguration.
 * Clients honour it, which is the point and also the problem: a
 * spoofed CSA claiming to come from the legitimate BSSID moves every
 * associated STA onto a channel the attacker chose, without a single
 * deauth frame and without out-signalling anything.
 *
 * Cheaper and quieter than a deauth flood, and it works on firmware
 * that ignores deauth entirely. The same frame repeated with changing
 * targets is a denial of service instead — clients churn between
 * channels and never settle. */
#define SLOTH_CSA_MAX_EVENTS  128

/* Where the announcement was carried. A beacon CSA is broadcast to
 * every associated client; an Action-frame CSA is addressed, and can be
 * aimed at one STA without the rest of the BSS noticing. */
typedef enum {
    CSA_SRC_BEACON     = 0,
    CSA_SRC_PROBE_RESP = 1,
    CSA_SRC_ACTION     = 2,
} sloth_csa_source_t;

typedef struct {
    uint8_t  bssid[6];        /* addr3 — the BSS being moved   */
    uint8_t  ta[6];           /* addr2 — who actually sent it  */
    uint8_t  new_op_class;    /* from tag 60; 0 when absent    */
    uint8_t  new_channel;
    uint8_t  switch_mode;     /* 0 = advisory, 1 = stop transmitting now */
    uint8_t  switch_count;    /* TBTTs until the switch         */
    uint8_t  source;          /* sloth_csa_source_t             */
    uint8_t  from_channel;    /* channel we heard it on, 0 = unknown */
    time_t   ts;
} sloth_csa_event_t;

/* > 3 distinct target channels from one BSSID inside the window is a
 * storm: a legitimate AP picks one destination and commits to it. */
#define CSA_STORM_THRESH    4
#define CSA_STORM_WIN_SECS 60

/* ── WPA / PMF downgrade posture (#62) ─────────────────────
 *
 * Four ways an AP can offer a client a weaker lane than the one it is
 * advertising. None of these is an attack in itself — every one is a
 * configuration the AP is choosing to broadcast — but each is the
 * *prerequisite* an attacker needs, and a client will take the weak
 * lane if the AP offers it.
 *
 * Kept as a bitfield rather than one "worst posture" value because an
 * AP can offer several at once, and which ones it offers is the finding
 * an operator has to fix. */
typedef enum {
    WPA_DG_TRANSITION_SAE_PSK = 1 << 0, /* PSK and SAE both on offer   */
    WPA_DG_OWE_TRANSITION     = 1 << 1, /* OWE BSS paired with an open one */
    WPA_DG_MFP_OPTIONAL       = 1 << 2, /* SAE with MFP capable-not-required */
    WPA_DG_WPA1_ALONGSIDE     = 1 << 3, /* legacy WPA1 IE beside the RSN IE */
} sloth_downgrade_kind_t;

/* An AP must be observed for at least this long before its posture is
 * reported. A single beacon caught while channel-hopping is a sample,
 * not a configuration, and firing on it would make --hop noisy. */
#define WPA_DOWNGRADE_MIN_OBSERVED_S 30

/* The same floor, longer, for the one finding whose evidence is an
 * *absence* (#101 slice 3). A posture report reads elements that are
 * there; rule_tpc_absent_high_band() reports elements that are not, and
 * a missing element is also what a radio that was listening elsewhere
 * produces. Thirty seconds of a hopping dwell can be two beacons; sixty
 * buys enough visits that silence is the AP's and not the receiver's. */
#define TPC_ABSENT_MIN_OBSERVED_S 60
/* ...and enough beacons to have actually read the elements that many
 * times. Age alone is not observation: a --hop run can hear ONE beacon
 * from a designated AP, hop away, never return, and satisfy a 60-second
 * floor on an entry whose regulatory fields were read exactly once.
 * Three is the smallest count that distinguishes "absent" from "missed
 * once", and a 5 GHz AP on its default 100 TU interval emits it in
 * roughly 300 ms, so this costs a correct finding nothing. */
#define TPC_ABSENT_MIN_BEACONS 3

/* COUNTRY_ABSENT (#101 slice A) uses the same two-part observation
 * floor as TPC_ABSENT_HIGH_BAND, for the same reason: a Country element
 * that was not heard is also what a radio listening elsewhere produces,
 * so "absent" needs both time and readings behind it. */
#define COUNTRY_ABSENT_MIN_OBSERVED_S 60
#define COUNTRY_ABSENT_MIN_BEACONS    3

/* DFS_MASKING (#101 slice A). A BSSID is only judged after this many
 * beacons from it, so one misread DS Parameter Set cannot place it on a
 * DFS channel. And a CSA counts as "leading there" when it was heard no
 * later than this long after the BSSID's first beacon: both stores are
 * stamped in whole seconds by different modules, and the last
 * announcement on the old channel and the first beacon on the new one
 * routinely share a second, so a strict "before" would drop the case
 * the exemption exists for. */
#define DFS_MASK_MIN_BEACONS   3
#define DFS_MASK_CSA_SLACK_S   2

/* ── BSS Transition Management steering (#59) ──────────────
 *
 * One row per (BSSID, STA) pair the AP has sent a BTM Request to. The
 * pair is the unit because that is what the attack targets: BTM is
 * addressed steering, not a broadcast, so "how often has this AP told
 * *this* client to leave" is the whole question.
 *
 * Legitimate 802.11v load balancing produces these too, which is why
 * the row records the picture rather than a verdict — the operator
 * reading [a] sees every steer, and the alert fires on the subset that
 * carries Disassociation Imminent at a rate no roaming policy needs.
 *
 * `candidates` is the list from the most recent Request: where the AP
 * says the client should go. Cross-referenced against the evil-twin
 * episode set, it answers whether the destination is a known rogue. */
#define MAX_BTM_PAIRS  128

typedef struct {
    uint8_t bssid[6];         /* addr3 — the AP doing the steering  */
    uint8_t sta[6];           /* addr1 — the client being steered   */
    int     req_count;        /* BTM Requests seen for this pair    */
    int     imminent_count;   /* subset carrying Disassociation Imminent */
    uint8_t last_request_mode;
    uint16_t last_disassoc_timer;   /* in beacon intervals */
    uint8_t last_validity_interval;
    /* Candidate list from the most recent Request. Bounded by the same
     * limit the parser uses, so a row can hold whatever was parsed. */
    uint8_t candidates[MAX_AP_NEIGHBORS][6];
    int     candidate_count;
    int     candidates_truncated;
    time_t  first_seen;
    time_t  last_seen;
} btm_steer_t;

/* ── EAPOL handshake event (WPA 4-way / PMKID) ────────────── *
 * One per observed EAPOL-Key frame.
 *
 * The three things a 4-way observation can tell you are deliberately
 * separate fields, because they are separate claims (#97 / T12):
 *
 *   handshake_complete  — candidate_message_pair. This M2 and a live M1
 *       belong to the SAME attempt: equal Key Replay Counters, M2 inside
 *       EAPOL_PAIR_WINDOW_S of the M1, that M1 not yet superseded. The
 *       only state from which a hashcat 22000 EAPOL record is exported.
 *   handshake_progress  — observed_handshake_progress: how far M1..M4
 *       got within that attempt, 0..4. Reporting only.
 *   assoc_evidence      — association_evidence: the AP installed a key
 *       for this STA (M3, AP→STA). Still protocol progression, not
 *       cryptographic verification — sloth never checks the MIC.
 *
 * replay_counter_ok records that THIS event's counter comparison
 * succeeded — on an M2, that it answers its M1; on an M3/M4, that the
 * attempt it belongs to has a counter-verified pair. It is what clears
 * hashcat's "not replaycount checked" bit on export. */
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
    int      handshake_progress;
    int      replay_counter_ok;
    int      assoc_evidence;
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

/* ── Bluetooth host source (#144 slice 2) ────────────────
 *
 * What the HCI monitor channel (libpcap `bluetooth-monitor`, DLT 254)
 * lets sloth see, decoded through an allow-list in src/ble_hci.c. The
 * operator's own stack drives the controller; sloth only listens to the
 * copy the kernel hands every monitor socket, and that socket has no
 * transmit path (MISSION §2).
 *
 * ble_device_t is one advertiser, keyed by (address, address type).
 * Decoded advertising fields only — the raw AD bytes are never kept,
 * because nothing that crossed the monitor channel is written anywhere
 * verbatim (link keys and LTKs travel the same channel). */
#define MAX_BLE_DEVICES   256
#define BLE_DEV_NAME_MAX  32

/* #156 item 2: a BLE address-rotation hint on one advertiser row,
 * src/ble_rotation.h. All zero unless --ble-rotation-hints is on, and
 * never exported: no view row, JSONL field or database column reads
 * it. A hypothesis that the row may be the same advertiser as another
 * row on the same sensor; it corroborates, does not confirm, and
 * identifies no device or person. Window-scoped: refreshed at every
 * snapshot, and zero once either address leaves the seam table. Its
 * one consumer is the [*] view's estimate; no detector reads it. */
typedef enum {
    BLE_HINT_NONE = 0,
    BLE_HINT_PAYLOAD,      /* grade A + B: a documented token carried across the seam */
    BLE_HINT_TIMING        /* grade B + C only: de-duplication, never shown as a link */
} ble_hint_basis_t;
typedef struct {
    uint8_t  basis;        /* ble_hint_basis_t of the committed link INTO this row */
    uint8_t  confidence;   /* 0..100, under BLE_ROT_CONF_*_MAX */
    uint8_t  hops;         /* links from the chain's first address */
    uint32_t chain;        /* per-run chain id, 0 = in no chain; rows sharing one count once */
    /* First report of the chain's first address (frame clock): a hook
     * for the deferred "non-resident" definition (src/ble_detect.h),
     * read by nothing yet. 0 = none. */
    time_t   root_first;
} ble_identity_hint_t;

typedef struct {
    uint8_t  addr[6];          /* display order, most significant octet first */
    uint8_t  addr_type;        /* 0 public, 1 random, 2/3 resolved identity */
    uint16_t adapter;          /* HCI index of the controller that heard it */
    /* ADV_IND .. SCAN_RSP, Vol 4 Part E §7.7.65.2, or BLE_EVT_EXT_ADV /
     * BLE_EVT_EXT_SCAN_RSP (src/ble_snoop.h) for an extended PDU */
    uint8_t  last_event_type;
    /* Bit per Event_Type 0..6 ever heard from this row, sticky (#144
     * slice 4 review). An ADV_IND and its SCAN_RSP alternate, so the
     * last type is display only: the JSONL change signature takes this
     * mask, which settles, and never last_event_type, which flips. */
    uint8_t  pdu_mask;
    uint8_t  has_name, name_complete;
    char     name[BLE_DEV_NAME_MAX + 1];
    uint8_t  has_uuid16;
    uint16_t uuid16;           /* first 16-bit service UUID advertised */
    uint8_t  has_mfr;
    uint16_t mfr_id;           /* manufacturer company identifier, FIRST seen */
    uint8_t  has_appearance;
    uint16_t appearance;
    uint8_t  has_tx_power;
    int8_t   tx_power;
    uint8_t  has_flags, flags;
    uint8_t  has_rssi;
    int8_t   rssi;             /* last report's RSSI, dBm */
    int8_t   rssi_best;        /* strongest seen, dBm */
    time_t   first_seen;       /* frame clock */
    time_t   last_seen;        /* frame clock */
    uint64_t adv_count;        /* advertising reports decoded for this row */
    /* Which sensor heard it (#144 slice 3). Part of the row's key, with
     * the address and its type, so the host controller and an Ubertooth
     * hearing the same advertiser are two rows: their counts mean
     * different things (below) and must not be summed. */
    uint8_t  sensor_kind;      /* sensor_kind_t, SENSOR_BLE today */
    char     sensor_iface[24]; /* BT_MONITOR_DEVICE or BT_CAPTURE_IFACE */
    /* 1 when adv_count is a SAMPLE: an Ubertooth listens on one RF
     * channel at a time (one of the three advertising channels unless
     * told to follow), so it hears a fraction of what was sent. */
    uint8_t  sampled;
    int8_t   channel;          /* LL channel index 0..39 last heard on, -1 unknown */
    /* #144 slice 4. The first octet of the manufacturer data after the
     * company ID: the message type for Apple Continuity, the beacon ID
     * for Microsoft. Only what the rules key on; still no raw AD bytes.
     * Kept as FIRST seen, paired with mfr_id: an Apple device rotates
     * its Continuity type report to report, and a last-value field would
     * make every ble_device record a change (the rules read the report,
     * not this). */
    uint8_t  has_mfr_sub;
    uint8_t  mfr_sub;
    uint8_t  has_svc_data;
    uint16_t svc_data_uuid16;  /* first Service Data - 16-bit UUID (AD 0x16) */
    /* BLE_HID_*: bit 0 a HID appearance (0x03C0..0x03CA) was advertised,
     * bit 1 the HID service UUID 0x1812 was listed. Kept once seen, like
     * every other field on the row. */
    uint8_t  hid;
    /* BLE_WATCHLIST category this row matched, "" for none. A category,
     * never an identity (src/ble_watchlist.h). */
    char     watch_cat[16];
    /* From LE Extended Advertising Reports (0x0D slice). ext_adv is 1
     * once an extended (non-legacy) PDU was heard from the row, sticky;
     * the PHYs and SID are the last 0x0D report's, 0 / 0xFF until one. */
    uint8_t  ext_adv;
    uint8_t  primary_phy;      /* 0 unknown, 0x01 LE 1M, 0x03 LE Coded (S=8), 0x04 LE Coded S=2 */
    uint8_t  secondary_phy;    /* 0 none or unknown, 0x01 1M, 0x02 2M, 0x03 Coded (S=8), 0x04 Coded S=2 */
    uint8_t  adv_sid;          /* 0x00..0x0F, 0xFF none (every legacy PDU) */
    ble_identity_hint_t hint;  /* #156: internal only, all zero with the flag off */
    /* TX_Power from the 0x0D report header (Core v6.0 Vol 4 Part E
     * §7.7.65.13), last report that carried one; 0x7F never sets it. */
    uint8_t  has_ext_tx_power;
    int8_t   ext_tx_power;
    rf_track_t dist;           /* distance data point, src/rf_distance.h */
} ble_device_t;

/* #156 item 2: the rotation-hint feature's aggregate state, copied by
 * ble_snapshot(). `enabled` 0 means every field is 0 and sensor_health
 * carries none of them. No address, token or digest is held here. */
typedef struct {
    int      enabled;
    uint64_t hints_payload;    /* payload links committed, lifetime */
    uint64_t hints_timing;     /* timing-only links committed, lifetime */
    uint64_t poisoned;         /* token digests poisoned (heard on interleaving addresses) */
    uint64_t seam_evictions;   /* seam-table entries dropped on full */
} ble_rot_stats_t;

#define BLE_HID_APPEARANCE  0x01
#define BLE_HID_SERVICE     0x02

/* ── BLE advertising-flood windows (#144 slice 4) ────────
 *
 * One row per (sensor, advertising type, payload family, id, subtype):
 * the observable BLE_ADV_FLOOD gates on. Filled by src/ble_flood.c from
 * every decoded advertisement, copied here by ble_snapshot(). Tumbling
 * windows of ble.flood_window_s on the monotonic clock; `cur` is the
 * window in progress, `prev` the one immediately before it (empty when
 * a whole window passed with nothing). */
#define MAX_BLE_FLOOD       32
#define BLE_FLOOD_ADDR_CAP  128   /* distinct addresses counted per window */
#define BLE_FLOOD_RSSI_CAP  64    /* RSSI samples kept per window, for the median */
typedef enum {
    BLE_FAM_NONE = 0,
    BLE_FAM_MFR,       /* Manufacturer Specific Data: id = company ID */
    BLE_FAM_SVC_DATA   /* Service Data - 16-bit UUID: id = the UUID */
} ble_family_t;
typedef struct {
    uint32_t total;            /* advertisements counted */
    uint16_t distinct;         /* distinct (address, type), at most BLE_FLOOD_ADDR_CAP */
    uint8_t  distinct_capped;  /* 1: more addresses than were counted */
    /* Addresses heard in this window that were not heard on this key in
     * the two windows before it (BLE_ADV_FLOOD gate 1). Uncapped: a
     * Bloom set per window, so a false positive only ever hides a fresh
     * address, never invents one. */
    uint32_t fresh;
    /* 1 when the window before this one held advertisements on this
     * key: only then is `fresh` a comparison against something. The
     * first window of a key, or one after a silent window, is 0. */
    uint8_t  baseline;
    uint8_t  has_rssi;
    int8_t   rssi_median;      /* dBm, of the first BLE_FLOOD_RSSI_CAP samples */
} ble_flood_win_t;
typedef struct {
    uint8_t  sensor_kind;      /* sensor_kind_t */
    char     sensor_iface[24];
    uint8_t  sampled;          /* 1: a one-channel sample (Ubertooth) */
    uint8_t  adv_type;         /* HCI Event_Type of the reports */
    uint8_t  family;           /* ble_family_t */
    uint16_t id;
    int16_t  subtype;          /* first payload octet; -1 for a family without one */
    uint8_t  spam_known;       /* the key is on the documented spam list (gate 3) */
    uint32_t window_ms;        /* window length the counts were taken over */
    uint32_t cur_elapsed_ms;   /* how far into `cur` the snapshot fell */
    ble_flood_win_t cur, prev;
    uint64_t total_all;        /* every advertisement on this key, ever */
    time_t   first_seen, last_seen;   /* wall clock */
} ble_flood_row_t;

/* LE scan type as last set by the host (LE Set [Extended] Scan
 * Parameters). UNKNOWN until such a command is actually seen: an
 * absence of scan requests is not evidence of a passive scan, and the
 * monitor channel would not show them anyway. */
typedef enum {
    BLE_SCAN_UNKNOWN = 0, BLE_SCAN_PASSIVE, BLE_SCAN_ACTIVE
} ble_scan_mode_t;

/* What the host controller was seen being told to put on the air. One
 * per command family on the own-transmission allow-list. Names are part
 * of the sensor_health JSONL contract — see bt_tx_kind_name(). */
typedef enum {
    BT_TX_NONE = 0,
    BT_TX_ACTIVE_SCAN,        /* LE scan set active, or enabled under active parameters (SCAN_REQ) */
    BT_TX_INQUIRY,            /* HCI_Inquiry */
    BT_TX_PERIODIC_INQUIRY,   /* HCI_Periodic_Inquiry_Mode, until Exit (0x0404) */
    BT_TX_ADV,                /* LE Set Advertising Enable = 1 */
    BT_TX_EXT_ADV,            /* LE Set Extended Advertising Enable = 1 */
    BT_TX_PERIODIC_ADV,       /* LE Set Periodic Advertising Enable = 1 */
    BT_TX_LE_CONNECT,         /* LE Create Connection / LE Extended Create Connection */
    BT_TX_BREDR_CONNECT,      /* HCI_Create_Connection (page) */
    BT_TX_REMOTE_NAME,        /* HCI_Remote_Name_Request (page) */
    BT_TX_SCAN_ENABLE,        /* Write_Scan_Enable with inquiry or page scan on */
    BT_TX_KIND_COUNT
} bt_tx_kind_t;

/* Recency of a transmit command. Bucketed, never latched: an inquiry
 * an hour ago is a different state from one now. Recency alone covers
 * the one-shot kinds (inquiry, connect, remote name); the persistent
 * kinds are also held on/off in ble_ctrl_t, because a controller told
 * to advertise is still advertising long after the command is old. */
typedef enum {
    BT_TX_NEVER = -1, BT_TX_RECENT = 0, BT_TX_EARLIER = 1
} bt_tx_recency_t;

/* One controller's transmit state, as far as the host's commands on
 * the monitor channel show it. The persistent kinds — advertising
 * (legacy, extended, periodic), inquiry / page scan, periodic inquiry
 * and an enabled active scan — stay on the air from their enable
 * command until a matching disable, HCI_Reset, or DEL_INDEX, so they
 * are held as on/off here rather than read off a command's age. */
#define BT_MAX_CTRL   8
#define BLE_SENSOR_IFACES_MAX 8   /* BLE sensor ifaces tracked per host, as ble_detect.c groups them */
#define BT_ADV_HANDLE_WORDS 8   /* 256-bit Advertising_Handle set */
typedef struct {
    int      index;             /* HCI index; -1 = free slot */
    uint8_t  live;              /* NEW_INDEX seen, no DEL_INDEX since */
    uint8_t  primary;           /* NEW_INDEX type 0x00 (HCI_PRIMARY) */
    uint8_t  reset_seen;        /* HCI_Reset seen: on-state complete from there */
    int8_t   scan_enabled;      /* -1 unknown, 0 off, 1 on (this controller) */
    int8_t   scan_mode;         /* ble_scan_mode_t (this controller) */
    int8_t   filter_dups;       /* -1 unknown, 0 off, 1 on: Filter_Duplicates of the last scan enable (#156) */
    uint8_t  adv_on;            /* LE Set Advertising Enable */
    uint8_t  page_inq_scan_on;  /* Write_Scan_Enable bit 0 or 1 */
    uint8_t  per_inquiry_on;    /* Periodic Inquiry Mode until Exit */
    uint8_t  ext_adv_unknown;   /* sets enabled whose handles were not read */
    uint32_t ext_adv_sets[BT_ADV_HANDLE_WORDS];
    uint32_t per_adv_sets[BT_ADV_HANDLE_WORDS];
    uint32_t on_mask;           /* derived: bit per bt_tx_kind_t now on */
} ble_ctrl_t;

typedef struct {
    /* Primary-type controllers live now: NEW_INDEX with type 0x00
     * (HCI_PRIMARY) not since removed by DEL_INDEX, among the
     * BT_MAX_CTRL tracked. A controller that resets or is rfkilled is
     * removed and re-announced, so it never counts twice. */
    int      controllers;
    int      ctrl_index;           /* HCI index of the most recent one, -1 none */
    uint8_t  ctrl_bus;             /* HCI bus type (USB, UART, ...) */
    uint8_t  ctrl_addr[6];         /* display order */
    char     ctrl_name[9];         /* "hci0" */
    /* Scan configuration, as the host last set it on any controller. */
    int      scan_mode;            /* ble_scan_mode_t */
    int      filter_policy;        /* Scanning_Filter_Policy 0..3, -1 unknown */
    int      scan_enabled;         /* -1 unknown, 0 off, 1 on */
    /* Own transmissions, by arrival wall clock (the liveness clock).
     * last_* is the newest command of any kind; tx_wall / tx_adapter
     * keep each kind's own newest, so two kinds inside the window are
     * two findings. */
    int      last_tx_kind;         /* bt_tx_kind_t */
    int      last_tx_adapter;      /* HCI index it was sent to, -1 none */
    time_t   last_tx_wall;         /* 0 = never */
    time_t   tx_wall[BT_TX_KIND_COUNT];      /* 0 = never */
    int      tx_adapter[BT_TX_KIND_COUNT];   /* -1 none */
    uint32_t tx_kind_mask;         /* bit per bt_tx_kind_t ever seen */
    uint32_t tx_on_mask;           /* bit per kind on, any controller */
    /* 1 when every tracked controller has been seen through HCI_Reset,
     * so tx_on_mask covers everything it was told. 0 means state set
     * before sloth opened the channel may be missing from it. */
    int      tx_baseline;
    uint64_t tx_count;
    ble_ctrl_t ctrl[BT_MAX_CTRL];
    /* Commands for a controller past BT_MAX_CTRL land here: its on-state
     * is never cleared (a disable cannot be told apart between the
     * controllers sharing it), and tx_baseline stays 0. */
    ble_ctrl_t ctrl_overflow;
    uint64_t ctrl_untracked;       /* records routed to ctrl_overflow */
    /* Record accounting: every record lands in exactly one bucket
     * besides `records`, which counts them all. */
    uint64_t records;              /* every monitor record offered */
    uint64_t adv_reports;          /* LE Advertising Report events decoded, every report */
    /* LE Extended Advertising Report events with at least one report
     * put in the table, and those with none (every report the tail of
     * an open fragment train). */
    uint64_t ext_adv_reports;
    uint64_t ext_adv_undecoded;
    /* Not buckets, counted per report: continuation fragments of an
     * open train, never walked; reports decoded from a leading or
     * truncated fragment (data status incomplete), so from the AD
     * structures the fragment held whole; and open fragment trains
     * pushed out of the bounded table. */
    uint64_t ext_fragments;
    uint64_t ext_adv_partial;
    uint64_t ext_trains_evicted;
    uint64_t index_records;        /* NEW_INDEX and DEL_INDEX records */
    uint64_t commands;             /* allow-listed host commands read */
    uint64_t ignored;              /* outside the allow-list, dropped unread */
    uint64_t malformed;            /* allow-listed type, bad length or snapped */
    /* Frame clock of the first and the newest advertisement any BLE
     * sensor decoded (#144 slice 4): the session BLE_HID_UNEXPECTED's
     * rotation window is measured inside. 0 = none yet. */
    time_t   adv_first_ts;
    time_t   adv_last_ts;
    /* The same first-advertisement clock per sensor iface (#144 slice 4
     * review): a second BLE sensor started later has its own first
     * window, in which every address it hears is new to it. */
    struct { char iface[24]; time_t first_ts; } adv_first_by[BLE_SENSOR_IFACES_MAX];
} ble_host_t;

/* ── Ubertooth capture stream (#144 slice 3) ─────────────
 *
 * --bt-capture PATH reads a classic pcap file or FIFO the operator
 * produces with ubertooth-btle or ubertooth-rx (docs/wiki/ubertooth.md).
 * sloth never drives the dongle: it reads a file, and the tool that owns
 * the radio is the operator's. Decoded by src/btle_ll.c (DLT 256 and
 * PPI around 251) and src/bredr_bb.c (DLT 255); framed and counted by
 * src/bt_stream.c. */
#define BT_CAPTURE_IFACE    "ubertooth"
#define BT_CAPTURE_PATH_MAX 256

/* Stream state. Names are part of the sensor_health JSONL contract —
 * see bt_cap_state_name(). */
typedef enum {
    BT_CAP_OFF = 0,     /* --bt-capture not given */
    BT_CAP_WAITING,     /* opened; no pcap file header read yet (a FIFO with no writer) */
    BT_CAP_STREAMING,   /* header accepted, records flowing */
    BT_CAP_EOF,         /* the file ended, or the FIFO's writer closed it */
    BT_CAP_REFUSED,     /* not a classic pcap, or a link type sloth does not read */
    BT_CAP_ERROR,       /* open or read failed, or the stream is corrupt */
    BT_CAP_STOPPED      /* sloth stopped the worker */
} bt_cap_state_t;

typedef struct {
    int      configured;       /* --bt-capture given */
    int      state;            /* bt_cap_state_t */
    char     err[96];          /* why REFUSED / ERROR, "" = none */
    int      dlt;              /* accepted link type, -1 none yet */
    int      refused_dlt;      /* link type refused, -1 none */
    /* 40 for a BLE stream, 79 for BR/EDR, 0 before the header: an
     * Ubertooth hears ONE of that many RF channels at a time, so every
     * count below is a sample of that one channel. */
    int      channels_of;
    /* Records. Each lands in exactly one of drop, adv, scan_req,
     * connect_ind, ext_adv, data_pdus, other, bredr, which sum to recv.
     * truncated overlaps them: a record decoded only up to its trusted
     * length is counted in its own bucket and here. */
    uint64_t recv;             /* records framed out of the stream */
    uint64_t drop;             /* refused at the edge, malformed, or over the record cap */
    uint64_t truncated;        /* PDU length claimed past the trusted length */
    uint64_t adv;              /* advertising PDUs that reached the device table */
    uint64_t scan_req;         /* SCAN_REQ: some scanner near the dongle is active */
    uint64_t connect_ind;      /* CONNECT_IND: a connection was set up */
    uint64_t ext_adv;          /* ADV_EXT_IND and later types, counted not decoded */
    uint64_t data_pdus;        /* data-channel PDUs (follow mode), counted not decoded */
    uint64_t other;            /* AUX_CONNECT_RSP and reserved advertising PDU types */
    uint64_t bredr;            /* DLT 255 packets */
    uint64_t bredr_iac;        /* of those, an inquiry access code: someone inquiring */
    time_t   last_frame_ts;    /* frame clock of the newest record, 0 = none */
    time_t   last_frame_wall;  /* arrival clock of it, 0 = none */
    int      stale_secs;       /* since a record last arrived, -1 = never */
} bt_capture_health_t;

/* One BR/EDR piconet as an Ubertooth hears it: by LAP only, the 24 bits
 * of the access code. The UAP and NAP are not in the access code or the
 * packet header (only an FHS payload carries them, and it is never
 * read), so no BD_ADDR and no vendor is ever derived from this row.
 * `ref_uap` is NOT sloth's observation: it is ubertooth-rx's reference
 * UAP for the piconet it tracks - configured with -u, or derived by
 * libbtbb itself - echoed in DLT 255's Reference UAP field when flag
 * 0x0080 is set, and it is kept only under that name. */
#define MAX_BREDR_LAPS 64
typedef struct {
    uint32_t lap;                /* 24-bit lower address part */
    uint8_t  iac;                /* 0x9E8B00..0x9E8B3F: an inquiry access code */
    uint8_t  has_rssi;
    int8_t   rssi, rssi_best;    /* dBm */
    int8_t   channel;            /* RF channel 0..78 last heard on */
    uint8_t  ref_uap_tool;       /* flag 0x0080 seen with this LAP as reference */
    uint8_t  ref_uap;            /* tool reference (-u or tool-derived), never observed */
    time_t   first_seen, last_seen;   /* frame clock */
    uint64_t count;              /* packets heard on the sampled channel */
} bredr_lap_t;

/* ── Capture-worker health (#91 slice 2) ─────────────────
 *
 * Both capture workers used to `break` out of their dispatch loop on a
 * negative pcap_dispatch() and return without publishing anything, so a
 * thread that died was indistinguishable from a quiet channel: the
 * handle stayed open, the tables stopped growing, and nothing said why.
 *
 * capture_exit_t is the classification of *why* a worker stopped.
 * NONE means it is still in its loop. The names are part of the JSONL
 * contract (`capture_exit` / `monitor_exit`) — see capture_exit_name().
 *
 * EOF is deliberately absent: sloth opens no savefiles, so an offline
 * end-of-capture state cannot be reached and a branch for it would be
 * untestable dead code. */
typedef enum {
    CAPTURE_EXIT_NONE = 0,       /* worker is still dispatching */
    CAPTURE_EXIT_STOPPED,        /* pcap_breakloop() after a stop request */
    CAPTURE_EXIT_IFACE_GONE,     /* the device the handle was bound to went away */
    CAPTURE_EXIT_PERM_LOST,      /* capability/permission revoked under us */
    CAPTURE_EXIT_NOT_ACTIVATED,  /* dispatch on a handle that was never activated */
    CAPTURE_EXIT_ERROR           /* any other PCAP_ERROR */
} capture_exit_t;

/* Liveness + drop accounting for one pcap handle. Refreshed once per
 * poll from the owning module (capture_health_poll / probe_health_poll).
 *
 * ps_* are lifetime totals accumulated from the per-tick deltas rather
 * than copied from libpcap, so a 32-bit counter that wraps or is reset
 * cannot make the exported total run backwards. d_* are that tick's
 * deltas — "am I dropping right now" is the operator question, and a
 * lifetime total answers it only by differencing two samples. */
typedef struct {
    int      open;              /* a pcap handle exists */
    int      running;           /* worker started and has not exited */
    int      exit_reason;       /* capture_exit_t */
    char     exit_detail[80];   /* pcap_geterr() text at exit, "" = none */
    int      stats_valid;       /* at least one pcap_stats() has landed */
    uint64_t ps_recv, ps_drop, ps_ifdrop;        /* lifetime, wrap-safe */
    uint32_t d_recv, d_drop, d_ifdrop;           /* delta over the last tick */
    uint32_t last_recv, last_drop, last_ifdrop;  /* previous raw sample */
    /* Per-stream freshness (#91). Two clocks, deliberately, because they
     * answer different questions and conflating them is the defect #92
     * fixed in this same callback:
     *
     *   last_frame_ts   the frame's OWN capture timestamp — what the
     *                   data says, reproducible from the capture, and
     *                   the value to correlate against other records.
     *   stale_secs      how long since a frame last ARRIVED, measured
     *                   on the host clock. This is the liveness
     *                   question: "is this stream still delivering?"
     *                   An offline replay carries timestamps far from
     *                   now, so deriving age from last_frame_ts would
     *                   report a dead stream for a healthy one.
     *
     * stale_secs is -1 until the first frame arrives: "never delivered"
     * is not the same claim as "delivered 0 seconds ago", and a
     * consumer that cannot tell them apart reads a stream that never
     * started as perfectly fresh. */
    time_t   last_frame_ts;
    int      stale_secs;
    /* Frames refused because their link-layer framing header did not
     * parse — for the monitor radio, a radiotap header radiotap_parse()
     * rejects (#123). Lifetime. Without it a radio delivering only
     * unparseable frames reads as a quiet channel. 0 on the IP stream,
     * which does not tally yet. Not exported to JSONL. */
    uint64_t parse_rejects;
} capture_health_t;

/* ── Capture-scope state (#85) ───────────────────────────
 *
 * Whether the launch-time allow-list (--iface / --monitor-only) is being
 * served as requested. The data-stream callback admits a frame only when
 * its SLL2 ingress index is in the (ifindex, name) set pinned before the
 * worker started; the poll loop re-checks each pin every tick and fails
 * one closed, for the rest of the run, the moment its index stops naming
 * the same interface (unplug, rename, index reuse, lookup failure).
 *
 * Fail-closed means nothing outside the scope is collected on the IP
 * capture stream in any state; the 802.11 monitor stream sits outside
 * the allow-list (owner decision, 2026-10-04). What NO_CAPTURE and
 * DEGRADED report is the other direction: part or all of what the
 * operator asked for is not being observed. Names are part of the JSONL
 * contract — see capture_scope_state_name(). */
typedef enum {
    CAPTURE_SCOPE_STATE_NONE = 0,   /* no restriction requested */
    CAPTURE_SCOPE_STATE_ENFORCED,   /* every requested iface pinned and still valid */
    CAPTURE_SCOPE_STATE_NO_CAPTURE, /* restriction requested, no live data-stream worker */
    CAPTURE_SCOPE_STATE_DEGRADED    /* >=1 requested iface failed closed */
} capture_scope_state_t;

/* Refreshed once per poll by capture_scope_poll(). */
typedef struct {
    int      state;       /* capture_scope_state_t */
    int      requested;   /* allow-list entries */
    int      enforced;    /* pins still admitting frames */
    uint32_t generation;  /* bumps each time a pin fails closed */
} capture_scope_health_t;

/* Cannot-persist state (#96): lifetime write-failure count per export
 * sink, refreshed once per poll by persist_health_poll(). Zero across
 * the board means every sink is keeping up; anything else renders the
 * tab-bar badge and is already summed into the JSONL sensor_health
 * record's storage failure field. */
typedef struct {
    int jsonl;        /* -o / --output stream (src/jsonl.c)      */
    int alert_pcap;   /* per-alert pcap export (src/alert_pcap.c) */
    int eapol;        /* --eapol-dir handshake export             */
} persist_health_t;

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
     * once at startup (--iface / --monitor-only) before the capture
     * thread is created, never mutated afterwards. The callback does not
     * read these names: capture_run() pins them to (ifindex, name) pairs
     * and that set is the authority (#85). Empty list =
     * unrestricted; startup refuses a requested scope that would leave
     * it empty or unenforceable. */
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
    int  pkt_detail_idx;       /* absolute packets[] index the panel shows */
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
    /* Enter detail (#106 round 2). Held by identity, not by row: the
     * table is re-sorted newest-first every tick, so a row index would
     * slide to another device under the operator. */
    int      device_detail;
    uint8_t  device_detail_mac[6];
    char     device_detail_ip[46];

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
    int            deauth_flood_active;  /* any victim aggregate currently flooded */
    deauth_victim_t deauth_victims[MAX_DEAUTH_VICTIMS];   /* (BSSID, victim) impact (#88) */
    int             deauth_victim_count;

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

    /* Research-corpus coverage (#73 slice 3). */
    research_cov_t research_cov[MAX_RESEARCH_COV];
    int            research_cov_count;
    int            research_sel;
    int            research_docs_total;   /* documents in the corpus */
    int            research_open;         /* 1 when a corpus is loaded */
    char           research_status[96];   /* why not, when it is not */

    /* FragAttacks per-BSS snapshot (#75 slice 5). */
    frag_bss_row_t frag_rows[MAX_FRAG_ROWS];
    int            frag_row_count;
    int            frag_sel;

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
    /* Hop-activity summary (#91), refreshed by chanhop_drive() each
     * poll while --hop is on; all zeroes otherwise. Answers whether the
     * radio is really rotating and whether the channels it visits ever
     * produce frames. chanhop_activity_t, declared in wifi_chanhop.h —
     * kept as plain fields here so sloth.h does not depend on it. */
    struct {
        int      channels;
        uint32_t visits;
        uint64_t frames;
        int      silent_channels;
        uint32_t cur_visits;
        uint64_t cur_frames;
    } hop_activity;
    /* Measured vs configured dwell (#91). A dwell is serviced only when
     * the poll loop next runs, so measured is the plan rounded up to
     * the poll interval; when the two diverge the scheduler's airtime
     * model is wrong and nothing else says so. chanhop_dwell_t in
     * wifi_chanhop.h, mirrored here to keep sloth.h independent. */
    struct {
        uint32_t last_planned_ms;
        uint32_t last_measured_ms;
        uint32_t worst_overshoot_ms;
        uint64_t completed;
        uint32_t mean_planned_ms;
        uint32_t mean_measured_ms;
    } hop_dwell;
    /* Requested vs confirmed monitor-radio channel (#91 slice 1):
     * chanhop_drive() used to call set_channel() without consuming its
     * return code, so the UI showed the intended channel even when the
     * retune silently failed. chan_confirmed only advances on a
     * successful set_channel(); chan_confirmed != chan_requested (both
     * non-zero) is a live, observable retune failure. */
    int            chan_requested;       /* channel last requested, 0 = none yet */
    int            chan_confirmed;       /* channel the platform actually confirmed, 0 = none yet */
    int            chan_retune_failures; /* lifetime count of failed set_channel() calls */
    /* Why (#91): the errno of the most recent FAILED retune - the
     * nl80211 ack's own error for a kernel refusal - kept across later
     * successes so it names the cause of the count above. 0 = never
     * failed. chanhop_retune_reason() buckets it for display. */
    int            chan_retune_last_errno;
    /* Rotation slots (chanhop index, CHANHOP_MAX <= 32) that have ever
     * refused a retune, published by chanhop_service(). Sticky, so it
     * is stable under the normal persistent case - one channel in a
     * --hop list the regdomain or driver will not take - where the
     * instantaneous requested/confirmed agreement flips twice per
     * rotation. That stability is what lets the sensor_health
     * change-only signature carry it (#91). */
    uint32_t       chan_refused_mask;
    /* Every retune-failure reason seen, one bit per
     * chanhop_retune_reason_bit() bucket, published by chanhop_service().
     * Sticky for the same reason as the mask above: two persistent
     * refusals with different causes (EINVAL from the regdomain on one
     * slot, EBUSY from the driver on another) alternate the last errno
     * twice a rotation, and signing over that brought the firehose back.
     * A reason never seen before is still news (#91 review). */
    uint32_t       chan_retune_reason_mask;
    char           probe_err[80];   /* last probe open/set error, "" = ok */

    /* Capture-worker liveness and drop accounting (#91 slice 2).
     * cap_health is the data-stream handle ("any"), mon_health the
     * monitor radio. Refreshed once per poll; exported by the
     * `sensor_health` JSONL record and the interface view's health
     * strip (#91 slice 3). */
    capture_health_t cap_health;
    capture_health_t mon_health;
    /* Launch-time scope enforcement (#85); same record, same strip. */
    capture_scope_health_t scope_health;
    /* Cannot-persist state (#96): per-sink lifetime write-failure
     * counts, synced once per tick by persist_health_poll() and
     * rendered as a tab-bar badge — an export that fails must be
     * visible from every view, not only its own. */
    persist_health_t persist_health;
    /* Bluetooth host source (#144 slice 2): the HCI monitor channel
     * (--bt-monitor) or a DLT 254 replay. bt_iface is "" when neither
     * is configured. */
    char             bt_iface[24];
    char             bt_err[80];
    capture_health_t bt_health;
    ble_host_t       ble_host;
    ble_device_t     ble_devices[MAX_BLE_DEVICES];
    int              ble_device_count;
    ble_rot_stats_t  ble_rot;             /* #156: --ble-rotation-hints, aggregates only */
    /* #144 slice 4: advertising-flood windows and the [*] BLE view. */
    ble_flood_row_t  ble_flood[MAX_BLE_FLOOD];
    int              ble_flood_count;
    int              ble_sel;
    int              ble_detail;          /* 1 while Enter's detail is open */
    uint8_t          ble_detail_addr[6];  /* the row the detail was opened on */
    uint8_t          ble_detail_type;
    char             ble_detail_iface[24];
    /* Ubertooth capture stream (#144 slice 3): --bt-capture PATH. */
    bt_capture_health_t btcap;
    bredr_lap_t      bredr_laps[MAX_BREDR_LAPS];
    int              bredr_lap_count;

    /* ── PNL snapshot (Preferred Network Lists per client) ── */
    pnl_client_t   pnl_clients[MAX_PNL_CLIENTS];
    int            pnl_count;
    int            pnl_sel;

    /* ── EAPOL / PMKID / 4-way handshake snapshot ─────────── */
    eapol_event_t  eapol_events[MAX_EAPOL_EVENTS];
    int            eapol_count;
    int            eapol_sel;
    /* --eapol-dir write failures (#87): count + latest reason, so a
     * failing handshake export is visible in the TUI, not only in a
     * one-line stderr notice the screen may have painted over. */
    int            eapol_export_failures;
    char           eapol_export_err[160];

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
    /* What clients asked for (#60), paired with the grants above by
     * (bssid, sta). Same bound: a request only matters once there is a
     * grant to compare it against. */
    assoc_req_t          assoc_reqs[MAX_ASSOC_ENTRIES];
    int                  assoc_req_count;
    int                  assoc_sel;
    /* 802.11v steering (#59). Sits with the association tables because
     * it answers the same question from the other end: assoc_t is where
     * a client landed, btm_steer_t is who told it to move. */
    btm_steer_t          btm_steers[MAX_BTM_PAIRS];
    int                  btm_steer_count;
    /* Action frames declined as PMF ciphertext (#124). Shown beside the
     * BTM count so an empty steering table on a PMF network reads as
     * "unreadable", not "nothing happening". */
    int                  action_protected_count;
    /* Channel-switch announcements (#63), newest first. */
    sloth_csa_event_t    csa_events[SLOTH_CSA_MAX_EVENTS];
    int                  csa_count;
    /* 802.11k survey activity (#61), busiest first. */
    sloth_rrm_pair_t     rrm_pairs[SLOTH_RRM_MAX_PAIRS];
    int                  rrm_pair_count;
    /* Wi-Fi 7 Multi-Link Devices (#67). */
    sloth_mld_t          mlds[SLOTH_MLD_MAX];
    int                  mld_count;
    /* Per-BSSID Multi-Link advertisement (#104 slice 6). */
    sloth_mle_bss_t      mle_bss[SLOTH_MLE_BSS_MAX];
    int                  mle_bss_count;
    /* Captive-portal interception events (#69), newest first. */
    cp_event_t           cp_events[CP_MAX_EVENTS];
    int                  cp_event_count;

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
    lan_role_t     lan_roles[MAX_LAN_ROLES];      /* #155 router-role vetoes */
    int            lan_role_count;
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

    /* ── WS-Discovery / ONVIF devices (#106) ──────────────── */
    onvif_device_t onvif_devices[MAX_ONVIF_DEVICES];
    int            onvif_count;

    /* ── RTSP DESCRIBE outcomes (#106 slice B) ─────────────── */
    rtsp_stream_t  rtsp_streams[MAX_RTSP_STREAMS];
    int            rtsp_stream_count;

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
 * ingress iface: deselected, or absent from a non-empty allow-list —
 * and, with a non-empty list, when the ingress iface cannot be
 * resolved at all (capture_frame_in_scope(), #85).
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

/* Format the monitor radio's --hop scan state into buf[sz]: the channel
 * list with the currently-dwelt channel bracketed, e.g.
 * "  ch: 1  6 [11] 36 44". A '?' inside the bracket (issue #91 slice 1)
 * means the last retune sloth requested has not been confirmed by the
 * platform (chan_confirmed != chan_requested) — the radio may still be
 * parked on the previous channel. scan_chan_count == 0 renders
 * "  [scanning]" (no live hop list). */
void iface_fmt_scan_bar(const sloth_state_t *s, char *buf, int sz);

/* Format the one-line sensor-health strip the interface view renders
 * under its rows (issue #91 slice 3). Always names both capture
 * streams — "cap" (the IP data stream) and "mon" (the monitor radio) —
 * as `off` (no handle), `up` (worker dispatching) or
 * `down (<reason>)` (worker exited; reason from capture_exit_name()).
 * Everything after that is a fault and appears only when non-zero:
 * per-stream `drop` / `ifdrop`, `retune-fail` from the #91 slice 1
 * counter, `evict` from the table-overflow tally, and `scope degraded
 * <enforced>/<requested>` or `scope no-capture` when a requested
 * --iface/--monitor-only scope is not being served (#85). A fully healthy
 * sensor therefore renders exactly "  health: cap up  mon up", which
 * is the line an operator learns to glance past. */
void iface_fmt_health_strip(const sloth_state_t *s, char *buf, int sz);

/* ── Merged packet timeline (shared by packets view + dashboard band) ──
 * One chronological sequence over BOTH capture streams: the IP packet
 * ring and the 802.11 monitor-frame snapshot. Position k counts from
 * the oldest (k = 0) to the newest (count - 1). pkt_mon_merged_at()
 * fills *is_mon and *idx — an absolute packets[] ring index, or a
 * mon_frames[] index (0 = newest) — and returns 0 when k is out of
 * range. Ties (the mon clock is whole seconds) order the mon frame
 * first. Lives in src/views/packets.c. */
int pkt_mon_merged_count(const sloth_state_t *s);
int pkt_mon_merged_at(const sloth_state_t *s, int k, int *is_mon, int *idx);

/* ── Key routing: does the active view claim this key over the global
 * view-switch letters? Kept in main.c as a small, centralized table;
 * exposed for direct unit-test coverage of the routing decision. */
int view_claims_key(view_t v, int key);

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
     * (issue #22, gated behind --hop). Returns 0 on an acknowledged
     * retune, or a NEGATIVE ERRNO saying why not (#91): -EOPNOTSUPP
     * where the platform or build cannot retune, the kernel's own
     * refusal (-EBUSY, -EINVAL, -EPERM) from the nl80211 ack. It used
     * to be a bare -1, which read as an errno is -EPERM. One of
     * two kernel-state writes reachable through this vtable — wifi_scan
     * kicks an nl80211 scan trigger when --allow-active permitted it
     * (#84). */
    int  (*set_channel)(const char *iface, int freq_mhz);
} platform_ops_t;

extern platform_ops_t g_platform;

#endif /* SLOTH_H */
