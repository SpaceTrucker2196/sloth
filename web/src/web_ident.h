/* slothweb identity tables (#161, M3): what sloth's stream already says
 * about who a device is, for rules A2, A5, A6 and A8 (web_anomaly.h).
 * slothweb resolves nothing and reads no sloth.db here: every name and
 * binding below is a field of a record src/jsonl.c writes.
 *
 *   MAC first_seen   probe_client.first_seen, pnl_client.first_seen and
 *                    assoc.first_seen (sta_mac): sloth's own first sight
 *                    of the row. The earliest one seen is kept.
 *   MAC randomised   the locally administered bit of the MAC's first
 *                    octet, which is exactly how sloth sets the
 *                    mac_random it writes on pnl_client and
 *                    seqnum_client (src/probe_pnl.c, src/seqnum_track.c).
 *   MAC <-> IP       arp (ip, mac) and device (mac, ip): the latest
 *                    binding wins on both sides.
 *   DHCP hostname    dhcp_lease.hostname (by ip) and device.hostname (by
 *                    mac; sloth copies the lease hostname onto the
 *                    device whose ARP IP matches it, src/devices.c).
 *   mDNS host        mdns_service.host (by ip), the SRV target.
 *   NBNS name        nbns_name.name (by ip), for suffix 0x00
 *                    (workstation) and 0x20 (server) only: the group
 *                    suffixes name a domain or workgroup, not a host.
 *   DNS by client    sloth's dns record names the sender only: a query's
 *                    src is the client, an answer's src the resolver, and
 *                    no record names the client an answer went to. So a
 *                    client's NXDOMAIN share is joined here: a query's
 *                    qname is remembered (as a 64-bit hash, never the
 *                    text) with its client for WEB_ID_DNS_MATCH_S, and an
 *                    NXDOMAIN answer for that qname is counted against
 *                    that client, once. Counted per client per minute
 *                    over the last WEB_ID_DNS_MINUTES minutes.
 *
 * Not in the stream, so not here: any first_seen for a wired-only MAC
 * (arp and device carry none, so A2 sees only stations sloth heard over
 * the air), and a vendor (A4 needs the OUI table, #162).
 *
 * Every name is cut to WEB_ID_NAME_MAX bytes on a code-point boundary
 * as it is stored, and leaves only through web_jw_str(). A name is
 * current for WEB_ID_TTL_S after the record that last carried it.
 * Comparison uses a normal form: ASCII lower case, the first label only
 * (so "laptop", "laptop.local" and "LAPTOP" agree), cut to the 15 bytes
 * NetBIOS keeps when either side is an NBNS name.
 *
 * Every table is bounded and evicts its least recently seen row when
 * full; evictions are counted (web_ident_stats(), on /api/health). The
 * ingest thread writes, the store thread reads; one mutex. */
#ifndef SLOTHWEB_IDENT_H
#define SLOTHWEB_IDENT_H

#include <pthread.h>
#include <stdint.h>

#include "web_jsonl.h"
#include "web_rollup.h"

#define WEB_ID_NAME_MAX     63
#define WEB_ID_NBNS_MAX     15
#define WEB_ID_TTL_S        900
#define WEB_ID_DNS_MATCH_S  10
#define WEB_ID_DNS_MINUTES  10
#define WEB_ID_QSLOTS       4096    /* remembered queries, a power of two */

enum { WEB_ID_SRC_DHCP = 0, WEB_ID_SRC_MDNS, WEB_ID_SRC_NBNS, WEB_ID_SRC_COUNT };

typedef struct {
    char      name[WEB_ID_NAME_MAX + 1];
    long long t;                     /* -1: none */
} web_id_name_t;

typedef struct {
    char          mac[WEB_KEY_MAX + 1];
    int           used, next;
    long long     last_seen;
    long long     first_seen;        /* the record's own; -1 none */
    char          first_src[16];
    int           random;
    char          ip[WEB_KEY_MAX + 1];
    long long     ip_t;
    web_id_name_t dhcp;              /* device.hostname */
} web_id_mac_t;

typedef struct {
    char          ip[WEB_KEY_MAX + 1];
    int           used, next;
    long long     last_seen;
    char          mac[WEB_KEY_MAX + 1];
    long long     mac_t;
    web_id_name_t name[WEB_ID_SRC_COUNT];
    /* DNS by client, per minute: [i] is minute dns_t[i] / 60. */
    long long     dns_t[WEB_ID_DNS_MINUTES];
    uint32_t      dns_q[WEB_ID_DNS_MINUTES], dns_nx[WEB_ID_DNS_MINUTES];
} web_id_ip_t;

typedef struct {
    uint64_t  h;                     /* qname hash; 0 empty */
    long long t;
    char      client[WEB_KEY_MAX + 1];
} web_id_query_t;

typedef struct {
    int           macs, mac_cap, ips, ip_cap;
    unsigned long mac_evictions, ip_evictions;
    unsigned long dns_matched, dns_unmatched, query_overwrites;
} web_id_stats_t;

typedef struct web_ident {
    pthread_mutex_t mu;
    web_id_mac_t   *mac;
    int            *mac_head;
    int             mac_cap, mac_n, mac_nhead;
    web_id_ip_t    *ip;
    int            *ip_head;
    int             ip_cap, ip_n, ip_nhead;
    web_id_query_t *q;
    web_id_stats_t  st;
} web_ident_t;

/* mac_cap MACs and ip_cap IPs (--web-max-keys and half of it). 0, or
 * -1 (memory). */
int  web_ident_init(web_ident_t *id, int mac_cap, int ip_cap);
void web_ident_destroy(web_ident_t *id);

/* One decoded record at now_s (slothweb's clock). */
void web_ident_record(web_ident_t *id, const web_jrec_t *r, long long now_s);

void web_ident_stats(web_ident_t *id, web_id_stats_t *out);

/* The comparison form of a name into out (WEB_ID_NAME_MAX + 1 bytes);
 * "" when nothing is left. */
void web_ident_norm(const char *name, char *out);

/* ── what the rules read (store thread) ─────────────────────────────── */

/* Each reader fills at most max rows and returns how many rows there
 * were, which is more than max when it had to stop short: the caller
 * counts that (a scan cut short skips whatever is in the later slots).
 * The rule engine sizes its buffers from the tables' caps, so it never
 * should. */

/* A2: every MAC that is not randomised, with a first_seen of its own
 * at or after since. */
typedef struct {
    char      mac[WEB_KEY_MAX + 1];
    long long first_seen;
    char      src[16];
} web_id_new_t;
int  web_ident_firsts(web_ident_t *id, long long since, web_id_new_t *out,
                      int max);

/* A5: (mac, name, source, randomised) for every MAC with a current
 * DHCP or mDNS name: its own device hostname, or the DHCP and mDNS
 * names of the IP that is bound to it now (and only while that IP's
 * own MAC binding is this MAC, so a lease handed to another device does
 * not name both). At most three rows per MAC. */
typedef struct {
    char mac[WEB_KEY_MAX + 1];
    char name[WEB_ID_NAME_MAX + 1];
    char norm[WEB_ID_NAME_MAX + 1];
    int  src;                         /* WEB_ID_SRC_DHCP or _MDNS */
    int  random;
} web_id_named_t;
int  web_ident_named(web_ident_t *id, long long now_s, web_id_named_t *out,
                     int max);

/* A6: every IP with current names from at least two sources. */
typedef struct {
    char ip[WEB_KEY_MAX + 1];
    char name[WEB_ID_SRC_COUNT][WEB_ID_NAME_MAX + 1];   /* "" absent */
} web_id_names_t;
int  web_ident_ip_names(web_ident_t *id, long long now_s, web_id_names_t *out,
                        int max);

/* A8: per client IP, queries and NXDOMAIN answers in the minutes
 * [to - WEB_ID_DNS_MINUTES*60, to). */
typedef struct {
    char     ip[WEB_KEY_MAX + 1];
    uint32_t q, nx;
} web_id_dns_t;
int  web_ident_dns(web_ident_t *id, long long to, web_id_dns_t *out, int max);

const char *web_ident_src_name(int src);

#endif
