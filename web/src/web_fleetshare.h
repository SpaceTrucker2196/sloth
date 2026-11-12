/* Fleet sharing: monitor data only (owner hard rule, 2026-11-12;
 * docs/wiki/adr/0009-fleet-monitor-only.md, docs/wiki/fleet.md "What
 * travels"). The owner's words: "when sloth shares data include the
 * local host name and also only share passively monitored data, do not
 * share information on the local wifi network the client is connected
 * to via authenticated wifi. ... local network data should only be
 * stored on local clients on the local network."
 *
 * What this module decides, for the export (web_fleet.c) and for the
 * importer, which applies the same rule to what a peer sends so an older
 * or hostile peer cannot plant local-network data here:
 *
 *   - which alert types travel: an explicit allow-list by name, every
 *     other type withheld, a type sloth adds later withheld until it is
 *     classified here (test_fleetshare.c holds every row of
 *     include/sloth_alerts.def to exactly one of the two lists, and every
 *     shareable type to a Monitor tag in web_scope.c);
 *   - this host's local network (web_fleet_local_t): the networks its
 *     managed card is or was joined to (wifi_aps.status >= 0, the
 *     station dump wifi_stas), every BSSID that carried a joined SSID,
 *     slothweb's own --my-ssid / --my-bssid, every MAC the neighbour
 *     table ever held (a host on the LAN), and this host's own radios.
 *     A device in it is a station of the local network, withheld whole;
 *     an AP in it is the local network, withheld whole; an SSID in it is
 *     not named by any line that travels. A read that fails or a set
 *     past its bound makes the whole set unknown, and then no sloth.db
 *     row travels (fail closed);
 *   - what the importer refuses (web_fleet_share_refuses()).
 *
 * Pure but for the sloth.db reads, which go through the M4 reader and
 * its column allow-list like every other. */
#ifndef SLOTHWEB_FLEETSHARE_H
#define SLOTHWEB_FLEETSHARE_H

#include <stddef.h>

#include "web_fleet.h"
#include "web_jsonl.h"
#include "web_slothdb.h"

/* The header's share_rule: an export that states it filtered its rows by
 * this rule. An answer without it (a build before the rule) is not
 * trusted with any row whose provenance only the sender can judge. */
#define WEB_FLEET_SHARE_RULE   "monitor_only"

/* Bounds of the local network's sets; past one, the set is unknown. */
#define WEB_FLEET_LOCAL_BSSIDS 1024
#define WEB_FLEET_LOCAL_SSIDS  64
#define WEB_FLEET_LOCAL_MACS   8192
/* A device's associations looked at, at most; more, and it is withheld. */
#define WEB_FLEET_LOCAL_ASSOCS 256

/* The alert types that travel, and the ones that never do, each
 * NULL-ended, by sloth's name (ALERT_TYPE_<name>). */
extern const char *const web_fleet_share_alerts[];
extern const char *const web_fleet_withheld_alerts[];
/* 1 when an alert of this type may travel; 0 for every other name,
 * NULL, and a name on neither list. */
int  web_fleet_alert_shareable(const char *name);

typedef struct {
    int    ok;                       /* every read ran to its end, every set fits */
    int    nbssid, nssid, nmac;
    char (*bssid)[WEB_FLEET_MAC_SZ]; /* sorted */
    char (*ssid)[WEB_FLEET_SSID_MAX + 1];
    char (*mac)[WEB_FLEET_MAC_SZ];   /* sorted */
} web_fleet_local_t;

/* This host's local network from sloth.db (c, NULL when it is not open:
 * nothing of it is then exported), the operator's own networks (mine,
 * may be NULL) and its own radios (own_csv, may be NULL). 0, or -1 with
 * ok 0 (a read failed, or a set is past its bound). Free with
 * web_fleet_local_free() either way. */
int  web_fleet_local_build(web_fleet_local_t *l, web_sdb_conn_t *c,
                           const web_fleet_mine_t *mine, const char *own_csv);
void web_fleet_local_free(web_fleet_local_t *l);
/* Is mac (any case) a BSSID or a station of the local network? */
int  web_fleet_local_addr(const web_fleet_local_t *l, const char *mac);
/* Is ssid one of the local network's SSIDs? */
int  web_fleet_local_ssid(const web_fleet_local_t *l, const char *ssid);
/* Does text name one of them (a substring), as an alert title can? */
int  web_fleet_local_names(const web_fleet_local_t *l, const char *text);
/* Every address of the set (BSSIDs, then stations), for an alert key's
 * check (web_sdb_keychk_open()); the count, at most max. */
int  web_fleet_local_needles(const web_fleet_local_t *l, const char **out, int max);

/* May this device row travel? d is read in the Monitor scope
 * (web_scope.h: no address, no name, sources masked to the radio's);
 * it travels only when the radio heard it, it is not the host's own or
 * a rostered device (DEV_RISK_SELF), and it is not in the local network. */
int  web_fleet_share_dev(const web_fleet_local_t *l, const web_sdb_dev_t *d);

/* The importer's rule over one decoded line of a peer's answer: NULL
 * when it may be stored, else why it is refused (a word). attested: the
 * answer's header states WEB_FLEET_SHARE_RULE. Refused: own_net (a
 * site's own networks never travel); wifi, ap and probe from an answer
 * that does not state the rule; an alert or a verdict of a type not on
 * the allow-list; an alert naming an address (ip); a verdict on an IP
 * address. */
const char *web_fleet_share_refuses(const char *type, const web_jrec_t *r, int attested);

#endif
