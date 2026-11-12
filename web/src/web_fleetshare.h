/* Fleet sharing: monitor data only (owner hard rule, 2026-11-12;
 * docs/wiki/adr/0009-fleet-monitor-only.md, docs/wiki/fleet.md "What
 * travels"). The owner's words: "when sloth shares data include the
 * local host name and also only share passively monitored data, do not
 * share information on the local wifi network the client is connected
 * to via authenticated wifi. ... local network data should only be
 * stored on local clients on the local network." And, the same day,
 * asked whether the joined network's own APs and stations may travel:
 * "yes anything that is thru monitor mode is game".
 *
 * So the rule is provenance, not subject: whatever sloth heard in
 * monitor mode (the monitor radio, the BLE receivers, the GNSS receiver,
 * the ADS-B SDR) travels, the joined network's APs and stations as
 * heard over the air and the operator's own networks included; what the
 * host learned through the joined network or the wire (the managed
 * card's scan and station dump, ARP, DHCP, mDNS, NBNS, DNS, the flows,
 * IP addresses, host names) never does, and a row known only that way
 * never travels.
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
 *   - which device rows travel (web_fleet_share_dev());
 *   - what the importer refuses (web_fleet_share_refuses()).
 *
 * Pure: no SQLite, no locks. */
#ifndef SLOTHWEB_FLEETSHARE_H
#define SLOTHWEB_FLEETSHARE_H

#include <stddef.h>

#include "web_fleet.h"
#include "web_jsonl.h"
#include "web_slothdb.h"

/* The header's share_rule: an export that states it filtered its rows by
 * this rule. "monitor_only/2" is the provenance rule (2026-11-12, the
 * owner's "anything that is thru monitor mode is game"); "monitor_only"
 * the first cut of it the same day, which withheld more and is taken as
 * attested too. An answer with neither (a build before the rule) is not
 * trusted with any row whose provenance only the sender can judge. */
#define WEB_FLEET_SHARE_RULE    "monitor_only/2"
#define WEB_FLEET_SHARE_RULE_V1 "monitor_only"
/* 1 when rule is one this importer takes as attested. */
int  web_fleet_share_rule_ok(const char *rule);

/* The alert types that travel, and the ones that never do, each
 * NULL-ended, by sloth's name (ALERT_TYPE_<name>). */
extern const char *const web_fleet_share_alerts[];
extern const char *const web_fleet_withheld_alerts[];
/* 1 when an alert of this type may travel; 0 for every other name,
 * NULL, and a name on neither list. */
int  web_fleet_alert_shareable(const char *name);

/* May this device row travel? d is read in the Monitor scope
 * (web_scope.h: no address, no name, sources masked to the radio's,
 * first and last seen and signal from the radio's own tables); it
 * travels when the radio heard it, whatever else the LAN knows of it.
 * Withheld: a row the radio did not hear (known only from the LAN or the
 * station dump), one carrying an address or a name (not read in the
 * scope), the host's own interfaces and the roster (DEV_RISK_SELF), and
 * the host's own radios self[0..nself) by address. */
int  web_fleet_share_dev(const web_sdb_dev_t *d, const char (*self)[WEB_FLEET_MAC_SZ],
                         int nself);

/* The importer's rule over one decoded line of a peer's answer: NULL
 * when it may be stored, else why it is refused (a word). attested: the
 * answer's header states a rule web_fleet_share_rule_ok() takes.
 * Refused: wifi, ap and probe from an answer that does not state the
 * rule; an alert or a verdict of a type not on the allow-list; an alert
 * naming an address (ip); a verdict on an IP address. own_net (the
 * operator's own networks, configuration about what the radio hears)
 * is taken. */
const char *web_fleet_share_refuses(const char *type, const web_jrec_t *r, int attested);

#endif
