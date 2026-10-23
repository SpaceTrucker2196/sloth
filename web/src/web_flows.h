/* slothweb Flows routes (#164, M6): docs/web-ui-spec.md §8.9, the
 * protocol flow tables of sloth.db through the M4 reader and its
 * column allow-list (web_slothdb.h). Every route needs --sloth-db;
 * without it each is a 503 "no_sloth_db", as History's are.
 *
 *   /api/flows?proto=&from=&to=&ip=&sort=&limit=&offset=
 *       one tab's rows overlapping [from, to) (History's range rules:
 *       the last 30 days by default, at most 400): src, dst (null for
 *       the per-source ldap and kerb tables), the table's counters in
 *       "columns" order, their total, the SMB server port and dialect
 *       ("smb1": true for an SMB1 session), the RDP proto_mask or the
 *       SNMP version, first and last seen. proto is required: ssh,
 *       rdp, smb, snmp, ldap, kerb or bgp; mqtt is refused
 *       ("proto_withheld": mqtt_flows holds MQTT usernames and is never
 *       read). ip (a literal address, canonicalised) matches src or
 *       dst. sort: last (default), total, src. limit 1..200 (default
 *       50), offset 0..1,000,000. "total" is every matching row; a page
 *       that would not fit its buffer stops early with "more", and the
 *       next page starts at offset + count. Columns a table has that
 *       slothweb does not read are named in "withheld".
 *   /api/flows/graph?from=&to=&nodes=&edges=
 *       the src -> dst pairs of the pair tables (ssh, rdp, smb, snmp,
 *       bgp), for the chord diagram: the `edges` largest by total
 *       (1..200, default 80), and of their endpoints the `nodes`
 *       busiest (2..64, default 24). A pair with an end outside those
 *       nodes is folded, and so is every pair past the `edges`
 *       largest; "fold" states how many pairs, flows and nodes were
 *       folded out of how many. "tabs" gives each tab's rows and total
 *       in the range (null for a table the file lacks; mqtt
 *       "withheld"), for the tab strip.
 *
 * Parameters are validated whole as /api/series's are; a refusal is a
 * 400 with a reason word of slothweb's own. */
#ifndef SLOTHWEB_FLOWS_H
#define SLOTHWEB_FLOWS_H

#include <stddef.h>

#include "web_devices.h"

#define WEB_FLOWS_LIMIT       50
#define WEB_FLOWS_LIMIT_MAX   200
#define WEB_FLOWS_OFFSET_MAX  1000000
#define WEB_FLOWS_NODES       24
#define WEB_FLOWS_NODES_MIN   2
#define WEB_FLOWS_NODES_MAX   64
#define WEB_FLOWS_EDGES       80
#define WEB_FLOWS_EDGES_MAX   200

int web_flows_route(const web_m4_t *m, const char *query, long long now_s,
                    char *body, size_t cap, size_t *len, int *status);
int web_flows_graph_route(const web_m4_t *m, const char *query,
                          long long now_s, char *body, size_t cap,
                          size_t *len, int *status);

#endif
