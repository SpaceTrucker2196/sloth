/* Which alert types' detail text slothweb shows (owner request
 * 2026-10-23..26: numbers, addresses, ports, channels and network names
 * only).
 *
 * An alert's detail is the text its rule wrote with snprintf() in
 * src/alerts/ (every .c), and for several rules that text carries what the wire
 * said in the clear: CLEARTEXT_CRED's username, SNMP_COMMUNITY_BRUTE's
 * community, RDP_BRUTE_FORCE's mstshash cookie, MQTT_BROKER_BRUTE's
 * username, SSH_BRUTE_FORCE's server banner, and free text (host names,
 * query names, paths, user agents, vendor strings) in others. So the
 * detail is withheld by default and shown only for the types listed
 * here, each audited: every snprintf() into the detail of every fire()
 * site of the type formats only numbers, string literals, and variables
 * holding an address, a MAC, a BSSID or an SSID (the names in
 * web_alert_fmt_names[]), plus the per-type names the row lists with its
 * reason. web/tests/test_alertfmt.c reads src/alerts/ (every .c) and fails if a
 * listed type's format gains any other string field, or a field named
 * for a username, credential, community, cookie or free text; and it
 * holds the credential-bearing types off the list.
 *
 * Every place a detail leaves slothweb asks web_alert_detail_ok(): the
 * stream's lifecycle records (web_live.c, before the detail is even
 * kept), the ticker's summary of them, and sloth.db's alerts.detail,
 * which the reader's SQL only selects through the web_detail_ok() SQL
 * function (web_alertdb.c), so a withheld detail never leaves SQLite. */
#ifndef SLOTHWEB_ALERTFMT_H
#define SLOTHWEB_ALERTFMT_H

#include <stddef.h>

typedef struct {
    const char *type;        /* the ALERT_TYPE_ suffix */
    const char *extra;       /* space-separated extra field names, or "" */
    const char *why;         /* why those extra names hold no free text */
} web_adf_t;

extern const web_adf_t   web_alert_detail_audited[];
extern const size_t      web_alert_detail_audited_n;
/* The variable names (their last member, an array index dropped) that a
 * listed type may format with %s: addresses, MACs, BSSIDs, SSIDs. */
extern const char *const web_alert_fmt_names[];
/* Substrings no %s field of a listed type may be named for. */
extern const char *const web_alert_fmt_banned[];

/* Is a detail of this alert type (sloth_alerts.def's row number, the
 * JSONL `ty`) shown? 0 for an unknown or negative type. */
int web_alert_detail_ok(long long type);

#endif
