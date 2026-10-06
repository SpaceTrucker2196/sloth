#ifndef ONVIF_DISCOVERY_H
#define ONVIF_DISCOVERY_H

#include <stdint.h>
#include "sloth.h"

/* Passive WS-Discovery / ONVIF snoop — UDP/3702 payload (multicast
 * 239.255.255.250 / ff02::c, OASIS WS-Discovery 1.1, 2009-07-01).
 *
 * sloth transmits nothing here. A Target Service (an ONVIF camera, in
 * the case this module cares about) announces its own presence with a
 * multicast Hello when it joins the network, a multicast Bye when it
 * leaves, and answers a client's Probe with a unicast ProbeMatches —
 * all unauthenticated, all broadcast or sent to the asker regardless
 * of who they are. sloth only reads what was already put on the wire. */

typedef struct {
    char uuid[48];      /* "urn:uuid:<...>" from EndpointReference/Address, "" = absent */
    char types[96];     /* d:Types text, e.g. "dn:NetworkVideoTransmitter" */
    char scopes[192];    /* d:Scopes text, space-separated onvif:// URIs   */
    char xaddrs[160];    /* d:XAddrs text, device service URL             */
    char kind[16];       /* "Hello", "Bye", "ProbeMatch", "ResolveMatch"   */
    int  is_camera;      /* 1 if Types names a NetworkVideoTransmitter    */
} onvif_msg_t;

/* Pure parse, no side effects: decides whether `data` is a WS-Discovery
 * Hello / Bye / ProbeMatches / ResolveMatches body and, if so, fills
 * `out`. A plain client Probe is not one of the four — it carries no
 * XAddrs/Types of its own — and is deliberately not recognised here.
 * Returns 1 on a recognised message, 0 otherwise.
 *
 * Leaf-element extraction (Types/Scopes/XAddrs) assumes the schema's
 * own content model: xs:list / xs:anyURI text, never a sub-element
 * (OASIS WS-Discovery 1.1 §2). It does not handle XML attributes on
 * those elements, CDATA, or an element name that recurs inside a text
 * value — none of which real WS-Discovery stacks produce for these
 * three fields. */
int onvif_ws_discovery_parse(const uint8_t *data, int len, onvif_msg_t *out);

/* Observe one UDP/3702 payload: parse + update the device table, keyed
 * by EndpointReference UUID (falling back to source IP when a message
 * carries none, which Bye never does but a malformed frame might).
 * Fills info/infosz with a short human-readable description. Returns
 * 1 if the payload was a recognised WS-Discovery message, 0 otherwise. */
int onvif_ws_discovery_snoop(const char *src_ip, const uint8_t *data, int len,
                             char *info, int infosz);

/* Copy the current device table into state under lock. */
void onvif_snapshot(sloth_state_t *s);

/* Clear the device table. */
void onvif_clear(void);

#endif /* ONVIF_DISCOVERY_H */
