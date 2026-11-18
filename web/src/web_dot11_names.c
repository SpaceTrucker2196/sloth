#include "web_dot11_names.h"

#include <stddef.h>

/* IEEE Std 802.11-2020 Table 9-1, Valid type and subtype combinations. */
static const char *const MGMT[16] = {
    "Association Request", "Association Response", "Reassociation Request",
    "Reassociation Response", "Probe Request", "Probe Response",
    "Timing Advertisement", "reserved", "Beacon", "ATIM", "Disassociation",
    "Authentication", "Deauthentication", "Action", "Action No Ack", "reserved",
};
static const char *const CTRL[16] = {
    "reserved", "reserved", "Trigger", "TACK", "Beamforming Report Poll",
    "VHT/HE NDP Announcement", "Control Frame Extension", "Control Wrapper",
    "Block Ack Request", "Block Ack", "PS-Poll", "RTS", "CTS", "Ack", "CF-End",
    "CF-End+CF-Ack",
};
static const char *const DATA[16] = {
    "Data", "Data+CF-Ack", "Data+CF-Poll", "Data+CF-Ack+CF-Poll", "Null",
    "CF-Ack", "CF-Poll", "CF-Ack+CF-Poll", "QoS Data", "QoS Data+CF-Ack",
    "QoS Data+CF-Poll", "QoS Data+CF-Ack+CF-Poll", "QoS Null", "reserved",
    "QoS CF-Poll", "QoS CF-Ack+CF-Poll",
};

const char *web_dot11_subtype_name(unsigned type, unsigned subtype) {
    if (subtype > 15) return "reserved";
    switch (type) {
    case 0: return MGMT[subtype];
    case 1: return CTRL[subtype];
    case 2: return DATA[subtype];
    case 3: return subtype == 0 ? "DMG Beacon" : subtype == 1 ? "S1G Beacon" : "reserved";
    default: return "reserved";
    }
}

/* Table 9-49, Reason codes, 0..66 as of IEEE Std 802.11-2020. The
 * entries for 46 and 47 carry two meanings in the table (a DLS Teardown
 * and a Disassociation); the Disassociation meaning is the one a
 * monitor sees. */
static const char *const REASON[] = {
    /* 0 */ "reserved",
    /* 1 */ "Unspecified reason",
    /* 2 */ "Previous authentication no longer valid",
    /* 3 */ "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS",
    /* 4 */ "Disassociated due to inactivity",
    /* 5 */ "Disassociated because AP is unable to handle all currently associated STAs",
    /* 6 */ "Class 2 frame received from nonauthenticated STA",
    /* 7 */ "Class 3 frame received from nonassociated STA",
    /* 8 */ "Disassociated because sending STA is leaving (or has left) BSS",
    /* 9 */ "STA requesting (re)association is not authenticated with responding STA",
    /* 10 */ "Disassociated because the information in the Power Capability element is unacceptable",
    /* 11 */ "Disassociated because the information in the Supported Channels element is unacceptable",
    /* 12 */ "Disassociated due to BSS transition management",
    /* 13 */ "Invalid element",
    /* 14 */ "Message integrity code (MIC) failure",
    /* 15 */ "4-way handshake timeout",
    /* 16 */ "Group key handshake timeout",
    /* 17 */ "Element in 4-way handshake different from (Re)Association Request/Probe Response/Beacon frame",
    /* 18 */ "Invalid group cipher",
    /* 19 */ "Invalid pairwise cipher",
    /* 20 */ "Invalid AKMP",
    /* 21 */ "Unsupported RSNE version",
    /* 22 */ "Invalid RSNE capabilities",
    /* 23 */ "IEEE 802.1X authentication failed",
    /* 24 */ "Cipher suite rejected because of the security policy",
    /* 25 */ "TDLS direct-link teardown due to TDLS peer STA unreachable via the TDLS direct link",
    /* 26 */ "TDLS direct-link teardown for unspecified reason",
    /* 27 */ "Disassociated because session terminated by SSP request",
    /* 28 */ "Disassociated because of lack of SSP roaming agreement",
    /* 29 */ "Requested service rejected because of SSP cipher suite or AKM requirement",
    /* 30 */ "Requested service not authorized in this location",
    /* 31 */ "TS deleted because QoS AP lacks sufficient bandwidth for this QoS STA due to a change in BSS service characteristics or operational mode",
    /* 32 */ "Disassociated for unspecified, QoS-related reason",
    /* 33 */ "Disassociated because QoS AP lacks sufficient bandwidth for this QoS STA",
    /* 34 */ "Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions",
    /* 35 */ "Disassociated because STA is transmitting outside the limits of its TXOPs",
    /* 36 */ "Requesting STA is leaving the BSS (or resetting)",
    /* 37 */ "Requesting STA is no longer using the stream or session",
    /* 38 */ "Requesting STA received frames using a mechanism for which a setup has not been completed",
    /* 39 */ "Requested from peer STA due to timeout",
    /* 40 */ "reserved", /* 41 */ "reserved", /* 42 */ "reserved",
    /* 43 */ "reserved", /* 44 */ "reserved",
    /* 45 */ "Peer STA does not support the requested cipher suite",
    /* 46 */ "Disassociated because authorized access limit reached",
    /* 47 */ "Disassociated due to external service requirements",
    /* 48 */ "Invalid FT Action frame count",
    /* 49 */ "Invalid pairwise master key identifier (PMKID)",
    /* 50 */ "Invalid MDE",
    /* 51 */ "Invalid FTE",
    /* 52 */ "Mesh peering canceled for unknown reasons",
    /* 53 */ "The mesh STA has reached the supported maximum number of peer mesh STAs",
    /* 54 */ "The received information violates the Mesh Configuration policy configured in the mesh STA profile",
    /* 55 */ "The mesh STA has received a Mesh Peering Close frame requesting to close the mesh peering",
    /* 56 */ "The mesh STA has resent dot11MeshMaxRetries Mesh Peering Open frames, without receiving a Mesh Peering Confirm frame",
    /* 57 */ "The confirmTimer for the mesh peering instance times out",
    /* 58 */ "The mesh STA fails to unwrap the GTK or the values in the wrapped contents do not match",
    /* 59 */ "The mesh STA receives inconsistent information about the mesh parameters between mesh peering Management frames",
    /* 60 */ "The mesh STA fails the authenticated mesh peering exchange because due to failure in selecting either the pairwise ciphersuite or group ciphersuite",
    /* 61 */ "The mesh STA does not have proxy information for this external destination",
    /* 62 */ "The mesh STA does not have forwarding information for this destination",
    /* 63 */ "The mesh STA determines that the link to the next hop of an active path in its forwarding information is no longer usable",
    /* 64 */ "The Deauthentication frame was sent because the MAC address of the STA already exists in the mesh BSS",
    /* 65 */ "The mesh STA performs channel switch to meet regulatory requirements",
    /* 66 */ "The mesh STA performs channel switching with unspecified reason",
};

const char *web_dot11_reason_name(unsigned code) {
    if (code < sizeof(REASON) / sizeof(REASON[0])) return REASON[code];
    return "reserved";
}

/* Table 9-50, Status codes: the ones a monitor sees in Authentication
 * and (Re)Association Response frames. The table runs past 130; the
 * rows left out here are DMG, TDLS, FILS and allocation detail, and
 * answer "unknown" with the number beside. */
static const struct { unsigned code; const char *name; } STATUS[] = {
    { 0, "Successful" },
    { 1, "Unspecified failure" },
    { 2, "TDLS wakeup schedule rejected but alternative schedule provided" },
    { 3, "TDLS wakeup schedule rejected" },
    { 5, "Security disabled" },
    { 6, "Unacceptable lifetime" },
    { 7, "Not in same BSS" },
    { 10, "Cannot support all requested capabilities in the Capability Information field" },
    { 11, "Reassociation denied due to inability to confirm that association exists" },
    { 12, "Association denied due to reason outside the scope of this standard" },
    { 13, "Responding STA does not support the specified authentication algorithm" },
    { 14, "Received an Authentication frame with authentication transaction sequence number out of expected sequence" },
    { 15, "Authentication rejected because of challenge failure" },
    { 16, "Authentication rejected due to timeout waiting for next frame in sequence" },
    { 17, "Association denied because AP is unable to handle additional associated STAs" },
    { 18, "Association denied due to requesting STA not supporting all of the data rates in the BSSBasicRateSet parameter" },
    { 19, "Association denied due to requesting STA not supporting the short preamble option" },
    { 22, "Association request rejected because Spectrum Management capability is required" },
    { 23, "Association request rejected because the information in the Power Capability element is unacceptable" },
    { 24, "Association request rejected because the information in the Supported Channels element is unacceptable" },
    { 25, "Association denied due to requesting STA not supporting the Short Slot Time option" },
    { 27, "Association denied because the requesting STA does not support HT features" },
    { 28, "R0KH unreachable" },
    { 29, "Association denied because the requesting STA does not support the phased coexistence operation (PCO) transition time required by the AP" },
    { 30, "Association request rejected temporarily; try again later" },
    { 31, "Robust management frame policy violation" },
    { 32, "Unspecified, QoS-related failure" },
    { 33, "Association denied because QoS AP or PCP has insufficient bandwidth to handle another QoS STA" },
    { 34, "Association denied due to excessive frame loss rates and/or poor conditions on current operating channel" },
    { 35, "Association (with QoS BSS) denied because the requesting STA does not support the QoS facility" },
    { 37, "The request has been declined" },
    { 38, "The request has not been successful as one or more parameters have invalid values" },
    { 39, "The allocation or TS has not been created because the request cannot be honored; a suggested TSPEC is provided" },
    { 40, "Invalid element" },
    { 41, "Invalid group cipher" },
    { 42, "Invalid pairwise cipher" },
    { 43, "Invalid AKMP" },
    { 44, "Unsupported RSNE version" },
    { 45, "Invalid RSNE capabilities" },
    { 46, "Cipher suite rejected because of security policy" },
    { 47, "The TS or allocation has not been created; the HC or PCP might be capable of creating one after the time indicated in the TS Delay element" },
    { 48, "Direct link is not allowed in the BSS by policy" },
    { 49, "The Destination STA is not present within this BSS" },
    { 50, "The Destination STA is not a QoS STA" },
    { 51, "Association denied because the listen interval is too large" },
    { 52, "Invalid FT Action frame count" },
    { 53, "Invalid pairwise master key identifier (PMKID)" },
    { 54, "Invalid MDE" },
    { 55, "Invalid FTE" },
    { 56, "Requested TCLAS processing is not supported by the AP or PCP" },
    { 57, "The AP or PCP has insufficient TCLAS processing resources to satisfy the request" },
    { 58, "The TS has not been created because the request cannot be honored; the HC or PCP suggests that the STA transition to a different BSS" },
    { 59, "GAS Advertisement Protocol not supported" },
    { 60, "No outstanding GAS request" },
    { 61, "GAS Response not received from the Advertisement Server" },
    { 62, "STA timed out waiting for GAS Query Response" },
    { 63, "LARGE GAS Query Response" },
    { 64, "Request refused because home network does not support request" },
    { 65, "Advertisement Server in the network is not currently reachable" },
    { 67, "Request refused due to permissions received via SSPN interface" },
    { 68, "Request refused because the AP or PCP does not support unauthenticated access" },
    { 72, "Invalid contents of RSNE" },
    { 73, "U-APSD coexistence is not supported" },
    { 74, "Requested U-APSD coexistence mode is not supported" },
    { 75, "Requested Interval/Duration value cannot be supported with U-APSD coexistence" },
    { 76, "Authentication is rejected because an Anti-Clogging Token is required" },
    { 77, "Authentication is rejected because the offered finite cyclic group is not supported" },
    { 78, "The TBTT adjustment request has not been successful because the STA could not find an alternative TBTT" },
    { 79, "Transmission failure" },
    { 80, "Requested TCLAS not supported" },
    { 81, "TCLAS resources exhausted" },
    { 82, "Rejected with suggested BSS transition" },
    { 83, "Reject with recommended schedule" },
    { 84, "Reject because no wakeup schedule specified" },
    { 85, "Success, the destination STA is in power save mode" },
    { 86, "FST pending, in process of admitting FST session" },
    { 87, "Performing FST now" },
    { 88, "FST pending, gap(s) in block ack window" },
    { 89, "Reject because of U-PID setting" },
    { 92, "(Re)Association refused for some external reason" },
    { 93, "(Re)Association refused because of memory limits at the AP" },
    { 94, "(Re)Association refused because emergency services are not supported at the AP" },
    { 95, "GAS query response not yet received" },
    { 96, "Reject since the request is for transition to a frequency band subject to DSE procedures and FST Initiator is a dependent STA" },
    { 97, "Requested TCLAS processing has been terminated by the AP" },
    { 98, "The TS schedule conflicts with an existing schedule; an alternative schedule is provided" },
    { 99, "The association has been denied; however, one or more Multi-band elements are included that can be used by the receiving STA to join the BSS" },
    { 100, "The request failed due to a reservation conflict" },
    { 101, "The request failed due to exceeded MAF limit" },
    { 102, "The request failed due to exceeded MCCA track limit" },
    { 103, "Association denied because the information in the Spectrum Management field is unacceptable" },
    { 104, "Association denied because the requesting STA does not support VHT features" },
    { 105, "Enablement denied" },
    { 106, "Enablement denied due to restriction from an authorized GDB" },
    { 107, "Authorization deenabled" },
    { 112, "Authentication rejected due to unknown password identifier" },
    { 123, "Authentication rejected due to the use of SAE Password Identifier being disabled" },
    { 124, "Rejected because the association is denied due to unsupported temporary band" },
    { 125, "Denied due to Reconfiguration" },
    { 126, "Authentication rejected because the hash-to-element method is required" },
};

const char *web_dot11_status_name(unsigned code) {
    for (size_t i = 0; i < sizeof(STATUS) / sizeof(STATUS[0]); i++)
        if (STATUS[i].code == code) return STATUS[i].name;
    return "unknown";
}

const char *web_dot11_auth_alg_name(unsigned alg) {
    switch (alg) {
    case 0: return "Open System";
    case 1: return "Shared Key";
    case 2: return "Fast BSS Transition";
    case 3: return "SAE";
    case 4: return "FILS Shared Key without PFS";
    case 5: return "FILS Shared Key with PFS";
    case 6: return "FILS Public Key";
    case 65535: return "vendor specific";
    default: return "reserved";
    }
}
