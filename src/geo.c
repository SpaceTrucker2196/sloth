#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "geo.h"

/*
 * /8-level country/region table indexed by first octet.
 * Keys: "US"=ARIN, "EU"=RIPE NCC, "AP"=APNIC, "SA"=LACNIC,
 *       "AF"=AFRINIC, "LO"=loopback, "MC"=multicast, "--"=special/private.
 * Sub-/8 private and special ranges are resolved by the if-chain in
 * geo_lookup() before this table is consulted.
 */
static const char * const g_geo8[256] = {
    /* 000 */ "--", "AP", "EU", "US", "US", "EU", "US", "US",
    /* 008 */ "US", "US", "--", "US", "US", "US", "AP", "US",
    /* 016 */ "US", "US", "US", "US", "US", "US", "US", "US",
    /* 024 */ "US", "EU", "US", "AP", "US", "US", "US", "EU",
    /* 032 */ "US", "US", "US", "US", "AP", "EU", "US", "AP",
    /* 040 */ "US", "AF", "AP", "AP", "US", "US", "EU", "US",
    /* 048 */ "US", "AP", "US", "EU", "US", "US", "US", "US",
    /* 056 */ "US", "AP", "AP", "AP", "AP", "AP", "EU", "US",
    /* 064 */ "US", "US", "US", "US", "US", "US", "US", "US",
    /* 072 */ "US", "US", "US", "US", "US", "EU", "EU", "EU",
    /* 080 */ "EU", "EU", "EU", "EU", "EU", "EU", "EU", "EU",
    /* 088 */ "EU", "EU", "EU", "EU", "EU", "EU", "EU", "EU",
    /* 096 */ "US", "US", "US", "US", "US", "AP", "AF", "AP",
    /* 104 */ "US", "AF", "AP", "US", "US", "EU", "AP", "AP",
    /* 112 */ "AP", "AP", "AP", "AP", "AP", "AP", "AP", "AP",
    /* 120 */ "AP", "AP", "AP", "AP", "AP", "AP", "AP", "LO",
    /* 128 */ "US", "US", "US", "US", "US", "AP", "US", "US",
    /* 136 */ "US", "US", "US", "US", "US", "EU", "US", "US",
    /* 144 */ "US", "EU", "EU", "US", "US", "US", "AP", "US",
    /* 152 */ "US", "AP", "AF", "US", "US", "US", "US", "US",
    /* 160 */ "US", "US", "US", "AP", "US", "US", "US", "US",
    /* 168 */ "US", "US", "US", "AP", "US", "US", "US", "AP",
    /* 176 */ "EU", "SA", "EU", "SA", "AP", "SA", "AP", "AP",
    /* 184 */ "US", "EU", "SA", "SA", "EU", "SA", "SA", "SA",
    /* 192 */ "US", "EU", "EU", "EU", "AF", "AF", "US", "US",
    /* 200 */ "SA", "SA", "AP", "AP", "US", "US", "US", "US",
    /* 208 */ "US", "US", "AP", "AP", "EU", "EU", "US", "US",
    /* 216 */ "US", "EU", "AP", "AP", "AP", "AP", "AP", "AP",
    /* 224 */ "MC", "MC", "MC", "MC", "MC", "MC", "MC", "MC",
    /* 232 */ "MC", "MC", "MC", "MC", "MC", "MC", "MC", "MC",
    /* 240 */ "--", "--", "--", "--", "--", "--", "--", "--",
    /* 248 */ "--", "--", "--", "--", "--", "--", "--", "--",
};

const char *geo_lookup(uint32_t ip) {
    /* Sub-/8 private and special ranges — checked before the /8 table. */
    if (ip < 0x01000000u)                              return "--"; /* 0.0.0.0/8 */
    if (ip >= 0x0A000000u && ip < 0x0B000000u)         return "--"; /* 10.0.0.0/8 */
    if (ip >= 0x64400000u && ip < 0x64800000u)         return "--"; /* 100.64.0.0/10 CGNAT */
    if (ip >= 0x7F000000u && ip < 0x80000000u)         return "LO"; /* 127.0.0.0/8 */
    if (ip >= 0xA9FE0000u && ip < 0xA9FF0000u)         return "--"; /* 169.254.0.0/16 */
    if (ip >= 0xAC100000u && ip < 0xAC200000u)         return "--"; /* 172.16.0.0/12 */
    if (ip >= 0xC0000200u && ip < 0xC0000300u)         return "--"; /* 192.0.2.0/24 */
    if (ip >= 0xC0A80000u && ip < 0xC0A90000u)         return "--"; /* 192.168.0.0/16 */
    if (ip >= 0xC6336400u && ip < 0xC6336500u)         return "--"; /* 198.51.100.0/24 */
    if (ip >= 0xCB007100u && ip < 0xCB007200u)         return "--"; /* 203.0.113.0/24 */
    if (ip >= 0xE0000000u && ip < 0xF0000000u)         return "MC"; /* 224.0.0.0/4 */
    if (ip >= 0xF0000000u)                             return "--"; /* 240.0.0.0/4 */

    return g_geo8[ip >> 24];
}

const char *geo_region_name(const char *code) {
    if (!code) return NULL;
    if (code[0] == 'U' && code[1] == 'S') return "ARIN (US/CA)";
    if (code[0] == 'E' && code[1] == 'U') return "RIPE NCC (EU/MEA)";
    if (code[0] == 'A' && code[1] == 'P') return "APNIC (Asia-Pac)";
    if (code[0] == 'S' && code[1] == 'A') return "LACNIC (LatAm)";
    if (code[0] == 'A' && code[1] == 'F') return "AFRINIC (Africa)";
    if (code[0] == 'L' && code[1] == 'O') return "Loopback";
    if (code[0] == 'M' && code[1] == 'C') return "Multicast";
    if (code[0] == '-' && code[1] == '-') return "Private / Reserved";
    return NULL;
}

/* IPv6 RIR allocations by /12 (or higher specificity for 2001::/16).
 * Global-unicast space (2000::/3) is carved up at /12 across the RIRs
 * with two exceptions: 2001::/16 was administered globally by RIPE and
 * 2002::/16 is 6to4 (now historic). The remaining ranges are stable. */
const char *geo_lookup_v6(const uint8_t a[16]) {
    if (!a) return NULL;
    /* Multicast / link-local / ULA / loopback. */
    if (a[0] == 0xff)                          return "MC";
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return "--";  /* link-local */
    if (a[0] == 0xfc || a[0] == 0xfd)          return "--";  /* ULA */
    /* ::1 loopback */
    int all_zero = 1;
    for (int i = 0; i < 15; i++) if (a[i]) { all_zero = 0; break; }
    if (all_zero && a[15] == 0x01)             return "LO";
    /* ::ffff:0:0/96 — IPv4-mapped, defer to v4 lookup at the caller */
    /* Global unicast 2000::/3 */
    if (a[0] == 0x24) return "AP";
    if (a[0] == 0x26) return "US";
    if (a[0] == 0x28) return "SA";
    if (a[0] == 0x2a) return "EU";
    if (a[0] == 0x2c) return "AF";
    /* 2001:: is RIPE-administered; specific sub-blocks delegate to other
     * RIRs, but the bulk of 2001::/16 sits with RIPE. 2003::/16 is
     * RIPE (Germany). 2002:: is 6to4 — call it "--" since the embedded
     * v4 is what would actually answer. */
    if (a[0] == 0x20 && a[1] == 0x02) return "--";
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0d && a[3] == 0xb8)
        return "--";                       /* 2001:db8::/32 documentation */
    if (a[0] == 0x20 && a[1] == 0x01) return "EU";
    if (a[0] == 0x20 && a[1] == 0x03) return "EU";
    return NULL;
}

const char *geo_lookup_str(const char *ip) {
    if (!ip || !*ip) return NULL;
    if (strchr(ip, ':')) {
        uint8_t v6[16];
        if (inet_pton(AF_INET6, ip, v6) != 1) return NULL;
        return geo_lookup_v6(v6);
    }
    unsigned a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return NULL;
    if (a > 255 || b > 255 || c > 255 || d > 255)     return NULL;
    uint32_t host = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                    ((uint32_t)c <<  8) |  (uint32_t)d;
    return geo_lookup(host);
}
