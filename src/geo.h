#ifndef GEO_H
#define GEO_H

#include <stdint.h>

/*
 * Compact embedded country/region table for IPv4.
 * Returns a 2-letter code (e.g. "US", "EU", "AP", "SA", "AF", "LO", "MC",
 * "--") or NULL for IPv6 / unparseable input.
 * Accuracy: /8-level RIR assignment plus specific sub-/8 private ranges.
 */
const char *geo_lookup(uint32_t ip_host);   /* host byte order */
const char *geo_lookup_str(const char *ip); /* dotted-decimal IPv4 */

/* Map a two-letter region code (as returned by geo_lookup_str) to a readable
 * name. Returns NULL for unknown codes. */
const char *geo_region_name(const char *code);

#endif /* GEO_H */
