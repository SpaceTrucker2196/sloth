#ifndef VENDOR_WATCHLIST_H
#define VENDOR_WATCHLIST_H

/* Surveillance-vendor cloud endpoints (#105, signal family B).
 *
 * A compile-time table of service domains belonging to body-worn-camera
 * and ALPR platform vendors. Embedded rather than loaded from a file,
 * for the same reason the IOC list in threat_intel.c is embedded
 * (MISSION.md §3): detection behaviour stays reproducible from the
 * commit. #105 asked for data/surveillance_vendors.csv with SIGHUP
 * reload; the owner ruled against it (#145 ruling 8: watchlist tables
 * are embedded in-tree, no runtime CSV or SIGHUP path), so this ships
 * the table the way src/wifi_oui_attacker.c ships its OUI tables.
 *
 * Every row is a domain a primary vendor source names as a service
 * address — see research/papers/surveillance-vendor-endpoints.md. No
 * row is guessed. A domain nobody publishes does not belong here: an
 * unverifiable row matches nothing while still attaching a vendor name
 * to whatever it does hit.
 *
 * On a match, *vendor and *family point at static strings in the table
 * (the caller must not free them).
 *
 * What a match means and does not mean is the whole care of this
 * module: it says a host on the monitored segment opened TLS to a
 * surveillance vendor's cloud. It cannot say which end is the device.
 * A docked body camera uploading and an analyst's browser tab on the
 * vendor's portal are the same observation here. */

int vendor_watchlist_match_domain(const char *host,
                                  const char **vendor,
                                  const char **family);

#endif /* VENDOR_WATCHLIST_H */
