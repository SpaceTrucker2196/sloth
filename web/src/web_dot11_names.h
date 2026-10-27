/* 802.11 names for the alert page's packet capture (owner request
 * 2026-10-27): the frame type/subtype, Reason Code and Status Code
 * tables of IEEE Std 802.11-2020, as text. The standard is paywalled;
 * the tables here were transcribed from the secondary tables that
 * reproduce it (Aruba, "802.11 Reason Codes and Status Codes",
 * blogs.arubanetworks.com/?p=9098; Netgear KB 000068418, which states
 * it is transcribed from IEEE Std 802.11-2020) and checked against
 * the ten codes src/views/deauth.c names. sloth's own reason_str() is
 * static in an ncurses view, so this table exists for the web page.
 *
 *   type/subtype   Table 9-1 (§9.2.4.1.3)
 *   reason code    Table 9-49 (§9.4.1.7); the 2016 edition numbers it 9-45
 *   status code    Table 9-50 (§9.4.1.9); the 2016 edition numbers it 9-46
 *
 * Every answer is a static string; an unknown code answers "reserved"
 * or "unknown", never NULL, and the page shows the number beside it. */
#ifndef SLOTHWEB_DOT11_NAMES_H
#define SLOTHWEB_DOT11_NAMES_H

const char *web_dot11_subtype_name(unsigned type, unsigned subtype);
const char *web_dot11_reason_name(unsigned code);
const char *web_dot11_status_name(unsigned code);
/* Authentication Algorithm Number (§9.4.1.1): 0 Open System, 1 Shared
 * Key, 2 Fast BSS Transition, 3 SAE, 4 FILS Shared Key without PFS,
 * 5 FILS Shared Key with PFS, 6 FILS Public Key, 65535 vendor. */
const char *web_dot11_auth_alg_name(unsigned alg);

#endif
