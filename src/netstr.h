/* Network-string hygiene: the one render/ingest choke point (#138).
 *
 * Before this module there were eight per-site filters, each with its
 * own idea of "printable", and the SSID / DNS / SNI / Host / NBNS / DHCP
 * / mDNS name fields were stored raw. ncurses renders most C0 octets as
 * ^X but *interprets* \n \r \b \t (cursor movement, so a crafted name
 * can spoof a row), and the ANSI fallback (WITH_NCURSES=0, `make
 * embedded`) wrote the octets to the terminal verbatim — ESC and CSI
 * included (CWE-150).
 *
 * Two layers, because neither alone is enough:
 *
 *   netstr_copy       ingest, name-class fields only. Bounded copy that
 *                     maps C0 (except NUL, which ends the string) and
 *                     DEL to '?'. High octets are kept: an SSID is an
 *                     opaque octet string (IEEE 802.11-2020 §9.4.2.2)
 *                     and --my-ssid / baseline matching compare it
 *                     octet for octet, so nothing above 0x7f is altered.
 *   display_sanitize  render, every string tui_printf / t_puts emits.
 *                     UTF-8 aware; see below. A format literal's '\n'
 *                     survives because it is indistinguishable from a
 *                     data '\n' at this point — which is exactly why the
 *                     ingest layer exists for the fields that can carry
 *                     one.
 *
 * The name-class stores that call netstr_copy — add a field here when
 * it joins them: SSID (dot11_ie_ssid_copy, shared by beacon, probe,
 * association and RRM), DNS qname (dns_log), NBNS name, DHCP option 12
 * hostname, TLS SNI (tls_log, sni_snoop), QUIC host, HTTP Host and
 * User-Agent (http_snoop, http_log), and every mDNS name (mdns_snoop
 * read_name).
 *
 * The per-site filters that predate this (snmp_snoop's reject, the
 * printable-ASCII credential and WPS copies) are stricter than either
 * layer and stay where they are. */
#ifndef SLOTH_NETSTR_H
#define SLOTH_NETSTR_H

#include <stddef.h>
#include <stdint.h>

/* Copy at most n octets of src (stopping early at a NUL) into dst,
 * always NUL-terminated within dstsz. 0x01..0x1f and 0x7f become '?';
 * every other octet is copied unchanged. dstsz 0 writes nothing.
 * Returns the number of octets written, excluding the NUL. */
size_t netstr_copy(char *dst, size_t dstsz, const uint8_t *src, size_t n);

/* The same mapping over a C string, in place. */
void netstr_scrub(char *s);

/* One UTF-8 scalar value at s[0..n) per RFC 3629 §4: rejects overlong
 * forms, surrogates (U+D800..U+DFFF) and anything above U+10FFFF.
 * Returns its length (1..4) and stores the code point, or 0 when s[0]
 * does not start a well-formed sequence (n == 0 included). */
int netstr_utf8_decode(const uint8_t *s, size_t n, uint32_t *cp);

/* 1 for a code point a terminal may act on rather than draw: C0 other
 * than '\n', DEL, C1 (U+0080..U+009F; U+009B is CSI), and the bidi
 * embedding / override / isolate controls U+202A..U+202E and
 * U+2066..U+2069 (CVE-2021-42574, "Trojan Source"). */
int netstr_is_display_control(uint32_t cp);

/* In place: each invalid UTF-8 octet becomes '?', and each code point
 * netstr_is_display_control() flags becomes one '?'. Valid UTF-8 and
 * '\n' are preserved. The string can only shrink. Returns the number of
 * substitutions made. */
size_t display_sanitize(char *s);

#endif /* SLOTH_NETSTR_H */
