/* SSIDs as slothweb shows them.
 *
 * An SSID is 0..32 octets an AP chose (IEEE 802.11-2020 9.4.2.2): not
 * text, and not necessarily UTF-8. sloth keeps its high octets as they
 * were sent (src/dot11_ie.c dot11_ie_ssid_copy(): only C0 and DEL
 * become '?'), so sloth.db can hold an SSID that is not valid UTF-8,
 * and the stream carries one with each such octet already replaced by
 * U+FFFD (src/jsonl.c json_escape()). Written raw, both reach the page
 * as replacement boxes, and an SSID made to look like another (a zero
 * width space, a bidi override) reads as that other.
 *
 * So every SSID slothweb sends is its display form: printable UTF-8 as
 * it is, every octet of anything else as \xNN (two lower-case hex
 * digits), and a backslash as \\, so that the form reads back to one
 * octet string only. Not printable: an octet that does not start a
 * well-formed RFC 3629 sequence; C0, DEL and C1; U+FFFD itself (what
 * the stream left where an octet was lost); the noncharacters
 * (U+FDD0..U+FDEF, and U+xFFFE / U+xFFFF of every plane); the format
 * and separator characters a reader cannot see (U+00AD, U+061C,
 * U+180E, U+200B..U+200F, U+2028..U+202E, U+2060..U+2064,
 * U+2066..U+206F, U+FEFF, U+FFF9..U+FFFB); the private-use areas
 * (U+E000..U+F8FF, planes 15 and 16) and the tag characters
 * (U+E0000..U+E007F), which no two fonts draw alike. Beside it goes a
 * flag saying something was escaped, which the page shows as a
 * "non-printable" marker.
 *
 * The colour is computed over the octets slothweb was given, never over
 * the display form: src/ip_color.c ip_color_index(), djb2 mod 8, which
 * is what tui_ssid_addstr() colours an SSID by. For an SSID read out
 * of sloth.db those are the octets the TUI hashes, so the page and the
 * TUI agree (web/tests/test_tui_colors.c holds the two equal on SSIDs
 * that are not UTF-8). One read off the stream has lost what U+FFFD
 * replaced, and its colour is that of the bytes the stream carried. */
#ifndef SLOTHWEB_SSID_H
#define SLOTHWEB_SSID_H

#include <stddef.h>

#include "web_json.h"

/* The most one input octet becomes in the display form (\xNN). */
#define WEB_SSID_EXPAND 4
/* The longest input read: an SSID is 32 octets, sloth.db text 63. */
#define WEB_SSID_IN_MAX 256

/* The display form of the n octets at s into out (cap bytes with its
 * NUL; cut before a whole escape or code point when it does not fit).
 * Returns its length; *np (when not NULL) is 1 when anything but a
 * backslash was escaped. */
size_t web_ssid_escape(const char *s, size_t n, char *out, size_t cap,
                       int *np);

/* The TUI's colour index of s: djb2 over its octets, mod 8; 0 for "". */
int web_ssid_color(const char *s);

/* One SSID's members. web_jw_ssid() writes the value: the display form
 * of s, or null when s is NULL or empty. web_jw_ssid_meta() writes
 * ,"<name>_k":<colour>,"<name>_np":<escaped>. Two calls, so that a
 * caller keeps the order of the members it already had. */
void web_jw_ssid(web_jw_t *w, const char *s);
void web_jw_ssid_meta(web_jw_t *w, const char *name, const char *s);

/* The most web_jw_ssid() writes for an n-octet SSID: each octet a \xNN,
 * five bytes once JSON has escaped the backslash. */
#define WEB_SSID_JSON_MAX(n) ((n) * 5 + 8)

#endif
