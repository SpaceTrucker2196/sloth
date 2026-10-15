#ifndef ALERT_KEY_H
#define ALERT_KEY_H

/* Typed alert dedup-key builder (#112).
 *
 * A dedup key decides what is one finding. Rules used to build theirs
 * with snprintf and a precision — `"ssidconf:%.30s:%s"` — and a
 * precision on a remote-chosen string MERGES: two SSIDs sharing a
 * 30-byte prefix became one incident, and whichever fired last wrote
 * the detail. Without a precision the same string could run the key past
 * ALERT_KEY_LEN, where the engine truncates it, which merges the same
 * way at byte 191.
 *
 * Each component here has a type, and the type decides its shape:
 *
 *   akey_mac     aa:bb:cc:dd:ee:ff                      fixed width
 *   akey_ip      1.2.3.4  |  [2001:db8::1]              <= 47 bytes
 *   akey_u       decimal                                <= 10 bytes
 *   akey_tok     sloth's own literal ("FTP", "HTTP-Basic")
 *   akey_hex     lowercase hex of raw bytes (a UUID)
 *   akey_remote  <= keep sanitised bytes, ':', 16-hex FNV-1a of the
 *                FULL string — readable prefix, no prefix merge
 *   akey_set     <n>:<16-hex FNV-1a> of the sorted members, so the
 *                key does not depend on the order they were seen in
 *
 * Components are joined with ':'. Sanitising maps ':' to '_' (with ','
 * '[' ']' and anything outside 0x21..0x7e), so a remote component never
 * contains the separator and the boundaries cannot be forged.
 *
 * Honest scope: this bounds LENGTH and removes truncation merges. It
 * does not bound CARDINALITY — a remote side that chooses a thousand
 * SSIDs still makes a thousand keys. That stays with the engine's
 * per-type fair eviction (8c35974) and is measured by SH_EVICT_ALERT.
 *
 * Overflow — a key that does not fit the buffer — is a programming
 * error: every rule's worst case is pinned by a test. akey_end() then
 * returns "" and the rule must skip, and fire() refuses an empty key,
 * so the failure is a missed alert rather than a merged one. */

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char  *buf;
    size_t n, len;
    int    overflow;
} akey_t;

void akey_begin(akey_t *k, char *buf, size_t n, const char *rule);
void akey_mac(akey_t *k, const uint8_t mac[6]);
void akey_ip(akey_t *k, const char *ip);
void akey_u(akey_t *k, unsigned v);
void akey_tok(akey_t *k, const char *tok);
void akey_hex(akey_t *k, const uint8_t *b, size_t n);
void akey_remote(akey_t *k, const char *s, size_t keep);
void akey_set(akey_t *k, const char *const *items, int n);
const char *akey_end(akey_t *k);

/* Longest akey_tok component accepted, and the most members akey_set
 * sorts. Beyond either is overflow, not truncation. */
#define AKEY_TOK_MAX  32
#define AKEY_SET_MAX  64
/* An ip that is not IP-shaped is keyed as akey_remote with this keep,
 * so a malformed address can never be longer than a real one. */
#define AKEY_IP_FALLBACK_KEEP 24

#endif /* ALERT_KEY_H */
