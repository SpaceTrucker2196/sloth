#ifndef CLEARTEXT_CREDS_H
#define CLEARTEXT_CREDS_H

#include "sloth.h"

/* Passive record of a cleartext credential exposure.
 *
 * Guardrail from MISSION.md / docs/wiki/jsonl-schema.md: the username
 * is retained; the password is NEVER stored, hashed, or truncated.
 * `pw_observed` records the *fact* that a password was on the wire,
 * nothing about its content. This is enforced by the record function
 * signature — there is no password parameter to pass in.
 *
 * The ring buffer coalesces on (src, dst, dst_port, protocol,
 * username): repeat exposures for the same tuple bump the timestamp
 * (and set pw_observed) but don't create a new row. */

void cleartext_creds_reset(void);

/* Register a username observed in the clear. Called by
 * src/http_snoop.c (HTTP Basic) and src/ftp_snoop.c (FTP USER). */
void cleartext_creds_record_user(const char *src, const char *dst,
                                 uint16_t dst_port, const char *protocol,
                                 const char *username);

/* Register that a password was observed on the wire — never the
 * password itself. Matches an existing (src, dst, port, protocol)
 * row and marks it. If no matching row exists (PASS before USER,
 * or after eviction), the call is a silent no-op. */
void cleartext_creds_mark_password(const char *src, const char *dst,
                                   uint16_t dst_port, const char *protocol);

/* Snapshot the ring into sloth_state_t so views/alerts/JSONL see a
 * stable copy. Called from the main loop, mirroring dns_log_snapshot. */
void cleartext_creds_snapshot(sloth_state_t *s);

#endif /* CLEARTEXT_CREDS_H */
