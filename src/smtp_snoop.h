#ifndef SMTP_SNOOP_H
#define SMTP_SNOOP_H

#include <stdint.h>

/* Passive SMTP AUTH observer (RFC 5321 + RFC 4954).
 *
 * Watches TCP/25/587 payloads for the `AUTH PLAIN <b64>` verb: the
 * base64 blob decodes to `\0<user>\0<pass>` (or `<authzid>\0<user>\0<pass>`).
 * The username is extracted and recorded; the password portion is
 * intentionally never touched.
 *
 * AUTH LOGIN — a stateful three-line exchange — is not handled here;
 * that variant will land in a follow-up when the snoop layer gains
 * per-flow scratch state.
 *
 * Returns 1 if the payload looked like SMTP, 0 otherwise. */
int smtp_snoop(const uint8_t *data, int len,
               const char *src, const char *dst, uint16_t dst_port);

/* Reset internal per-flow state. Used by tests to isolate cases;
 * production code never calls it. */
void smtp_snoop_reset(void);

#endif /* SMTP_SNOOP_H */
