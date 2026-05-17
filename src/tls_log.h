#ifndef TLS_LOG_H
#define TLS_LOG_H

#include <stdint.h>
#include "sloth.h"

/* Parse a TLS ClientHello from the start of a TCP payload segment.
   Extracts SNI hostname (extension 0x0000) and TLS version (extension
   0x002b supported_versions, falling back to legacy_version).
   src_ip and dst_ip are copied verbatim into *out.
   Returns 1 if a valid ClientHello was found, 0 otherwise. */
int tls_log_parse(const uint8_t *data, int len,
                  const char *src_ip, const char *dst_ip,
                  tls_log_entry_t *out);

/* Append entry to the rolling log (thread-safe). */
void tls_log_record(const tls_log_entry_t *e);

/* Copy the log into s->tls_log[] in reverse-chronological order
   (newest at index 0).  Clamps s->tls_log_sel if needed. */
void tls_log_snapshot(sloth_state_t *s);

/* Clear the rolling log. */
void tls_log_clear(void);

#endif /* TLS_LOG_H */
