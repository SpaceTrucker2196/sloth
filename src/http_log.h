#ifndef HTTP_LOG_H
#define HTTP_LOG_H

#include <stdint.h>
#include "sloth.h"

/* Parse an HTTP/1.x request TCP payload.  Extracts method, Host header,
   and request URI into *out.  src_ip is copied verbatim into out->src.
   Returns 1 if the payload is a valid HTTP request, 0 otherwise. */
int http_log_parse(const uint8_t *data, int len, const char *src_ip,
                   http_log_entry_t *out);

/* Append entry to the rolling log (thread-safe). */
void http_log_record(const http_log_entry_t *e);

/* Copy the log into s->http_log[] in reverse-chronological order
   (newest at index 0).  Clamps s->http_log_sel if needed. */
void http_log_snapshot(sloth_state_t *s);

/* Clear the rolling log. */
void http_log_clear(void);

#endif /* HTTP_LOG_H */
