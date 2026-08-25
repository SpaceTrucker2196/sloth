#ifndef HTTP_LOG_H
#define HTTP_LOG_H

#include <stdint.h>
#include "sloth.h"

/* Parse an HTTP/1.x request TCP payload.  Extracts method, Host header,
   and request URI into *out.  src_ip is copied verbatim into out->src.
   Returns 1 if the payload is a valid HTTP request, 0 otherwise. */
int http_log_parse(const uint8_t *data, int len, const char *src_ip,
                   http_log_entry_t *out);

/* Parse an HTTP/1.x *response* (#71): status line, the headers that
 * describe the body, and as much of the body as the segment carries.
 *
 * Returns 1 when the payload starts a response, 0 otherwise.
 *
 * ── What body_complete means, and why it exists ──
 *
 * sloth does not reassemble TCP. A response body larger than the
 * segment carrying its status line arrives truncated, and the parser
 * cannot invent the rest. So the output distinguishes three states, not
 * two:
 *
 *   body_complete = 1   the whole declared body is in resp_body
 *   body_complete = 0   we have a prefix, or none of it
 *   chunked = 1         Transfer-Encoding: chunked, not decoded
 *
 * A consumer doing a byte-exact comparison — which is the reason this
 * exists — must only compare when body_complete is 1. A partial body
 * that happens to differ from an expected value is not evidence of
 * anything, and treating it as a mismatch would turn every large
 * response into a false positive.
 *
 * That is a deliberate trade: it makes the comparison exact at the cost
 * of being silent on responses sloth cannot see whole. Silence that
 * knows it is silent beats a guess. */
int http_log_parse_response(const uint8_t *data, int len,
                            const char *src_ip, http_log_entry_t *out);

/* Pair a response with the most recent request seen on the same flow,
 * matching on the four-tuple reversed. Returns 1 and fills the response
 * entry's host/path from that request, so a consumer knows *what was
 * asked for*; 0 when no request can be confidently paired.
 *
 * Deliberately conservative. HTTP pipelining and keep-alive reuse make
 * "which request does this answer" genuinely ambiguous, and a wrong
 * pairing attributes a response to the wrong URL — which for a sentinel
 * comparison is worse than no pairing at all. One request in flight per
 * flow is paired; anything else is left unpaired and says so. */
int http_log_pair_response(http_log_entry_t *resp);

/* Append entry to the rolling log (thread-safe). */
void http_log_record(const http_log_entry_t *e);

/* Copy the log into s->http_log[] in reverse-chronological order
   (newest at index 0).  Clamps s->http_log_sel if needed. */
void http_log_snapshot(sloth_state_t *s);

/* Clear the rolling log. */
void http_log_clear(void);

#endif /* HTTP_LOG_H */
