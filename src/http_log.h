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

/* Flows held open for pairing. Bounded, and LRU-evicted by the flow's
 * own `ts`; a displaced slot is counted as SH_EVICT_HTTP_FLOW (#91).
 *
 * NOT "like every other table here", which an earlier version of this
 * comment said: the module's other bounded store, g_log[MAX_HTTP_LOG],
 * is a positional circular ring that overwrites the oldest slot by
 * index, and sensor_health classifies it as a flow ring rather than a
 * synthesis table (sh_evict_is_flow_ring). The two evict on different
 * principles and their counters mean different things — one is a lost
 * pairing, the other is lost view scrollback — so conflating them in a
 * header is how a consumer comes to read the wrong one.
 *
 * Exposed so the eviction test pins to the real bound rather than to a
 * copy of the literal that could drift from it. */
#define HTTP_FLOW_MAX 64

/* ── Direction is part of a record, and so is attribution (#197) ──
 *
 * One ring holds both halves of a conversation: requests from
 * http_log_parse(), responses from http_log_parse_response(). On a
 * request, `src` is the endpoint that chose `host` and `path`. On a
 * response, `src` is the **server** — and http_log_pair_response() has
 * deliberately copied the request's `host` and `path` onto it, so those
 * three fields describe two different endpoints. That is the point of
 * the pairing and it is not a defect; what is a defect is reading the
 * three together without asking which half you have.
 *
 * So a consumer that attributes a path or a host to the endpoint that
 * *asked for it* walks requests only, and says so with this predicate.
 * #197 is what it cost not to: rule_attack_path() keyed `path:%s` on
 * `e->src` for every ring entry, so every malicious request fired a
 * second CRIT naming the victim as its own attacker — the ring is
 * newest-first, so the victim's row was the one the operator saw first
 * — and pointed `match_ip`, and with it `--pcap-dir` export and the
 * device's ALERT_TAGGED risk bit, at the victim.
 *
 * A predicate rather than a filter inside the ring, because the ring is
 * right to carry both: the [h] view renders them interleaved and
 * cp_check_response() wants responses and nothing else. The contract is
 * "say which half you mean", and this is how a caller says it. It is
 * not a claim that a response's other fields are meaningless — status,
 * body and the paired path are exactly why #71 recorded responses. */
static inline int http_entry_is_request(const http_log_entry_t *e)
{
    return e && !e->is_response;
}

/* Append entry to the rolling log (thread-safe). */
void http_log_record(const http_log_entry_t *e);

/* Copy the log into s->http_log[] in reverse-chronological order
   (newest at index 0).  Clamps s->http_log_sel if needed. */
void http_log_snapshot(sloth_state_t *s);

/* Clear the rolling log. */
void http_log_clear(void);

#endif /* HTTP_LOG_H */
