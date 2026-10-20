#ifndef RTSP_SNOOP_H
#define RTSP_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* Passive RTSP observer — TCP/554 and TCP/8554 (#106 slice B).
 *
 * RTSP/1.0 is RFC 2326; RTSP/2.0 is RFC 7826, whose §10.2 names 554 as
 * the registered port and 8554 as the registered alternative. sloth
 * transmits nothing here: it reads a DESCRIBE some client already sent
 * and the answer the server already gave, and records per
 * (server, port, path) whether that answer was a stream description
 * handed over with no authentication step in between.
 *
 * Credential guardrail (src/cleartext_creds.h, MISSION.md): no
 * credential is ever stored, decoded or compared here. rtsp_msg_t has
 * no field that could hold one — an Authorization header is reduced to
 * the fact that it was present, and a Request-URI carrying userinfo or
 * a credential-shaped query is flagged and then not tracked at all. */

typedef enum {
    RTSP_MSG_NONE = 0,
    RTSP_MSG_REQUEST,
    RTSP_MSG_RESPONSE,
} rtsp_msg_kind_t;

typedef struct {
    rtsp_msg_kind_t kind;
    int      version;          /* 1 for RTSP/1.0, 2 for RTSP/2.0          */
    /* Request (RFC 2326 §6.1, RFC 7826 §7.1). */
    char     method[16];       /* "DESCRIBE", "SETUP", ...                */
    char     path[RTSP_PATH_LEN]; /* abs_path of the Request-URI; "" when
                                * the URI carried a credential            */
    int      has_auth;         /* Authorization or Proxy-Authorization
                                * header present — presence, never value */
    int      url_creds;        /* Request-URI carried userinfo or a
                                * credential-shaped token (see .c)        */
    /* Response (RFC 2326 §7.1, RFC 7826 §8.1). */
    int      status;           /* 3-digit Status-Code                     */
    int      has_sdp;          /* Content-Type: application/sdp           */
    char     auth_scheme[16];  /* WWW-Authenticate first token ("Digest") */
    /* Both (RFC 2326 §12.17, RFC 7826 §18.20: MUST be present). */
    int      has_cseq;
    uint32_t cseq;
} rtsp_msg_t;

/* Pure parse of the first RTSP message in `data`: the start line and
 * header block up to the blank line or the end of the segment. A line
 * the segment cuts off before its CRLF is not read — a truncated
 * "CSeq: 3" may be the front of "CSeq: 31". Interleaved binary data
 * ('$' framing, RFC 7826 §14) and anything whose version token is not
 * RTSP/1.0 or RTSP/2.0 is not a message. Returns 1 and fills `out` on
 * a recognised request or response, 0 otherwise. */
int rtsp_parse(const uint8_t *data, int len, rtsp_msg_t *out);

/* Observe one TCP payload on 554/8554. A DESCRIBE is remembered against
 * its connection and CSeq; the response carrying the same CSeq
 * (RFC 7826 §18.20: "the agent MUST use the sequence number in the
 * response to pair it with the corresponding request") settles the
 * (server, port, path) row. Fills info with a short label. Returns 1
 * when the payload was an RTSP message, 0 otherwise. */
int rtsp_snoop_observe(const char *src, uint16_t sport,
                       const char *dst, uint16_t dport,
                       const uint8_t *data, int len,
                       char *info, int infosz);

/* Copy the stream table into s->rtsp_streams under lock. */
void rtsp_snoop_snapshot(sloth_state_t *s);

/* Clear both tables. */
void rtsp_snoop_clear(void);

#endif /* RTSP_SNOOP_H */
