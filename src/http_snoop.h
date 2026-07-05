#ifndef HTTP_SNOOP_H
#define HTTP_SNOOP_H

#include <stdint.h>

/* Parse an HTTP/1.x request payload starting at the TCP payload.
   If a Host header is found, writes the hostname (port stripped) into
   host[hostsz] and returns 1.  Returns 0 if the payload is not an HTTP
   request or no Host header is present. */
int http_snoop(const uint8_t *data, int len, char *host, int hostsz);

/* Scan an HTTP/1.x request payload for cleartext credential exposures
 * (currently: Authorization: Basic <b64>). On a match, calls the
 * cleartext_creds recorder. Never touches the password portion of the
 * decoded value — see roadmap #16 phase 3. */
void http_snoop_scan_creds(const uint8_t *data, int len,
                           const char *src, const char *dst,
                           uint16_t dst_port);

#endif /* HTTP_SNOOP_H */
