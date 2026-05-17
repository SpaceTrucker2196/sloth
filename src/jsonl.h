#ifndef JSONL_H
#define JSONL_H

#include "sloth.h"

/* Optional JSONL forensic export.
 *
 * Disabled until jsonl_open() is called. All emit functions are no-ops
 * when the file isn't open, so log modules can call them unconditionally. */

int  jsonl_open  (const char *path);     /* returns 0 on failure */
void jsonl_close (void);
int  jsonl_is_open(void);

/* Per-type emitters. Each writes one JSON object terminated by '\n'. */
void jsonl_emit_dns  (const dns_log_entry_t  *e);
void jsonl_emit_tls  (const tls_log_entry_t  *e);
void jsonl_emit_quic (const quic_log_entry_t *e);
void jsonl_emit_http (const http_log_entry_t *e);
void jsonl_emit_ntp  (const ntp_log_entry_t  *e);
void jsonl_emit_icmp (const icmp_log_entry_t *e);
void jsonl_emit_alert(const alert_t          *a);

#endif /* JSONL_H */
