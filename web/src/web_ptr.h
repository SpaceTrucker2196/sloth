/* slothweb passive PTR cache (#162, M4): docs/web-ui-spec.md §9.3,
 * without its cut active half. slothweb never resolves anything; this
 * holds only what a PTR answer already on the wire said.
 *
 * Input is sloth's dns record: qtype "PTR", is_resp 1, qname the
 * reverse name ("5.1.0.10.in-addr.arpa", or the 32 nibbles of an
 * ip6.arpa name) and answer the name it pointed to. Today sloth fills
 * answer only from the first A or AAAA record of a response
 * (src/dns_log.c reads no PTR rdata; docs/wiki/jsonl-schema.md says
 * "first A/AAAA answer"), so a PTR answer reaches slothweb with an
 * empty answer and nothing is recorded: the cache fills once sloth
 * writes a PTR answer's target there. That is a sloth change outside
 * web/ and is stated as a gap, not worked around: slothweb does not
 * parse packets.
 *
 * What is recorded is checked as if hostile: the qname must decode to
 * an address web_key_ip() keeps, the answer must be 1..63 bytes of a
 * host name (letters, digits, '-', '_', '.'), and NXDOMAIN or an
 * address-looking answer is not a name. The table holds cap addresses,
 * least recently seen out first (counted); the store thread writes the
 * changed rows to slothweb.db passive_ptr (v4) and reads them back at
 * start (web_anomaly.c's persist, which owns the writer). The ingest
 * thread writes, the HTTP and store threads read; one mutex. */
#ifndef SLOTHWEB_PTR_H
#define SLOTHWEB_PTR_H

#include <pthread.h>

#include "web_rollup.h"
#include "web_store.h"

#define WEB_PTR_CAP      4096
#define WEB_PTR_NAME_MAX WEB_STORE_PTR_NAME_MAX

typedef struct {
    char      ip[WEB_KEY_MAX + 1];
    char      name[WEB_PTR_NAME_MAX + 1];
    long long first_seen, last_seen;
    int       used, next, dirty;
} web_ptr_ent_t;

typedef struct {
    unsigned long seen;        /* PTR answers in the stream */
    unsigned long stored;      /* recorded (new or changed) */
    unsigned long empty;       /* PTR answers with no target: sloth's
                                  dns record carries none today */
    unsigned long refused;     /* a qname or a name that did not pass */
    unsigned long evictions;   /* the table full */
    unsigned long db_evictions;/* rows the file's bound dropped */
    unsigned long persist_errors;
    int           n, cap;
} web_ptr_stats_t;

typedef struct web_ptr {
    pthread_mutex_t mu;
    web_ptr_ent_t  *e;
    int            *head;
    int             cap, nhead, n;
    web_ptr_stats_t st;
} web_ptr_t;

int  web_ptr_init(web_ptr_t *p, int cap);
void web_ptr_destroy(web_ptr_t *p);

/* One dns record's fields (any of them NULL when absent). */
void web_ptr_record(web_ptr_t *p, const char *qtype, long long is_resp,
                    const char *qname, const char *answer, long long now_s);

/* The name for a canonical ip: 1 (copied, with its last_seen), or 0. */
int  web_ptr_get(web_ptr_t *p, const char *ip, char *name, long long *t);

/* The reverse name to a canonical address (out WEB_KEY_MAX + 1). 0, or
 * -1. Exposed for the tests. */
int  web_ptr_qname_ip(const char *qname, char *out);

/* The store thread: changed rows out (marked clean), and back if the
 * write failed; the rows read at start in. */
int  web_ptr_take_dirty(web_ptr_t *p, web_store_ptr_t *out, int max);
void web_ptr_redirty(web_ptr_t *p, const web_store_ptr_t *r, int n);
void web_ptr_load_row(void *p, const web_store_ptr_t *r);
void web_ptr_note_persist(web_ptr_t *p, int ok, long long db_evicted);

void web_ptr_stats(web_ptr_t *p, web_ptr_stats_t *out);

#endif
