/* The links of an attack chain, as sloth made them (#171 V4, G8 in
 * docs/web-visual-spec.md §5; F14).
 *
 * sloth's own rules know that a deauth flood, then an evil twin, then a
 * client association to the twin is one event in three parts. Two of
 * the links between those parts are sloth's and reach the page only
 * through the stream's `twin_episode` snapshot (docs/wiki/jsonl-schema.md):
 *
 *   attack_in_progress  1 when rule_evil_twin_attack_chain() tainted
 *                       twin_bssid: a DEAUTH_FLOOD against the other
 *                       half within DEAUTH_TWIN_WIN_SECS (5 s default)
 *   attributed          1 when something other than radio physics said
 *                       which half is the impostor (an operator BSSID,
 *                       the deauth taint, an attacker-tool OUI)
 *   confidence          the pair's EVIL_TWIN confidence, 5..95
 *
 * sloth.db does not keep them in a form G8 can draw: its twin_episodes
 * table latches attack_in_progress per pair with no time it was set,
 * and keeps neither attributed nor confidence; its twin-chain alert's
 * key names the SSID, not the BSSIDs, and its detail is withheld on the
 * web. So this keeps them, in memory, from the stream: WEB_CHAIN_PAIRS pairs
 * keyed by the unordered pair of BSSIDs (an unattributed pair's two
 * fields are only canonical byte order, and attribution can swap them),
 * each with the first and newest record, the first record that carried
 * the taint and the first that carried attribution, and the newest
 * confidence. The least recently reported pair is evicted, and counted,
 * when a new one arrives. Nothing is persisted: a link before slothweb
 * started is not known, and the route says since when it is.
 *
 * Every string is hostile: a BSSID that web_key_mac() does not take is
 * a rejected record, counted; the SSID is not kept at all. One mutex:
 * the ingest thread writes, the HTTP thread reads. */
#ifndef SLOTHWEB_CHAIN_H
#define SLOTHWEB_CHAIN_H

#include <pthread.h>

#include "web_jsonl.h"
#include "web_rollup.h"

#define WEB_CHAIN_PAIRS 64
/* The most links a BSSID's chain carries: one per pair naming it. */
#define WEB_CHAIN_LINKS 4

typedef struct {
    char      lo[WEB_KEY_MAX + 1], hi[WEB_KEY_MAX + 1];   /* the pair, in order */
    char      real[WEB_KEY_MAX + 1], twin[WEB_KEY_MAX + 1]; /* the newest record's */
    long long first_ts, last_ts;
    long long taint_ts;      /* the first record with attack_in_progress 1; 0 none */
    long long attr_ts;       /* the first with attributed 1; 0 none */
    int       attributed;    /* the newest record's */
    int       confidence;    /* the newest record's, -1 absent */
    unsigned  records;
} web_chain_pair_t;

typedef struct web_chain {
    pthread_mutex_t   mu;
    web_chain_pair_t *pairs;
    int               n;
    long long         since;     /* the first twin_episode kept, 0 none */
    unsigned long     records, evictions, rejected;
} web_chain_t;

int  web_chain_init(web_chain_t *c);
void web_chain_destroy(web_chain_t *c);
/* One stream record; anything but a twin_episode is ignored. */
void web_chain_record(web_chain_t *c, const web_jrec_t *r);
/* The pairs naming bssid (canonical, either half) whose first to newest
 * record overlaps [from, to), at most max into out, oldest first; *since
 * is the first record kept (0 none). The count. */
int  web_chain_links(web_chain_t *c, const char *bssid, long long from,
                     long long to, web_chain_pair_t *out, int max,
                     long long *since);

/* The first twin_episode kept, 0 none. */
long long web_chain_since(web_chain_t *c);

#endif
