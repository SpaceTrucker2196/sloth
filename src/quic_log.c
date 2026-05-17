#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sloth.h"
#include "quic_snoop.h"
#include "quic_log.h"
#include "jsonl.h"

static quic_log_entry_t g_log[MAX_QUIC_LOG];
static int              g_head  = 0;
static int              g_count = 0;
static pthread_mutex_t  g_mu    = PTHREAD_MUTEX_INITIALIZER;

int quic_log_parse(const uint8_t *data, int len,
                   const char *src_ip, const char *dst_ip,
                   const char *host,
                   quic_log_entry_t *out)
{
    char ver[8] = "";
    if (!quic_detect(data, len, ver, sizeof(ver))) return 0;
    memset(out, 0, sizeof(*out));
    if (src_ip) snprintf(out->src,  sizeof(out->src),  "%s", src_ip);
    if (dst_ip) snprintf(out->dst,  sizeof(out->dst),  "%s", dst_ip);
    if (host && host[0]) snprintf(out->host, sizeof(out->host), "%s", host);
    snprintf(out->ver, sizeof(out->ver), "%s", ver);
    out->ts = time(NULL);
    return 1;
}

void quic_log_record(const quic_log_entry_t *e)
{
    pthread_mutex_lock(&g_mu);
    g_log[g_head] = *e;
    g_head = (g_head + 1) % MAX_QUIC_LOG;
    if (g_count < MAX_QUIC_LOG) g_count++;
    pthread_mutex_unlock(&g_mu);
    jsonl_emit_quic(e);
}

void quic_log_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_QUIC_LOG ? g_count : MAX_QUIC_LOG;
    for (int i = 0; i < n; i++) {
        int idx = ((g_head - 1 - i) % MAX_QUIC_LOG + MAX_QUIC_LOG) % MAX_QUIC_LOG;
        s->quic_log[i] = g_log[idx];
    }
    s->quic_log_count = n;
    s->quic_log_head  = g_head;
    if (s->quic_log_sel >= n) s->quic_log_sel = n > 0 ? n - 1 : 0;
    pthread_mutex_unlock(&g_mu);
}

void quic_log_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_head  = 0;
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
