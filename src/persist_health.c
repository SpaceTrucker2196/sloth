#include <stdio.h>

#include "persist_health.h"
#include "jsonl.h"
#include "alert_pcap.h"
#include "eapol_log.h"

void persist_health_poll(persist_health_t *p) {
    if (!p) return;
    p->jsonl      = jsonl_write_failures();
    p->alert_pcap = alert_pcap_failures();
    p->eapol      = eapol_export_failures();
}

int persist_badge(const persist_health_t *p, char *buf, size_t sz) {
    if (buf && sz) buf[0] = '\0';
    if (!p || !buf || !sz) return 0;
    int total = p->jsonl + p->alert_pcap + p->eapol;
    if (total <= 0) return 0;
    size_t off = (size_t)snprintf(buf, sz, "!persist");
    /* snprintf never returns negative here (fixed format); clamp so a
     * tiny buffer degrades to truncation, not an out-of-bounds off. */
    if (off >= sz) return total;
    if (p->jsonl > 0)
        off += (size_t)snprintf(buf + off, sz - off, " jsonl:%d", p->jsonl);
    if (p->alert_pcap > 0 && off < sz)
        off += (size_t)snprintf(buf + off, sz - off, " pcap:%d",
                                p->alert_pcap);
    if (p->eapol > 0 && off < sz)
        snprintf(buf + off, sz - off, " eapol:%d", p->eapol);
    return total;
}
