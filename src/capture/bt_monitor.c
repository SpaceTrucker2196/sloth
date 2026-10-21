#ifdef WITH_PCAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <pcap.h>

#include "sloth.h"
#include "capture/bt_monitor.h"
#include "capture/capture.h"     /* exit classification, stats, savefile seam */
#include "capture/frame_edge.h"  /* the pcap-edge gate (#141) */
#include "ble_hci.h"
#include "sensor_health.h"
#include "sloth_clock.h"
#include "worker_thread.h"

/* Contract in bt_monitor.h. Shaped like the data-stream worker in
 * capture.c — run flag, exit classification under the module mutex,
 * freshness on two clocks — so the BT stream reports its health the
 * same way the IP and 802.11 streams do. */

static pcap_t            *g_bh;
static pthread_t          g_thread;
static capture_run_flag_t g_running = CAPTURE_RUN_FLAG_INIT;
static pthread_mutex_t    g_mu = PTHREAD_MUTEX_INITIALIZER;
static int                g_exit_reason = CAPTURE_EXIT_NONE;
static char               g_exit_detail[80];
static time_t             g_last_frame_ts;
static time_t             g_last_frame_wall;

static void on_bt_frame(u_char *user, const struct pcap_pkthdr *hdr,
                        const u_char *data) {
    (void)user;
    frame_view_t f;
    if (!frame_view_init(&f, data, hdr->caplen, hdr->len,
                         (long)hdr->ts.tv_sec, (long)hdr->ts.tv_usec,
                         BT_DLT_LINUX_MONITOR)) {
        sh_parse_fault_note(SH_PF_FRAME_EDGE);
        return;
    }
    time_t wall = sloth_wall();
    (void)ble_mon_ingest(f.data, (size_t)f.caplen, (size_t)f.origlen,
                         f.ts_sec, wall);
    pthread_mutex_lock(&g_mu);
    g_last_frame_ts   = f.ts_sec;
    g_last_frame_wall = wall;
    pthread_mutex_unlock(&g_mu);
}

int bt_monitor_open(sloth_state_t *s) {
    if (!s) return -1;
    s->bt_err[0] = '\0';
    /* The device is a constant, never an argument, and the refusal is
     * checked anyway: if BT_MONITOR_DEVICE were ever edited to a raw
     * HCI name, this is where it stops. */
    if (bt_dev_is_raw_hci(BT_MONITOR_DEVICE)) {
        snprintf(s->bt_err, sizeof(s->bt_err), "raw HCI device refused");
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';
    pcap_t *h = pcap_create(BT_MONITOR_DEVICE, errbuf);
    if (!h) {
        snprintf(s->bt_err, sizeof(s->bt_err), "pcap(%s): %.40s",
                 BT_MONITOR_DEVICE, errbuf);
        return -1;
    }
    pcap_set_snaplen(h, BT_MONITOR_SNAPLEN);
    pcap_set_timeout(h, 100);
    int rc = pcap_activate(h);
    if (capture_activate_failed(rc)) {
        snprintf(s->bt_err, sizeof(s->bt_err), "pcap(%s): %.40s",
                 BT_MONITOR_DEVICE, pcap_geterr(h));
        pcap_close(h);
        return -1;
    }
    int dlt = pcap_datalink(h);
    if (dlt != BT_DLT_LINUX_MONITOR) {
        pcap_close(h);
        snprintf(s->bt_err, sizeof(s->bt_err), "%s: DLT %d, want %d",
                 BT_MONITOR_DEVICE, dlt, BT_DLT_LINUX_MONITOR);
        return -1;
    }
    g_bh = h;
    snprintf(s->bt_iface, sizeof(s->bt_iface), "%s", BT_MONITOR_DEVICE);
    return 0;
}

int bt_monitor_is_open(void) { return g_bh != NULL; }

static void *bt_thread(void *arg) {
    (void)arg;
    int r = 0;
    while (capture_run_flag_get(&g_running)) {
        r = pcap_dispatch(g_bh, 32, on_bt_frame, NULL);
        if (r < 0) break;
    }
    const char *err = (r < 0 && g_bh) ? pcap_geterr(g_bh) : "";
    int stop_requested = !capture_run_flag_get(&g_running);
    pthread_mutex_lock(&g_mu);
    snprintf(g_exit_detail, sizeof(g_exit_detail), "%s", err ? err : "");
    g_exit_reason = (int)capture_classify_exit(r, stop_requested, g_exit_detail);
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

void bt_monitor_run(void) {
    if (!g_bh || capture_run_flag_get(&g_running)) return;
    pthread_mutex_lock(&g_mu);
    g_exit_reason    = CAPTURE_EXIT_NONE;
    g_exit_detail[0] = '\0';
    pthread_mutex_unlock(&g_mu);
    capture_run_flag_set(&g_running, 1);
    if (worker_thread_create(&g_thread, bt_thread, NULL) != 0)
        capture_run_flag_set(&g_running, 0);
}

void bt_monitor_stop(void) {
    if (capture_run_flag_take(&g_running)) {
        if (g_bh) pcap_breakloop(g_bh);
        pthread_join(g_thread, NULL);
    }
    if (g_bh) { pcap_close(g_bh); g_bh = NULL; }
}

void bt_monitor_health_poll(capture_health_t *h) {
    if (!h) return;
    h->open = g_bh != NULL;
    pthread_mutex_lock(&g_mu);
    h->exit_reason = g_exit_reason;
    snprintf(h->exit_detail, sizeof(h->exit_detail), "%s", g_exit_detail);
    int reason = g_exit_reason;
    time_t fts = g_last_frame_ts, fwall = g_last_frame_wall;
    pthread_mutex_unlock(&g_mu);
    h->running = capture_worker_live(g_bh != NULL,
                                     capture_run_flag_get(&g_running), reason);
    h->last_frame_ts = fts;
    h->stale_secs = fwall ? (int)(sloth_wall() - fwall) : -1;
    if (!g_bh) return;
    struct pcap_stat ps;
    memset(&ps, 0, sizeof(ps));
    /* libpcap's monitor backend may not implement stats; stats_valid
     * stays 0 then, which reads as "not measured", not as "no drops". */
    if (pcap_stats(g_bh, &ps) == 0)
        capture_stats_accumulate(h, (uint32_t)ps.ps_recv, (uint32_t)ps.ps_drop,
                                 (uint32_t)ps.ps_ifdrop);
}

int bt_monitor_dispatch_frames(const uint8_t *const *frames, const int *lens,
                               const int *orig_lens, const uint32_t *ts_secs,
                               int n) {
    size_t total = 0;
    uint8_t *img = capture_test_savefile(BT_DLT_LINUX_MONITOR, frames, lens,
                                         orig_lens, ts_secs, n, &total);
    if (!img) return -1;
    FILE *fp = fmemopen(img, total, "rb");
    if (!fp) { free(img); return -1; }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_fopen_offline(fp, errbuf);
    if (!pc) { fclose(fp); free(img); return -1; }
    int got = pcap_dispatch(pc, n > 0 ? n : -1, on_bt_frame, NULL);
    pcap_close(pc);
    free(img);
    return got;
}

#endif /* WITH_PCAP */
