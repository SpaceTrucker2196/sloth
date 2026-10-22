/* The live state (web_live.c) and the line framer (web_ingest.c
 * web_feed_*), fed hand-written JSONL in the shapes and order sloth
 * writes them: jsonl_emit_state_snapshots() emits iface, ..., top_host,
 * then one device record per row of s->devices, then beacon and the
 * rest, sensor_health last. No socket here; test_ingest.c repeats the
 * important cases over real ones. */
#include <stdlib.h>
#include <string.h>

#include "web_ingest.h"
#include "web_live.h"
#include "web_routes.h"
#include "web_server.h"
#include "wtest.h"

static web_live_t g_live;
static web_feed_t g_feed;
static char       g_json[WEB_SSE_MAX_UNSENT];

static void fresh(void) {
    web_live_init(&g_live, "unix:/test/sloth.sock");
    web_live_sock_connected(&g_live, 0);
    web_feed_reset(&g_feed);
}

static void done(void) { web_live_destroy(&g_live); }

static void feed_at(const char *s, long long now_ms) {
    web_feed_bytes(&g_feed, &g_live, s, strlen(s), now_ms);
}
static void feed(const char *s) { feed_at(s, 1000); }

static web_live_sum_t sum(void) {
    web_live_sum_t s;
    web_live_summary(&g_live, &s, 1000);
    return s;
}

static const char *live_json(void) {
    size_t n = web_live_json(&g_live, g_json, sizeof(g_json), 1000);
    if (!n) g_json[0] = '\0';
    return g_json;
}

/* One snapshot batch: the iface records first, as sloth writes them,
 * then n device records, then a beacon. */
static void batch(int n, long long ts) {
    char line[256];
    snprintf(line, sizeof(line), "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"lo\"}\n"
                                 "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"eth0\"}\n"
                                 "{\"type\":\"top_host\",\"ts\":%lld,\"ip\":\"10.0.0.1\"}\n",
             ts, ts, ts);
    feed(line);
    for (int i = 0; i < n; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"device\",\"ts\":%lld,\"mac\":\"02:00:00:00:00:%02x\","
                 "\"ip\":\"10.0.0.%d\",\"hostname\":\"\"}\n", ts, i, i);
        feed(line);
    }
    snprintf(line, sizeof(line), "{\"type\":\"beacon\",\"ts\":%lld,\"ssid\":\"x\"}\n", ts);
    feed(line);
}

/* ── the device count ──────────────────────────────────────────────── */

static void test_device_count_is_the_latest_pass(void) {
    fresh();
    web_live_sum_t s = sum();
    WT_EQ(s.dev_known, 0);
    WT_EQ(s.dev_stale, 1);
    WT_HAS(live_json(), "\"devices\":null");

    batch(3, 100);
    s = sum();
    WT_EQ(s.dev_known, 1);
    WT_EQ(s.devices, 3);
    WT_EQ(s.dev_stale, 0);
    WT_HAS(live_json(), "\"devices\":3,\"devices_stale\":false,\"devices_ts\":100");

    batch(5, 101);
    WT_EQ(sum().devices, 5);
    /* The same MAC twice in one pass is two rows in sloth's table, and
     * the TUI counts rows: so does this. */
    feed("{\"type\":\"iface\",\"ts\":102}\n"
         "{\"type\":\"device\",\"ts\":102,\"mac\":\"02:00:00:00:00:01\"}\n"
         "{\"type\":\"device\",\"ts\":102,\"mac\":\"02:00:00:00:00:01\"}\n"
         "{\"type\":\"sensor_health\",\"ts\":102}\n");
    WT_EQ(sum().devices, 2);

    /* A pass is published when the first record of another type ends
     * it, not before: a pass still arriving is not a count. */
    feed("{\"type\":\"iface\",\"ts\":103}\n"
         "{\"type\":\"device\",\"ts\":103,\"mac\":\"02:00:00:00:00:01\"}\n");
    WT_EQ(sum().devices, 2);
    feed("{\"type\":\"connections\",\"ts\":104}\n");
    WT_EQ(sum().devices, 1);
    done();
}

/* A socket_gap or an undecodable line inside a pass means rows may be
 * missing: the pass is not published and the previous count stands.
 * Seen red (2, 2, 1 and 2 published) with the round_taint test removed
 * from close_round(). */
static void test_cut_pass_is_not_published(void) {
    fresh();
    batch(4, 100);
    WT_EQ(sum().devices, 4);

    /* A gap inside the pass. */
    feed("{\"type\":\"iface\",\"ts\":101}\n"
         "{\"type\":\"device\",\"ts\":101,\"mac\":\"a\"}\n"
         "{\"type\":\"socket_gap\",\"ts\":101,\"seq\":9,\"dropped\":2,\"dropped_total\":2}\n"
         "{\"type\":\"device\",\"ts\":101,\"mac\":\"b\"}\n"
         "{\"type\":\"beacon\",\"ts\":101}\n");
    WT_EQ(sum().devices, 4);

    /* A gap just before it: what was dropped may have been its start. */
    feed("{\"type\":\"iface\",\"ts\":102}\n"
         "{\"type\":\"top_host\",\"ts\":102}\n"
         "{\"type\":\"socket_gap\",\"ts\":102,\"seq\":20,\"dropped\":1,\"dropped_total\":3}\n"
         "{\"type\":\"device\",\"ts\":102,\"mac\":\"a\"}\n"
         "{\"type\":\"device\",\"ts\":102,\"mac\":\"b\"}\n"
         "{\"type\":\"beacon\",\"ts\":102}\n");
    WT_EQ(sum().devices, 4);

    /* A line that would not decode may have been a device record. */
    feed("{\"type\":\"iface\",\"ts\":103}\n"
         "{\"type\":\"device\",\"ts\":103,\"mac\":\"a\"}\n"
         "{\"type\":\"device\",\"ts\":103,\"mac\":\"b\n"
         "{\"type\":\"beacon\",\"ts\":103}\n");
    WT_EQ(sum().devices, 4);

    /* A record whose type is not a plausible name is the same doubt. */
    feed("{\"type\":\"iface\",\"ts\":104}\n"
         "{\"type\":\"device\",\"ts\":104,\"mac\":\"a\"}\n"
         "{\"type\":\"DEVICE\",\"ts\":104,\"mac\":\"b\"}\n"
         "{\"type\":\"device\",\"ts\":104,\"mac\":\"c\"}\n"
         "{\"type\":\"beacon\",\"ts\":104}\n");
    WT_EQ(sum().devices, 4);
    WT_HAS(live_json(), "\"device_passes_unpublished\":4");

    /* The next whole pass is published again. */
    batch(6, 105);
    WT_EQ(sum().devices, 6);
    done();
}

/* sloth's table empties: its batches carry no device record at all.
 * The next batch's start publishes 0, unless the batch may have lost
 * them. Seen red (0 published after the gap) with the batch_taint test
 * removed from devices_step(). */
static void test_empty_table_publishes_zero(void) {
    fresh();
    batch(4, 100);
    batch(0, 101);
    /* The empty batch is only known to be empty once the next starts. */
    WT_EQ(sum().devices, 4);
    feed("{\"type\":\"iface\",\"ts\":102}\n");
    WT_EQ(sum().devices, 0);
    WT_EQ(sum().dev_known, 1);

    /* No devices again, but a gap in the batch: not a zero. */
    batch(3, 103);
    feed("{\"type\":\"iface\",\"ts\":104}\n"
         "{\"type\":\"socket_gap\",\"ts\":104,\"seq\":5,\"dropped\":4,\"dropped_total\":4}\n"
         "{\"type\":\"beacon\",\"ts\":104}\n"
         "{\"type\":\"iface\",\"ts\":105}\n");
    WT_EQ(sum().devices, 3);
    done();
}

/* A new connection is a new stream: a pass begun on the old one is not
 * finished by the new one, and the count is stale until a pass arrives
 * on the new one. Seen red (2 published, not stale) with reset_stream()
 * removed from both web_live_sock_failed() and web_live_sock_connected();
 * either one alone covers the case, since a connect always follows a
 * failure. */
static void test_reconnect_is_a_new_stream(void) {
    fresh();
    batch(3, 100);
    feed("{\"type\":\"iface\",\"ts\":101}\n"
         "{\"type\":\"device\",\"ts\":101,\"mac\":\"a\"}\n"
         "{\"type\":\"device\",\"ts\":101,\"mac\":\"b\"}\n");
    web_live_sock_failed(&g_live, "peer closed the stream", 250, 2000);
    web_live_sum_t s = sum();
    WT_EQ(s.sock_state, WEB_SOCK_RETRYING);
    WT_EQ(s.devices, 3);
    WT_EQ(s.dev_stale, 1);
    WT_HAS(live_json(), "\"socket\":\"retrying\",\"devices\":3,\"devices_stale\":true");

    web_live_sock_connected(&g_live, 2500);
    feed("{\"type\":\"beacon\",\"ts\":102}\n");
    s = sum();
    WT_EQ(s.devices, 3);
    WT_EQ(s.dev_stale, 1);
    batch(7, 103);
    s = sum();
    WT_EQ(s.devices, 7);
    WT_EQ(s.dev_stale, 0);
    done();
}

/* sloth's capture thread writes dns, tls, quic, http, ntp, icmp and
 * cleartext_cred through the same emit_line() as the poll thread's
 * snapshot, with no lock spanning a pass, so one can land between two
 * device rows. A pass of 300 with a
 * dns at row 150 is still 300. Seen red (150, 290, 3, 0 and 1)
 * with the poll_type() return removed from devices_step(). */
static void pass_with(int n, int at, const char *extra, long long ts) {
    char line[256];
    snprintf(line, sizeof(line), "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"lo\"}\n", ts);
    feed(line);
    for (int i = 0; i < n; i++) {
        if (i == at) feed(extra);
        snprintf(line, sizeof(line),
                 "{\"type\":\"device\",\"ts\":%lld,\"mac\":\"02:00:00:00:%02x:%02x\"}\n",
                 ts, i / 256, i % 256);
        feed(line);
    }
    snprintf(line, sizeof(line), "{\"type\":\"beacon\",\"ts\":%lld}\n", ts);
    feed(line);
}

static void test_capture_records_inside_a_pass(void) {
    fresh();
    pass_with(300, -1, "", 100);
    WT_EQ(sum().devices, 300);
    pass_with(300, 150, "{\"type\":\"dns\",\"ts\":101,\"qname\":\"a.example\"}\n", 101);
    WT_EQ(sum().devices, 300);
    WT_HAS(live_json(), "\"devices\":300,");
    pass_with(300, 10, "{\"type\":\"dns\",\"ts\":102,\"qname\":\"b.example\"}\n", 102);
    WT_EQ(sum().devices, 300);
    /* Every capture-thread type, and the alert records, in one pass. */
    pass_with(5, 2,
              "{\"type\":\"tls\",\"ts\":103}\n{\"type\":\"quic\",\"ts\":103}\n"
              "{\"type\":\"http\",\"ts\":103}\n{\"type\":\"ntp\",\"ts\":103}\n"
              "{\"type\":\"icmp\",\"ts\":103}\n{\"type\":\"cleartext_cred\",\"ts\":103}\n"
              "{\"type\":\"alert\",\"ts\":103}\n"
              "{\"type\":\"alert.create\",\"ts\":103,\"incident_id\":\"x\",\"sev\":1}\n",
              103);
    WT_EQ(sum().devices, 5);
    /* One between two iface records is not a new batch: no false 0 for
     * a batch that "had no devices". */
    feed("{\"type\":\"iface\",\"ts\":104,\"name\":\"lo\"}\n"
         "{\"type\":\"dns\",\"ts\":104}\n"
         "{\"type\":\"iface\",\"ts\":104,\"name\":\"eth0\"}\n");
    WT_EQ(sum().devices, 5);
    feed("{\"type\":\"device\",\"ts\":104,\"mac\":\"a\"}\n"
         "{\"type\":\"device\",\"ts\":104,\"mac\":\"b\"}\n"
         "{\"type\":\"device\",\"ts\":104,\"mac\":\"c\"}\n"
         "{\"type\":\"device\",\"ts\":104,\"mac\":\"d\"}\n"
         "{\"type\":\"sensor_health\",\"ts\":104}\n");
    WT_EQ(sum().devices, 4);
    /* Passed over means passed over: a dns record is no end of a pass,
     * so a pass still arriving is not published by one. */
    feed("{\"type\":\"iface\",\"ts\":105}\n"
         "{\"type\":\"device\",\"ts\":105,\"mac\":\"a\"}\n"
         "{\"type\":\"dns\",\"ts\":105}\n");
    WT_EQ(sum().devices, 4);
    feed("{\"type\":\"beacon\",\"ts\":105}\n");
    WT_EQ(sum().devices, 1);
    WT_HAS(live_json(), "\"device_passes_unpublished\":0");
    done();
}

/* ── alerts ───────────────────────────────────────────────────────── */

static void test_alert_lifecycle_counts(void) {
    fresh();
    feed("{\"type\":\"alert.create\",\"ts\":1,\"incident_id\":\"aaaa\",\"title\":\"A\",\"detail\":\"a\",\"sev\":2}\n"
         "{\"type\":\"alert\",\"ts\":1,\"title\":\"A\",\"detail\":\"a\",\"sev\":2}\n"
         "{\"type\":\"alert.create\",\"ts\":2,\"incident_id\":\"bbbb\",\"title\":\"B\",\"detail\":\"b\",\"sev\":1}\n"
         "{\"type\":\"alert.create\",\"ts\":3,\"incident_id\":\"cccc\",\"title\":\"C\",\"detail\":\"c\",\"sev\":0}\n");
    web_live_sum_t s = sum();
    WT_EQ(s.alerts[0], 1);
    WT_EQ(s.alerts[1], 1);
    WT_EQ(s.alerts[2], 1);
    feed("{\"type\":\"alert.escalate\",\"ts\":4,\"incident_id\":\"bbbb\",\"sev\":2,\"prev_sev\":1}\n"
         /* opened before this connection: still open */
         "{\"type\":\"alert.update\",\"ts\":5,\"incident_id\":\"dddd\",\"sev\":1}\n"
         "{\"type\":\"alert.resolve\",\"ts\":6,\"incident_id\":\"aaaa\",\"sev\":2,\"reason\":\"expired\"}\n"
         /* resolving one never seen changes nothing */
         "{\"type\":\"alert.resolve\",\"ts\":7,\"incident_id\":\"zzzz\",\"sev\":2}\n"
         /* a severity outside 0..2, or no incident, counts nowhere */
         "{\"type\":\"alert.create\",\"ts\":8,\"incident_id\":\"eeee\",\"sev\":7}\n"
         "{\"type\":\"alert.create\",\"ts\":9,\"sev\":2}\n");
    s = sum();
    WT_EQ(s.alerts[0], 1);
    WT_EQ(s.alerts[1], 1);
    WT_EQ(s.alerts[2], 1);
    const char *j = live_json();
    WT_HAS(j, "\"alerts_open\":{\"low\":1,\"warn\":1,\"crit\":1,\"overflow\":false}");
    /* newest first, the last WEB_LIVE_ALERTS of them */
    WT_HAS(j, "\"alerts\":[{\"ts\":9,\"type\":\"alert.create\",\"sev\":2,");
    WT_HAS(j, "{\"ts\":8,\"type\":\"alert.create\",\"sev\":null,");
    WT_LACKS(j, "{\"ts\":1,\"type\":\"alert.create\"");   /* fell out: 9 records */

    /* The severity indexes the summary's alerts[3], so its bound is
     * pinned at both edges: 3 and -1 are no severity. A sev of 3 let
     * through writes alerts[3], which lands inside the summary struct
     * where ASan cannot see it. Seen red (the record's sev 3, not null)
     * with sev_ok() widened to s <= 3. */
    feed("{\"type\":\"alert.create\",\"ts\":10,\"incident_id\":\"ffff\",\"sev\":3}\n");
    s = sum();
    WT_EQ(s.alerts[0] + s.alerts[1] + s.alerts[2], 3);
    WT_EQ(s.alerts_overflow, 0);
    WT_HAS(live_json(), "{\"ts\":10,\"type\":\"alert.create\",\"sev\":null,");
    WT_HAS(live_json(), "\"alerts_open\":{\"low\":1,\"warn\":1,\"crit\":1,\"overflow\":false}");
    feed("{\"type\":\"alert.create\",\"ts\":11,\"incident_id\":\"gggg\",\"sev\":-1}\n");
    s = sum();
    WT_EQ(s.alerts[0] + s.alerts[1] + s.alerts[2], 3);
    WT_HAS(live_json(), "{\"ts\":11,\"type\":\"alert.create\",\"sev\":null,");
    /* An incident_id one byte over WEB_LIVE_ID_MAX is not tracked, not
     * cut to fit (two such ids could then collide). Seen red (crit 2)
     * with the strlen test removed from alert_record(). */
    feed("{\"type\":\"alert.create\",\"ts\":12,"
         "\"incident_id\":\"012345678901234567890123456789012\",\"sev\":2}\n");
    s = sum();
    WT_EQ(s.alerts[2], 1);
    feed("{\"type\":\"alert.create\",\"ts\":13,"
         "\"incident_id\":\"01234567890123456789012345678901\",\"sev\":2}\n");
    WT_EQ(sum().alerts[2], 2);   /* 32 bytes: tracked */
    feed("{\"type\":\"alert.resolve\",\"ts\":14,"
         "\"incident_id\":\"01234567890123456789012345678901\",\"sev\":2}\n");
    WT_EQ(sum().alerts[2], 1);

    /* A reconnect starts the open set empty: a resolve may have been
     * missed. */
    web_live_sock_failed(&g_live, "x", 250, 2000);
    web_live_sock_connected(&g_live, 2100);
    s = sum();
    WT_EQ(s.alerts[0] + s.alerts[1] + s.alerts[2], 0);
    done();
}

/* The incident table is full at WEB_LIVE_INCIDENTS: the next one is
 * flagged, not stored. Seen red with the bound in alert_record() raised
 * by one: inc[256] overran into the members after the table, and the
 * summary then counted a LOW alert never sent and a garbage overflow
 * flag. */
static void test_incident_table_cap(void) {
    fresh();
    char line[128];
    for (int i = 0; i < WEB_LIVE_INCIDENTS + 1; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"alert.create\",\"ts\":1,\"incident_id\":\"i%d\",\"sev\":2}\n", i);
        feed(line);
    }
    web_live_sum_t s = sum();
    WT_EQ(s.alerts[2], WEB_LIVE_INCIDENTS);
    WT_EQ(s.alerts[0] + s.alerts[1], 0);
    WT_EQ(s.alerts_overflow, 1);
    WT_HAS(live_json(), "\"overflow\":true}");
    /* A resolve frees a slot; the flag stays, since one was missed. */
    feed("{\"type\":\"alert.resolve\",\"ts\":2,\"incident_id\":\"i0\",\"sev\":2}\n");
    WT_EQ(sum().alerts[2], WEB_LIVE_INCIDENTS - 1);
    WT_EQ(sum().alerts_overflow, 1);
    done();
}

/* ── types, rate, sensor health ───────────────────────────────────── */

static void test_types_counted_by_plausible_name(void) {
    fresh();
    feed("{\"type\":\"dns\"}\n{\"type\":\"dns\"}\n{\"type\":\"alert.create\"}\n"
         "{\"type\":\"<b>x</b>\"}\n{\"type\":\"\"}\n"
         "{\"type\":\"abcdefghijklmnopqrstuvwxyz0123456\"}\n");
    const char *j = live_json();
    WT_HAS(j, "\"types\":{\"dns\":2,\"alert.create\":1}");
    WT_HAS(j, "\"types_invalid\":3");
    /* Seen red ("\u003cb" present) with type_ok() always 1. */
    WT_LACKS(j, "u003cb");
    char line[64];
    for (int i = 0; i < WEB_LIVE_TYPES + 3; i++) {
        snprintf(line, sizeof(line), "{\"type\":\"t%d\"}\n", i);
        feed(line);
    }
    j = live_json();
    WT_HAS(j, "\"types_other\":5");   /* 48 slots, 2 taken before */
    done();
}

static void test_records_per_second(void) {
    fresh();
    /* 10 records in each of seconds 10..14, read at 15.5 s: 10/s. */
    for (long long sec = 10; sec < 15; sec++)
        for (int i = 0; i < 10; i++)
            feed_at("{\"type\":\"dns\"}\n", sec * 1000 + i * 50);
    web_live_sum_t s;
    web_live_summary(&g_live, &s, 15500);
    WT_EQ(s.rate10, 100);
    WT_EQ(s.records, 50);
    /* Records in the current second are not counted yet; old ones age
     * out. */
    feed_at("{\"type\":\"dns\"}\n", 15600);
    web_live_summary(&g_live, &s, 15700);
    WT_EQ(s.rate10, 100);
    web_live_summary(&g_live, &s, 18000);
    WT_EQ(s.rate10, 42);   /* 10+10+1 over 5 s: 4.2 */
    web_live_summary(&g_live, &s, 30000);
    WT_EQ(s.rate10, 0);
    done();
}

static void test_sensor_health_liveness(void) {
    fresh();
    WT_ASSERT(!strcmp(web_live_sensor_word(&g_live, 0), "unknown"));
    feed_at("{\"type\":\"sensor_health\",\"ts\":5,\"capture_iface\":\"any\","
            "\"capture_open\":1,\"capture_running\":1,\"monitor_iface\":\"\","
            "\"monitor_open\":0,\"monitor_running\":0,\"scope\":\"none\","
            "\"scope_not_enforced\":0}\n", 1000);
    WT_ASSERT(!strcmp(web_live_sensor_word(&g_live, 1000), "ok"));
    WT_ASSERT(!strcmp(web_live_sensor_word(&g_live, 1000 + WEB_LIVE_SH_STALE_MS),
                      "ok"));
    WT_ASSERT(!strcmp(web_live_sensor_word(&g_live, 1001 + WEB_LIVE_SH_STALE_MS),
                      "stale"));
    /* The record #91 was added for: an open handle behind a dead
     * thread. */
    feed_at("{\"type\":\"sensor_health\",\"ts\":6,\"capture_iface\":\"any\","
            "\"capture_open\":1,\"capture_running\":0,"
            "\"capture_exit\":\"iface_gone\"}\n", 2000);
    WT_ASSERT(!strcmp(web_live_sensor_word(&g_live, 2000), "degraded"));
    WT_HAS(live_json(), "\"capture_exit\":\"iface_gone\"");
    feed_at("{\"type\":\"sensor_health\",\"ts\":7,\"capture_open\":1,"
            "\"capture_running\":1,\"scope_not_enforced\":1}\n", 3000);
    WT_ASSERT(!strcmp(web_live_sensor_word(&g_live, 3000), "degraded"));
    feed_at("{\"type\":\"sensor_health\",\"ts\":8}\n", 4000);
    WT_ASSERT(!strcmp(web_live_sensor_word(&g_live, 4000), "not_observing"));
    done();
}

/* ── the recent ring ──────────────────────────────────────────────── */

static void test_recent_ring(void) {
    fresh();
    web_live_rec_t out[WEB_LIVE_RING];
    unsigned long long latest;
    WT_EQ(web_live_recent_after(&g_live, 0, out, 20, &latest), 0);
    WT_EQ(latest, 0);
    char line[96];
    for (int i = 1; i <= 70; i++) {
        snprintf(line, sizeof(line), "{\"type\":\"dns\",\"ts\":%d,\"qname\":\"q%d\"}\n",
                 i, i);
        feed(line);
    }
    /* The newest 20 of the 70, oldest first. */
    int n = web_live_recent_after(&g_live, 0, out, 20, &latest);
    WT_EQ(n, 20);
    WT_EQ(latest, 70);
    WT_EQ(out[0].seq, 51);
    WT_EQ(out[19].seq, 70);
    WT_ASSERT(!strcmp(out[19].text, "q70"));
    n = web_live_recent_after(&g_live, 65, out, 20, &latest);
    WT_EQ(n, 5);
    WT_EQ(out[0].seq, 66);
    WT_EQ(web_live_recent_after(&g_live, 70, out, 20, &latest), 0);
    /* Never older than the ring holds. */
    n = web_live_recent_after(&g_live, 0, out, WEB_LIVE_RING, &latest);
    WT_EQ(n, WEB_LIVE_RING);
    WT_EQ(out[0].seq, 70 - WEB_LIVE_RING + 1);
    WT_HAS(live_json(), "\"recent\":[{\"seq\":21,\"type\":\"dns\",\"ts\":21,\"text\":\"q21\"}");
    done();
}

/* ── hostile strings ──────────────────────────────────────────────── */

/* #159: a record with markup in an SSID or hostname renders as text.
 * The live document carries no raw < or > at all, wherever the string
 * was put. Seen red ("<img" present) with '<' and '>' dropped from the
 * escape condition in web_jw_strn(). */
static void test_hostile_strings_are_escaped(void) {
    fresh();
    feed("{\"type\":\"device\",\"ts\":1,\"mac\":\"02:00:00:00:00:01\","
         "\"hostname\":\"<img src=x onerror=alert(1)>\"}\n"
         "{\"type\":\"beacon\",\"ts\":1,\"ssid\":\"</script><script>alert(1)</script>\"}\n"
         "{\"type\":\"alert.create\",\"ts\":2,\"incident_id\":\"<i>\",\"sev\":2,"
         "\"title\":\"<b>T</b>\",\"detail\":\"a\\u2028b & 'c' \\\"d\\\"\"}\n"
         "{\"type\":\"sensor_health\",\"ts\":3,\"capture_iface\":\"<x>\",\"capture_open\":1}\n");
    const char *j = live_json();
    WT_ASSERT(j[0] == '{');
    WT_LACKS(j, "<");
    WT_LACKS(j, ">");
    WT_LACKS(j, "\xe2\x80\xa8");
    WT_HAS(j, "\\u003cimg src=x onerror=alert(1)\\u003e");
    WT_HAS(j, "\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e");
    WT_HAS(j, "a\\u2028b \\u0026 \\u0027c\\u0027 \\\"d\\\"");
    WT_HAS(j, "\"capture_iface\":\"\\u003cx\\u003e\"");

    /* The ticker's event too. */
    web_live_rec_t out[4];
    unsigned long long latest;
    int n = web_live_recent_after(&g_live, 0, out, 4, &latest);
    WT_EQ(n, 4);
    char ev[2048];
    for (int i = 0; i < n; i++) {
        size_t len = web_sse_record(ev, sizeof(ev), &out[i]);
        WT_ASSERT(len > 0);
        WT_LACKS(ev, "<");
        /* one data line: "event:", "data:", then the blank line */
        int lfs = 0;
        for (size_t k = 0; k < len; k++) lfs += ev[k] == '\n';
        WT_EQ(lfs, 3);
    }
    done();
}

/* A ticker line is cut to WEB_LIVE_TEXT_MAX on a code-point boundary,
 * never inside one, so what leaves is valid UTF-8 and needs no U+FFFD.
 * 'a' then 2-byte e-acutes puts byte 80 mid-sequence; the 600-byte
 * qname is also cut by summarise()'s own snprintf, mid-sequence, at
 * 511 bytes. Seen red (\ufffd in the JSON, text 80 bytes) with the
 * continuation-byte loop removed from web_utf8_copy(). */
static void test_ticker_cut_is_on_a_code_point(void) {
    fresh();
    char q[700];
    size_t o = 0;
    q[o++] = 'a';
    for (int i = 0; i < 40; i++) { q[o++] = '\xc3'; q[o++] = '\xa9'; }
    q[o] = '\0';
    char line[1024];
    snprintf(line, sizeof(line), "{\"type\":\"dns\",\"ts\":1,\"qname\":\"%s\"}\n", q);
    feed(line);
    o = 0;
    for (int i = 0; i < 300; i++) { q[o++] = '\xc3'; q[o++] = '\xa9'; }
    q[o] = '\0';
    snprintf(line, sizeof(line), "{\"type\":\"dns\",\"ts\":2,\"qname\":\"%s\"}\n", q);
    feed(line);
    WT_EQ(sum().records, 2);

    web_live_rec_t out[2];
    unsigned long long latest;
    WT_EQ(web_live_recent_after(&g_live, 0, out, 2, &latest), 2);
    WT_EQ(strlen(out[0].text), 79);   /* 'a' and 39 whole e-acutes */
    WT_EQ(strlen(out[1].text), 80);   /* 40 whole e-acutes */
    for (int k = 0; k < 2; k++) {
        size_t n = strlen(out[k].text), i = 0;
        while (i < n) {
            unsigned cp;
            size_t l = web_utf8_seq((const unsigned char *)out[k].text + i, n - i, &cp);
            WT_ASSERT(l > 0);
            if (!l) break;
            i += l;
        }
    }
    const char *j = live_json();
    WT_LACKS(j, "ufffd");
    WT_HAS(j, "\"text\":\"a\xc3\xa9");
    done();
}

/* Every table full, every string at its cap and made of the byte that
 * escapes widest: /api/live still fits the connection buffer behind its
 * header. If a cap is ever raised past what fits, this is what says so
 * (the route would answer 503). */
static void test_worst_case_live_fits(void) {
    char big[600];
    memset(big, '<', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    web_live_init(&g_live, big);
    web_live_sock_connected(&g_live, 0);
    web_live_sock_failed(&g_live, big, 4000, 1);
    web_live_sock_connected(&g_live, 2);
    web_feed_reset(&g_feed);
    static char line[4096];
    for (int i = 0; i < WEB_LIVE_TYPES; i++) {
        snprintf(line, sizeof(line), "{\"type\":\"%032d\",\"ts\":-9223372036854775807,"
                                     "\"qname\":\"%s\"}\n", i, big);
        feed(line);
    }
    for (int i = 0; i < WEB_LIVE_ALERTS; i++) {
        snprintf(line, sizeof(line),
                 "{\"type\":\"alert.escalate\",\"ts\":-9223372036854775807,"
                 "\"incident_id\":\"%.32s\",\"sev\":2,\"title\":\"%s\",\"detail\":\"%s\"}\n",
                 big, big, big);
        feed(line);
    }
    for (int i = 0; i < WEB_LIVE_RING; i++) {
        snprintf(line, sizeof(line), "{\"type\":\"%032d\",\"ts\":-9223372036854775807,"
                                     "\"qname\":\"%s\",\"host\":\"%s\"}\n", i, big, big);
        feed(line);
    }
    snprintf(line, sizeof(line),
             "{\"type\":\"sensor_health\",\"ts\":1,\"capture_iface\":\"%s\","
             "\"monitor_iface\":\"%s\",\"capture_exit\":\"%s\",\"monitor_exit\":\"%s\","
             "\"scope\":\"%s\",\"capture_open\":1,\"monitor_open\":1}\n",
             big, big, big, big, big);
    feed(line);
    size_t n = web_live_json(&g_live, g_json,
                             WEB_SSE_MAX_UNSENT - WEB_LIVE_HDR_RESERVE, 1000);
    WT_ASSERT(n > 0);
    WT_ASSERT(n < WEB_SSE_MAX_UNSENT - WEB_LIVE_HDR_RESERVE);
    fprintf(stderr, "    worst-case /api/live: %zu bytes of %d\n", n,
            WEB_SSE_MAX_UNSENT - WEB_LIVE_HDR_RESERVE);
    WT_LACKS(g_json, "<");

    char hbuf[4096];
    web_jw_t w;
    web_jw_init(&w, hbuf, sizeof(hbuf));
    web_live_health_members(&g_live, &w, 1000);
    WT_EQ(w.overflow, 0);
    done();
}

/* ── the framer ───────────────────────────────────────────────────── */

static unsigned long long records(void) { return sum().records; }

static void test_framer_splits_and_joins(void) {
    fresh();
    /* One record a byte at a time, then three in one read, with an
     * empty line and a CRLF. */
    const char *one = "{\"type\":\"dns\",\"qname\":\"a\"}\n";
    for (size_t i = 0; one[i]; i++)
        web_feed_bytes(&g_feed, &g_live, one + i, 1, 1000);
    WT_EQ(records(), 1);
    feed("{\"type\":\"dns\"}\n\n{\"type\":\"tls\"}\r\n{\"type\":\"quic\"}\n");
    WT_EQ(records(), 4);
    WT_EQ(g_live.decode_errors, 0);

    /* The connection ends inside a line: counted, not decoded. */
    feed("{\"type\":\"device\",\"mac\":\"a\"}");
    WT_EQ(records(), 4);
    web_feed_eof(&g_feed, &g_live);
    WT_EQ(g_live.truncated, 1);
    WT_EQ(records(), 4);
    /* and the next connection starts clean */
    feed("{\"type\":\"dns\"}\n");
    WT_EQ(records(), 5);
    done();
}

/* A line over WEB_JL_MAX_LINE is dropped through its newline, however
 * the reads split it, and counted once. Its tail here is a valid
 * record on purpose: seen red (that record counted) with the
 * discarding flag never set in web_feed_bytes(). */
static void test_framer_drops_overlong_lines(void) {
    fresh();
    size_t pad = WEB_JL_MAX_LINE - 10;
    char *junk = malloc(pad);
    memset(junk, 'Z', pad);
    web_feed_bytes(&g_feed, &g_live, junk, pad, 1000);
    web_feed_bytes(&g_feed, &g_live, junk, 20, 1000);   /* now over */
    feed("{\"type\":\"device\",\"mac\":\"evil\"}\n{\"type\":\"dns\"}\n");
    WT_EQ(records(), 1);
    WT_EQ(g_live.dec_by[WEB_JL_ELONG], 1);
    WT_EQ(g_live.decode_errors, 1);
    WT_HAS(live_json(), "\"types\":{\"dns\":1}");
    free(junk);

    /* The boundary: WEB_JL_MAX_LINE bytes is a line, one more is not. */
    char *line = malloc(WEB_JL_MAX_LINE + 2);
    for (int extra = 0; extra < 2; extra++) {
        size_t len = WEB_JL_MAX_LINE + (size_t)extra;
        memset(line, ' ', len);
        memcpy(line, "{\"type\":\"ntp\"}", 14);
        line[len] = '\n';
        web_feed_bytes(&g_feed, &g_live, line, len + 1, 1000);
    }
    WT_EQ(records(), 2);
    WT_EQ(g_live.dec_by[WEB_JL_ELONG], 2);

    /* The framer's own boundary, apart from web_jl_parse()'s re-check:
     * WEB_JL_MAX_LINE + 1 bytes with no newline yet is already over,
     * counted then, and the connection ending there is no truncated
     * record. Seen red (ELONG still 2, truncated 1) with the framer's
     * test loosened to > WEB_JL_MAX_LINE + 1. */
    memset(line, 'Y', WEB_JL_MAX_LINE + 1);
    web_feed_bytes(&g_feed, &g_live, line, WEB_JL_MAX_LINE + 1, 1000);
    WT_EQ(g_live.dec_by[WEB_JL_ELONG], 3);
    web_feed_eof(&g_feed, &g_live);
    WT_EQ(g_live.truncated, 0);
    WT_EQ(g_live.dec_by[WEB_JL_ELONG], 3);
    /* and exactly WEB_JL_MAX_LINE with no newline is still a line */
    memset(line, ' ', WEB_JL_MAX_LINE);
    memcpy(line, "{\"type\":\"ntp\"}", 14);
    web_feed_bytes(&g_feed, &g_live, line, WEB_JL_MAX_LINE, 1000);
    WT_EQ(g_live.dec_by[WEB_JL_ELONG], 3);
    web_feed_bytes(&g_feed, &g_live, "\n", 1, 1000);
    WT_EQ(records(), 3);
    free(line);
    done();
}

void run_live_tests(void) {
    WT_RUN(test_device_count_is_the_latest_pass);
    WT_RUN(test_cut_pass_is_not_published);
    WT_RUN(test_empty_table_publishes_zero);
    WT_RUN(test_reconnect_is_a_new_stream);
    WT_RUN(test_capture_records_inside_a_pass);
    WT_RUN(test_alert_lifecycle_counts);
    WT_RUN(test_incident_table_cap);
    WT_RUN(test_types_counted_by_plausible_name);
    WT_RUN(test_records_per_second);
    WT_RUN(test_sensor_health_liveness);
    WT_RUN(test_recent_ring);
    WT_RUN(test_hostile_strings_are_escaped);
    WT_RUN(test_ticker_cut_is_on_a_code_point);
    WT_RUN(test_worst_case_live_fits);
    WT_RUN(test_framer_splits_and_joins);
    WT_RUN(test_framer_drops_overlong_lines);
}
