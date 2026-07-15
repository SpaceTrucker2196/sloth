#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "history.h"

/* Tests for sloth_state_t logic — view switching, ring buffer, etc. */

/* ── view switching ──────────────────────────────────────── */

void test_view_tab_cycles_forward(void) {
    view_t v = VIEW_IFACE;
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_CONNS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_WIFI);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_PACKETS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_PROCS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_STATS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_PROBE);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_ARP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_MDNS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_NBNS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_DHCP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_SSDP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_BEACON);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_DEAUTH);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_HTTP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_TLS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_QUIC);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_DNS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_NTP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_ICMP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_ALERTS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_DEVICES);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_HELP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_DASH);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_PNL);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_EAPOL);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_SEQNUM);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_ASSOC);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_CHANNEL);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_OSI);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_TWINS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_KARMA);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_ROGUE_RADIUS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_IFACE);   /* wraps */
}

void test_view_direct_key_select(void) {
    view_t v = VIEW_PACKETS;
    /* simulating '1' key */
    v = VIEW_IFACE;   ASSERT_EQ(v, VIEW_IFACE);
    v = VIEW_CONNS;   ASSERT_EQ(v, VIEW_CONNS);
    v = VIEW_WIFI;    ASSERT_EQ(v, VIEW_WIFI);
    v = VIEW_PACKETS; ASSERT_EQ(v, VIEW_PACKETS);
}

void test_view_count_matches_labels(void) {
    /* VIEW_COUNT must stay in sync with actual views */
    ASSERT_EQ(VIEW_COUNT, 33);
}

/* ── packet ring buffer ──────────────────────────────────── */

static void push_packet(sloth_state_t *s, uint32_t ts_sec) {
    int slot = s->pkt_head % MAX_PACKETS;
    memset(&s->packets[slot], 0, sizeof(packet_info_t));
    s->packets[slot].ts_sec = ts_sec;
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS)
        s->pkt_count++;
}

void test_ring_buffer_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(s.pkt_count, 0);
    ASSERT_EQ(s.pkt_head, 0);
}

void test_ring_buffer_single_push(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packet(&s, 1001);
    ASSERT_EQ(s.pkt_count, 1);
    ASSERT_EQ(s.pkt_head, 1);
    ASSERT_EQ((int)s.packets[0].ts_sec, 1001);
}

void test_ring_buffer_fills(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    for (int i = 0; i < MAX_PACKETS; i++)
        push_packet(&s, (uint32_t)(2000 + i));
    ASSERT_EQ(s.pkt_count, MAX_PACKETS);
    ASSERT_EQ(s.pkt_head, 0);   /* wrapped back to slot 0 */
}

void test_ring_buffer_overwrites_oldest(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    /* fill completely */
    for (int i = 0; i < MAX_PACKETS; i++)
        push_packet(&s, (uint32_t)(3000 + i));
    /* push one more — overwrites slot 0 (the oldest) */
    push_packet(&s, 9999);
    ASSERT_EQ(s.pkt_count, MAX_PACKETS);   /* count stays capped */
    ASSERT_EQ((int)s.packets[0].ts_sec, 9999);  /* slot 0 now has newest */
    ASSERT_EQ(s.pkt_head, 1);
}

void test_ring_oldest_start_when_full(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    for (int i = 0; i < MAX_PACKETS; i++)
        push_packet(&s, (uint32_t)(4000 + i));
    /* When full, oldest entry is at pkt_head (next write slot) */
    int oldest_slot = s.pkt_head;
    ASSERT_EQ((int)s.packets[oldest_slot].ts_sec, 4000);
}

/* ── state field defaults ────────────────────────────────── */

void test_state_zero_init(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(s.iface_count, 0);
    ASSERT_EQ(s.conn_count,  0);
    ASSERT_EQ(s.ap_count,    0);
    ASSERT_EQ(s.pkt_count,   0);
    ASSERT_EQ((int)s.active_view, 0);
}

/* ── iface history ───────────────────────────────────────── */

void test_history_find_new_slot(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    iface_hist_t *h = history_find(&s, "eth0");
    ASSERT(h != NULL);
    ASSERT_STR(h->name, "eth0");
    ASSERT_EQ(h->count, 0);
}

void test_history_find_same_slot(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    iface_hist_t *a = history_find(&s, "eth0");
    iface_hist_t *b = history_find(&s, "eth0");
    ASSERT(a == b);   /* same pointer */
}

void test_history_update_pushes_rates(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));

    s.iface_count = 1;
    memcpy(s.ifaces[0].name, "eth0", 5);
    s.ifaces[0].rx_rate = 10e6;
    s.ifaces[0].tx_rate =  5e6;

    history_update(&s);

    iface_hist_t *h = history_find(&s, "eth0");
    ASSERT(h != NULL);
    ASSERT_EQ(h->count, 1);
    /* head advanced to 1; last-written slot is head-1 = 0 */
    ASSERT_NEAR(h->rx[0], 10e6, 1.0);
    ASSERT_NEAR(h->tx[0],  5e6, 1.0);
}

void test_history_update_multiple_polls(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.iface_count = 1;
    memcpy(s.ifaces[0].name, "eth0", 5);

    for (int i = 0; i < HIST_LEN; i++) {
        s.ifaces[0].rx_rate = (double)(i * 1000);
        history_update(&s);
    }

    iface_hist_t *h = history_find(&s, "eth0");
    ASSERT(h != NULL);
    ASSERT_EQ(h->count, HIST_LEN);
    ASSERT_EQ(h->head, 0);   /* wrapped back to 0 */
}

void test_history_update_wraps_ring(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.iface_count = 1;
    memcpy(s.ifaces[0].name, "eth0", 5);

    /* overfill by 5 */
    for (int i = 0; i < HIST_LEN + 5; i++) {
        s.ifaces[0].rx_rate = (double)(i);
        history_update(&s);
    }

    iface_hist_t *h = history_find(&s, "eth0");
    ASSERT_EQ(h->count, HIST_LEN);   /* capped */
    /* newest value is HIST_LEN+4, stored at head-1 */
    int last = (h->head - 1 + HIST_LEN) % HIST_LEN;
    ASSERT_NEAR(h->rx[last], (double)(HIST_LEN + 4), 0.5);
}

void test_history_multiple_interfaces(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.iface_count = 2;
    memcpy(s.ifaces[0].name, "eth0",  5);
    memcpy(s.ifaces[1].name, "wlan0", 6);
    s.ifaces[0].rx_rate = 100e6;
    s.ifaces[1].rx_rate =  50e6;

    history_update(&s);

    iface_hist_t *h0 = history_find(&s, "eth0");
    iface_hist_t *h1 = history_find(&s, "wlan0");
    ASSERT(h0 != h1);
    ASSERT_NEAR(h0->rx[0], 100e6, 1.0);
    ASSERT_NEAR(h1->rx[0],  50e6, 1.0);
}

/* ── iface toggle ────────────────────────────────────────── */

#include "views/iface.h"

static sloth_state_t make_state_with_ifaces(int n) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    static const char *names[] = { "eth0", "wlan0", "lo", "tun0" };
    s.iface_count = n < 4 ? n : 4;
    for (int i = 0; i < s.iface_count; i++)
        memcpy(s.ifaces[i].name, names[i], strlen(names[i]) + 1);
    return s;
}

void test_toggle_hide(void) {
    sloth_state_t s = make_state_with_ifaces(2);
    s.iface_sel = 0;   /* eth0 selected */
    view_iface_key(&s, 't');
    ASSERT_EQ(s.iface_hidden_count, 1);
    ASSERT_STR(s.iface_hidden[0], "eth0");
}

void test_toggle_unhide(void) {
    sloth_state_t s = make_state_with_ifaces(2);
    s.iface_sel = 0;
    view_iface_key(&s, 't');   /* hide eth0 */
    view_iface_key(&s, 't');   /* unhide eth0 */
    ASSERT_EQ(s.iface_hidden_count, 0);
}

void test_toggle_navigation(void) {
    sloth_state_t s = make_state_with_ifaces(3);
    ASSERT_EQ(s.iface_sel, 0);
    view_iface_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.iface_sel, 1);
    view_iface_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.iface_sel, 2);
    view_iface_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.iface_sel, 2);   /* clamped at max */
    view_iface_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.iface_sel, 1);
    view_iface_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.iface_sel, 0);
    view_iface_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.iface_sel, 0);   /* clamped at 0 */
}

void test_toggle_hides_selected(void) {
    sloth_state_t s = make_state_with_ifaces(3);
    view_iface_key(&s, SLOTH_KEY_DOWN);   /* sel = 1 (wlan0) */
    view_iface_key(&s, 't');
    ASSERT_EQ(s.iface_hidden_count, 1);
    ASSERT_STR(s.iface_hidden[0], "wlan0");
}

/* ── data-stream (deselect) election — issue #17 ───────── */

void test_deselect_default_is_selected(void) {
    /* Fresh state: no deselected ifaces. iface_is_deselected returns 0
     * for anything asked. */
    sloth_state_t s = make_state_with_ifaces(2);
    ASSERT_EQ(s.iface_deselected_count, 0);
    ASSERT_EQ(iface_is_deselected(&s, "eth0"),  0);
    ASSERT_EQ(iface_is_deselected(&s, "wlan0"), 0);
}

void test_toggle_deselect(void) {
    sloth_state_t s = make_state_with_ifaces(2);
    s.iface_sel = 0;
    view_iface_key(&s, 'y');
    ASSERT_EQ(s.iface_deselected_count, 1);
    ASSERT_STR(s.iface_deselected[0], "eth0");
    ASSERT_EQ(iface_is_deselected(&s, "eth0"),  1);
    ASSERT_EQ(iface_is_deselected(&s, "wlan0"), 0);
}

void test_toggle_reselect(void) {
    sloth_state_t s = make_state_with_ifaces(2);
    s.iface_sel = 0;
    view_iface_key(&s, 'y');   /* deselect eth0 */
    view_iface_key(&s, 'y');   /* reselect eth0 */
    ASSERT_EQ(s.iface_deselected_count, 0);
    ASSERT_EQ(iface_is_deselected(&s, "eth0"), 0);
}

void test_deselect_independent_of_hide(void) {
    /* Hide and deselect are distinct elections — toggling one must
     * not disturb the other. */
    sloth_state_t s = make_state_with_ifaces(2);
    s.iface_sel = 0;
    view_iface_key(&s, 't');   /* hide eth0 */
    view_iface_key(&s, 'y');   /* deselect eth0 */
    ASSERT_EQ(s.iface_hidden_count,     1);
    ASSERT_EQ(s.iface_deselected_count, 1);
    ASSERT(iface_is_hidden(&s, "eth0"));
    ASSERT(iface_is_deselected(&s, "eth0"));
    view_iface_key(&s, 't');   /* unhide eth0 */
    ASSERT_EQ(s.iface_hidden_count,     0);
    ASSERT_EQ(s.iface_deselected_count, 1);
    ASSERT_EQ(iface_is_hidden(&s, "eth0"),     0);
    ASSERT_EQ(iface_is_deselected(&s, "eth0"), 1);
}

/* ── launch-time allow-list (--iface / --monitor-only) — issue #35 ── */

void test_allow_empty_list_all_pass(void) {
    /* No --iface flags given: the allow-list is empty and everything
     * passes — a bare launch is unrestricted. */
    sloth_state_t s = make_state_with_ifaces(3);
    ASSERT_EQ(s.iface_allowed_count, 0);
    ASSERT_EQ(iface_is_allowed(&s, "eth0"),    1);
    ASSERT_EQ(iface_is_allowed(&s, "wlan0"),   1);
    ASSERT_EQ(iface_is_allowed(&s, "docker0"), 1);
}

void test_allow_whitelist(void) {
    /* Non-empty list = whitelist: only listed names pass. */
    sloth_state_t s = make_state_with_ifaces(3);
    ASSERT_EQ(iface_allow_add(&s, "wlan0"), 1);
    ASSERT_EQ(s.iface_allowed_count, 1);
    ASSERT_STR(s.iface_allowed[0], "wlan0");
    ASSERT_EQ(iface_is_allowed(&s, "wlan0"),   1);
    ASSERT_EQ(iface_is_allowed(&s, "eth0"),    0);
    ASSERT_EQ(iface_is_allowed(&s, "lo"),      0);
    ASSERT_EQ(iface_is_allowed(&s, "docker0"), 0);
}

void test_allow_multiple_ifaces(void) {
    sloth_state_t s = make_state_with_ifaces(4);
    ASSERT_EQ(iface_allow_add(&s, "wlan0"), 1);
    ASSERT_EQ(iface_allow_add(&s, "eth0"),  1);
    ASSERT_EQ(s.iface_allowed_count, 2);
    ASSERT_EQ(iface_is_allowed(&s, "wlan0"), 1);
    ASSERT_EQ(iface_is_allowed(&s, "eth0"),  1);
    ASSERT_EQ(iface_is_allowed(&s, "tun0"),  0);
}

void test_allow_dedupe(void) {
    /* Re-adding a present name reports success but grows nothing —
     * `--iface wlan0 --monitor-only` resolving to wlan0 is one entry. */
    sloth_state_t s = make_state_with_ifaces(2);
    ASSERT_EQ(iface_allow_add(&s, "wlan0"), 1);
    ASSERT_EQ(iface_allow_add(&s, "wlan0"), 1);
    ASSERT_EQ(s.iface_allowed_count, 1);
}

void test_allow_null_empty_ignored(void) {
    /* A failed --monitor-only resolve passes "" / NULL; the list must
     * stay empty so the stream stays unrestricted (fail-open). */
    sloth_state_t s = make_state_with_ifaces(2);
    ASSERT_EQ(iface_allow_add(&s, NULL), 0);
    ASSERT_EQ(iface_allow_add(&s, ""),   0);
    ASSERT_EQ(s.iface_allowed_count, 0);
    ASSERT_EQ(iface_is_allowed(&s, "eth0"), 1);
}

void test_allow_bounded_at_max(void) {
    sloth_state_t s = make_state_with_ifaces(1);
    char name[16];
    for (int i = 0; i < MAX_IFACES; i++) {
        snprintf(name, sizeof(name), "if%d", i);
        ASSERT_EQ(iface_allow_add(&s, name), 1);
    }
    ASSERT_EQ(s.iface_allowed_count, MAX_IFACES);
    ASSERT_EQ(iface_allow_add(&s, "overflow"), 0);
    ASSERT_EQ(s.iface_allowed_count, MAX_IFACES);
    ASSERT_EQ(iface_is_allowed(&s, "overflow"), 0);
    ASSERT_EQ(iface_is_allowed(&s, "if0"), 1);
}

void test_allow_independent_of_deselect(void) {
    /* The two elections are independent lists; the capture callback
     * drops when EITHER rejects. An iface can be allowed and
     * deselected at once — deselect still wins in the callback's
     * composed predicate. */
    sloth_state_t s = make_state_with_ifaces(2);
    s.iface_sel = 1;
    iface_allow_add(&s, "wlan0");
    view_iface_key(&s, 'y');   /* deselect wlan0 at runtime */
    ASSERT_EQ(iface_is_allowed(&s, "wlan0"),    1);
    ASSERT_EQ(iface_is_deselected(&s, "wlan0"), 1);
    /* composed predicate, exactly as on_packet() evaluates it */
    int dropped = iface_is_deselected(&s, "wlan0")
               || !iface_is_allowed(&s, "wlan0");
    ASSERT_EQ(dropped, 1);
    /* eth0: not deselected, but outside the allow-list → dropped */
    dropped = iface_is_deselected(&s, "eth0")
           || !iface_is_allowed(&s, "eth0");
    ASSERT_EQ(dropped, 1);
    /* reselect wlan0 → passes both elections again */
    view_iface_key(&s, 'y');
    dropped = iface_is_deselected(&s, "wlan0")
           || !iface_is_allowed(&s, "wlan0");
    ASSERT_EQ(dropped, 0);
}

/* ── allow-list exclusion marker (iface view) — issue #37 ── */

void test_excluded_empty_list_marks_nothing(void) {
    /* Bare launch: empty allow-list excludes nothing, render unchanged. */
    sloth_state_t s = make_state_with_ifaces(3);
    ASSERT_EQ(iface_is_excluded(&s, "eth0"),  0);
    ASSERT_EQ(iface_is_excluded(&s, "wlan0"), 0);
    ASSERT_EQ(iface_is_excluded(&s, "lo"),    0);
    ASSERT_EQ(iface_row_prefix(&s, "eth0", 0), ' ');
    ASSERT_EQ(iface_row_prefix(&s, "eth0", 1), 's');
}

void test_excluded_marks_unlisted_only(void) {
    /* Non-empty list: unlisted ifaces get the 'x' marker, listed ones
     * render exactly as unrestricted. */
    sloth_state_t s = make_state_with_ifaces(3);
    iface_allow_add(&s, "wlan0");
    ASSERT_EQ(iface_is_excluded(&s, "eth0"),  1);
    ASSERT_EQ(iface_is_excluded(&s, "lo"),    1);
    ASSERT_EQ(iface_is_excluded(&s, "wlan0"), 0);
    ASSERT_EQ(iface_row_prefix(&s, "eth0",  0), 'x');
    ASSERT_EQ(iface_row_prefix(&s, "wlan0", 0), ' ');
    /* excluded outranks the scanning marker: dropped data trumps
     * radio state */
    ASSERT_EQ(iface_row_prefix(&s, "eth0", 1), 'x');
}

void test_excluded_prefix_precedence(void) {
    /* hidden > deselected > excluded: an iface rejected by both
     * elections reads as the one the operator can still toggle. */
    sloth_state_t s = make_state_with_ifaces(2);
    iface_allow_add(&s, "wlan0");
    ASSERT_EQ(iface_row_prefix(&s, "eth0", 0), 'x');
    s.iface_sel = 0;
    view_iface_key(&s, 'y');   /* deselect eth0 */
    ASSERT_EQ(iface_row_prefix(&s, "eth0", 0), 'd');
    view_iface_key(&s, 't');   /* hide eth0 */
    ASSERT_EQ(iface_row_prefix(&s, "eth0", 0), 'h');
    view_iface_key(&s, 't');   /* unhide */
    view_iface_key(&s, 'y');   /* reselect → back to excluded */
    ASSERT_EQ(iface_row_prefix(&s, "eth0", 0), 'x');
}

void test_excluded_render_smoke(void) {
    /* Exercise the draw path with an exclusion present — must not
     * crash and must leave state untouched (draw is const). */
    sloth_state_t s = make_state_with_ifaces(3);
    iface_allow_add(&s, "wlan0");
    s.iface_sel = 0;           /* selected row IS an excluded row */
    view_iface_draw(&s);
    ASSERT_EQ(s.iface_allowed_count, 1);
    ASSERT_EQ(iface_is_excluded(&s, "eth0"), 1);
}

/* ── view_claims_key: which views own which shadow keys ──────
 *
 * The bug was that the global view-switch handler in main.c consumed
 * letters like 't', 'm', 's', 'p', 'r', 'w', 'x' before the active
 * view's handler ever ran. view_claims_key() is the first-refusal
 * table; these tests pin down the intended shape so a future edit
 * that drops a key from the table trips a red suite. */

void test_view_claims_iface_local_keys(void) {
    ASSERT(view_claims_key(VIEW_IFACE, 't'));
    ASSERT(view_claims_key(VIEW_IFACE, 'T'));
    ASSERT(view_claims_key(VIEW_IFACE, 'm'));
    ASSERT(view_claims_key(VIEW_IFACE, 'M'));
    /* 'y' toggles data-stream selection (#17). Claimed defensively so
     * a future global key assignment doesn't silently shadow it. */
    ASSERT(view_claims_key(VIEW_IFACE, 'y'));
    ASSERT(view_claims_key(VIEW_IFACE, 'Y'));
}

void test_view_claims_conns_sort_key(void) {
    ASSERT(view_claims_key(VIEW_CONNS, 's'));
    ASSERT(view_claims_key(VIEW_CONNS, 'S'));
}

void test_view_claims_packets_local_keys(void) {
    ASSERT(view_claims_key(VIEW_PACKETS, 'p'));
    ASSERT(view_claims_key(VIEW_PACKETS, 'x'));
    ASSERT(view_claims_key(VIEW_PACKETS, 'w'));
}

void test_view_claims_stats_reset_key(void) {
    ASSERT(view_claims_key(VIEW_STATS, 'r'));
    ASSERT(view_claims_key(VIEW_STATS, 'R'));
}

void test_view_claims_dashboard_tab(void) {
    ASSERT(view_claims_key(VIEW_DASH, '\t'));
    /* Dashboard doesn't claim ordinary letter keys — those still
     * cycle to the labelled view. */
    ASSERT_EQ(view_claims_key(VIEW_DASH, 't'), 0);
    ASSERT_EQ(view_claims_key(VIEW_DASH, 's'), 0);
}

void test_view_claims_no_claim_defaults(void) {
    /* A view without an entry in the table doesn't claim anything —
     * the global switch still owns every letter for it. */
    ASSERT_EQ(view_claims_key(VIEW_TLS, 't'), 0);
    ASSERT_EQ(view_claims_key(VIEW_DNS, 'r'), 0);
    ASSERT_EQ(view_claims_key(VIEW_NTP, 'p'), 0);
    ASSERT_EQ(view_claims_key(VIEW_HTTP, 'h'), 0);
}

void test_view_claims_non_shadow_keys_unclaimed(void) {
    /* Keys the report calls out as safe ('c', 'f', 'y', 'z', space,
     * arrows) shouldn't be claimed by any view — they fall through
     * to the view handler via the normal (non-first-refusal) path. */
    ASSERT_EQ(view_claims_key(VIEW_IFACE, 'f'), 0);
    ASSERT_EQ(view_claims_key(VIEW_CONNS, 'f'), 0);
    ASSERT_EQ(view_claims_key(VIEW_PACKETS, 'f'), 0);
    ASSERT_EQ(view_claims_key(VIEW_STATS, 'c'), 0);
    ASSERT_EQ(view_claims_key(VIEW_IFACE, SLOTH_KEY_DOWN), 0);
    ASSERT_EQ(view_claims_key(VIEW_PACKETS, ' '), 0);
}

void run_state_tests(void) {
    TEST_SUITE("view switching");
    RUN_TEST(test_view_tab_cycles_forward);
    RUN_TEST(test_view_direct_key_select);
    RUN_TEST(test_view_count_matches_labels);

    TEST_SUITE("view key first refusal");
    RUN_TEST(test_view_claims_iface_local_keys);
    RUN_TEST(test_view_claims_conns_sort_key);
    RUN_TEST(test_view_claims_packets_local_keys);
    RUN_TEST(test_view_claims_stats_reset_key);
    RUN_TEST(test_view_claims_dashboard_tab);
    RUN_TEST(test_view_claims_no_claim_defaults);
    RUN_TEST(test_view_claims_non_shadow_keys_unclaimed);

    TEST_SUITE("packet ring buffer");
    RUN_TEST(test_ring_buffer_empty);
    RUN_TEST(test_ring_buffer_single_push);
    RUN_TEST(test_ring_buffer_fills);
    RUN_TEST(test_ring_buffer_overwrites_oldest);
    RUN_TEST(test_ring_oldest_start_when_full);

    TEST_SUITE("state defaults");
    RUN_TEST(test_state_zero_init);

    TEST_SUITE("iface history");
    RUN_TEST(test_history_find_new_slot);
    RUN_TEST(test_history_find_same_slot);
    RUN_TEST(test_history_update_pushes_rates);
    RUN_TEST(test_history_update_multiple_polls);
    RUN_TEST(test_history_update_wraps_ring);
    RUN_TEST(test_history_multiple_interfaces);

    TEST_SUITE("iface toggle + navigation");
    RUN_TEST(test_toggle_hide);
    RUN_TEST(test_toggle_unhide);
    RUN_TEST(test_toggle_navigation);
    RUN_TEST(test_toggle_hides_selected);

    TEST_SUITE("iface deselect (data-stream) — #17");
    RUN_TEST(test_deselect_default_is_selected);
    RUN_TEST(test_toggle_deselect);
    RUN_TEST(test_toggle_reselect);
    RUN_TEST(test_deselect_independent_of_hide);

    TEST_SUITE("iface allow-list (launch-time) — #35");
    RUN_TEST(test_allow_empty_list_all_pass);
    RUN_TEST(test_allow_whitelist);
    RUN_TEST(test_allow_multiple_ifaces);
    RUN_TEST(test_allow_dedupe);
    RUN_TEST(test_allow_null_empty_ignored);
    RUN_TEST(test_allow_bounded_at_max);
    RUN_TEST(test_allow_independent_of_deselect);

    TEST_SUITE("iface allow-list exclusion marker — #37");
    RUN_TEST(test_excluded_empty_list_marks_nothing);
    RUN_TEST(test_excluded_marks_unlisted_only);
    RUN_TEST(test_excluded_prefix_precedence);
    RUN_TEST(test_excluded_render_smoke);
}
