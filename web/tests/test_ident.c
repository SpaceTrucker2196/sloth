/* The identity tables (#161, M3): names, MAC/IP bindings, first_seen
 * and the DNS client join, from decoded records on a pinned clock. */
#include <stdio.h>
#include <string.h>

#include "web_ident.h"
#include "web_jsonl.h"
#include "wtest.h"

static web_ident_t id;

static void rec(const char *line, long long now) {
    static web_jrec_t r;
    WT_EQ(web_jl_parse(line, strlen(line), &r), WEB_JL_OK);
    web_ident_record(&id, &r, now);
}

/* The randomised MAC left out: seen red with web_ident_firsts()
 * keeping it. */
static void test_first_seen_keeps_the_earliest(void) {
    WT_EQ(web_ident_init(&id, 8, 8), 0);
    rec("{\"type\":\"probe_client\",\"mac\":\"00:11:22:33:44:55\",\"first_seen\":500}", 1000);
    rec("{\"type\":\"assoc\",\"sta_mac\":\"00:11:22:33:44:55\",\"bssid\":"
        "\"00:aa:00:00:00:01\",\"first_seen\":400}", 1000);
    rec("{\"type\":\"pnl_client\",\"mac\":\"00:11:22:33:44:55\",\"first_seen\":900}", 1000);
    rec("{\"type\":\"probe_client\",\"mac\":\"02:11:22:33:44:56\",\"first_seen\":700}", 1000);
    web_id_new_t out[8];
    int n = web_ident_firsts(&id, out, 8);
    WT_EQ(n, 1);                         /* the randomised one is left out */
    WT_EQ(out[0].first_seen, 400);
    WT_HAS(out[0].src, "assoc");
    web_ident_destroy(&id);
}

/* A name is cut to WEB_ID_NAME_MAX bytes on a code-point boundary. */
static void test_names_are_bounded(void) {
    WT_EQ(web_ident_init(&id, 8, 8), 0);
    char line[1024], name[400];
    size_t o = 0;
    while (o + 3 < 300) { memcpy(name + o, "\xc3\xa9", 2); o += 2; }
    name[o] = '\0';
    snprintf(line, sizeof(line), "{\"type\":\"dhcp_lease\",\"ip\":\"10.0.0.1\","
             "\"hostname\":\"%s\"}", name);
    rec(line, 1000);
    rec("{\"type\":\"nbns_name\",\"ip\":\"10.0.0.1\",\"name\":\"WORKSTATION-NAME-LONG\","
        "\"suffix\":0}", 1000);
    web_id_names_t out[4];
    WT_EQ(web_ident_ip_names(&id, 1000, out, 4), 1);
    WT_ASSERT(strlen(out[0].name[WEB_ID_SRC_DHCP]) <= WEB_ID_NAME_MAX);
    WT_EQ(strlen(out[0].name[WEB_ID_SRC_DHCP]) % 2, 0);   /* whole é's */
    WT_EQ(strlen(out[0].name[WEB_ID_SRC_NBNS]), WEB_ID_NBNS_MAX);
    web_ident_destroy(&id);
}

/* Group suffixes are not host names; and a name is current for its
 * TTL only. Seen red with the suffix test removed, and separately with
 * the TTL. */
static void test_nbns_suffix_and_ttl(void) {
    WT_EQ(web_ident_init(&id, 8, 8), 0);
    rec("{\"type\":\"dhcp_lease\",\"ip\":\"10.0.0.2\",\"hostname\":\"a\"}", 1000);
    rec("{\"type\":\"nbns_name\",\"ip\":\"10.0.0.2\",\"name\":\"WORKGROUP\",\"suffix\":28}", 1000);
    web_id_names_t out[4];
    WT_EQ(web_ident_ip_names(&id, 1000, out, 4), 0);
    rec("{\"type\":\"mdns_service\",\"ip\":\"10.0.0.2\",\"host\":\"a.local\"}", 1000);
    WT_EQ(web_ident_ip_names(&id, 1000, out, 4), 1);
    WT_EQ(web_ident_ip_names(&id, 1000 + WEB_ID_TTL_S + 1, out, 4), 0);
    web_ident_destroy(&id);
}

/* Full tables evict their least recently seen row, and count it. */
static void test_tables_evict_and_count(void) {
    WT_EQ(web_ident_init(&id, 2, 2), 0);
    rec("{\"type\":\"arp\",\"ip\":\"10.0.0.1\",\"mac\":\"00:00:00:00:00:01\"}", 1);
    rec("{\"type\":\"arp\",\"ip\":\"10.0.0.2\",\"mac\":\"00:00:00:00:00:02\"}", 2);
    rec("{\"type\":\"arp\",\"ip\":\"10.0.0.3\",\"mac\":\"00:00:00:00:00:03\"}", 3);
    web_id_stats_t st;
    web_ident_stats(&id, &st);
    WT_EQ(st.macs, 2);
    WT_EQ(st.ips, 2);
    WT_EQ(st.mac_evictions, 1UL);
    WT_EQ(st.ip_evictions, 1UL);
    web_ident_destroy(&id);
}

/* An NXDOMAIN answer is the client's when it asked that qname within
 * WEB_ID_DNS_MATCH_S, counted once; later, or a qname nobody asked, is
 * unmatched. "Once" seen red with the slot not cleared after a match;
 * "later" with the window test removed. */
static void test_dns_join_by_qname(void) {
    WT_EQ(web_ident_init(&id, 8, 8), 0);
    rec("{\"type\":\"dns\",\"src\":\"10.0.0.7\",\"qname\":\"a.example\",\"is_resp\":0}", 1000);
    rec("{\"type\":\"dns\",\"src\":\"10.0.0.1\",\"qname\":\"A.example\",\"answer\":"
        "\"NXDOMAIN\",\"is_resp\":1}", 1002);
    rec("{\"type\":\"dns\",\"src\":\"10.0.0.1\",\"qname\":\"a.example\",\"answer\":"
        "\"NXDOMAIN\",\"is_resp\":1}", 1003);
    rec("{\"type\":\"dns\",\"src\":\"10.0.0.7\",\"qname\":\"b.example\",\"is_resp\":0}", 1004);
    rec("{\"type\":\"dns\",\"src\":\"10.0.0.1\",\"qname\":\"b.example\",\"answer\":"
        "\"NXDOMAIN\",\"is_resp\":1}", 1004 + WEB_ID_DNS_MATCH_S + 1);
    web_id_dns_t out[4];
    int n = web_ident_dns(&id, 1080, out, 4);
    WT_EQ(n, 1);
    WT_HAS(out[0].ip, "10.0.0.7");
    WT_EQ(out[0].q, 2);
    WT_EQ(out[0].nx, 1);
    web_id_stats_t st;
    web_ident_stats(&id, &st);
    WT_EQ(st.dns_matched, 1UL);
    WT_EQ(st.dns_unmatched, 2UL);
    /* Out of the window: nothing. */
    WT_EQ(web_ident_dns(&id, 1080 + WEB_ID_DNS_MINUTES * 60, out, 4), 0);
    web_ident_destroy(&id);
}

static void test_norm(void) {
    char o[WEB_ID_NAME_MAX + 1];
    web_ident_norm("Laptop.local", o);  WT_HAS(o, "laptop");
    WT_EQ(strlen(o), 6);
    web_ident_norm("LAPTOP   ", o);     WT_EQ(strlen(o), 6);
    web_ident_norm(".hidden", o);       WT_EQ(strlen(o), 0);
}

void run_ident_tests(void) {
    WT_RUN(test_first_seen_keeps_the_earliest);
    WT_RUN(test_names_are_bounded);
    WT_RUN(test_nbns_suffix_and_ttl);
    WT_RUN(test_tables_evict_and_count);
    WT_RUN(test_dns_join_by_qname);
    WT_RUN(test_norm);
}
