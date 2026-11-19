/* sloth-ios sensor posts (#205 slice 1; docs/wiki/post-protocol.md).
 *
 * A post is a phone running sloth-ios that serves its own sensors as a
 * one-way JSONL stream. slothweb, not sloth, reads it (owner ruling
 * 2026-11-13 on #205): the sensor stays silent and the networked
 * read-only consumer does the dialling.
 *
 * --post HOST:PORT names one post, by literal address (nothing is
 * resolved, and nothing is browsed: no mDNS in this slice). Each gets
 * one thread that connects, reads lines, and never writes to the
 * socket; when the post goes away (the app left the foreground, the
 * phone left the tailnet) it waits a back-off that doubles from
 * WEB_POST_BACKOFF_MIN_MS to WEB_POST_BACKOFF_MAX_MS and tries again.
 * web_config_check() refuses any --post under --strict, and one outside
 * the tailnet without --post-allow-outside-tailnet.
 *
 * What is kept is the roster: per post its identity from ios_post (name,
 * role, platform, app version, battery, charging, uptime) and a count of
 * each record type. No record's contents but ios_post's are kept in this
 * slice, so no position, movement or joined network is held at all.
 *
 * Fleet sharing (owner rulings 2026-11-19 on #205, ADR 0009): only
 * ble_contact, a passive BLE receive, may travel to a peer. ios_post is
 * the post's own state; wifi_self is the phone's joined, authenticated
 * network (managed provenance); geo_fix and imu_sample are the
 * operator's own position and movement; radio_scan is the phone's
 * ordinary Wi-Fi card scanning, treated as the managed card's scan. All
 * of those stay on the slothweb that read them, and so does any type not
 * on this list (fail closed). */
#ifndef SLOTHWEB_POSTS_H
#define SLOTHWEB_POSTS_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_ingest.h"
#include "web_jsonl.h"

#define WEB_POSTS_MAX            8
#define WEB_POST_BACKOFF_MIN_MS  1000
/* A post is foreground-only: a phone in a pocket refuses for minutes at
 * a time, and a redial every few seconds would be chatter on its link. */
#define WEB_POST_BACKOFF_MAX_MS  30000
#define WEB_POST_CONNECT_MS      5000
#define WEB_POST_ID_MAX          64
#define WEB_POST_NAME_MAX        64

/* The six record types of the protocol, in its table's order. */
enum {
    WEB_PT_IOS_POST = 0, WEB_PT_BLE_CONTACT, WEB_PT_IMU_SAMPLE,
    WEB_PT_WIFI_SELF, WEB_PT_GEO_FIX, WEB_PT_RADIO_SCAN, WEB_PT_COUNT
};
extern const char *const web_post_type_names[WEB_PT_COUNT];
/* WEB_PT_*, or -1 for a type the protocol does not name. */
int  web_post_type(const char *t);
/* 1 when a record of this type may travel in a fleet export: only
 * ble_contact. 0 for every other name, NULL included. */
int  web_post_type_travels(const char *t);

/* "A.B.C.D:PORT" or "[V6]:PORT", literal addresses only. 0, or -1 with
 * the reason in err. */
int  web_post_parse(const char *s, web_sockspec_t *out, char *err, size_t errsz);
/* In 100.64.0.0/10 or fd7a:115c:a1e0::/48 (Tailscale's ranges). */
int  web_post_in_tailnet(const web_sockspec_t *sp);

typedef struct {
    char      post[WEB_POST_ID_MAX + 1];      /* the envelope's uuid; "" none yet */
    char      name[WEB_POST_NAME_MAX + 1];
    char      role[16 + 1];
    char      platform[16 + 1];
    char      app_ver[32 + 1];
    int       has_battery;
    double    battery;                        /* 0..1 */
    int       charging;                       /* -1 unknown, 0, 1 */
    long long uptime_s;                       /* -1 unknown */
    long long ts;                             /* the ios_post's own ts; 0 none */
} web_post_ident_t;

struct web_posts;

typedef struct {
    web_sockspec_t     spec;
    struct web_posts  *set;
    /* Under the set's lock. */
    int                state;                 /* WEB_POST_ST_* */
    unsigned long long attempts, connects;
    char               last_error[128];
    long long          heard_ms;              /* monotonic; 0 never */
    unsigned long long bytes, lines, decode_errors, foreign, other;
    unsigned long long count[WEB_PT_COUNT];
    web_post_ident_t   id;
    /* The reader's alone. */
    int                relatch;               /* a new connection: take a new uuid */
    pthread_t          th;
    int                running;
    size_t             len;
    int                discarding;
    char               line[WEB_JL_MAX_LINE + 1];
    web_jrec_t         rec;
    char               rbuf[16384];
} web_post_t;

enum { WEB_POST_ST_WAITING = 0, WEB_POST_ST_CONNECTING, WEB_POST_ST_CONNECTED };

typedef struct web_posts {
    pthread_mutex_t mu;
    int             n;
    web_post_t     *p;                        /* n of them, or NULL */
    int             stop[2];
    int             backoff_min_ms, backoff_max_ms, connect_ms;
} web_posts_t;

/* Allocate n readers (0 is a set with none). 0, or -1 out of memory. */
int  web_posts_init(web_posts_t *s, const web_sockspec_t *specs, int n);
/* One thread per post. 0, or -1 with err (none left running). */
int  web_posts_start(web_posts_t *s, char *err, size_t errsz);
/* Stop and join them; safe when never started. */
void web_posts_stop(web_posts_t *s);
void web_posts_destroy(web_posts_t *s);

/* Post i's framer, without a socket: what its thread does with the
 * bytes it reads. Returns the complete lines seen. Tests drive it. */
size_t web_posts_feed(web_posts_t *s, int i, const char *buf, size_t n,
                      long long now_ms);
/* A new connection on post i: the next record's uuid is taken. */
void web_posts_connected(web_posts_t *s, int i);

/* /api/posts: the roster as JSON into out. Its length, 0 when it did not
 * fit. */
size_t web_posts_json(web_posts_t *s, long long now_ms, char *out, size_t cap);

#endif
