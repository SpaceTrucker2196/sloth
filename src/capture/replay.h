#ifndef CAPTURE_REPLAY_H
#define CAPTURE_REPLAY_H

/* --replay FILE[,FILE] (#119, owner ruling 2026-10-15).
 *
 * Feeds libpcap savefiles through the same callbacks a live capture
 * uses, so `main.c`'s argv handling, the poll loop and every sink run in
 * CI without an interface (MISSION §2 forbids running sloth against one
 * there). A savefile is evidence input, not a fixture: nothing under
 * tests/ is one, and the CI job generates its inputs at run time from
 * the hand-built byte arrays (tests/replay/gen_replay.c).
 *
 * Routing is by the file's datalink, the way the live handles split the
 * world: Ethernet and Linux cooked capture go to the IP path
 * (on_packet()), radiotap goes to the monitor path (on_probe_frame()).
 * Anything else is refused at startup, before a sink opens. */

#include <stdint.h>
#include "sloth.h"

#define REPLAY_MAX_FILES 8
#define REPLAY_PATH_MAX  256

typedef enum {
    REPLAY_ROUTE_NONE = 0,   /* datalink sloth has no decoder for */
    REPLAY_ROUTE_WIRED,      /* EN10MB, LINUX_SLL, LINUX_SLL2 → on_packet() */
    REPLAY_ROUTE_MONITOR     /* IEEE802_11_RADIO → on_probe_frame() */
} replay_route_t;

/* Which path a savefile with link type `dlt` is replayed through. Pure;
   defined in every configuration so the test build reaches it. */
replay_route_t replay_route(int dlt);

/* Split the --replay argument on commas into `out`. Returns the number
   of paths, or -1 when the list is empty, holds an empty element
   ("a,,b", "a,", ","), names more than `max` files, or has a path of
   REPLAY_PATH_MAX bytes or more. A refusal, not a truncation: a replay
   that silently dropped a file would report on less than it was given. */
int replay_split_list(const char *arg, char out[][REPLAY_PATH_MAX], int max);

/* One opened replay source, checked before any sink opens. */
typedef struct {
    char           path[REPLAY_PATH_MAX];
    int            dlt;
    replay_route_t route;
} replay_src_t;

#ifdef WITH_PCAP

/* Open `path`, read its datalink and route it, then close it again.
   Returns 0, or -1 with the reason in `err` (unreadable, not a
   savefile, or a datalink with no route). */
int replay_check(const char *path, replay_src_t *src, char *err, int errsz);

/* Dispatch every record of `src` through its path, synchronously, in
   bounded batches (memory does not grow with the file). Each record
   keeps its own ts_sec and its own len, so a frame the capture snapped
   still reads as snapped. Returns the number of frames dispatched, or
   -1 with the reason in `err`. */
long replay_run(sloth_state_t *s, const replay_src_t *src,
                char *err, int errsz);

#endif /* WITH_PCAP */

/* Point every platform op at an empty source (#119). A replay is a
   report on the savefiles, so the host's own interfaces, sockets, ARP
   table, DHCP leases and Wi-Fi scan must not leak into it: they would
   make the output a function of whichever machine ran it, and the
   replay-check golden diff would fail on every host but one. */
void replay_platform_install(void);

#endif /* CAPTURE_REPLAY_H */
