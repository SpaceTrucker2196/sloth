/* Read-only JSONL data socket. Streams the same content as the
 * `-o FILE` JSONL writer to any consumer that connects. Per MISSION §4
 * this is a *data-only* surface — no verbs accepted from the wire, no
 * inbound commands, no reads from connected clients.
 *
 * Supports two transports:
 *   "unix:/var/run/sloth.sock"  — UNIX-domain stream, for local SIEMs.
 *   "tcp:HOST:PORT"             — TCP listen on the literal HOST:PORT.
 *                                 Caller picks the bind address (e.g.
 *                                 the host's Tailscale IP). No magic
 *                                 wildcards — pass 0.0.0.0 explicitly
 *                                 if you really mean it. */

#ifndef SLOTH_DATA_SOCKET_H
#define SLOTH_DATA_SOCKET_H

/* Parse `spec` and start listening. Returns 0 on success, -1 on error
 * (with a one-line diagnostic on stderr). Idempotent if called twice
 * with the same arg — the second call replaces the first. */
int  data_socket_init(const char *spec);

/* Call from the main poll loop. Accepts any pending connections,
 * flushes queued bytes to clients that have become writable, and
 * disconnects clients stalled past DATA_SOCKET_STALL_SECS. Cheap when
 * no listener is configured.
 *
 * Accepting at least one client clears the jsonl change-only cache
 * (jsonl_dedup_reset), so the next snapshot pass re-emits a full
 * baseline for the newcomer — a connecting client is a fresh sink in
 * the same sense as a reopened file (#47). The baseline is also
 * re-broadcast to already-connected clients and re-written to the file
 * sink; redundant but harmless, since consumers already tolerate
 * repeats from the heartbeat re-emit. */
void data_socket_tick(void);

/* Broadcast one JSON line to every connected client. A trailing '\n'
 * is appended so consumers can frame on newlines. Safe to call when no
 * socket is configured.
 *
 * Delivery is whole records or none (#93). Each client owns a bounded
 * queue of complete encoded records (payload + '\n') and a byte offset
 * into the head record; writes are non-blocking and resume where the
 * last one stopped, so a record that was partly written is always
 * finished before the next one starts:
 *
 *   - short write / EINTR   retried at once;
 *   - EAGAIN                bytes stay queued, retried on the next emit
 *                           or tick;
 *   - any other error, 0    client closed (a started record is never
 *                           followed by a different one);
 *   - queue full            the *incoming* record is dropped whole and
 *                           counted — never one that has started;
 *   - no progress for       client closed by data_socket_tick(): a
 *     DATA_SOCKET_STALL_SECS  blocked peer is not guaranteed to EPIPE.
 *
 * After a drop, the next record the client receives is preceded by one
 * socket-only marker, built in the configured --out-format:
 *   {"type":"socket_gap","ts":T,"seq":S,"dropped":K,"dropped_total":D}
 * S = records offered to this client before the marker (delivered +
 * dropped), so records received + sum of `dropped` == S. */
void data_socket_emit(const char *line);

/* Bytes of complete records a client may have queued but not yet
 * written. Sized for a baseline burst on top of the kernel send buffer:
 * ~2000 typical 250-byte records, 32 worst-case 16 KiB ones. */
#define DATA_SOCKET_QUEUE_MAX   (512u * 1024u)

/* A client holding queued bytes that the kernel has accepted none of
 * for this long is disconnected. */
#define DATA_SOCKET_STALL_SECS  30

/* Records dropped on queue overflow, all clients, since start. */
unsigned long long data_socket_dropped_total(void);

/* True iff at least one client is connected. Used by jsonl.c so the
 * emit functions can short-circuit the format work when neither the
 * file sink nor the socket sink has a consumer. */
int  data_socket_has_clients(void);

/* Close all clients, the listening socket, and (for UNIX-domain) unlink
 * the path. Safe to call when no socket was configured. */
void data_socket_cleanup(void);

/* ── Test-only syscall hooks ────────────────────────────────
 *
 * Internal indirection lets unit tests force send/accept failures
 * (EAGAIN, partial send, EMFILE) that real-socket fixtures can't
 * reliably trigger. Pass NULL to either setter to restore the real
 * libc function. Production code must not call these. */
#include <sys/types.h>           /* ssize_t, socklen_t */
#include <sys/socket.h>          /* struct sockaddr    */
#include <time.h>                /* time_t             */
typedef ssize_t (*data_socket_send_fn)(int, const void *, size_t, int);
typedef int     (*data_socket_accept_fn)(int, struct sockaddr *, socklen_t *);
typedef time_t  (*data_socket_clock_fn)(void);
void data_socket_test_set_send_fn  (data_socket_send_fn   fn);
void data_socket_test_set_accept_fn(data_socket_accept_fn fn);
/* Monotonic seconds for the stall policy; NULL restores the real one. */
void data_socket_test_set_clock_fn (data_socket_clock_fn  fn);

#endif /* SLOTH_DATA_SOCKET_H */
