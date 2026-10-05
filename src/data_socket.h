/* Read-only JSONL data socket. Streams the same content as the
 * `-o FILE` JSONL writer to any consumer that connects. Per MISSION §4
 * this is a *data-only* surface — no verbs accepted from the wire, no
 * inbound commands, no reads from connected clients.
 *
 * Supports two transports:
 *   "unix:/var/run/sloth.sock"  — UNIX-domain stream, for local SIEMs.
 *                                 Created 0600: the kernel checks the
 *                                 peer's credentials on connect, so
 *                                 filesystem permissions *are* the
 *                                 authentication. This is the
 *                                 recommended deployment.
 *   "tcp:HOST:PORT"             — TCP listen on the literal HOST:PORT.
 *                                 Loopback (127.0.0.0/8) binds freely.
 *                                 Anything else — including the 0.0.0.0
 *                                 wildcard — is refused unless the
 *                                 operator passes the explicit opt-in
 *                                 (see data_socket_init_ex), because
 *                                 the stream carries no authentication
 *                                 and no encryption (#86). */

#ifndef SLOTH_DATA_SOCKET_H
#define SLOTH_DATA_SOCKET_H

/* Parse `spec` and start listening, local transports only. Equivalent
 * to data_socket_init_ex(spec, 0). Returns 0 on success, -1 on error
 * (with a one-line diagnostic on stderr). Idempotent if called twice
 * with the same arg — the second call replaces the first. */
int  data_socket_init(const char *spec);

/* As data_socket_init, but `allow_remote` non-zero carries the
 * operator's explicit consent to bind a non-loopback address. Without
 * it a routable spec is refused *before any socket is created*, and the
 * diagnostic names the flag that would permit it. With it, the bind
 * proceeds and a warning naming the exposed address and port is printed
 * — the guard is a speed bump on a deliberate choice, not a veto.
 *
 * Nothing about `unix:` or loopback TCP depends on this argument. */
int  data_socket_init_ex(const char *spec, int allow_remote);

/* Would `spec` put the stream on an address something other than this
 * host can reach? 1 = yes (routable literal, or the 0.0.0.0 wildcard),
 * 0 = no (127.0.0.0/8, or a `unix:` path, which never reaches the
 * wire), -1 = the spec is malformed and would be rejected anyway.
 *
 * Fails closed by construction: a caller gating on `== 0` treats
 * anything it cannot parse as unsafe. Exported so the policy can be
 * tested directly against addresses a test is not permitted to bind. */
int  data_socket_spec_is_remote(const char *spec);

/* The port of a syntactically well-formed `tcp:HOST:PORT` spec, parsed
 * by the same full-string rule the binder uses (1..65535, no trailing
 * bytes — so "8765x" is malformed, not 8765). -1 for a `unix:` spec, a
 * host that is not an IPv4 literal, or a port that fails that rule.
 * Exported so a consumer of the spec (mDNS discovery) cannot read a
 * different port out of it than the one actually bound.
 *
 * Syntax only: a non-negative return means the spec parses, *not* that
 * the binder would accept it. In particular this says nothing about the
 * routable-address refusal — `tcp:192.0.2.1:8765` yields 8765 here and
 * is still rejected at init without --data-socket-allow-remote. Callers
 * that need the policy answer ask data_socket_spec_is_remote(). */
int  data_socket_spec_tcp_port(const char *spec);

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
 * Internal indirection lets unit tests force send/accept/socket
 * failures (EAGAIN, partial send, EMFILE) that real-socket fixtures
 * can't reliably trigger, and lets a test observe the flags a new
 * descriptor was created with. Pass NULL to any setter to restore the
 * real libc function (for accept and socket, the close-on-exec wrapper
 * around it). Production code must not call these.
 *
 * Note what the socket hook can and cannot see: it observes the flags
 * passed to socket(), so on Linux it pins the atomic SOCK_CLOEXEC
 * path. The non-atomic fallback, which applies set_cloexec() after the
 * call for platforms without it, is downstream of the hook and is not
 * covered by that observation. */
#include <sys/types.h>           /* ssize_t, socklen_t */
#include <sys/socket.h>          /* struct sockaddr    */
#include <time.h>                /* time_t             */
typedef ssize_t (*data_socket_send_fn)(int, const void *, size_t, int);
typedef int     (*data_socket_accept_fn)(int, struct sockaddr *, socklen_t *);
typedef time_t  (*data_socket_clock_fn)(void);
typedef int     (*data_socket_nonblock_fn)(int);
typedef int     (*data_socket_socket_fn)(int, int, int);
void data_socket_test_set_send_fn  (data_socket_send_fn   fn);
void data_socket_test_set_accept_fn(data_socket_accept_fn fn);
/* Monotonic seconds for the stall policy; NULL restores the real one. */
void data_socket_test_set_clock_fn (data_socket_clock_fn  fn);
/* fcntl(F_SETFL, O_NONBLOCK) indirection; NULL restores the real one. */
void data_socket_test_set_nonblock_fn(data_socket_nonblock_fn fn);
/* socket() indirection; NULL restores the real one. Unlike the others
 * this exists to *observe*: the stale-socket probe in
 * unix_path_removable() is created, connect()ed and closed inside one
 * call and reaches no other seam, so FD_CLOEXEC on it is otherwise
 * unobservable from a test. A fake is expected to create the socket for
 * real and hand back the fd. */
void data_socket_test_set_socket_fn(data_socket_socket_fn fn);

#endif /* SLOTH_DATA_SOCKET_H */
