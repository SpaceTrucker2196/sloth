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

/* Call from the main poll loop. Accepts any pending connections and
 * harvests dead ones. Cheap when no listener is configured. */
void data_socket_tick(void);

/* Broadcast one JSON line to every connected client. A trailing '\n'
 * is appended so consumers can frame on newlines. Non-blocking: a slow
 * client whose send buffer is full will drop this single line and keep
 * the connection; a broken pipe closes the client fd. Safe to call when
 * no socket is configured. */
void data_socket_emit(const char *line);

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
typedef ssize_t (*data_socket_send_fn)(int, const void *, size_t, int);
typedef int     (*data_socket_accept_fn)(int, struct sockaddr *, socklen_t *);
void data_socket_test_set_send_fn  (data_socket_send_fn   fn);
void data_socket_test_set_accept_fn(data_socket_accept_fn fn);

#endif /* SLOTH_DATA_SOCKET_H */
