#ifndef SLOTH_DAEMON_START_H
#define SLOTH_DAEMON_START_H

#include <time.h>
#include "privdrop.h"

/* The start-up steps both daemons take the same way (#213).
 *
 * `sloth` (src/main.c) and sloth-rf (src/rf/main.c) each have a main()
 * of their own, because they open different inputs, but they share the
 * flags that are not about an input: --tune, --user / --no-privdrop,
 * -o, --db, --data-socket and --strict's hold on it. What those flags
 * refuse, what they announce and the exit code they give must be the
 * same in both, so the code is here once and both mains call it. Each
 * function prints on stderr what src/main.c printed inline before
 * #213, byte for byte, and returns the process exit code: 0 to go on.
 * "sloth:" in both daemons (src/gnss_flags.h says why).
 *
 * Nothing here opens an input, and nothing here needs the capture to
 * link. The inputs' own flags are src/gnss_flags.h and src/rf_flags.h. */

/* --tune NAME=VALUE. `arg` is the value, NULL when the flag was last on
 * the line. 2 on a missing value, an unknown knob or a value out of
 * range. */
int daemon_flag_tune(const char *arg);

/* --value-period KIND=SECS (#245). `arg` as --tune's. 2 on a missing
 * value, an unknown kind, or SECS not in 1..30 days. */
int daemon_flag_value_period(const char *arg);

/* --ticks N: 1..1000000, strict. */
int daemon_flag_ticks(const char *arg, long *out);

/* The privilege plan (#140), decided before anything opens so a --user
 * that names no account exits having opened nothing. `*user` is --user
 * NAME or NULL; on return it is the account the plan is for
 * (PRIVDROP_DEFAULT_USER when none was given). `hop` and
 * `allow_active` are the two flags that keep CAP_NET_ADMIN; a daemon
 * with neither passes 0. Returns the plan's exit code. */
int daemon_privdrop_plan(const char **user, int no_privdrop, int hop,
                         int allow_active, privdrop_req_t *req,
                         privdrop_plan_t *plan);

/* Apply it: after every handle that needs privilege is open, before
 * any thread exists and before any sink is created. 2 when a step
 * failed (half-dropped is not a state to run in); the caller closes
 * what it opened and exits. Announces what was done. */
int daemon_privdrop_apply(const privdrop_req_t *req,
                          const privdrop_plan_t *plan, const char *user);

/* A bare --data-socket: `spec` when `dir` is fit to hold it, else NULL
 * with the refusal and its remedy printed (the caller exits 2). Never a
 * TCP spec. `runtime_dir` is the systemd RuntimeDirectory= name the
 * remedy cites, `tcp_example` the explicit loopback transport it
 * offers: the calling daemon's own, never the other's port. */
const char *daemon_data_socket_default(const char *dir, const char *spec,
                                       const char *runtime_dir,
                                       const char *tcp_example);

/* --strict's refusal of a routable --data-socket, printed. The caller
 * has the profile's verdict (observe_resolve_profile()) and exit code. */
void daemon_strict_socket_refusal(const char *spec);

/* The three sinks, opened after the drop as the account the run lives
 * as. Each returns 0, or 1 with the reason printed. `preferred` is the
 * unix: spec a loopback-TCP listener is told to prefer. */
int daemon_open_jsonl(const char *path);
int daemon_open_db(const char *path, const char *site_label,
                   time_t session_start);
int daemon_open_data_socket(const char *spec, int allow_remote,
                            const char *preferred);

/* Wait out a poll interval without touching the terminal (#50); a
 * readable `wake_fd` (an alert, src/event_wake.h) ends it early. */
void daemon_wait(int timeout_ms, int wake_fd);

#endif /* SLOTH_DAEMON_START_H */
