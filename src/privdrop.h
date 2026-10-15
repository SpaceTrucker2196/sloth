#ifndef SLOTH_PRIVDROP_H
#define SLOTH_PRIVDROP_H

#include <stddef.h>
#include <sys/types.h>

/* In-process privilege drop (#140; owner ruling 2026-10-15, "only use
 * root when necessary").
 *
 * sloth needs privilege for exactly two things: opening the capture
 * handles (CAP_NET_RAW, once, at startup — pcap_activate() creates the
 * AF_PACKET sockets and reading them needs nothing) and retuning the
 * monitor radio (CAP_NET_ADMIN, for the whole run, because every
 * linux_wifi_set_channel() and every scan trigger opens a fresh nl80211
 * socket). Everything else — /proc, rtnetlink dumps, INET_DIAG, every
 * sink — runs unprivileged. Before this module a `sudo ./sloth` ran as
 * uid 0 with every capability for its whole life (CWE-250).
 *
 * Split the way observe_resolve_profile() is (#84): a pure plan that
 * decides, and a thin apply that only performs. The plan is the tested
 * unit because CI is not root; apply is tested on the one plan a
 * non-root process can carry out (shed what it holds, set NNP).
 *
 * Default ON for root runs. A root run switches to the `sloth` account
 * when it exists (or --user NAME), keeping CAP_NET_ADMIN only for --hop
 * or --allow-active. With no such account it keeps uid 0 but still sheds
 * every capability it does not need, and says so — it never silently
 * stays fully root. --no-privdrop is the explicit, announced escape. */

typedef struct {
    /* Probed from the process (privdrop_probe()). */
    int euid_is_root;
    int have_cap_setuid;     /* CAP_SETUID and CAP_SETGID, both effective */
    int have_cap_setpcap;    /* effective: needed for PR_CAPBSET_DROP     */
    int have_cap_net_admin;  /* permitted */
    int have_cap_net_raw;    /* permitted */
    /* From the command line. */
    int hop;                 /* --hop          */
    int allow_active;        /* --allow-active */
    int no_privdrop;         /* --no-privdrop  */
    int user_given;          /* --user NAME    */
    /* Target account: the --user NAME, or the default "sloth". */
    int   user_resolved;     /* getpwnam() found it */
    uid_t uid;
    gid_t gid;
} privdrop_req_t;

typedef enum {
    PRIVDROP_NONE_UNPRIVILEGED,  /* not root: uid kept, unneeded caps shed  */
    PRIVDROP_DROP,               /* switch to the target account            */
    PRIVDROP_ROOT_KEEP_UID,      /* root, no target account: uid 0 kept,
                                    every unneeded capability shed          */
    PRIVDROP_DISABLED,           /* --no-privdrop: nothing shed, announced  */
    PRIVDROP_REFUSE_NO_SUCH_USER,/* --user NAME does not exist              */
    PRIVDROP_REFUSE_CANNOT       /* --user asked for and impossible, or
                                    --user with --no-privdrop               */
} privdrop_action_t;

typedef struct {
    privdrop_action_t action;
    int   keep_net_admin;    /* CAP_NET_ADMIN left in permitted+effective */
    int   keep_net_raw;      /* CAP_NET_RAW likewise                      */
    int   set_no_new_privs;  /* always 1                                  */
    int   change_uid;        /* setgroups/setresgid/setresuid to uid/gid  */
    int   shed_caps;         /* capset to exactly the kept set            */
    int   drop_bounding;     /* PR_CAPBSET_DROP every cap not kept        */
    uid_t uid;
    gid_t gid;
    int   exit_code;         /* non-zero on a refusal                     */
    const char *reason;      /* refusal text; NULL otherwise              */
} privdrop_plan_t;

/* The default target account a root run drops to. */
#define PRIVDROP_DEFAULT_USER "sloth"

/* Pure: decides, touches nothing. */
void privdrop_resolve(const privdrop_req_t *req, privdrop_plan_t *plan);

/* Pure: the one stderr line announcing what the plan did (without the
 * trailing newline). `user` is the target account name. Writes "" when
 * there is nothing worth saying — an unprivileged run that held no
 * capability to shed. Refusals are main's text, from plan->reason. */
void privdrop_describe(const privdrop_req_t *req, const privdrop_plan_t *plan,
                       const char *user, char *buf, size_t sz);

/* Fill the process-derived fields of `req` (euid, capabilities). Leaves
 * the command-line and account fields alone. Returns 0, or -1 when
 * capget fails (the req is then left describing no capabilities). */
int  privdrop_probe(privdrop_req_t *req);

/* Perform the plan. Must run before any thread exists: capset and
 * NO_NEW_PRIVS are per-thread. Every step is read back; any mismatch
 * fails closed. Returns 0 on success, -1 with `err` filled otherwise —
 * the caller exits 2. A refusal plan is never applied (returns -1). */
int  privdrop_apply(const privdrop_plan_t *plan, char *err, size_t errsz);

#endif /* SLOTH_PRIVDROP_H */
