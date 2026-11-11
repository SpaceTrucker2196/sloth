/* slothweb: how a write is known to be an agent's (owner request
 * 2026-11-11: an OpenClaw agent on the same machine reads slothweb
 * through slothweb-mcp and adds triage, notes and links).
 *
 * The page and the history must always be able to tell an agent's
 * write from the operator's, so the mark (via "agent", web_frrs.h) can
 * not be something a request says about itself: a web page could then
 * label its writes as it liked, and an agent could pass as the
 * operator. It is decided from what the request proves:
 *
 *   --web-agent-secret PATH   at start slothweb draws 32 bytes from the
 *       kernel, writes them as 64 hex digits to PATH (created 0600 by
 *       descriptor, never through a link, put in place by rename so a
 *       reader sees the old secret or the new one, never half of one)
 *       and keeps them in memory. A new secret every run; the file is
 *       removed at a clean exit. Without the flag there is no secret
 *       and no agent path at all.
 *   --web-agent-group NAME    the file is 0640 and in group NAME instead,
 *       so slothweb-mcp can run as the operator's own user, a member of
 *       NAME, with no sudo rule (slothweb's user must be a member too:
 *       only then may it give a file that group).
 *   X-Slothweb-Agent: <secret>   on a POST. slothweb-mcp reads the file
 *       (it runs on the same machine, as a user that may read it) and
 *       sends it on every write.
 *
 * web_agent_check() is the whole rule, run by the write path's gate
 * before a body byte is read and again by the router:
 *
 *   no such header           the browser's path, exactly as before:
 *                            Origin equal to Host, Sec-Fetch-Site, and
 *                            the row is via manual (or recommended).
 *                            It can never be recorded as an agent's.
 *   the header, and all of:  the agent's path: the row is via agent.
 *     a secret is configured,
 *     the header came once and is the secret (compared in constant
 *     time over its fixed length),
 *     the peer is loopback (the secret is a same-machine credential
 *     and never crosses a network in the clear),
 *     no Origin and no Sec-Fetch-Site header (a browser sends Origin
 *     on every POST and cannot be told not to, so a request carrying
 *     one is a page's, whatever else it carries)
 *   the header, otherwise    refused, 403. Never downgraded to the
 *                            browser's path: a wrong secret is not a
 *                            reason to try the request as something
 *                            else.
 *
 * The secret stands in for the Origin check on that one path and
 * nowhere else. Origin is a CSRF defence: it stops a page on another
 * site making the operator's browser write. A request with no Origin
 * and the secret is not a browser's, and CSRF needs a browser; a page
 * cannot read the file, cannot set the header across origins without a
 * preflight slothweb never answers, and cannot strip its own Origin.
 * The browser's path is not weakened: without the header nothing about
 * it changed.
 *
 * What the agent's path may write is narrower than the page's: triage,
 * a note, a link (web_frrs.c refuses the TACDB and the import to it),
 * each under a name ("by" is required), and it removes only links an
 * agent made and takes back only notes an agent wrote (any agent's,
 * the operator's never: 403 not_agent_note, web_notes.c). The token
 * bucket applies, in a bucket of the agent's own
 * per peer, so an agent can exhaust neither the operator's allowance
 * nor its own unbounded. */
#ifndef SLOTHWEB_AGENT_H
#define SLOTHWEB_AGENT_H

#include <stddef.h>
#include <sys/types.h>

#include "web_http.h"

#define WEB_AGENT_SECRET_LEN 64

/* --web-agent-group NAME (owner ruling 2026-11-11: slothweb-mcp runs as
 * the operator's own user and reads the secret through a group, with no
 * sudo rule): the group's id, looked up at start. 0, or -1 with err
 * (no such group, or the lookup failed). */
int  web_agent_group_resolve(const char *name, gid_t *gid, char *err, size_t errsz);

/* A fresh secret into out and into the file at path (see above). group
 * NULL: the file is 0600, as before the group existed. A gid: the file
 * is created 0600 under a temporary name, given (this user, *group) and
 * made 0640 there, and only then renamed into place, so it is never
 * readable by anyone else at any instant; giving the group fails (and
 * so does the start) unless this user is a member of it. An existing
 * file at path must be a regular one of this user's with one link and
 * no group or other permission, or, with a group, mode 0640 and that
 * group: it is replaced; anything else is refused, not repaired. 0, or
 * -1 with err. */
int  web_agent_secret_make(const char *path, const gid_t *group,
                           char out[WEB_AGENT_SECRET_LEN + 1], char *err, size_t errsz);

/* The rule above for one parsed request. secret is the configured one
 * or "" (none). 0 the browser's path, 1 the agent's, -1 refused with a
 * word in *why: "agent_off", "bad_agent_secret", "agent_not_local",
 * "agent_with_origin". */
int  web_agent_check(const char *secret, const web_req_t *rq, const char **why);

#endif
