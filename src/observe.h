#ifndef SLOTH_OBSERVE_H
#define SLOTH_OBSERVE_H

/* Observation policy — the run-wide answer to "may sloth originate
 * traffic or change kernel state?" (issue #84).
 *
 * Slice 2 kept this switch inside src/dns.c because the reverse-DNS
 * resolver was the only active path it had to gate. Slice 3 gates two
 * more subsystems — the nl80211 scan trigger in
 * src/platform/linux_wifi.c and the Avahi service file in
 * src/discovery.c — and neither of those can sensibly depend on the DNS
 * module. So the policy lives on its own here and every subsystem asks
 * the same object. One owner is the whole point: the defect #84 reports
 * is a promise made in the README that no single place in the code was
 * responsible for keeping.
 *
 * Two bits, deliberately distinct:
 *
 *   active_allowed  the operator opted in to active behaviour
 *                   (--allow-active). Default 0 — strict observation is
 *                   what an operator gets without asking for it, per the
 *                   Captain's written decision of 2026-09-25.
 *   strict_locked   the operator pinned that for the whole run
 *                   (--strict). A locked run refuses every later enable,
 *                   so the guarantee holds until the process exits rather
 *                   than until the next call.
 */

/* Lock strict observation for the run. Clears active_allowed now and
   makes observe_set_active_allowed(1) a refused no-op from here on. */
void observe_lock_strict(void);
int  observe_strict_locked(void);

/* Opt in to (or back out of) active behaviour. Enabling is refused while
   the run is strict-locked; disabling is always honoured — tightening
   never needs permission. */
void observe_set_active_allowed(int allowed);

/* The single question every active path asks before it acts. Today:
   the nl80211 scan trigger. */
int  observe_active_allowed(void);

/* May sloth publish the Avahi service file for a routable data socket
 * (MISSION.md §2.1's second, opt-out carve-out)?
 *
 * This deliberately tracks the strict LOCK, not active_allowed. The
 * plain default leaves the carve-out alone: discovery already requires
 * the operator to bind the data socket to a routable address and to pass
 * --data-socket-allow-remote, so it cannot fire on a default run at all,
 * and silently dropping it would break sloth-ios discovery for a
 * deployment that asked for it. --strict is different — it is an
 * explicit statement that nothing about this run should touch the
 * network, and avahi-daemon announcing on sloth's behalf is still the
 * host's presence on the wire even though sloth transmits nothing. */
int  observe_discovery_allowed(void);

/* Does --strict refuse this data socket? (#84, owner ruling 2026-10-06)
 *
 * A routable listener transmits to whoever connects, which is what
 * --strict declines for the run; a loopback or unix: socket does not
 * leave the host, and README has long published bare
 * `--strict --data-socket` (loopback default) as usable, so refusing
 * that would break a documented pairing.
 *
 * spec_is_remote is data_socket_spec_is_remote()'s answer: 1 routable,
 * 0 loopback/unix, -1 unparseable. Taken as an int rather than parsed
 * here so this stays a pure policy predicate with no dependency on the
 * socket module — which is also what makes it testable without linking
 * main().
 *
 * Refuses only on 1. A -1 spec never binds and
 * data_socket_init_ex() rejects it with a message about the actual
 * typo; reporting a strict violation for a mistyped host would be
 * precise about the wrong thing.
 *
 * The lock beats --data-socket-allow-remote deliberately: that flag is
 * how an operator says "expose this", --strict is how they say "not on
 * this run", and a lock any other flag can override is not a lock. */
int  observe_strict_refuses_socket(int strict_locked, int spec_is_remote);

/* Restore the shipped default and clear the lock (for testing). */
void observe_reset_policy(void);

#endif /* SLOTH_OBSERVE_H */
