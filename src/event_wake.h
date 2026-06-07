#ifndef EVENT_WAKE_H
#define EVENT_WAKE_H

/* Self-pipe wakeup. The TUI loop normally blocks in select() for up
 * to one refresh interval; modules call event_wake_signal() to break
 * that wait so the next redraw happens immediately. Used by alert
 * firing so new alerts pop in milliseconds instead of waiting for
 * the next tick. */

int  event_wake_init  (void);   /* 0 on success, -1 on failure */
int  event_wake_fd    (void);   /* read-end fd, or -1 if uninitialised */
void event_wake_signal(void);   /* signal the loop — safe from any thread */
void event_wake_drain (void);   /* drain pending bytes after waking */

#endif /* EVENT_WAKE_H */
