#include <stdio.h>
#include "ntop.h"
#include "tui.h"
#include "views/conns.h"

#define CONNS_PAGE 40

static const char *tcp_state_name(int st) {
    static const char *names[] = {
        "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
        "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE",
        "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"
    };
    if (st < 0 || st > 11) return "UNKNOWN";
    return names[st];
}

void view_conns_draw(const ntop_state_t *s) {
    TPRINT("  %-22s  %-22s  %-5s  %-13s\n",
           "Local", "Remote", "Proto", "State");
    TPRINT("  %-22s  %-22s  %-5s  %-13s\n",
           "----------------------", "----------------------",
           "-----", "-------------");

    int shown = (s->conn_count < CONNS_PAGE) ? s->conn_count : CONNS_PAGE;
    for (int i = 0; i < shown; i++) {
        const conn_t *c = &s->conns[i];
        char local[56], remote[56];  /* addr[46] + ':' + port[5] + '\0' */
        snprintf(local,  sizeof(local),  "%s:%u", c->local_addr,  c->local_port);
        snprintf(remote, sizeof(remote), "%s:%u", c->remote_addr, c->remote_port);
        const char *proto = (c->proto == PROTO_TCP) ? "TCP" : "UDP";
        const char *state = (c->proto == PROTO_TCP) ? tcp_state_name(c->state) : "";
        TPRINT("  %-22s  %-22s  %-5s  %-13s\n",
               local, remote, proto, state);
    }

    if (s->conn_count == 0)
        TPRINT("  (no connections)\n");
    else if (s->conn_count > CONNS_PAGE)
        TPRINT("  ... and %d more\n", s->conn_count - CONNS_PAGE);
}
