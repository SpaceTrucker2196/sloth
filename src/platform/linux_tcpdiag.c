#ifdef PLATFORM_LINUX

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/tcp.h>

#include "ntop.h"
#include "platform/linux_tcpdiag.h"

#define RECV_BUF 65536

static void query_family(int fd, int family,
                         conn_t *conns, int n) {
    struct {
        struct nlmsghdr        nlh;
        struct inet_diag_req_v2 req;
    } msg;

    memset(&msg, 0, sizeof(msg));
    msg.nlh.nlmsg_len   = sizeof(msg);
    msg.nlh.nlmsg_type  = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.req.sdiag_family    = (uint8_t)family;
    msg.req.sdiag_protocol  = IPPROTO_TCP;
    msg.req.idiag_ext       = (1 << (INET_DIAG_INFO - 1));
    msg.req.idiag_states    = 0xffffffffu;

    if (send(fd, &msg, sizeof(msg), 0) < 0) return;

    char buf[RECV_BUF];
    ssize_t rlen;

    while ((rlen = recv(fd, buf, sizeof(buf), 0)) > 0) {
        struct nlmsghdr *nlh = (struct nlmsghdr *)(void *)buf;

        for (; NLMSG_OK(nlh, (uint32_t)rlen); nlh = NLMSG_NEXT(nlh, rlen)) {
            if (nlh->nlmsg_type == NLMSG_DONE) return;
            if (nlh->nlmsg_type == NLMSG_ERROR) return;
            if (nlh->nlmsg_type != SOCK_DIAG_BY_FAMILY) continue;

            struct inet_diag_msg *diag = NLMSG_DATA(nlh);
            unsigned long inode = (unsigned long)diag->idiag_inode;

            /* walk netlink attributes for INET_DIAG_INFO (= tcp_info) */
            int attr_len = (int)(nlh->nlmsg_len - NLMSG_SPACE(sizeof(*diag)));
            struct rtattr *attr = (struct rtattr *)(void *)(diag + 1);
            uint32_t rtt_us = 0;

            while (RTA_OK(attr, attr_len)) {
                if (attr->rta_type == INET_DIAG_INFO
                    && RTA_PAYLOAD(attr) >= sizeof(struct tcp_info)) {
                    struct tcp_info ti;
                    memcpy(&ti, RTA_DATA(attr), sizeof(ti));
                    rtt_us = ti.tcpi_rtt;
                    break;
                }
                attr = RTA_NEXT(attr, attr_len);
            }

            /* match by inode and set rtt_us */
            for (int i = 0; i < n; i++) {
                if (conns[i].proto == PROTO_TCP && conns[i].inode == inode) {
                    conns[i].rtt_us = rtt_us;
                    break;
                }
            }
        }
    }
}

void linux_tcpdiag_fill(conn_t *conns, int n) {
    if (n == 0) return;

    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    if (fd < 0) return;

    query_family(fd, AF_INET,  conns, n);
    query_family(fd, AF_INET6, conns, n);

    close(fd);
}

#endif /* PLATFORM_LINUX */
