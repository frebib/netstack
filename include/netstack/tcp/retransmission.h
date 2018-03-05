#ifndef NETSTACK_TCP_RETRANSMISSION_H
#define NETSTACK_TCP_RETRANSMISSION_H

#include <stdint.h>
#include <netstack/tcp/tcp.h>

struct tcp_seq_data {
    uint32_t seq;
    uint16_t len;
};

struct tcp_rto_data {
    struct tcp_sock *sock;
    uint32_t seq;
    uint16_t len;
};

void tcp_retransmission_timeout(void *arg);

void tcp_update_rtq(struct tcp_sock *sock);

#endif //NETSTACK_TCP_RETRANSMISSION_H
