#ifndef NETSTACK_TCP_RETRANSMISSION_H
#define NETSTACK_TCP_RETRANSMISSION_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netstack/tcp/tcp.h>

struct tcp_seq_data {
    uint32_t seq;
    uint16_t len;
    uint8_t flags;
    struct timespec when;       // A CLOCK_MONOTONIC timestamp when when the
};                              // segment was transmitted

struct tcp_rto_data {
    struct tcp_sock *sock;
    uint32_t seq;
    uint16_t len;
    uint8_t flags;
};

void tcp_syn_retransmission_timeout(void *arg);

void tcp_start_rto(struct tcp_sock *sock, uint16_t count, uint8_t flags);

void tcp_retransmission_timeout(void *arg);

void tcp_update_rtq(struct tcp_sock *sock);

void tcp_update_rtt(struct tcp_sock *sock, struct tcp_seq_data *pData);

#endif //NETSTACK_TCP_RETRANSMISSION_H
