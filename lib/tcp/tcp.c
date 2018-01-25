#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/in.h>

#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

llist_t tcp_sockets = LLIST_INITIALISER;

bool tcp_log(struct pkt_log *log, struct frame *frame, uint16_t net_csum) {
    struct tcp_hdr *hdr = tcp_hdr(frame);
    frame->data = frame->head + tcp_hdr_len(hdr);
    struct log_trans *trans = &log->t;

    // Print IPv4 payload size
    LOGT(trans, "length %hu ", frame_data_len(frame));

    // TODO: Work out why sometimes this is 0x0200 too small (in netwk byte-ord)
    // Print and check checksum
    uint16_t pkt_csum = hdr->csum;
    uint16_t calc_csum = in_csum(hdr, frame_pkt_len(frame), net_csum) + hdr->csum;
    LOGT(trans, "csum 0x%04x", ntohs(pkt_csum));
    if (pkt_csum != calc_csum)
        LOGT(trans, " (invalid 0x%04x)", ntohs(calc_csum));
    LOGT(trans, ", ");

    char sflags[9];
    LOGT(trans, "flags [%s] ", fmt_tcp_flags(hdr, sflags));

    LOGT(trans, "seq %u ", ntohl(hdr->seqn));
    if (hdr->flags.ack)
        LOGT(trans, "ack %u ", ntohl(hdr->ackn));

    LOGT(trans, "wind %hu ", ntohs(hdr->wind));

    return true;
}

void tcp_ipv4_recv(struct frame *frame, struct ipv4_hdr *hdr) {
    struct tcp_hdr *tcp_hdr = tcp_hdr(frame);
    uint16_t sport = htons(tcp_hdr->sport);
    uint16_t dport = htons(tcp_hdr->dport);
    addr_t saddr = {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->saddr)};
    addr_t daddr = {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->daddr)};
    struct tcp_sock *sock = tcp_sock_lookup(&saddr, &daddr, sport, dport);

    // https://blog.cloudflare.com/syn-packet-handling-in-the-wild

    // No (part/complete) established connection was found
    if (sock == NULL) {
        LOG(LWARN, "[IPv4] Unrecognised incoming TCP connection");
        // Allocate a new socket to provide address to tcp_send_rst()
        sock = malloc(sizeof(struct tcp_sock));
        sock->state = TCP_CLOSED;
        sock->inet = (struct inet_sock) {
                .remaddr = saddr,
                .remport = sport,
                .locaddr = daddr,
                .locport = dport,
        };
        llist_append(&tcp_sockets, sock);
    } else if (sock->state == TCP_LISTEN) {
        sock->inet.remaddr = saddr;
        sock->inet.remport = sport;
        sock->inet.locaddr = daddr;
    }

    /* Pass initial network csum as TCP packet csum seed */
    tcp_recv(frame, sock, inet_ipv4_csum(hdr));
}

void tcp_recv(struct frame *frame, struct tcp_sock *sock, uint16_t net_csum) {

    /* Don't parse yet, we need to check the checksum first */
    struct tcp_hdr *hdr = tcp_hdr(frame);
    frame->data += tcp_hdr_len(hdr);

    if (tcp_hdr_len(hdr) > frame_pkt_len(frame)) {
        LOG(LWARN, "Error: TCP header is too short!");
        goto drop_pkt;
    }

    // Invalid TCP checksums are caused by 'segmentation offload', or
    // more specifically 'generic-receive-offload' in Linux.
    // See also:
    //   - https://lwn.net/Articles/358910/
    //   - https://www.kernel.org/doc/Documentation/networking/segmentation-offloads.txt

    // TODO: Check for TSO and GRO and account for it, somehow..
    if (in_csum(frame->head, frame_pkt_len(frame), net_csum) != 0) {
        LOG(LTRCE, "Dropping TCP packet with invalid checksum!");
        goto drop_pkt;
    }

    // TODO: Other integrity checks

    tcp_seg_arr(frame, sock);

    drop_pkt:
    return;
}

void tcp_setstate(struct tcp_sock *sock, enum tcp_state state) {
    // TODO: Perform queued actions when reaching certain states
    // TODO: Lock sock->state
    sock->state = state;
    LOG(LDBUG, "[TCP] %s state reached", tcp_strstate(state));
}

void tcp_established(struct tcp_sock *sock, struct tcp_hdr *seg) {

    // Allocate send/receive buffers
    rbuf_init(&sock->rcvbuf, sock->tcb.rcv.wnd, BYTE);
    rbuf_init(&sock->sndbuf, sock->tcb.snd.wnd, BYTE);
    LOG(LDBUG, "[TCP] Allocated SND.WND %hu, RCV.WND %hu",
        sock->tcb.snd.wnd, sock->tcb.rcv.wnd);
}

inline void tcp_free_sock(struct tcp_sock *sock) {
    // Cancel all running timers
    tcp_timewait_cancel(sock);

    // Deallocate dynamically allocated data buffers
    if (sock->rcvbuf.size > 0)
        rbuf_destroy(&sock->rcvbuf);
    if (sock->sndbuf.size > 0)
        rbuf_destroy(&sock->sndbuf);

    free(sock);
}

inline void tcp_destroy_sock(struct tcp_sock *sock) {
    tcp_untrack_sock(sock);
    tcp_free_sock(sock);
}

void tcp_sock_cleanup(struct tcp_sock *sock) {

    pthread_mutex_lock(&sock->openlock);
    sock->openret = -ECONNABORTED;
    pthread_mutex_unlock(&sock->openlock);
    pthread_cond_broadcast(&sock->openwait);

    // TODO: Interrupt waiting send()/recv() calls with ECONNABORTED

    switch(sock->state) {
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSE_WAIT:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
            tcp_send_rst(sock, sock->tcb.snd.nxt);
            break;
        case TCP_TIME_WAIT:
            tcp_timewait_cancel(sock);
            break;
        default:
            break;
    }

    // Deallocate socket memory
    tcp_destroy_sock(sock);
}


/*
 * TCP Internet functions
 */

uint16_t tcp_randomport() {
    // TODO: Choose a random unused outgoing port
    return (uint16_t) rand();
}

uint32_t tcp_seqnum() {
    // TODO: Choose a secure initial sequence number
    return (uint32_t) rand();
}

