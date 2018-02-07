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
        sock = tcp_sock_init(malloc(sizeof(struct tcp_sock)));
        sock->state = TCP_CLOSED;
        sock->inet = (struct inet_sock) {
                .remaddr = saddr,
                .remport = sport,
                .locaddr = daddr,
                .locport = dport,
        };
        tcp_sock_lock(sock);
        llist_append(&tcp_sockets, sock);
    } else if (sock->state == TCP_LISTEN) {
        tcp_sock_lock(sock);
        sock->inet.remaddr = saddr;
        sock->inet.remport = sport;
        sock->inet.locaddr = daddr;
    } else {
        // Always lock the socket
        tcp_sock_lock(sock);

        // Set peer addresses on LISTENing sockets
        if (sock->state == TCP_LISTEN) {
            sock->inet.remaddr = saddr;
            sock->inet.remport = sport;
            sock->inet.locaddr = daddr;
        }
    }
    tcp_sock_incref(sock);

    /* Pass initial network csum as TCP packet csum seed */
    tcp_recv(frame, sock, inet_ipv4_csum(hdr));

    // Decrement sock refcount and unlock
    tcp_sock_decref(sock);
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

    // Push TCP into protocol stack
    frame_layer_push(frame, PROTO_TCP);

    // TODO: Other integrity checks

    tcp_seg_arr(frame, sock);

    drop_pkt:
    return;
}

void _tcp_setstate(struct tcp_sock *sock, enum tcp_state state) {
    // TODO: Perform queued actions when reaching certain states
    sock->state = state;

    switch (state) {
        case TCP_CLOSING:
            // Signal EOF to any waiting recv() calls
            retlock_broadcast(&sock->recvwait, 0);
            break;
        default:
            break;
    }
}

void tcp_established(struct tcp_sock *sock, struct tcp_hdr *seg) {

    tcp_setstate(sock, TCP_ESTABLISHED);

    // Set the initial recv value to the first byte in stream
    sock->recvptr = ntohl(seg->seqn) + 1;
    LOG(LTRCE, "[TCP] set recvptr to %u", sock->recvptr);

    // Allocate send/receive buffers
//    rbuf_init(&sock->rcvbuf, sock->tcb.rcv.wnd, BYTE);
    rbuf_init(&sock->sndbuf, sock->tcb.snd.wnd, BYTE);
    LOG(LDBUG, "[TCP] Allocated SND.WND %hu, RCV.WND %hu",
        sock->tcb.snd.wnd, sock->tcb.rcv.wnd);
}

struct tcp_sock *tcp_sock_init(struct tcp_sock *sock) {
    memset(sock, 0, sizeof(struct tcp_sock));
    sock->state = TCP_CLOSED;
    atomic_init(&sock->refcount, 1);
    pthread_mutex_init(&sock->lock, NULL);
    retlock_init(&sock->openwait);
    retlock_init(&sock->sendwait);
    retlock_init(&sock->recvwait);
    return sock;
}

inline void tcp_sock_free(struct tcp_sock *sock) {
    // Cancel all running timers
    tcp_timewait_cancel(sock);

    // Deallocate dynamically allocated data buffers
//    if (sock->rcvbuf.size > 0)
//        rbuf_destroy(&sock->rcvbuf);
    if (sock->sndbuf.size > 0)
        rbuf_destroy(&sock->sndbuf);

    tcp_sock_unlock(sock);

    free(sock);
}

inline void tcp_sock_destroy(struct tcp_sock *sock) {
    tcp_sock_untrack(sock);
    tcp_sock_free(sock);
}

void tcp_sock_cleanup(struct tcp_sock *sock) {

    // Set the open() return value and wake it up
    retlock_broadcast(&sock->openwait, -ECONNABORTED);
    retlock_broadcast(&sock->sendwait, -ECONNABORTED);
    retlock_broadcast(&sock->recvwait, -ECONNABORTED);

    switch (sock->state) {
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

    // Wait for all tracked socket operations to complete before free'ing sock
//    refcount_wait(&sock->refcount);

    // Deallocate socket memory
    tcp_sock_destroy(sock);
}

uint tcp_sock_incref(struct tcp_sock *sock) {
    return atomic_fetch_add(&sock->refcount, 1);
}

uint tcp_sock_decref(struct tcp_sock *sock) {
    // Subtract and destroy socket if no more refs held
    uint refcnt;
    if ((refcnt = atomic_fetch_sub(&sock->refcount, 1)) == 1) {
        LOG(LDBUG, "dereferencing sock %p", sock);
        tcp_sock_unlock(sock);
        tcp_sock_destroy(sock);
    } else {
        tcp_sock_unlock(sock);
    }
    return refcnt;
}

/*
 * TCP Internet functions
 */

uint16_t tcp_randomport() {
    // TODO: Choose a random unused outgoing port
    return (uint16_t) (rand() * time(NULL));
}

uint32_t tcp_seqnum() {
    // TODO: Choose a secure initial sequence number
    return (uint32_t) (rand() * time(NULL));
}

int tcp_seg_cmp(const struct frame *fa, const struct frame *fb) {

    struct tcp_hdr *a = tcp_hdr(fa);
    struct tcp_hdr *b = tcp_hdr(fb);

    LOG(LTRCE, "[TCP] tcp_seg_cmp (a)%u - (b)%u (cmp %d)",
        ntohl(a->seqn), ntohl(b->seqn),
        ((int) ntohl(a->seqn) - ntohl(b->seqn)));

    return ntohl(a->seqn) - ntohl(b->seqn);
}

uint32_t tcp_recvqueue_contigseq(struct tcp_sock *sock, uint32_t init) {

    // TODO: Ensure no off-by-one errors in tcp_recvqueue_contigseq
    for_each_llist(&sock->recvqueue) {
        struct frame *frame = llist_elem_data();
        struct tcp_hdr *hdr = tcp_hdr(frame);

        uint32_t seg_seq = ntohl(hdr->seqn);
        uint16_t seg_len = frame_data_len(frame);
        LOGFN(LVERB, "init %u, seg->seq %u, end %u",
              init, seg_seq, seg_seq + seg_len);
        if (init >= seg_seq && init <= (seg_seq + seg_len))
            init = seg_seq + seg_len;
        else
            break;
    }

    LOGFN(LTRCE, "recvqueue contiguous %u", init);
    return init;
}
