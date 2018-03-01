#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/in.h>

#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>
#include <netstack/ip/route.h>

llist_t tcp_sockets = LLIST_INITIALISER;

bool tcp_log(struct pkt_log *log, struct frame *frame, uint16_t net_csum,
             addr_t saddr, addr_t daddr) {
    struct tcp_hdr *hdr = tcp_hdr(frame);
    frame->data = frame->head + tcp_hdr_len(hdr);
    struct log_trans *trans = &log->t;

    // Print and check checksum
    uint16_t pkt_csum = hdr->csum;
    uint16_t calc_csum = in_csum(hdr, frame_pkt_len(frame), net_csum) + hdr->csum;
    LOGT(trans, "csum 0x%04x", ntohs(pkt_csum));
    if (pkt_csum != calc_csum)
        LOGT(trans, " (invalid 0x%04x)", ntohs(calc_csum));

    char sflags[9];
    LOGT(trans, ", flags [%s]", fmt_tcp_flags(hdr->flagval, sflags));

    // TODO: Use frame->sock for socket lookup
    uint16_t sport = htons(hdr->sport);
    uint16_t dport = htons(hdr->dport);
    struct tcp_sock *sock = tcp_sock_lookup(&saddr, &daddr, sport, dport);
    uint32_t irs = (sock == NULL || hdr->flags.syn == 1) ? 0 : sock->tcb.irs;
    uint32_t iss = (sock == NULL) ? 0 : sock->tcb.iss;
    uint32_t seqn = ntohl(hdr->seqn) - irs;
    uint32_t ackn = ntohl(hdr->ackn) - iss;
    uint16_t len = frame_data_len(frame);

    if (len > 0)
        LOGT(trans, ", seq %u-%u", seqn, seqn + len - 1);
    else if (hdr->flags.syn || hdr->flags.fin || hdr->flags.rst)
        LOGT(trans, ", seq %u", seqn);

    if (hdr->flags.ack)
        LOGT(trans, ", ack %u", ackn);

    LOGT(trans, ", wind %hu", ntohs(hdr->wind));

    // Print IPv4 payload size
    LOGT(trans, ", length %hu", len);

    return true;
}

void tcp_log_recvqueue(struct tcp_sock *sock) {
    if (sock->recvqueue.length > 0) {
        struct log_trans t = LOG_TRANS(LVERB);
        uint i = 0;
        uint32_t ctr = sock->tcb.rcv.nxt;
        for_each_llist(&sock->recvqueue) {
            struct frame *qframe = llist_elem_data();
            struct tcp_hdr *hdr = tcp_hdr(qframe);
            uint32_t seqn = ntohl(hdr->seqn);
            uint32_t relseq = seqn - sock->tcb.irs;
            if (seqn > ctr)
                LOGT(&t, "[TCP] recvqueue    < GAP OF %u bytes>\n", seqn - ctr);
            LOGT(&t, "[TCP] recvqueue[%u] seq %u-%u\n",
                 i++, relseq, relseq + frame_data_len(qframe) - 1);
            ctr = seqn + frame_data_len(qframe);
        }
        LOGT_COMMIT(&t);
    } else {
        LOG(LVERB, "[TCP] recvqueue is empty");
    }
}

void tcp_ipv4_recv(struct frame *frame, struct ipv4_hdr *hdr) {

    struct tcp_hdr *tcp_hdr = tcp_hdr(frame);
    frame->remport = htons(tcp_hdr->sport);
    frame->locport = htons(tcp_hdr->dport);
    struct tcp_sock *sock =
            tcp_sock_lookup(&frame->remaddr, &frame->locaddr,
                             frame->remport,  frame->locport);

    // https://blog.cloudflare.com/syn-packet-handling-in-the-wild

    // No (part/complete) established connection was found
    if (sock == NULL) {
        LOGFN(LWARN, "[IPv4] Unrecognised incoming TCP connection");
    } else {
        LOGFN(LWARN, "[TCP] Socket in state %s", tcp_strstate(sock->state));
        tcp_sock_incref(sock);
    }
    /* Pass initial network csum as TCP packet csum seed */
    tcp_recv(frame, sock, inet_ipv4_csum(hdr));

    // Decrement sock refcount and unlock
    if (sock != NULL)
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
        LOGFN(LTRCE, "Dropping TCP packet with invalid checksum!");
        goto drop_pkt;
    }

    // Push TCP into protocol stack
    frame_layer_push(frame, PROTO_TCP);

    // TODO: Other integrity checks

    // Parse segment TCP options
    // TODO: Parse incoming TCP segment options

    if (sock == NULL || sock->state == TCP_CLOSED)
        tcp_recv_closed(frame, hdr);
    else if (sock->state == TCP_LISTEN)
        tcp_recv_listen(frame, sock, hdr);
    else
        tcp_seg_arr(frame, sock);

    drop_pkt:
    return;
}

void _tcp_setstate(struct tcp_sock *sock, enum tcp_state state) {
    // TODO: Perform queued actions when reaching certain states
    sock->state = state;

    switch (state) {
        case TCP_CLOSING:
        case TCP_CLOSE_WAIT:
            // Signal EOF to any waiting recv() calls
            LOGFN(LTRCE, "[TCP] Waking all waiting user calls");
            retlock_broadcast_bare(&sock->wait, 0);
            break;
        default:
            break;
    }
}

void tcp_established(struct tcp_sock *sock, uint32_t firstbyte) {

    tcp_setstate(sock, TCP_ESTABLISHED);

    // Set the initial recv value to the first byte in stream
    sock->recvptr = firstbyte;
    LOG(LTRCE, "[TCP] set recvptr to %u", sock->recvptr);

    // Allocate send/receive buffers
//    rbuf_init(&sock->rcvbuf, sock->tcb.rcv.wnd, BYTE);
    rbuf_init(&sock->sndbuf, sock->tcb.snd.wnd, BYTE);
    LOG(LDBUG, "[TCP] Allocated SND.WND %hu, RCV.WND %hu",
        sock->tcb.snd.wnd, sock->tcb.rcv.wnd);

    // If socket was PASSIVE open, notify the parent socket if waiting on accept()
    if (sock->parent != NULL) {
        retlock_broadcast(&sock->parent->wait, 1);
    }
}

struct tcp_sock *tcp_sock_init(struct tcp_sock *sock) {
    sock->passive = NULL;
    sock->timewait = (timeout_t) {0};
    sock->tcb = (struct tcb) {0};
    // Use default MSS for outgoing send() calls
    sock->mss = TCP_DEF_MSS;
    atomic_init(&sock->refcount, 1);
    retlock_init(&sock->wait);
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

    if (tcp_sock_trylock(sock) != EBUSY) {
        LOGFN(LERR, "[TCP] tcp_sock_free() called on unlocked socket!");
        return;
    }
    tcp_sock_unlock(sock);

    free(sock);
}

inline void tcp_sock_destroy(struct tcp_sock *sock) {
    tcp_sock_untrack(sock);
    tcp_sock_free(sock);
}

void tcp_sock_cleanup(struct tcp_sock *sock) {

    // Set the open() return value and wake it up
    retlock_broadcast(&sock->wait, -ECONNABORTED);

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

uint _tcp_sock_decref(struct tcp_sock *sock, const char *file, int line, const char *func) {
    // Subtract and destroy socket if no more refs held
    uint refcnt;
    if ((refcnt = atomic_fetch_sub(&sock->refcount, 1)) == 1) {
        LOG(LDBUG, "[TCP] dereferencing sock %p" ": %s:%u<%s>", sock,
            file, line, func);
        tcp_sock_destroy(sock);
    }
    return refcnt - 1;
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
    return tcp_seq_gt(ntohl(tcp_hdr(fb)->seqn), ntohl(tcp_hdr(fa)->seqn));
}

uint32_t tcp_recvqueue_contigseq(struct tcp_sock *sock, uint32_t init) {

    for_each_llist(&sock->recvqueue) {
        struct frame *frame = llist_elem_data();
        struct tcp_hdr *hdr = tcp_hdr(frame);

        uint32_t seg_seq = ntohl(hdr->seqn);
        uint16_t seg_len = frame_data_len(frame);
        uint32_t seg_end = seg_seq + seg_len - 1;
        // If initial byte resides within the segment
        if (tcp_seq_geq(init, seg_seq) && tcp_seq_leq(init, seg_end))
            // jump to the next byte after the segment
            init = seg_end + 1;
        else if (tcp_seq_gt(init, seg_end))
            // account for duplicate segments
            continue;
        else
            break;
    }

    return init;
}
