#include <stdlib.h>

#include <sys/param.h>
#include <netinet/in.h>

#define NETSTACK_LOG_UNIT "TCP"
#include <netstack/checksum.h>
#include <netstack/inet/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/tcp/option.h>
#include <netstack/tcp/retransmission.h>
#include <netstack/time/contimer.h>
#include <netstack/time/util.h>


int tcp_send(struct inet_sock *inet, struct frame *frame, struct neigh_route *rt) {
    struct tcp_hdr *hdr = tcp_hdr(frame);

    frame_lock(frame, SHARED_RD);
    uint16_t pktlen = frame_pkt_len(frame);
    frame_unlock(frame);

    // TODO: Don't assume IPv4 L3, choose based on sock->saddr
    struct inet_ipv4_phdr phdr = {
            .saddr = htonl(inet->locaddr.ipv4),
            .daddr = htonl(inet->remaddr.ipv4),
            .hlen  = htons(pktlen),
            .proto = IP_P_TCP,
            .rsvd = 0
    };

    // Calculate TCP checksum, including IP layer
    // TODO: Don't assume IPv4 pseudo-header for checksumming
    uint16_t ph_csum = in_csum(&phdr, sizeof(phdr), 0);
    hdr->csum = in_csum(hdr, pktlen, ~ph_csum);

    frame_incref(frame);

    // TODO: Implement functionality to specify IP flags (different for IP4/6?)
    // TODO: Send socket flags to neigh_send_to() in tcp_send()
    int ret = neigh_send_to(rt, frame, IP_P_TCP, 0, inet->flags);

    frame_decref(frame);
    return ret;
}

int tcp_send_syn(struct tcp_sock *sock) {

    // Find route to next-hop
    int err;
    struct neigh_route route = {
            .intf = sock->inet.intf,
            .saddr = sock->inet.locaddr,
            .daddr = sock->inet.remaddr
    };
    if ((err = neigh_find_route(&route)))
        return err;

    struct intf *intf = route.intf;
    struct frame *seg = intf_frame_new(intf, intf_max_frame_size(intf));

    // Send 0 datalen for empty control packet
    long count = tcp_init_header(seg, sock, htonl(sock->tcb.iss), 0, TCP_FLAG_SYN, 0);
    // < 0 indicates error
    if (count < 0)
        return (int) count;

    // Start the SYN connect timeout if this is the first tcp_send_syn() call
    // The timer will be automatically rescheduled each time by itself on expiry
    if (sock->backoff < 1) {

        LOG(LTRCE, "starting SYN rto for sock %p", sock);
        
        // Use the SYN connect timeout for ACTIVE open SYN packets
        struct timespec timeout;
        timespecns(&timeout, TCP_SYN_RTO);
        LOG(LVERB, "setting sock connect timeout %.3fs", tstosec(&timeout, float));

        struct tcp_rto_data rtd = { .sock = sock, .seq = sock->tcb.iss,
                                    .len = 0, .flags = TCP_FLAG_SYN };

        // Hold another reference to the socket to prevent it being free'd
        tcp_sock_incref(sock);

        sock->rto_event = contimer_queue_rel(&sock->rtimer, &timeout,
                                             tcp_syn_retransmission_timeout,
                                             &rtd, sizeof(rtd));
    }

    // Unlock and send the segment
    frame_unlock(seg);

    int ret = tcp_send(&sock->inet, seg, &route);

    frame_decref(seg);

    return ret;
}

int tcp_send_empty(struct tcp_sock *sock, uint32_t seqn, uint32_t ackn,
                   uint8_t flags) {

    // Find route to next-hop
    int err;
    struct neigh_route route = {
            .intf = sock->inet.intf,
            .saddr = sock->inet.locaddr,
            .daddr = sock->inet.remaddr
    };
    if ((err = neigh_find_route(&route)))
        return err;

    struct intf *intf = route.intf;
    struct frame *seg = intf_frame_new(intf, intf_max_frame_size(intf));

    // Send 0 datalen for empty control packet
    long count = tcp_init_header(seg, sock, htonl(seqn), htonl(ackn), flags, 0);
    // < 0 indicates error
    if (count < 0)
        return (int) count;

    // Queue control segments in case they expire and start the rto
    tcp_queue_unacked(sock, seqn, 0, tcp_hdr(seg)->flagval);

    // Unlock and send the segment
    frame_unlock(seg);

    int ret = tcp_send(&sock->inet, seg, &route);

    frame_decref(seg);

    return ret;
}

int tcp_send_data(struct tcp_sock *sock, uint32_t seqn, size_t len,
                  uint8_t flags) {

    int err;
    uint16_t count;

    // Find route to next-hop
    struct neigh_route route = {
            .intf = sock->inet.intf,
            .saddr = sock->inet.locaddr,
            .daddr = sock->inet.remaddr
    };
    if ((err = neigh_find_route(&route)))
        return err;

    struct tcb *tcb = &sock->tcb;
    struct intf *intf = route.intf;
    uint32_t ackn = htonl(tcb->rcv.nxt);
    flags |= TCP_FLAG_ACK;

    // Initialise a new frame to carry outgoing segment
    struct frame *seg = intf_frame_new(intf, intf_max_frame_size(intf));

    tcp_sock_lock(sock);

    // Get the maximum available bytes to send
    long tosend = seqbuf_available(&sock->sndbuf, seqn);

    // There is no data to send from seqn. Return ENODATA
    // This is performed after the expensive intf_frame_new() because it is
    // unlikely to happen in most cases
    if (tosend < 0) {
        LOGSE(LERR, "sendbuf_available", -tosend);
        frame_decref_unlock(seg);
        return (int) tosend;
    } else if (tosend == 0) {
        return -ENODATA;
    }

    // Bound payload size by requested length
    if (len > 0)
        tosend = MIN(tosend, len);

    err = tcp_init_header(seg, sock, htonl(seqn), ackn, flags, (size_t) tosend);
    if (err < 0) {
        frame_decref_unlock(seg);
        // < 0 indicates error
        return err;
    }

    // Set the PUSH flag if we're sending the last data in the buffer
    count = (uint16_t) err;
    if (count >= tosend)
        tcp_hdr(seg)->flags.psh = 1;

    // Queue the segment in case of later retransmission and start the rto
    tcp_queue_unacked(sock, seqn, count, tcp_hdr(seg)->flagval);

    // Read data from the send buffer into the segment payload
    long readerr = seqbuf_read(&sock->sndbuf, seqn, seg->data, (size_t) count);
    if (readerr < 0) {
        LOGSE(LERR, "seqbuf_read (%li)", -readerr, readerr);
        tcp_sock_unlock(sock);
        frame_decref_unlock(seg);
        return (int) readerr;
    } else if (readerr == 0) {
        // This is unlikely/impossible because there is a data check above
        LOG(LWARN, "No data to send");
        tcp_sock_unlock(sock);
        frame_decref_unlock(seg);
        return -ENODATA;
    }

    tcp_sock_unlock(sock);
    frame_unlock(seg);

    // Send to neigh, passing IP options
    int ret = tcp_send(&sock->inet, seg, &route);

    frame_decref(seg);

    return (ret < 0 ? ret : count);
}

void tcp_queue_unacked(struct tcp_sock *sock, uint32_t seqn, uint16_t len,
                       uint8_t flags) {

    // Start the retransmission timeout
    if (sock->unacked.length == 0)
        tcp_start_rto(sock, len, flags);

    // Only queue segments if they are not retransmissions
    if (seqn != sock->tcb.snd.nxt) {
        LOG(LVERB, "not queuing segment %u (snd.nxt %u)", seqn, sock->tcb.snd.nxt);
        return;
    }

    // Don't queue empty ACK packets
    if (len == 0 && flags == TCP_FLAG_ACK) {
        LOG(LVERB, "not queuing ACK segment %u", seqn);
        return;
    }

    char tmp[20];
    LOG(LTRCE, "adding segment %u to unacked queue (flags %s)", seqn, fmt_tcp_flags(flags, tmp));

    // Store sequence information for the rto
    struct tcp_seq_data *seg_data = malloc(sizeof(struct tcp_seq_data));
    seg_data->seq = seqn;
    seg_data->len = len;
    seg_data->flags = flags;
    clock_gettime(CLOCK_MONOTONIC, &seg_data->when);

    // Log unsent/unacked segment data for potential later retransmission
    llist_append(&sock->unacked, seg_data);

    // Advance SND.NXT past this segment
    sock->tcb.snd.nxt += len;
}

int tcp_init_header(struct frame *seg, struct tcp_sock *sock, uint32_t seqn,
                     uint32_t ackn, uint8_t flags, size_t datalen) {

    // Obtain TCP options + hdrlen
    // Maximum of 40 bytes of options
    uint8_t tcp_optdat[40];
    // optdat doesn't need to be zero'ed as the final 4 bytes are cleared later
    size_t tcp_optsum = tcp_options(sock, flags, tcp_optdat);
    size_t tcp_optlen = (tcp_optsum + 3) & -4;    // Round to multiple of 4

    // Obtain IP options + hdrlen
    // TODO: Calculate IP layer options in tcp_send_data()
    size_t ip_optlen = 0;

    // TODO: Take into account ethernet header variations, such as VLAN tags

    // Find the largest possible segment payload with headers taken into account
    // then clamp the value to at most the requested payload size
    // https://tools.ietf.org/html/rfc793#section-3.7
    // (see https://tools.ietf.org/html/rfc879 for details)
    size_t count = MIN((sock->mss - tcp_optlen - ip_optlen), datalen);

    // Allocate TCP payload and header space, including options
    size_t hdrlen = sizeof(struct tcp_hdr) + tcp_optlen;
    frame_data_alloc(seg, count);
    struct tcp_hdr *hdr = frame_head_alloc(seg, hdrlen);

    seg->intf = sock->inet.intf;

    // Set connection values in header
    hdr->flagval = flags;
    hdr->seqn = seqn;
    hdr->ackn = ackn;
    hdr->sport = htons(sock->inet.locport);
    hdr->dport = htons(sock->inet.remport);
    // Zero out some constant values
    hdr->rsvd = 0;
    hdr->csum = 0;
    hdr->urg_ptr = 0;
    hdr->hlen = (uint8_t) (hdrlen >> 2);     // hdrlen / 4
    hdr->wind = htons(sock->tcb.rcv.wnd);

    // Copy options
    uint8_t *optptr = (seg->head + sizeof(struct tcp_hdr));
    // Zero last 4 bytes for padding
    *((uint32_t *) (optptr - 4)) = 0;
    memcpy(optptr, tcp_optdat, tcp_optsum);

    return (int) count;
}

size_t tcp_options(struct tcp_sock *sock, uint8_t tcp_flags, uint8_t *opt) {
    // Track the start pointer
    uint8_t *optstart = opt;

    // Only send MSS option in SYN flags
    uint16_t mss = tcp_mss_ipv4(sock->inet.intf);
    if ((tcp_flags & TCP_FLAG_SYN) && (mss != TCP_DEF_MSS)) {
        // Maximum Segment Size option is 1+1+2 bytes:
        // https://tools.ietf.org/html/rfc793#page-19
        LOG(LDBUG, "MSS option enabled with mss = %u", mss);

        *opt++ = TCP_OPT_MSS;
        *opt++ = TCP_OPT_MSS_LEN;
        *((uint16_t *) opt) = htons(mss);   // MSS value
        opt += 2;
    }

    // Length of options is delta
    uint64_t len = opt - optstart;
    LOG(LVERB, "options length %lu", len);

    return len;
}
