#include <sys/param.h>
#include <netinet/in.h>

#include <netstack/checksum.h>
#include <netstack/ip/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/tcp/tcpopt.h>


int tcp_send(struct tcp_sock *sock, struct frame *frame, struct neigh_route *rt) {
    struct inet_sock *inet = &sock->inet;
    struct tcp_hdr *hdr = tcp_hdr(frame);

    // TODO: Don't assume IPv4 L3, choose based on sock->saddr
    struct inet_ipv4_phdr phdr = {
            .saddr = htonl(inet->locaddr.ipv4),
            .daddr = htonl(inet->remaddr.ipv4),
            .hlen  = htons(frame_pkt_len(frame)),
            .proto = IP_P_TCP,
            .rsvd = 0
    };

    // Calculate TCP checksum, including IP layer
    // TODO: Don't assume IPv4 pseudo-header for checksumming
    uint16_t ph_csum = in_csum(&phdr, sizeof(phdr), 0);
    hdr->csum = in_csum(hdr, frame_pkt_len(frame), ~ph_csum);

    frame_unlock(frame);

    // TODO: Implement functionality to specify IP flags (different for IP4/6?)
    return neigh_send_to(rt, frame, IP_P_TCP, 0, 0);
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
    
    long count = tcp_init_header(seg, sock, htonl(seqn), htonl(ackn), flags, 0);
    // < 0 indicates error
    if (count < 0)
        return (int) count;

    int ret = tcp_send(sock, seg, &route);
    // We created the frame so ensure it's unlocked if it never sent
    frame_decref(seg);

    return ret;
}

int tcp_send_data(struct tcp_sock *sock, uint8_t flags) {

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

    size_t tosend = rbuf_count(&sock->sndbuf);
    uint32_t seqn = htonl(sock->tcb.snd.nxt);
    uint32_t ackn = htonl(sock->tcb.rcv.nxt);
    long count = tcp_init_header(seg, sock, seqn, ackn, flags, tosend);
    // < 0 indicates error
    if (count < 0)
        return (int) count;
    sock->tcb.snd.nxt += count;

    // https://tools.ietf.org/html/rfc793#section-3.7
    // Calculate data size to send, limited by MSS (- options)
    // rbuf_read already does a count upper-bounds check to prevent over-reading
    rbuf_read(&sock->sndbuf, seg->data, (size_t) count);

    // TODO: Start the retransmission timeout

    // Send to neigh, passing IP options
    int ret = tcp_send(sock, seg, &route);
    // We created the frame so ensure it's unlocked if it never sent
    if (ret)
        frame_unlock(seg);
    frame_decref(seg);

    return (ret < 0 ? ret : (int) count);
}

long tcp_init_header(struct frame *seg, struct tcp_sock *sock, uint32_t seqn,
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

    // Only send MSS option in SYN flags, if the MSS has been set
    if ((tcp_flags & TCP_FLAG_SYN) && (sock->mss != TCP_DEF_MSS)) {
        // Maximum Segment Size option is 1+1+2 bytes:
        // https://tools.ietf.org/html/rfc793#page-19
        LOG(LDBUG, "[TCP] MSS option enabled with mss = %hu", sock->mss);

        *opt++ = TCP_OPT_MSS;
        *opt++ = TCP_OPT_MSS_LEN;
        *((uint16_t *) opt) = htons(sock->mss);   // MSS value
        opt += 2;
    }

    // Length of options is delta
    uint64_t len = opt - optstart;
    LOG(LVERB, "[TCP] options length %lu", len);

    return len;
}
