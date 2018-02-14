#include <sys/param.h>
#include <netinet/in.h>

#include <netstack/checksum.h>
#include <netstack/ip/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/ip/neigh.h>

struct tcp_hdr *tcp_addoptions(struct tcp_sock *sock, struct frame *frame, uint8_t flags);

int tcp_send(struct tcp_sock *sock, struct frame *frame) {
    struct inet_sock *inet = &sock->inet;
    struct tcp_hdr *hdr = tcp_hdr(frame);

    // Zero out some constant values
    hdr->rsvd = 0;
    hdr->csum = 0;
    hdr->urg_ptr = 0;
    hdr->hlen = ((frame->data - frame->head) >> 2);
    // TODO: Vary hdr->wind in tcp_send()
    hdr->wind = htons(sock->tcb.rcv.wnd);

    // Set some values from the socket object
    hdr->sport = htons(inet->locport);
    hdr->dport = htons(inet->remport);

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
    return neigh_send(frame, IP_P_TCP, 0, 0, &inet->remaddr, &inet->locaddr);
}

int tcp_send_empty(struct tcp_sock *sock, uint32_t seqn, uint32_t ackn,
                   uint8_t flags) {

    size_t size = intf_max_frame_size(sock->inet.intf);
    struct frame *seg = intf_frame_new(sock->inet.intf, size);
    seg->head = seg->data;
    seg->intf = sock->inet.intf;

    // TODO: Allocate space for TCP options
    struct tcp_hdr *hdr = tcp_addoptions(sock, seg, flags);
    hdr->seqn = htonl(seqn);
    hdr->ackn = htonl(ackn);
    hdr->flagval = flags;

    int ret = tcp_send(sock, seg);
    // We created the frame so ensure it's unlocked if it never sent
    frame_decref(seg);

    return ret;
}

int tcp_send_data(struct tcp_sock *sock, uint8_t flags) {

    size_t size = intf_max_frame_size(sock->inet.intf);
    struct frame *seg = intf_frame_new(sock->inet.intf, size);
    seg->head = seg->data;
    seg->intf = sock->inet.intf;

    // https://tools.ietf.org/html/rfc793#section-3.7
    // Calculate data size to send, limited by MSS
    size_t count = MIN(rbuf_count(&sock->sndbuf), sock->mss);
    void* data = frame_data_alloc(seg, count);
    // rbuf_read already does a count upper-bounds check to prevent over-reading
    rbuf_read(&sock->sndbuf, data, count);

    struct tcp_hdr *hdr = tcp_addoptions(sock, seg, flags);
    hdr->seqn = htonl(sock->tcb.snd.nxt);
    hdr->ackn = htonl(sock->tcb.rcv.nxt);
    hdr->flagval = flags;

    sock->tcb.snd.nxt += count;

    // TODO: Start the retransmission timeout

    int ret = tcp_send(sock, seg);
    // We created the frame so ensure it's unlocked if it never sent
    if (ret)
        frame_unlock(seg);
    frame_decref(seg);

    return (ret < 0 ? ret : (int) count);
}

struct tcp_hdr *tcp_addoptions(struct tcp_sock *sock, struct frame *frame,
                               uint8_t flags) {
    // Cumulative count of all options in octets/bytes
    size_t optlen = 0;

    bool mssopt = false;

    // Only send MSS option in SYN flags, if the MSS has been set
    if (flags & TCP_FLAG_SYN && sock->mss != TCP_DEF_MSS) {
        // Maximum Segment Size option is 1+1+2 bytes:
        // https://tools.ietf.org/html/rfc793#page-19
        mssopt = true;
        optlen += 4;
        LOG(LVERB, "[TCP] MSS option enabled with mss = %hu", sock->mss);
    }

    // No options to add, return just the standard header size
    if (optlen < 1)
        return frame_head_alloc(frame, sizeof(struct tcp_hdr));

    /*
     * Add all options to header now we know what and how big
     */

    size_t total_optlen = (optlen + 3) & -4;    // Round to multiple of 4
    size_t hdrsize = sizeof(struct tcp_hdr) + total_optlen;
    struct tcp_hdr *hdr = frame_head_alloc(frame, hdrsize);
    uint8_t *optptr = (frame->head + sizeof(struct tcp_hdr));

    if (mssopt) {
        *optptr++ = 0x02;   // Option type   2
        *optptr++ = 0x04;   // Option length 4
        *((uint16_t *) optptr) = htons(sock->mss);   // MSS value
        optptr += 2;    // MSS value is 2 bytes long
    }

    if (optptr > frame->data)
        LOG(LERR, "[TCP] options overflowed into payload: frame->head %p, "
                    "frame->data %p, optptr %p, optlen %lu",
                    (void *) frame->head, (void *) frame->data,
                    (void *)optptr, optlen);

    // Fill remaining option space with 0s
    memset(optptr, 0, frame->data - optptr);

    return hdr;
}
