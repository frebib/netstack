#include <sys/param.h>
#include <netinet/in.h>

#include <netstack/checksum.h>
#include <netstack/ip/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/ip/neigh.h>

int tcp_send(struct tcp_sock *sock, struct frame *frame) {
    struct inet_sock *inet = &sock->inet;
    struct tcp_hdr *hdr = tcp_hdr(frame);

    // Zero out some constant values
    hdr->rsvd = 0;
    hdr->csum = 0;
    hdr->urg_ptr = 0;
    // TODO: Allow for tcp_hdr->hlen options
    hdr->hlen = 5;
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
    struct tcp_hdr *hdr = frame_head_alloc(seg, sizeof(struct tcp_hdr));
    hdr->seqn = htonl(seqn);
    hdr->ackn = htonl(ackn);
    hdr->flagval = flags;

    int ret = tcp_send(sock, seg);
    // We created the frame so ensure it's unlocked if it never sent
    if (ret)
        frame_unlock(seg);
    frame_decref(seg);

    return ret;
}

int tcp_send_data(struct tcp_sock *sock, uint8_t flags) {

    size_t size = intf_max_frame_size(sock->inet.intf);
    struct frame *seg = intf_frame_new(sock->inet.intf, size);
    seg->head = seg->data;
    seg->intf = sock->inet.intf;

    // https://tools.ietf.org/html/rfc793#section-3.7
    // TODO: Implement MSS variability. Default MSS is quite small
    // Calculate data size to send, limited by MSS
    size_t count = MIN(rbuf_count(&sock->sndbuf), TCP_DEF_MSS);
    void* data = frame_data_alloc(seg, count);
    // rbuf_read already does a count upper-bounds check to prevent over-reading
    rbuf_read(&sock->sndbuf, data, count);

    // TODO: Allocate space for TCP options
    struct tcp_hdr *hdr = frame_head_alloc(seg, sizeof(struct tcp_hdr));
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
