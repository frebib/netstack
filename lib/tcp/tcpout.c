#include <netinet/in.h>

#include <netstack/checksum.h>
#include <netstack/ip/route.h>
#include <netstack/tcp/tcp.h>

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

    uint32_t daddr = inet->remaddr.ipv4;
    uint32_t saddr = inet->locaddr.ipv4;
    // TODO: Implement functionality to specify IP flags (different for IP4/6?)
    int ret = ipv4_send(frame, IP_P_TCP, 0, daddr, saddr);
    frame_deref(frame);
    return ret;
}

int tcp_send_ack(struct tcp_sock *sock) {
    // TODO: Work out route interface before allocating buffer
    struct route_entry *rt = route_lookup(sock->inet.remaddr.ipv4);

    size_t size = intf_max_frame_size(rt->intf);
    struct frame *ack = intf_frame_new(rt->intf, size);

    size_t payld_sz = 0;
    uint8_t *payld = frame_alloc(ack, payld_sz);
    // TODO: Allow for attaching data to SYN/ACK packet
    ack->data = payld;


    // TODO: Allocate space for TCP options
    struct tcp_hdr *hdr = frame_head_alloc(ack, sizeof(struct tcp_hdr));
    hdr->seqn = htonl(sock->tcb.snd.nxt);
    hdr->ackn = htonl(sock->tcb.rcv.nxt);
    hdr->flagval = TCP_FLAG_ACK;

    return tcp_send(sock, ack);
}

int tcp_send_synack(struct tcp_sock *sock) {

    // TODO: Work out route interface before allocating buffer
    struct route_entry *rt = route_lookup(sock->inet.remaddr.ipv4);

    size_t size = intf_max_frame_size(rt->intf);
    struct frame *synack = intf_frame_new(rt->intf, size);

    // TODO: Allocate space for TCP options
    struct tcp_hdr *hdr = frame_head_alloc(synack, sizeof(struct tcp_hdr));
    hdr->seqn = htonl(sock->tcb.iss);
    hdr->ackn = htonl(sock->tcb.rcv.nxt);
    hdr->flagval = TCP_FLAG_SYN | TCP_FLAG_ACK;

    return tcp_send(sock, synack);
}

int tcp_send_rst(struct tcp_sock *sock, uint32_t seqn) {

    // TODO: Work out route interface before allocating buffer
    struct route_entry *rt = route_lookup(sock->inet.remaddr.ipv4);

    size_t size = intf_max_frame_size(rt->intf);
    struct frame *rst = intf_frame_new(rt->intf, size);

    // TODO: Allocate space for TCP options
    struct tcp_hdr *hdr = frame_head_alloc(rst, sizeof(struct tcp_hdr));
    hdr->seqn = htonl(seqn);
    hdr->ackn = 0;
    hdr->flagval = TCP_FLAG_RST;

    return tcp_send(sock, rst);
}
