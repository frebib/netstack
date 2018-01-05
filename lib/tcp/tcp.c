#include <stdio.h>
#include <netinet/in.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

struct llist tcp_sockets = LLIST_INITIALISER;

struct tcp_hdr *tcp_ntoh(void *data) {
    struct tcp_hdr *tcp_hdr = (struct tcp_hdr *) data;

    tcp_hdr->sport = ntohs(tcp_hdr->sport);
    tcp_hdr->dport = ntohs(tcp_hdr->dport);
    tcp_hdr->seqn = ntohl(tcp_hdr->seqn);
    tcp_hdr->ackn = ntohl(tcp_hdr->ackn);
    tcp_hdr->wind = ntohs(tcp_hdr->wind);
    tcp_hdr->csum = ntohs(tcp_hdr->csum);
    tcp_hdr->urg_ptr = ntohs(tcp_hdr->urg_ptr);

    return tcp_hdr;
}

void tcp_recv(struct frame *frame, struct tcp_sock *sock, uint16_t net_csum) {

    /* Don't parse yet, we need to check the checksum first */
    struct tcp_hdr *hdr = tcp_hdr(frame);
    frame->data += tcp_hdr_len(hdr);
    uint16_t pkt_len = frame_pkt_len(frame);

    printf(" %hu bytes", frame_data_len(frame));

    /* Save and empty packet checksum */
    uint16_t pkt_csum = hdr->csum;
    hdr->csum = 0;

    uint16_t calc_csum = in_csum(frame->head, pkt_len, net_csum);
    printf(", csum 0x%04x", calc_csum);

    // TODO: Investigate TCP checksums invalid with long packets
    // Research suggests this is caused by 'segmentation offload', or
    // more specifically 'generic-receive-offload' in Linux.
    // See also:
    //   - https://lwn.net/Articles/358910/
    //   - https://www.kernel.org/doc/Documentation/networking/segmentation-offloads.txt

    // TODO: Check for TSO and GRO and account for it, somehow..
    if (pkt_csum != calc_csum) {
        printf(" (invalid 0x%04x)", pkt_csum);
        goto drop_pkt;
    }

    // TODO: Other integrity checks

    tcp_ntoh(frame->head);

    tcp_seg_arr(frame, sock);

    drop_pkt:
    return;
}
struct tcp_sock *tcp_sock_lookup(addr_t *saddr, addr_t *daddr,
                                 uint16_t sport, uint16_t dport) {
    // TODO: Use hashtbl instead of list to lookup sockets
    // TODO: Lock llist tcp_sockets for concurrent access

    for_each_llist(&tcp_sockets) {
        struct tcp_sock *sock = llist_elem_data();
        if (!sock)
            continue;
        if (addreq(saddr, &sock->saddr) && sport == sock->sport &&
                addreq (daddr, &sock->daddr) && dport == sock->dport) {
            return sock;
        }
    }

    return NULL;
}