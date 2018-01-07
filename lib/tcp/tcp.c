#include <stdio.h>
#include <netinet/in.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

struct llist tcp_sockets = LLIST_INITIALISER;

bool tcp_log(struct pkt_log *log, struct frame *frame, uint16_t net_csum) {
    struct tcp_hdr *hdr = tcp_hdr(frame);
    frame->data += tcp_hdr_len(hdr);
    struct log_trans *trans = &log->t;

    // Print IPv4 payload size
    LOGT(trans, "length %hu ", frame_data_len(frame));

    // Print and check checksum
    uint16_t pkt_csum = hdr->csum;
    uint16_t calc_csum = in_csum(frame->head, (size_t) tcp_hdr_len(hdr), net_csum)
                         + hdr->csum;
    LOGT(trans, "csum 0x%04x", ntohs(pkt_csum));
    if (pkt_csum != calc_csum)
        LOGT(trans, " (invalid 0x%04x)", ntohs(calc_csum));
    LOGT(trans, ", ");

    char sflags[9];
    LOGT(trans, "flags [%s] ", fmt_tcp_flags(hdr, sflags));

    LOGT(trans, "seq %zu ", hdr->seqn);

    return true;
}

void tcp_recv(struct frame *frame, struct tcp_sock *sock, uint16_t net_csum) {

    /* Don't parse yet, we need to check the checksum first */
    struct tcp_hdr *hdr = tcp_hdr(frame);
    frame->data += tcp_hdr_len(hdr);

    // TODO: Investigate TCP checksums invalid with long packets
    // Research suggests this is caused by 'segmentation offload', or
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
struct tcp_sock *tcp_sock_lookup(addr_t *saddr, addr_t *daddr,
                                 uint16_t sport, uint16_t dport) {
    // TODO: Use hashtbl instead of list to lookup sockets
    // TODO: Lock llist tcp_sockets for concurrent access

    for_each_llist(&tcp_sockets) {
        struct tcp_sock *sock = llist_elem_data();
        if (!sock) {
            LOG(LWARN, "tcp_sockets contains a NULL element!");
            continue;
        }
        if (addreq(saddr, &sock->saddr) && sport == sock->sport &&
                addreq (daddr, &sock->daddr) && dport == sock->dport) {
            return sock;
        }
    }

    return NULL;
}
