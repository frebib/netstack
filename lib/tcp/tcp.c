#include <stdio.h>
#include <netinet/in.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

struct llist tcp_sockets = LLIST_INITIALISER;

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

    LOGT(trans, "seq %zu ", ntohl(hdr->seqn));
    if (hdr->ackn)
        LOGT(trans, "ack %zu ", ntohl(hdr->ackn));

    return true;
}

void tcp_recv(struct frame *frame, struct tcp_sock *sock, uint16_t net_csum) {

    /* Don't parse yet, we need to check the checksum first */
    struct tcp_hdr *hdr = tcp_hdr(frame);
    frame->data += tcp_hdr_len(hdr);

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

/*!
 * Finds a matching TCP socket, including listening and closed sockets.
 * Will return wildcard address sockets for any match (0.0.0.0 or equiv
 * addrs) if any are found (e.g. TCP_LISTEN should be source: 0.0.0.0:0)
 *
 * Note: Some socket objects should be treated as immutable, such as those
 * with TCP_LISTEN and a new one inserted specific to the connection.
 *
 * Courtesy of @Steamlined: https://i.giphy.com/media/czwo5mMtaknhC/200.gif
 *
 * @param remaddr remote address
 * @param locaddr local address
 * @param remport remote port
 * @param locport local port
 * @return a matching tcp_sock object, or NULL if no matches found
 */
struct tcp_sock *tcp_sock_lookup(addr_t *remaddr, addr_t *locaddr,
                                 uint16_t remport, uint16_t locport) {
    // TODO: Use hashtbl instead of list to lookup sockets
    // TODO: Lock llist tcp_sockets for concurrent access

    for_each_llist(&tcp_sockets) {
        struct tcp_sock *sock = llist_elem_data();
        if (!sock) {
            LOG(LWARN, "tcp_sockets contains a NULL element!");
            continue;
        }


        // struct log_trans t = LOG_TRANS(LDBUG);
        // LOGT(&t, "remote: %s:%hu ", straddr(remaddr), remport);
        // LOGT(&t, "local: %s:%hu ", straddr(locaddr), locport);
        // LOGT_COMMIT(&t);

        // Check matching saddr assuming it's non-zero
        if (!addrzero(&sock->remaddr) && !addreq(remaddr, &sock->remaddr)) {
            // LOG(LDBUG, "Remote address %s doesn't match", straddr(remaddr));
            // LOG(LDBUG, "   compared to %s", straddr(&sock->remaddr));
            continue;
        }
        // Check matching remport assuming it's non-zero
        if (sock->remport != 0 && sock->remport != remport) {
            // LOG(LDBUG, "Remote port %hu doesn't match %hu", sock->remport, remport);
            continue;
        }

        // Check matching daddr assuming it's non-zero
        if (!addrzero(&sock->locaddr) && !addreq(locaddr, &sock->locaddr)) {
            // LOG(LDBUG, "Local address %s doesn't match", straddr(remaddr));
            // LOG(LDBUG, "  compared to %s", straddr(&sock->remaddr));
            continue;
        }
        if (locport != sock->locport) {
            // LOG(LDBUG, "Local port %hu doesn't match %hu", sock->locport, remport);
            continue;
        }

        // t = (struct log_trans) LOG_TRANS(LDBUG);
        // LOGT(&t, "Found matching tcp_sock\t");
        // LOGT(&t, "\tsource: %s:%hu ", straddr(&sock->remaddr), sock->remport);
        // LOGT(&t, "\tdest: %s:%hu ", straddr(&sock->locaddr), sock->locport);
        // LOGT_COMMIT(&t);

        // Passed all matching checks
        return sock;
    }

    return NULL;
}
