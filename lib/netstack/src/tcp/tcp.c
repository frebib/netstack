#include <stdio.h>
#include <netinet/in.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

struct tcp_hdr *parse_tcp(void *data) {
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

void recv_tcp(struct intf *intf, struct frame *frame, uint16_t net_csum) {

    /* Don't parse yet, we need to check the checksum first */
    struct tcp_hdr *hdr = tcp_hdr(frame);
    frame->data += tcp_hdr_len(hdr);
    uint16_t pkt_len = (uint16_t) (frame->tail - frame->head);

    // TODO: Investigate TCP checksums invalid with long packets
    // Could be something to do with TCP checksum offloading in Linux?
    // Regardless, large packets are discarded unless it is fixed
    if (in_csum(frame->head, pkt_len, net_csum) != 0) {
        fprintf(stderr, "\n\n\n\nError: TCP packet checksum is "
                "corrupt (size %d)\n\n\n\n\n", pkt_len);
    }

    // TODO: Other integrity checks

    // TODO: Check TCP packet checksum

    parse_tcp(frame->head);
}
