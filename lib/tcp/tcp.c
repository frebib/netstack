#include <netinet/in.h>
#include <libnet/tcp/tcp.h>

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

void recv_tcp(struct interface *intf, struct frame *frame) {

    /* Don't parse yet, we need to check the checksum first */
    struct tcp_hdr *hdr = tcp_hdr(frame);
    /* hdr->hdr_len is 1 byte, soo 4x is 1 word size */
    frame->data += tcp_hdr_len(hdr);
    uint16_t pkt_len = (uint16_t) (frame->tail - frame->head);

    // TODO: Other integrity checks

    // TODO: Check TCP packet checksum

    parse_tcp(frame->head);
}
