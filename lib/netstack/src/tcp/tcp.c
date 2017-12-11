#include <stdio.h>
#include <netinet/in.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

struct tcphdr *parse_tcp(void *data) {
    struct tcphdr *hdr = (struct tcphdr *) data;

    hdr->th_sport = ntohs(hdr->th_sport);
    hdr->th_dport = ntohs(hdr->th_dport);
    hdr->th_seq   = ntohl(hdr->th_seq);
    hdr->th_ack   = ntohl(hdr->th_ack);
    hdr->th_win   = ntohs(hdr->th_win);
    hdr->th_sum   = ntohs(hdr->th_sum);
    hdr->th_urp   = ntohs(hdr->th_urp);

    return hdr;
}

void recv_tcp(struct intf *intf, struct frame *frame, uint16_t net_csum) {

    /* Don't parse yet, we need to check the checksum first */
    struct tcphdr *hdr = tcp_hdr(frame);
    frame->data += tcp_hdr_len(hdr);
    uint16_t pkt_len = (uint16_t) (frame->tail - frame->head);

    printf(" %lu bytes", (frame->tail - frame->data));

    /* Save and empty packet checksum */
    uint16_t pkt_csum = hdr->th_sum;
    hdr->th_sum = 0;

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

    // TODO: Check TCP packet checksum

    parse_tcp(frame->head);

    drop_pkt:
    return;
}
