#include <stdio.h>
#include <netinet/in.h>
#include <netstack/ip/icmp.h>
#include <netstack/checksum.h>
#include <netstack/ip/ipv4.h>

struct icmp_hdr *parse_icmp(void *data) {
    struct icmp_hdr *hdr = (struct icmp_hdr *) data;
    hdr->csum = ntohs(hdr->csum);
    return hdr;
}

struct icmp_echo *icmp_echo(void *data) {
    struct icmp_echo *echo = (struct icmp_echo *) data;
    echo->id  = ntohs(echo->id);
    echo->seq = ntohs(echo->seq);
    return echo;
}

void recv_icmp(struct intf *intf, struct frame *frame) {

    struct icmp_hdr *hdr = icmp_hdr(frame);
    frame->data += sizeof(struct icmp_hdr);

    // TODO: Check ICMP csum

    hdr = parse_icmp(hdr);

    switch (hdr->type) {
        case ICMP_T_ECHORPLY: {
            struct icmp_echo *echo = icmp_echo(frame->data);
            printf(" echoreply id %d, seq %d", echo->id, echo->seq);
            break;
        }
        case ICMP_T_DESTUNR:
            printf(" dest-unreachable");
            break;
        case ICMP_T_ECHOREQ: {
            struct icmp_echo *echo = icmp_echo(frame->data);
            printf(" echoreq id %d, seq %d", echo->id, echo->seq);

            // TODO: If the request was for us, send a reply
            break;
        }
    }
}

