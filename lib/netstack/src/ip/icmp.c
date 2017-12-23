#include <stdio.h>
#include <netinet/in.h>

#include <netstack/checksum.h>
#include <netstack/ip/icmp.h>
#include <netstack/ip/ipv4.h>

struct icmp_echo *icmp_echo(void *data) {
    struct icmp_echo *echo = (struct icmp_echo *) data;
    echo->id  = ntohs(echo->id);
    echo->seq = ntohs(echo->seq);
    return echo;
}

void icmp_recv(struct frame *frame) {
    struct icmp_hdr *hdr = icmp_hdr(frame);
    frame->data += sizeof(struct icmp_hdr);

    /* Save and empty packet checksum */
    uint16_t pkt_csum = hdr->csum;
    hdr->csum = 0;
    uint16_t calc_csum = in_csum(frame->head, frame_pkt_len(frame), 0);
    printf(", csum 0x%04x", calc_csum);

    if (pkt_csum != calc_csum) {
        printf(" (invalid 0x%04x)", pkt_csum);
        return;
    }

    struct frame *ctrl = frame_child_copy(frame);
    switch (hdr->type) {
        case ICMP_T_ECHORPLY: {
            struct icmp_echo *echo = icmp_echo(ctrl->head);
            ctrl->data += sizeof(struct icmp_echo);
            printf(" echoreply id %d, seq %d", echo->id, echo->seq);
            break;
        }
        case ICMP_T_DESTUNR:
            printf(" dest-unreachable");
            break;
        case ICMP_T_ECHOREQ: {
            struct icmp_echo *echo = icmp_echo(ctrl->head);
            ctrl->data += sizeof(struct icmp_echo);
            printf(" echoreq id %d, seq %d", echo->id, echo->seq);
            send_icmp_reply(ctrl);
            break;
        }
    }
}

/*
 *  The echo reply is an ICMP message generated in response to an echo request;
 *  it is mandatory for all hosts, and must include the exact payload received
 *  in the request.
 *  Source: https://en.wikipedia.org/wiki/Ping_(networking_utility)#Echo_reply
 */
int send_icmp_reply(struct frame *ctrl) {
    // TODO: Don't assume IPv4 parent
    struct ipv4_hdr  *ip    = ipv4_hdr(ctrl->parent->parent);
    struct icmp_echo *ping  = icmp_echo_hdr(ctrl);

    size_t size = intf_max_frame_size(ctrl->intf);
    struct frame *reply = intf_frame_new(ctrl->intf, size);
    // TODO: Fix frame->data pointer head/tail difference
    reply->data = reply->tail;

    // Mark and copy payload from request packet
    uint8_t *payld = frame_alloc(reply, frame_data_len(ctrl));
    memcpy(payld, ctrl->data, frame_data_len(ctrl));

    struct icmp_echo *echo = frame_alloc(reply, sizeof(struct icmp_echo));
    struct icmp_hdr *hdr = frame_alloc(reply, sizeof(struct icmp_hdr));
    echo->id = htons(ping->id);
    echo->seq = htons(ping->seq);
    hdr->type = ICMP_T_ECHORPLY;
    hdr->code = 0;
    hdr->csum = 0;
    hdr->csum = in_csum(hdr, frame_data_len(reply), 0);

    // Swap source/dest IP addresses
    int ret;
    if ((ret = send_ipv4(reply, IP_P_ICMP, IP_DF, ip->saddr, ip->daddr)) != 0) {
        intf_frame_free(reply);
    }
    return ret;
}
