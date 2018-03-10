#include <stdio.h>
#include <netinet/in.h>

#define NETSTACK_LOG_UNIT "ICMP"
#include <netstack/checksum.h>
#include <netstack/inet/icmp.h>
#include <netstack/inet/ipv4.h>
#include <netstack/inet/neigh.h>


bool icmp_log(struct pkt_log *log, struct frame *frame) {
    struct log_trans *trans = &log->t;
    struct icmp_hdr *hdr = icmp_hdr(frame);

    LOGT(trans, "length %hu ", frame_data_len(frame));
    frame->data += sizeof(struct icmp_hdr);

    // Print and check checksum
    uint16_t pkt_csum = hdr->csum;
    uint16_t calc_csum = in_csum(frame->head, frame_pkt_len(frame), 0) + hdr->csum;
    LOGT(trans, "csum 0x%04x", ntohs(pkt_csum));
    if (pkt_csum != calc_csum)
        LOGT(trans, " (invalid 0x%04x)", ntohs(calc_csum));
    LOGT(trans, ", ");

    frame->head = frame->data;
    switch (hdr->type) {
        case ICMP_T_ECHORPLY: {
            struct icmp_echo *echo = (struct icmp_echo *) frame->head;
            LOGT(trans, "echoreply id %d, seq %d ", ntohs(echo->id),
                   ntohs(echo->seq));
            break;
        }
        case ICMP_T_ECHOREQ: {
            struct icmp_echo *echo = (struct icmp_echo *) frame->head;
            LOGT(trans, "echoreq id %d, seq %d ", ntohs(echo->id),
                 ntohs(echo->seq));
            break;
        }
        case ICMP_T_DESTUNR:
            LOGT(trans, "dest-unreachable ");
            break;
        default:
            LOGT(trans, "type %d ", hdr->type);
            break;
    }
    return true;
}

void icmp_recv(struct frame *frame) {
    struct icmp_hdr *hdr = icmp_hdr(frame);
    frame->data += sizeof(struct icmp_hdr);

    if (in_csum(frame->head, frame_pkt_len(frame), 0) != 0) {
        LOG(LWARN, "checksum is invalid!");
        return;
    }

    // Push ICMP into protocol stack
    frame_layer_push(frame, PROTO_ICMP);

    frame->head = frame->data;
    switch (hdr->type) {
        case ICMP_T_ECHORPLY: {
            break;
        }
        case ICMP_T_ECHOREQ: {
            frame->data += sizeof(struct icmp_echo);
            frame_layer_push(frame, PROTO_ICMP_ECHO);
            send_icmp_reply(frame);
            break;
        }
        case ICMP_T_DESTUNR:
        default:
            break;
    }
}

/*
 *  The echo reply is an ICMP message generated in response to an echo request;
 *  it is mandatory for all hosts, and must include the exact payload received
 *  in the request.
 *  Source: https://en.wikipedia.org/wiki/Ping_(networking_utility)#Echo_reply
 */
int send_icmp_reply(struct frame *ctrl) {
    // Go up 2 layers as the outer of this is the ICMP header
    struct frame_layer *outer = frame_layer_outer(ctrl, 2);
    if (outer == NULL) {
        LOG(LERR, "echo layer has no parent!");
        return -1;
    }
    // TODO: Don't assume IPv4 parent
    struct ipv4_hdr *ip = (struct ipv4_hdr *) outer->hdr;
    switch(outer->proto) {
        case PROTO_IPV4:
        case PROTO_IPV6:
            // TODO: Find ICMP route
            break;
        default:
            LOG(LWARN, "echo parent isn't a recognised protocol (%x)",
                 outer->proto);
    }
    struct icmp_echo *ping = icmp_echo_hdr(ctrl);

    // Allocate and lock new frame
    size_t size = intf_max_frame_size(ctrl->intf);
    struct frame *reply = intf_frame_new(ctrl->intf, size);

    // Mark and copy payload from request packet
    uint16_t datalen = frame_data_len(ctrl);
    uint8_t *payld = (reply->data -= datalen);
    memcpy(payld, ctrl->data, datalen);
    // TODO: Fix frame->data pointer head/tail difference
    reply->head = reply->data;

    struct icmp_echo *echo = frame_head_alloc(reply, sizeof(struct icmp_echo));
    struct icmp_hdr *hdr = frame_head_alloc(reply, sizeof(struct icmp_hdr));
    echo->id = ping->id;
    echo->seq = ping->seq;
    hdr->type = ICMP_T_ECHORPLY;
    hdr->code = 0;
    hdr->csum = 0;
    hdr->csum = in_csum(hdr, frame_pkt_len(reply), 0);

    frame_unlock(reply);

    // Swap source/dest IP addresses
    addr_t saddr = { .proto = PROTO_IPV4, .ipv4 = ntohl(ip->saddr) };
    addr_t daddr = { .proto = PROTO_IPV4, .ipv4 = ntohl(ip->daddr) };
    int ret = neigh_send(reply, IP_P_ICMP, IP_DF, O_NONBLOCK, &saddr, &daddr);

    frame_decref(reply);

    return ret;
}
