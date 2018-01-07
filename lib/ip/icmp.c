#include <stdio.h>
#include <netinet/in.h>

#include <netstack/checksum.h>
#include <netstack/ip/icmp.h>
#include <netstack/ip/ipv4.h>


bool icmp_log(struct pkt_log *log, struct frame *frame) {
    struct log_trans *trans = &log->t;
    struct icmp_hdr *hdr = icmp_hdr(frame);
    frame->data += sizeof(struct icmp_hdr);
    
    // Print and check checksum
    uint16_t pkt_csum = hdr->csum;
    uint16_t calc_csum = in_csum(frame->head, frame_pkt_len(frame), 0) + hdr->csum;
    LOGT(trans, "csum 0x%04x", ntohs(pkt_csum));
    if (pkt_csum != calc_csum)
        LOGT(trans, " (invalid 0x%04x)", ntohs(calc_csum));
    LOGT(trans, ", ");

    struct frame *ctrl = frame_child_copy(frame);
    switch (hdr->type) {
        case ICMP_T_ECHORPLY: {
            struct icmp_echo *echo = (struct icmp_echo *) ctrl->head;
            LOGT(trans, "echoreply id %d, seq %d ", ntohs(echo->id),
                   ntohs(echo->seq));
            break;
        }
        case ICMP_T_ECHOREQ: {
            struct icmp_echo *echo = (struct icmp_echo *) ctrl->head;
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
        LOG(LWARN, "ICMP checksum is invalid!");
        return;
    }

    struct frame *ctrl = frame_child_copy(frame);
    switch (hdr->type) {
        case ICMP_T_ECHORPLY: {
            struct icmp_echo *echo = (struct icmp_echo *) ctrl->head;
            ctrl->data += sizeof(struct icmp_echo);
            break;
        }
        case ICMP_T_ECHOREQ: {
            struct icmp_echo *echo = (struct icmp_echo *) ctrl->head;
            ctrl->data += sizeof(struct icmp_echo);
            send_icmp_reply(ctrl);
            break;
        }
        case ICMP_T_DESTUNR:
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
    // TODO: Don't assume IPv4 parent
    struct ipv4_hdr *ip = ipv4_hdr(ctrl->parent->parent);
    struct icmp_echo *ping = icmp_echo_hdr(ctrl);

    size_t size = intf_max_frame_size(ctrl->intf);
    struct frame *reply = intf_frame_new(ctrl->intf, size);
    // TODO: Fix frame->data pointer head/tail difference
    reply->data = reply->tail;

    // Mark and copy payload from request packet
    uint8_t *payld = frame_alloc(reply, frame_data_len(ctrl));
    memcpy(payld, ctrl->data, frame_data_len(ctrl));

    struct icmp_echo *echo = frame_alloc(reply, sizeof(struct icmp_echo));
    struct icmp_hdr *hdr = frame_alloc(reply, sizeof(struct icmp_hdr));
    echo->id = ping->id;
    echo->seq = ping->seq;
    hdr->type = ICMP_T_ECHORPLY;
    hdr->code = 0;
    hdr->csum = 0;
    hdr->csum = in_csum(hdr, frame_data_len(reply), 0);

    // Swap source/dest IP addresses
    int ret = send_ipv4(reply, IP_P_ICMP, IP_DF,
                        ntohl(ip->saddr), ntohl(ip->daddr));
    // Reply frame is no longer our responsibility. Ensure it is cleaned up
    // in the case that it wasn't actually sent
    frame_deref(reply);
    return ret;
}
