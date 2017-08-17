#include <netinet/in.h>
#include <libnet/frame.h>
#include <libnet/eth/arp.h>
#include <stdio.h>

struct arp_hdr *recv_arp(struct frame *frame) {
    struct arp_hdr *msg = (struct arp_hdr *) frame->head;
    frame->data += ARP_HDR_LEN;

    msg->hw_type = ntohs(msg->hw_type);
    msg->prot_type = ntohs(msg->prot_type);
    msg->op = ntohs(msg->op);

    switch (msg->hw_type) {
        case ARP_HW_ETHER:
            // this is good
            break;
        default:
            fprintf(stderr, "ARP hardware %d not supported\n", msg->hw_type);
            return NULL;
    }

    struct arp_ipv4 *req;
    switch (msg->prot_type) {
        case ETH_P_IP:
            req = (struct arp_ipv4 *) frame->data;
            req->sipv4 = ntohl(req->sipv4);
            req->dipv4 = ntohl(req->dipv4);
            // also good
            break;
        default:
            fprintf(stderr, "ARP protocol %s not supported\n",
                    fmt_ethertype(msg->prot_type));
            return NULL;
    }

    return msg;
}
