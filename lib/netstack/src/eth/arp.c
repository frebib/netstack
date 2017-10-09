#include <stdio.h>

#include <netinet/in.h>
#include <netstack/eth/arp.h>

struct arp_hdr *parse_arp(void *data) {
    struct arp_hdr *hdr = (struct arp_hdr *) data;

    hdr->hw_type = ntohs(hdr->hw_type);
    hdr->prot_type = ntohs(hdr->prot_type);
    hdr->op = ntohs(hdr->op);

    return hdr;
}

void recv_arp(struct intf *intf, struct frame *frame) {
    struct arp_hdr *msg = parse_arp(frame->data);
    frame->data += ARP_HDR_LEN;

    switch (msg->hw_type) {
        case ARP_HW_ETHER:
            // this is good
            break;
        default:
            fprintf(stderr, "ARP hardware %d not supported\n", msg->hw_type);
    }

    // TODO: If we sent a request, cache the reply

    struct arp_ipv4 *req;
    switch (msg->prot_type) {
        case ETH_P_IP:
            // also good
            req = (struct arp_ipv4 *) frame->data;
            req->sipv4 = ntohl(req->sipv4);
            req->dipv4 = ntohl(req->dipv4);
            break;
        default:
            fprintf(stderr, "ARP protocol %s not supported\n",
                    fmt_ethertype(msg->prot_type));
    }
}
