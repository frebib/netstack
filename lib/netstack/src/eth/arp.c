#include <stdio.h>

#include <netinet/in.h>
#include <netstack/eth/arp.h>
#include <netstack/ip/ipv4.h>

struct arp_hdr *parse_arp(void *data) {
    struct arp_hdr *hdr = (struct arp_hdr *) data;

    hdr->hw_type = ntohs(hdr->hw_type);
    hdr->prot_type = ntohs(hdr->prot_type);
    hdr->op = ntohs(hdr->op);

    return hdr;
}

void recv_arp(struct intf *intf, struct frame *frame) {
    struct arp_hdr *msg = parse_arp(frame->data);
    struct eth_hdr *eth = eth_hdr(frame->parent);
    frame->data += ARP_HDR_LEN;

    switch (msg->hw_type) {
        case ARP_HW_ETHER:
            // this is good
            break;
        default:
            fprintf(stderr, "ARP hardware %d not supported\n", msg->hw_type);
    }

    // TODO: If we sent a request, cache the reply
    // https://tools.ietf.org/html/rfc826

    struct arp_ipv4 *req;
    switch (msg->prot_type) {
        case ETH_P_IP:
            // also good
            req = (struct arp_ipv4 *) frame->data;
            req->sipv4 = ntohl(req->sipv4);
            req->dipv4 = ntohl(req->dipv4);
            char ssaddr[16], sdaddr[16], ssethaddr[18];
            fmt_ipv4(req->sipv4, ssaddr);
            fmt_ipv4(req->dipv4, sdaddr);
            fmt_mac(eth->saddr, ssethaddr);

            switch (msg->op) {
                case ARP_OP_REQUEST:
                    printf(" Who has %s? Tell %s", sdaddr, ssaddr);
                    break;
                case ARP_OP_REPLY:
                    printf(" Reply %s is at %s", ssaddr, ssethaddr);
                    break;
            }
            break;
        default:
            fprintf(stderr, "ARP protocol %s not supported\n",
                    fmt_ethertype(msg->prot_type));
    }
}
