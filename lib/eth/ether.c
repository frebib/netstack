#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <libnet/ip/ipv4.h>
#include <libnet/eth/arp.h>

struct eth_hdr *parse_ether(void *data) {
    struct eth_hdr *hdr = (struct eth_hdr *) data;
    hdr->ethertype = ntohs(hdr->ethertype);
    return hdr;
}

void recv_ether(struct interface *intf, struct frame *frame) {

    struct eth_hdr *hdr = parse_ether(frame->buffer);
    /* Frame data is after fixed header size */
    frame->data += ETH_HDR_LEN;

    // TODO: Move ethernet address into interface struct

    /* Ensure packet received has a matching address to our interface */
    if (memcmp(hdr->daddr, ETH_ADDR, ETH_ADDR_LEN) != 0) {
        return;
    }

    struct frame *child_frame = frame_child_copy(frame);
    switch (hdr->ethertype) {
        case ETH_P_ARP:
            return recv_arp(intf, child_frame);
        case ETH_P_IP:
            return recv_ipv4(intf, child_frame);
        case ETH_P_IPV6:
            fprintf(stderr, "ETH: Unimplemented frame type %s\n",
                    fmt_ipproto(hdr->ethertype));
        default:
            fprintf(stderr, "ETH: Unrecognised frame type: %s\n",
                    fmt_ethertype(hdr->ethertype));
    }
}


