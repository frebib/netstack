#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <netstack/ip/ipv4.h>
#include <netstack/eth/arp.h>

struct eth_hdr *parse_ether(void *data) {
    struct eth_hdr *hdr = (struct eth_hdr *) data;
    hdr->ethertype = ntohs(hdr->ethertype);
    return hdr;
}

void recv_ether(struct intf *intf, struct frame *frame) {

    struct eth_hdr *hdr = parse_ether(frame->buffer);
    /* Frame data is after fixed header size */
    frame->data += ETH_HDR_LEN;

    /* Check for our sent packets */
    if (memcmp(hdr->saddr, intf->ll_addr, ETH_ADDR_LEN) == 0)
        printf("(out)");
    else if (memcmp(hdr->daddr, intf->ll_addr, ETH_ADDR_LEN) == 0)
        printf("(in) ");
    else
        printf("     ");

    // Print ether addresses
    char ssaddr[18], sdaddr[18];
    fmt_mac(hdr->saddr, ssaddr);
    fmt_mac(hdr->daddr, sdaddr);
    printf(" %s > %s ", ssaddr, sdaddr);

    /* Check for broadcast packets */
    if (memcmp(hdr->daddr, &ETH_BRD_ADDR, ETH_ADDR_LEN) == 0) {
        printf("Broadcast ");
    }

    /* Ensure packet received has a matching address to our interface */
    if (memcmp(hdr->daddr, intf->ll_addr, ETH_ADDR_LEN) != 0) {
        // printf("Packet not destined for us");
    }

    struct frame *child_frame = frame_child_copy(frame);
    switch (hdr->ethertype) {
        case ETH_P_ARP:
            printf("ARP");
            recv_arp(intf, child_frame);
            return;
        case ETH_P_IP:
            printf("IPv4");
            recv_ipv4(intf, child_frame);
            return;
        case ETH_P_IPV6:
            printf("IPv6 unimpl");
            return;
        default:
            printf("unrecognised %s", fmt_ethertype(hdr->ethertype));
            return;
    }
}


