#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <netstack/ip/ipv4.h>
#include <netstack/eth/arp.h>

struct ethhdr *parse_ether(void *data) {
    struct ethhdr *hdr = (struct ethhdr *) data;
    hdr->h_proto = ntohs(hdr->h_proto);
    return hdr;
}

void recv_ether(struct intf *intf, struct frame *frame) {

    struct ethhdr *hdr = parse_ether(frame->buffer);
    /* Frame data is after fixed header size */
    frame->data += ETH_HDR_LEN;

    /* Check for our sent packets */
    if (memcmp(hdr->h_source, intf->ll_addr, ETH_ALEN) == 0)
        printf("(out)");
    else if (memcmp(hdr->h_dest, intf->ll_addr, ETH_ALEN) == 0)
        printf("(in) ");
    else
        printf("     ");

    // Print ether addresses
    char ssaddr[18], sdaddr[18];
    fmt_mac(hdr->h_source, ssaddr);
    fmt_mac(hdr->h_dest, sdaddr);
    printf(" %s > %s ", ssaddr, sdaddr);

    /* Check for broadcast packets */
    if (memcmp(hdr->h_dest, &ETH_BRD_ADDR, ETH_ALEN) == 0) {
        printf("Broadcast ");
    }

    /* Ensure packet received has a matching address to our interface */
    if (memcmp(hdr->h_dest, intf->ll_addr, ETH_ALEN) != 0) {
        // printf("Packet not destined for us");
    }

    struct frame *child_frame = frame_child_copy(frame);
    switch (hdr->h_proto) {
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
            printf("unrecognised %s", fmt_ethertype(hdr->h_proto));
            return;
    }
}


