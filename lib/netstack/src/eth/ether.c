#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <netstack/ip/ipv4.h>
#include <netstack/eth/arp.h>

struct eth_hdr *ether_ntoh(void *data) {
    struct eth_hdr *hdr = (struct eth_hdr *) data;
    hdr->ethertype = ntohs(hdr->ethertype);
    return hdr;
}

void ether_recv(struct frame *frame) {

    struct eth_hdr *hdr = ether_ntoh(frame->head);
    struct intf *intf = frame->intf;

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

    if (!ether_should_accept(hdr, intf)) {
        return;
    }

    struct frame *child_frame = frame_child_copy(frame);
    switch (hdr->ethertype) {
        case ETH_P_ARP:
            printf("ARP");
            arp_recv(child_frame);
            return;
        case ETH_P_IP:
            printf("IPv4");
            ipv4_recv(child_frame);
            return;
        case ETH_P_IPV6:
            printf("IPv6 unimpl");
            return;
        default:
            printf("unrecognised %s", fmt_ethertype(hdr->ethertype));
            return;
    }
}


bool ether_should_accept(struct eth_hdr *hdr, struct intf *intf) {
    /* Check for broadcast packets */
    if (memcmp(hdr->daddr, &ETH_BRD_ADDR, ETH_ADDR_LEN) == 0) {
        printf("Broadcast ");
        return true;
    }

    /* Ensure packet received has a matching address to our interface */
    if (memcmp(hdr->daddr, intf->ll_addr, ETH_ADDR_LEN) == 0) {
        return true;
    }

    return false;
}

