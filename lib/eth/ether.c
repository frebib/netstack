#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <netstack/ip/ipv4.h>
#include <netstack/eth/arp.h>


void ether_recv(struct frame *frame) {

    struct eth_hdr *hdr = (struct eth_hdr *) frame->head;
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
    switch (ntohs(hdr->ethertype)) {
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
        default: {
            const char *ethertype = fmt_ethertype(hdr->ethertype);
            if (ethertype != NULL)
                printf("unrecognised %s", ethertype);
            else
                printf("unrecognised %04x", ntohs(hdr->ethertype));
        }
            return;
    }
}

int ether_send(struct frame *child, uint16_t ethertype, eth_addr_t mac) {

    struct frame *frame = frame_parent_copy(child);
    struct intf *intf = frame->intf;
    struct eth_hdr *hdr = frame_alloc(frame, sizeof(struct eth_hdr));
    memcpy(hdr->saddr, intf->ll_addr, ETH_ADDR_LEN);
    memcpy(hdr->daddr, mac, ETH_ADDR_LEN);
    hdr->ethertype = htons(ethertype);

    return intf_dispatch(frame);
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

