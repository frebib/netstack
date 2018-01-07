#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <netstack/ip/ipv4.h>
#include <netstack/eth/arp.h>


bool ether_log(struct pkt_log *log, struct frame *frame) {
    struct eth_hdr *hdr = (struct eth_hdr *) frame->head;
    struct intf *intf = frame->intf;
    struct log_trans *trans = &log->t;

    /* Check for our sent packets */
    if (memcmp(hdr->saddr, intf->ll_addr, ETH_ADDR_LEN) == 0)
        LOGT(trans, "(out) ");
    else if (memcmp(hdr->daddr, intf->ll_addr, ETH_ADDR_LEN) == 0)
        LOGT(trans, "(in)  ");
    else if (!ether_should_accept(hdr, intf))
        return false;
    else
        LOGT(trans, "      ");

    // Print ether addresses
    LOGT(trans, "%s > ", fmtmac(hdr->saddr));
    LOGT(trans, "%s ", fmtmac(hdr->daddr));

    if (memcmp(hdr->daddr, &ETH_BRD_ADDR, ETH_ADDR_LEN) == 0)
        LOGT(trans, "Broadcast ");

    frame->data += ETH_HDR_LEN;
    struct frame *child_frame = frame_child_copy(frame);
    switch (ntohs(hdr->ethertype)) {
        case ETH_P_ARP:
            LOGT(trans, "ARP ");
            return arp_log(log, child_frame);
        case ETH_P_IP:
            LOGT(trans, "IPv4 ");
            return ipv4_log(log, child_frame);
        case ETH_P_IPV6:
            LOGT(trans, "IPv6 unimpl ");
            return false;
        default: {
            const char *ethertype = fmt_ethertype(hdr->ethertype);
            if (ethertype != NULL)
                LOGT(trans, "unrecognised %s", ethertype);
            else
                LOGT(trans, "unrecognised %04x", ntohs(hdr->ethertype));
        }
    }
    return true;
}

void ether_recv(struct frame *frame) {

    struct eth_hdr *hdr = (struct eth_hdr *) frame->head;
    struct intf *intf = frame->intf;

    /* Frame data is after fixed header size */
    frame->data += ETH_HDR_LEN;

    if (!ether_should_accept(hdr, intf)) {
        return;
    }

    struct frame *child_frame = frame_child_copy(frame);
    switch (ntohs(hdr->ethertype)) {
        case ETH_P_ARP:
            arp_recv(child_frame);
            return;
        case ETH_P_IP:
            ipv4_recv(child_frame);
            return;
        default:
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
        return true;
    }

    /* Ensure packet received has a matching address to our interface */
    if (memcmp(hdr->daddr, intf->ll_addr, ETH_ADDR_LEN) == 0) {
        return true;
    }

    return false;
}

