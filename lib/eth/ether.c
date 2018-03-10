#include <stdio.h>
#include <string.h>

#define NETSTACK_LOG_UNIT "ETH"
#include <netinet/in.h>
#include <netstack/inet/ipv4.h>
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
    // TODO: Check and compare intf->vlan to hdr->vlan and reject if no match
    else if (!ether_should_accept(hdr, intf))
        return false;
    else
        LOGT(trans, "      ");

    // Print ether addresses
    LOGT(trans, "%s > ", fmtmac(hdr->saddr));
    LOGT(trans, "%s ", fmtmac(hdr->daddr));

    if (memcmp(hdr->daddr, &ETH_BRD_ADDR, ETH_ADDR_LEN) == 0)
        LOGT(trans, "Broadcast ");

    uint16_t ethertype = ntohs(hdr->ethertype);
    if (ethertype == ETH_P_VLAN) {
        struct eth_hdr_vlan *vhdr = (void *) hdr;
        ethertype = ntohs(vhdr->ethertype);
        LOGT(trans, "VLAN %d, ", ntohs(vhdr->vlan));
    }

    frame->data = frame->head + ether_hdr_len(frame);
    frame->head = frame->data;
    switch (ethertype) {
        case ETH_P_ARP:
            LOGT(trans, "ARP ");
            return arp_log(log, frame);
        case ETH_P_IP:
            LOGT(trans, "IPv4 ");
            return ipv4_log(log, frame);
        case ETH_P_IPV6:
            LOGT(trans, "IPv6 unimpl ");
            return false;
        default: {
            const char *strethertype = fmt_ethertype(ethertype);
            if (strethertype != NULL)
                LOGT(trans, "unrecognised %s", strethertype);
            else
                LOGT(trans, "unrecognised 0x%04x", ethertype);
        }
    }
    return true;
}

void ether_recv(struct frame *frame) {

    struct eth_hdr *hdr = (struct eth_hdr *) frame->head;
    struct intf *intf = frame->intf;

    // Frame data is after fixed header size
    frame->data += ether_hdr_len(frame);

    // Handle 802.1Q VLANs
    proto_t proto = PROTO_ETHER;
    uint16_t ethertype = ntohs(hdr->ethertype);
    if (ethertype == ETH_P_VLAN) {
        ethertype = ntohs(((struct eth_hdr_vlan *) hdr)->ethertype);
        proto = PROTO_ETHER_VL;
    }

    // Drop packets that we're not accepting
    if (!ether_should_accept(hdr, intf)) {
        return;
    }

    // Push ethernet into protocol stack
    frame_layer_push(frame, proto);

    frame->head = frame->data;
    switch (ethertype) {
        case ETH_P_ARP:
            arp_recv(frame);
            return;
        case ETH_P_IP:
            ipv4_recv(frame);
            return;
        default:
            return;
    }
}

int ether_send(struct frame *frame, uint16_t ethertype, eth_addr_t mac) {

    frame_lock(frame, SHARED_RW);
    struct intf *intf = frame->intf;
    struct eth_hdr *hdr = frame_head_alloc(frame, sizeof(struct eth_hdr));
    memcpy(hdr->saddr, intf->ll_addr, ETH_ADDR_LEN);
    memcpy(hdr->daddr, mac, ETH_ADDR_LEN);
    hdr->ethertype = htons(ethertype);
    frame_unlock(frame);

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

