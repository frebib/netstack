#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <memory.h>

#include <netinet/in.h>
#include <netstack/eth/arp.h>

struct arp_hdr *parse_arp(void *data) {
    struct arp_hdr *hdr = (struct arp_hdr *) data;

    hdr->hwtype = ntohs(hdr->hwtype);
    hdr->proto = ntohs(hdr->proto);
    hdr->op = ntohs(hdr->op);

    return hdr;
}

void arp_recv(struct frame *frame) {
    struct arp_hdr *msg = parse_arp(frame->data);
    frame->data += ARP_HDR_LEN;

    switch (msg->hwtype) {
        case ARP_HW_ETHER:
            // this is good
            break;
        default:
            fprintf(stderr, "ARP hardware %d not supported\n", msg->hwtype);
    }

    // https://tools.ietf.org/html/rfc826

    struct arp_ipv4 *req;
    switch (msg->proto) {
        case ETH_P_IP:
            // also good
            req = (struct arp_ipv4 *) frame->data;
            req->sipv4 = ntohl(req->sipv4);
            req->dipv4 = ntohl(req->dipv4);
            char ssaddr[16], sdaddr[16], ssethaddr[18];
            fmt_ipv4(req->sipv4, ssaddr);
            fmt_ipv4(req->dipv4, sdaddr);
            fmt_mac(req->saddr, ssethaddr);

            addr_t ether = {.proto = PROTO_ETHER, .ether = eth_arr(req->saddr)};
            addr_t ipv4 = {.proto = PROTO_IPV4, .ipv4 = req->sipv4};

            bool updated = arp_update_entry(frame->intf, &ether, &ipv4);

            // Only cache ARP entry if it was sent to us
            if (!updated && intf_has_addr(frame->intf, &ipv4))
                arp_cache_entry(frame->intf, &ether, &ipv4);

            arp_print_tbl(frame->intf, stderr);

            // TODO: Check for queued outgoing packets that can
            //       now be sent with the ARP information recv'd

            switch (msg->op) {
                case ARP_OP_REQUEST:
                    printf(" Who has %s? Tell %s", sdaddr, ssaddr);
                    // If asking for us, send a reply with our LL address
                    addr_t ip = {.proto = PROTO_IPV4, .ipv4 = req->dipv4};
                    if (intf_has_addr(frame->intf, &ip))
                        arp_send_reply(frame->intf, ARP_HW_ETHER, req->dipv4,
                                       req->sipv4, req->saddr);
                    break;
                case ARP_OP_REPLY:
                    printf(" Reply %s is at %s", ssaddr, ssethaddr);
                    break;
            }
            break;
        default:
            fprintf(stderr, "ARP protocol %s not supported\n",
                    fmt_ethertype(msg->proto));
    };
}

void arp_print_tbl(struct intf *intf, FILE *file) {
    fprintf(file, "Intf\tProtocol\tHW Address\t\tState\n");
    for_each_llist(&intf->arptbl) {
        struct arp_entry *entry = llist_elem_data();
        fprintf(file, "%s\t", intf->name);
        fprintf(file, "%s\t", straddr(&entry->protoaddr));
        fprintf(file, "%s\t", entry->state & ARP_PENDING ?
                              "(pending)\t" : straddr(&entry->hwaddr));
        fprintf(file, "%s\n", fmt_arp_state(entry->state));
        fflush(file);
    }
}

/* Retrieves IPv4 address from table, otherwise NULL */
addr_t *arp_get_hwaddr(struct intf *intf, uint16_t hwtype, addr_t *protoaddr) {

    // TODO: Implement ARP cache locking
    for_each_llist(&intf->arptbl) {
        struct arp_entry *entry = llist_elem_data();

        if (entry == NULL) {
            fprintf(stderr, "Error: arp_entry_ipv4 is null?\t");
            return NULL;
        }
        // Check matching protocols
        if (addreq(&entry->protoaddr, protoaddr)) {
            if (entry->state != ARP_RESOLVED)
                continue;
            if (entry->hwaddr.proto == hwtype)
                return &entry->hwaddr;
        }
    }

    return NULL;
}

bool arp_update_entry(struct intf *intf, addr_t *hwaddr, addr_t *protoaddr) {

    // TODO: Use hashtable for ARP lookups on IPv4

    for_each_llist(&intf->arptbl) {
        struct arp_entry *entry = llist_elem_data();

        // If existing IP match, update it
        // TODO: This doesn't account for protocol addresses that change hw
        if (addreq(&entry->protoaddr, protoaddr)) {
            // Only update hwaddr if it has actually changed
            if (!addreq(&entry->hwaddr, hwaddr)) {
                fprintf(stderr, "INFO: ARP cache entry for %s changed\n",
                        straddr(protoaddr));

                // Update hwaddr for IP
                memcpy(&entry->hwaddr, hwaddr, sizeof(addr_t));
            }
            // Remove PENDING and add RESOLVED
            entry->state &= ~ARP_PENDING;
            entry->state |= ARP_RESOLVED;

            // An entry was updated
            return true;
        }
    }
    // Nothing was updated
    return false;
}

bool arp_cache_entry(struct intf *intf, addr_t *hwaddr, addr_t *protoaddr) {

    fprintf(stderr, "DEBUG: Storing new ARP entry for %s\n", straddr(protoaddr));

    struct arp_entry *entry = malloc(sizeof(struct arp_entry));
    entry->state = ARP_RESOLVED;
    memcpy(&entry->hwaddr, hwaddr, sizeof(addr_t));
    memcpy(&entry->protoaddr, protoaddr, sizeof(addr_t));

    llist_append(&intf->arptbl, entry);

    return true;
}

int arp_send_req(struct intf *intf, uint16_t hwtype,
                 uint32_t saddr, uint32_t daddr) {

    struct frame *frame = intf_frame_new(intf, intf_max_frame_size(intf));
    struct arp_ipv4 *req = frame_alloc(frame, sizeof(struct arp_ipv4));
    struct arp_hdr *hdr = frame_alloc(frame, sizeof(struct arp_hdr));

    // TODO: Use hwtype to determine length and type of address
    memcpy(&req->saddr, intf->ll_addr, ETH_ADDR_LEN);
    memcpy(&req->daddr, ETH_BRD_ADDR, ETH_ADDR_LEN);
    req->sipv4 = htonl(saddr);
    req->dipv4 = htonl(daddr);
    hdr->hwtype = htons(hwtype);
    hdr->proto = htons(ETH_P_IP);
    hdr->hlen = ETH_ADDR_LEN;
    hdr->plen = (uint8_t) addrlen(PROTO_IPV4);
    hdr->op = htons(ARP_OP_REQUEST);

    int ret = ether_send(frame, ETH_P_ARP, ETH_BRD_ADDR);

    // Sending ARP request was successful, add incomplete cache entry
    if (!ret) {
        struct arp_entry *entry = malloc(sizeof(struct arp_entry));
        entry->state = ARP_PENDING;
        *entry = (struct arp_entry){
            .state = ARP_PENDING,
            .hwaddr = {.proto = PROTO_ETHER, .ether = eth_arr(ETH_NUL_ADDR)},
            .protoaddr = {.proto = PROTO_IPV4, .ipv4 = daddr}
        };
        llist_append(&intf->arptbl, entry);

        arp_print_tbl(intf, stderr);
    }

    return ret;
}

int arp_send_reply(struct intf *intf, uint8_t hwtype, uint32_t sip,
                   uint32_t dip, uint8_t *daddr) {
    // TODO: Add 'incomplete' entry to arp cache

    struct frame *frame = intf_frame_new(intf, intf_max_frame_size(intf));
    struct arp_ipv4 *req = frame_alloc(frame, sizeof(struct arp_ipv4));
    struct arp_hdr *hdr = frame_alloc(frame, sizeof(struct arp_hdr));

    // TODO: Use hwtype to determine length and type of address
    memcpy(&req->saddr, intf->ll_addr, ETH_ADDR_LEN);
    memcpy(&req->daddr, daddr, ETH_ADDR_LEN);
    req->sipv4 = htonl(sip);
    req->dipv4 = htonl(dip);
    hdr->hwtype = htons(hwtype);
    hdr->proto = htons(ETH_P_IP);
    hdr->hlen = ETH_ADDR_LEN;
    hdr->plen = (uint8_t) addrlen(PROTO_IPV4);
    hdr->op = htons(ARP_OP_REPLY);

    return ether_send(frame, ETH_P_ARP, ETH_BRD_ADDR);
}
