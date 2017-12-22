#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <memory.h>

#include <netinet/in.h>
#include <netstack/eth/arp.h>
#include <netstack/ip/ipv4.h>

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

            // TODO: Don't cache ARP that we sent..

            bool added = arp_cache_ipv4(frame->intf, msg, req);

            if (added) {
                // Print ARP table
                fprintf(stderr, "IPv4\t\tHW Address\t\tHW type\tState\n");
                for_each_llist(&frame->intf->arptbl) {
                    struct arp_entry_ipv4 *entry = llist_elem_data();
                    fprintf(stderr, "%s\t%s\t%d\t%s\n",
                            fmtip4(entry->ip),
                            fmtmac(&entry->hwaddr),
                            entry->hwtype,
                            fmt_arp_state(entry->state));
                }
            }

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
    }
}

/* Retrieves IPv4 address from table, otherwise NULL */
uint8_t *arp_ipv4_get_hwaddr(struct intf *intf, uint8_t hwtype, uint32_t ipv4) {

    // TODO: Implement ARP cache locking
    for_each_llist(&intf->arptbl) {
        struct arp_entry_ipv4 *entry = llist_elem_data();

        if (entry == NULL) {
            fprintf(stderr, "Error: arp_entry_ipv4 is null?\t");
            return NULL;
        }
        if (entry->ip == ipv4) {
            if (entry->state != ARP_RESOLVED)
                continue;
            if (entry->hwtype == hwtype)
                return &entry->hwaddr;
        }
    }

    return NULL;
}

/* Insert IPv4 entry into the ARP table
   Returns true if new entry inserted, false if an old updated */
bool arp_cache_ipv4(struct intf *intf, struct arp_hdr *hdr,
                    struct arp_ipv4 *req) {

    char sip[16];
    fmt_ipv4(req->sipv4, sip);

    // TODO: Use hashtable for ARP lookups on IPv4

    for_each_llist(&intf->arptbl) {
        struct arp_entry_ipv4 *entry = llist_elem_data();

        // If existing IP match, update it
        if (entry->ip == req->sipv4) {
            // Only update hwaddr if it has actually changed
            if (memcmp(&entry->hwaddr, req->saddr, hdr->hlen) != 0) {
                fprintf(stderr, "INFO: ARP cache entry for %s changed\n", sip);

                // Update hwaddr for IP
                memcpy(&entry->hwaddr, req->saddr, hdr->hlen);
            }
            entry->state |= ARP_RESOLVED;

            // Don't insert a new entry if an old one was updated
            return false;
        }
    }

    // Don't cache ARP entry if it wasn't for us
    addr_t ip = {.proto = PROTO_IPV4, .ipv4 = req->dipv4};
    if (!intf_has_addr(intf, &ip))
        return false;

    fprintf(stderr, "DEBUG: Storing new ARP entry for %s\n", sip);

    struct arp_entry_ipv4 *entry = malloc(arp_entry_ipv4_len(hdr->hlen));
    entry->hwtype = hdr->hwtype;
    entry->state = ARP_RESOLVED;
    entry->ip = req->sipv4;
    entry->hwlen = hdr->hlen;
    memcpy(&entry->hwaddr, req->saddr, hdr->hlen);

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

    return ether_send(frame, ETH_P_ARP, ETH_BRD_ADDR);
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
