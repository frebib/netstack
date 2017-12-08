#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <memory.h>

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

            // TODO: Don't cache ARP that we sent..

            bool inserted = arp_cache_ipv4(intf, req->sipv4, ARP_HW_ETHER,
                                           ETH_ADDR_LEN, eth->saddr);

            if (inserted) {
                // Print ARP table
                fprintf(stderr, "IPv4\t\tHW Address\t\tHW type\tState\n");
                for_each_llist(intf->arptbl) {
                    struct arp_entry_ipv4 *entry = (elem->data);
                    char sip[16], shw[18];
                    fmt_ipv4(entry->ip, sip);
                    fmt_mac(&entry->hwaddr, shw);
                    fprintf(stderr, "%s\t%s\t%d\t%s\n", sip, shw, entry->hwtype,
                            fmt_arp_state(entry->state));
                }
            }

            // TODO: Check for queued outgoing packets that can
            //       now be sent with the ARP information recv'd

            switch (msg->op) {
                case ARP_OP_REQUEST:
                    printf(" Who has %s? Tell %s", sdaddr, ssaddr);
                    // If asking for us, send a reply with our LL address
                    // TODO: ARP Reply with our eth addr to requests
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

/* Retrieves IPv4 address from table, otherwise NULL */
uint8_t *arp_ipv4_get_hwaddr(struct intf *intf, uint8_t hwtype, uint32_t ipv4) {

    // TODO: Implement ARP cache locking
    for_each_llist(intf->arptbl) {
        struct arp_entry_ipv4 *entry = (elem->data);

        if (entry->ip == ipv4) {
            if (entry->state != ARP_RESOLVED)
                continue;

            char sip[16];
            fmt_ipv4(ipv4, sip);
            fprintf(stderr, "ARP cache hit for %s", sip);

            if (entry->hwtype == hwtype) {
                fprintf(stderr, ", hwtype match %d\n", hwtype);
                return &entry->hwaddr;
            } else
                fprintf(stderr, ", incorrect hwtype %d != %d\n",
                        hwtype, entry->hwtype);
        }
    }

    return NULL;
}

/* Insert IPv4 entry into the ARP table
   Returns true if new entry inserted, false if an old updated */
bool arp_cache_ipv4(struct intf *intf, uint32_t ipv4, uint8_t hwtype,
                    uint8_t hwlen, uint8_t *hwaddr) {

    char sip[16];
    fmt_ipv4(ipv4, sip);

    // TODO: Use hashtable for ARP lookups on both IPv4 & HW addresses

    for_each_llist(intf->arptbl) {
        struct arp_entry_ipv4 *entry = (elem->data);

        // If existing IP match, update it
        if (entry->ip == ipv4) {
            // Only update hwaddr if it has actually changed
            if (memcmp(&entry->hwaddr, hwaddr, hwlen) != 0) {
                fprintf(stderr, "INFO: ARP cache entry for %s changed\n", sip);

                // Update hwaddr for IP
                memcpy(&entry->hwaddr, hwaddr, hwlen);
            }
            entry->state = ARP_RESOLVED;

            // Don't insert a new entry if an old one was updated
            return false;
        }
    }

    fprintf(stderr, "DEBUG: Storing new ARP entry for %s\n", sip);

    struct arp_entry_ipv4 *entry = malloc(arp_entry_ipv4_len(hwlen));
    entry->hwtype = hwtype;
    entry->state = ARP_RESOLVED;
    entry->ip = ipv4;
    entry->hwlen = hwlen;
    memcpy(&entry->hwaddr, hwaddr, hwlen);

    intf->arptbl = llist_prepend(intf->arptbl, entry);

    return true;
}
