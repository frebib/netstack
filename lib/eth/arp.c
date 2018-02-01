#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <memory.h>

#include <netinet/in.h>

#include <netstack/eth/arp.h>
#include <netstack/ip/neigh.h>


bool arp_log(struct pkt_log *log, struct frame *frame) {
    struct arp_hdr *msg = (struct arp_hdr *) frame->head;
    frame->data += ARP_HDR_LEN;
    struct log_trans *trans = &log->t;

    LOGT(trans, "hw 0x%X ", ntohs(msg->hwtype));

    struct arp_ipv4 *req;
    switch (ntohs(msg->proto)) {
        case ETH_P_IP:
            req = (struct arp_ipv4 *) frame->data;
            switch (ntohs(msg->op)) {
                case ARP_OP_REQUEST:
                    LOGT(trans, "Who has %s? ", fmtip4(ntohl(req->dipv4)));
                    LOGT(trans, "Tell %s ", fmtip4(ntohl(req->sipv4)));
                    break;
                case ARP_OP_REPLY:
                    LOGT(trans, "Reply %s ", fmtip4(ntohl(req->sipv4)));
                    LOGT(trans, "is at %s ", fmtmac(req->saddr));
                    break;
                default:
                    LOGT(trans, "invalid op %d", ntohs(msg->op));
            }
            break;
        default:
            LOGT(trans, "unrecognised proto %d", ntohs(msg->proto));
            break;
    };

    return true;
}

void arp_recv(struct frame *frame) {
    struct arp_hdr *msg = (struct arp_hdr *) frame->head;
    frame->data += ARP_HDR_LEN;

    switch (ntohs(msg->hwtype)) {
        case ARP_HW_ETHER:
            // this is good
            break;
        default:
            LOG(LINFO, "ARP hardware %d not supported\n", ntohs(msg->hwtype));
    }

    // https://tools.ietf.org/html/rfc826

    struct arp_ipv4 *req;
    switch (ntohs(msg->proto)) {
        case ETH_P_IP:
            // also good
            req = (struct arp_ipv4 *) frame->data;

            addr_t ether = {.proto = PROTO_ETHER, .ether = eth_arr(req->saddr)};
            addr_t ipv4 = {.proto = PROTO_IPV4, .ipv4 = ntohl(req->sipv4)};

            // Try to update an existing ARP entry
            bool updated = arp_update_entry(frame->intf, &ether, &ipv4);

            // Only cache ARP entry if it was sent to us
            if (intf_has_addr(frame->intf, &ipv4)) {

                // If the entry wasn't an update, it must be new
                if (!updated)
                    arp_cache_entry(frame->intf, &ether, &ipv4);
            }

            // Print the newly-updated/inserted ARP table
            if (updated)
                arp_log_tbl(frame->intf, LINFO);

            switch (ntohs(msg->op)) {
                case ARP_OP_REQUEST: {
                    // If asking for us, send a reply with our LL address
                    addr_t ip = {.proto = PROTO_IPV4, .ipv4 = ntohl(req->dipv4)};
                    if (intf_has_addr(frame->intf, &ip))
                        arp_send_reply(frame->intf, ARP_HW_ETHER,
                                       ntohl(req->dipv4), ntohl(req->sipv4),
                                       req->saddr);
                    break;
                }
                case ARP_OP_REPLY:
                default:
                    break;
            }
            break;
        default:
            LOG(LINFO, "ARP protocol %s not supported",
                    fmt_ethertype(ntohs(msg->proto)));
    };
}

void arp_log_tbl(struct intf *intf, loglvl_t level) {
    struct log_trans trans = LOG_TRANS(level);
    LOGT(&trans, "Intf\tProtocol\tHW Address\t\tState\n");
    for_each_llist(&intf->arptbl) {
        struct arp_entry *entry = llist_elem_data();
        LOGT(&trans, "%s\t", intf->name);
        LOGT(&trans, "%s\t", straddr(&entry->protoaddr));
        LOGT(&trans, "%s\t", (entry->state & ARP_PENDING) ?
                              "(pending)\t" : straddr(&entry->hwaddr));
        LOGT(&trans, "%s\n", fmt_arp_state(entry->state));
    }
    LOGT_COMMIT(&trans);
}

/* Retrieves IPv4 address from table, otherwise NULL */
struct arp_entry *arp_get_entry(llist_t *arptbl, proto_t hwtype,
                                 addr_t *protoaddr) {

    // Lock the table
    pthread_mutex_lock(&arptbl->lock);

    for_each_llist(arptbl) {
        struct arp_entry *entry = llist_elem_data();

        if (entry == NULL) {
            LOG(LERR, "arp_entry_ipv4 is null?\t");
            continue;
        }

        pthread_mutex_lock(&entry->lock);
        // Check matching protocols
        if (addreq(&entry->protoaddr, protoaddr)
             && entry->hwaddr.proto == hwtype) {

            // Release the locks and return found entry
            pthread_mutex_unlock(&arptbl->lock);
            return entry;
        }
        pthread_mutex_unlock(&entry->lock);
    }

    pthread_mutex_unlock(&arptbl->lock);

    return NULL;
}

uint16_t arp_proto_hw(proto_t proto) {
    switch (proto) {
        case PROTO_ETHER:
            return ARP_HW_ETHER;
        default:
            return 0;
    }
}

bool arp_update_entry(struct intf *intf, addr_t *hwaddr, addr_t *protoaddr) {

    // TODO: Use hashtable for ARP lookups on IPv4

    // Lock the table
    pthread_mutex_lock(&intf->arptbl.lock);

    for_each_llist(&intf->arptbl) {
        struct arp_entry *entry = llist_elem_data();

        pthread_mutex_lock(&entry->lock);

        // If existing IP match, update it
        // TODO: ARP doesn't account for protocol addresses that change hw
        if (addreq(&entry->protoaddr, protoaddr)) {
            bool updated = false;

            // Only update hwaddr if it has actually changed
            if (!addreq(&entry->hwaddr, hwaddr)) {
                LOG(LINFO, "ARP cache entry %s changed", straddr(protoaddr));

                // Update hwaddr for IP
                memcpy(&entry->hwaddr, hwaddr, sizeof(addr_t));

                updated = true;
            }

            // Remove PENDING and add RESOLVED
            entry->state &= ~ARP_PENDING;
            entry->state |= ARP_RESOLVED;

            // Release all locks
            pthread_mutex_unlock(&entry->lock);
            pthread_mutex_unlock(&intf->arptbl.lock);

            // Send any queued packets waiting for a hwaddr
            neigh_update_hwaddr(intf, protoaddr, hwaddr);

            // An entry was updated
            return updated;
        }

        // Unlock entry lock
        pthread_mutex_unlock(&entry->lock);
    }

    // Unlock the ARP table
    pthread_mutex_unlock(&intf->arptbl.lock);

    // Nothing was updated
    return false;
}

bool arp_cache_entry(struct intf *intf, addr_t *hwaddr, addr_t *protoaddr) {

    LOG(LINFO, "Storing new ARP entry for %s\n", straddr(protoaddr));

    struct arp_entry *entry = malloc(sizeof(struct arp_entry));
    entry->state = ARP_RESOLVED;
    entry->lock = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
    memcpy(&entry->hwaddr, hwaddr, sizeof(addr_t));
    memcpy(&entry->protoaddr, protoaddr, sizeof(addr_t));

    llist_append(&intf->arptbl, entry);

    return true;
}

int arp_send_req(struct intf *intf, uint16_t hwtype,
                 addr_t *saddr, addr_t *daddr) {

    struct log_trans trans = LOG_TRANS(LVERB);
    LOGT(&trans, "arp_request(%s, %s", intf->name, straddr(saddr));
    LOGT(&trans, ", %s);", straddr(daddr));
    LOGT_COMMIT(&trans);

    struct frame *frame = intf_frame_new(intf, intf_max_frame_size(intf));
    struct arp_ipv4 *req = frame_data_alloc(frame, sizeof(struct arp_ipv4));
    struct arp_hdr *hdr = frame_data_alloc(frame, sizeof(struct arp_hdr));

    // TODO: Use hwtype to determine length and type of address
    // TODO: Change arp_send_req to handle other address types
    memcpy(&req->saddr, intf->ll_addr, ETH_ADDR_LEN);
    memcpy(&req->daddr, ETH_BRD_ADDR, ETH_ADDR_LEN);
    req->sipv4 = htonl(saddr->ipv4);
    req->dipv4 = htonl(daddr->ipv4);
    hdr->hwtype = htons(hwtype);
    hdr->proto = htons(ETH_P_IP);
    hdr->hlen = ETH_ADDR_LEN;
    hdr->plen = (uint8_t) addrlen(PROTO_IPV4);
    hdr->op = htons(ARP_OP_REQUEST);

    // Send the request frame
    int ret = ether_send(frame, ETH_P_ARP, ETH_BRD_ADDR);

    // Ensure frame is free'd if it was never actually sent
    frame_decref(frame);

    // Sending ARP request was successful, add incomplete cache entry
    struct arp_entry *entry = NULL;
    if (ret) {
        // Frame was never sent so ensure it is unlocked
        frame_unlock(frame);
        // There was an error, return error-code immediately
        return ret;
    } else {
        // Lock arptbl before sending to prevent race condition where reply
        // arrives before we wait on it, deadlocking waiting on the reply that
        // has already arrived.
        pthread_mutex_lock(&intf->arptbl.lock);

        // Check if partial entry already exists, so to not add multiple
        for_each_llist(&intf->arptbl) {
            entry = llist_elem_data();
            if (entry == NULL)
                continue;

            pthread_mutex_lock(&entry->lock);
            if (addreq(&entry->protoaddr, daddr))
                break;

            // Not the entry we want. Unlock it and put it back
            pthread_mutex_unlock(&entry->lock);
        }

        // Don't add another partial entry if one is there already
        if (entry == NULL) {
            entry = malloc(sizeof(struct arp_entry));
            *entry = (struct arp_entry) {
                .state = ARP_PENDING,
                .hwaddr = {.proto = PROTO_ETHER, .ether = eth_arr(ETH_NUL_ADDR)},
                .protoaddr = *daddr,
                .lock = PTHREAD_MUTEX_INITIALIZER
            };
            pthread_mutex_lock(&entry->lock);
            llist_append_nolock(&intf->arptbl, entry);

            arp_log_tbl(intf, LINFO);
        }
    }

    // At this point we have an arp_entry that is locked with entry->lock
    pthread_mutex_unlock(&intf->arptbl.lock);

    // Unlock the entry
    pthread_mutex_unlock(&entry->lock);

    return ret;
}

int arp_send_reply(struct intf *intf, uint16_t hwtype, ip4_addr_t sip,
                   ip4_addr_t dip, eth_addr_t daddr) {

    // TODO: Change arp_send_reply to handle other address types

    struct frame *frame = intf_frame_new(intf, intf_max_frame_size(intf));
    struct arp_ipv4 *req = frame_data_alloc(frame, sizeof(struct arp_ipv4));
    struct arp_hdr *hdr = frame_data_alloc(frame, sizeof(struct arp_hdr));

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

    int ret = ether_send(frame, ETH_P_ARP, daddr);
    // We created the frame so ensure it's unlocked if it never sent
    if (ret)
        frame_unlock(frame);
    frame_decref(frame);
    return ret;
}
