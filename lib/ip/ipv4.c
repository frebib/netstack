#include <stdio.h>
#include <errno.h>

#include <netinet/in.h>

#include <netstack/log.h>
#include <netstack/eth/arp.h>
#include <netstack/ip/ipv4.h>
#include <netstack/ip/icmp.h>
#include <netstack/ip/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

struct ipv4_hdr *ipv4_ntoh(void *data) {
    struct ipv4_hdr *hdr = (struct ipv4_hdr *) data;

    hdr->frag_ofs = ntohs(hdr->frag_ofs);
    hdr->saddr = ntohl(hdr->saddr);
    hdr->daddr = ntohl(hdr->daddr);
    hdr->len = ntohs(hdr->len);
    hdr->id = ntohs(hdr->id);

    return hdr;
}

void ipv4_recv(struct frame *frame) {

    /* Don't parse yet, we need to check the checksum first */
    struct ipv4_hdr *hdr = ipv4_hdr(frame);
    uint16_t hdr_len = (uint16_t) ipv4_hdr_len(hdr);
    uint16_t pkt_len = ntohs(hdr->len);
    uint16_t payload_len = pkt_len - hdr_len;
    frame->data += hdr_len;
    frame->tail = frame->data + payload_len;

    // TODO: Keep track of invalid packets

    if (hdr_len < sizeof(struct ipv4_hdr)) {
        LOG(LWARN, "Error: IPv4 packet header is too short!");
        return;
    }

    if (hdr->version != 4) {
        LOG(LWARN, "Error: IPv4 packet version is wrong: %d", hdr->version);
        return;
    }

    // TODO: Take options into account here

    if (in_csum(frame->head, (size_t) hdr_len, 0) != 0) {
        LOG(LWARN, "Error: IPv4 packet checksum is corrupt");
        return;
    }

    // TODO: Other integrity checks

    /* Fix network endianness in header */
    hdr = ipv4_ntoh(frame->head);

    char ssaddr[16], sdaddr[16];
    fmt_ipv4(hdr->saddr, ssaddr);
    fmt_ipv4(hdr->daddr, sdaddr);

    // TODO: Change to `if (!ipv4_should_accept(frame))` to accept other packets
    // such as multicast, broadcast etc.
    addr_t ip = {.proto = PROTO_IPV4, .ipv4 = hdr->daddr};
    if (!intf_has_addr(frame->intf, &ip)) {
        printf(" %s > %s", ssaddr, sdaddr);
        return;
    }

    struct frame *child_frame = frame_child_copy(frame);
    switch (hdr->proto) {
        case IP_P_TCP: {
            printf(" TCP");

            /* Calculate TCP pseudo-header checksum */
            struct tcp_ipv4_phdr pseudo_hdr;
            pseudo_hdr.saddr = htonl(hdr->saddr);
            pseudo_hdr.daddr = htonl(hdr->daddr);
            pseudo_hdr.hlen  = htons(payload_len);
            pseudo_hdr.proto = hdr->proto;
            pseudo_hdr.rsvd  = 0;
            uint16_t ipv4_csum = ~in_csum(&pseudo_hdr, sizeof(pseudo_hdr), 0);

            /* Print ip:port > ip:port */
            uint16_t sport = htons(tcp_hdr(child_frame)->sport);
            uint16_t dport = htons(tcp_hdr(child_frame)->dport);
            printf(" %s:%d > %s:%d", ssaddr, sport, sdaddr, dport);

            addr_t saddr = {.proto=PROTO_IPV4, .ipv4 = hdr->saddr};
            addr_t daddr = {.proto=PROTO_IPV4, .ipv4 = hdr->daddr};
            struct tcp_sock *sock = tcp_sock_lookup(&saddr, &daddr,
                                                    sport, dport);

            /* Pass initial network csum as TCP packet csum seed */
            tcp_recv(child_frame, sock, ipv4_csum);
            return;
        }
        case IP_P_UDP:
            printf(" %s > %s", ssaddr, sdaddr);
            printf(" unimpl %s", fmt_ipproto(hdr->proto));
            return;
        case IP_P_ICMP: {
            printf(" ICMP");
            printf(" %s > %s", ssaddr, sdaddr);
            icmp_recv(child_frame);
            return;
        }
        default:
            printf(" %s > %s", ssaddr, sdaddr);
            printf(" unsupported %s", fmt_ipproto(hdr->proto));
            return;
    }
}

int send_ipv4(struct frame *child, uint8_t proto, uint16_t flags,
              ip4_addr_t daddr, ip4_addr_t saddr) {

    struct route_entry *rt = route_lookup(daddr);
    if (!rt) {
        // If no route found, return DESTUNREACHABLE error
        return -EHOSTUNREACH;
    }

    // TODO: Perform correct route/hardware address lookups when appropriate
    if (rt->intf == NULL) {
        LOG(LERR, "Route interface is null for %p", (void *) rt);
        return -EINVAL;
    }

    // Set frame interface now it is known from route
    struct frame *frame = frame_parent_copy(child);
    frame->intf = rt->intf;

    ip4_addr_t nexthop = (rt->flags & RT_GATEWAY) ? rt->gwaddr : daddr;

    if (saddr) {
        addr_t req_saddr = { .proto = PROTO_IPV4, .ipv4 = saddr };
        if (!intf_has_addr(rt->intf, &req_saddr)) {
            LOG(LERR, "The requested address %s is invalid for "
                    "interface %s", fmtip4(saddr), rt->intf->name);

            frame_parent_free(frame);
            return -EADDRNOTAVAIL;
        }
    } else {
        addr_t def_addr = { .proto = PROTO_IPV4, .ipv4 = 0 };
        if (!intf_get_addr(rt->intf, &def_addr)) {
            LOG(LERR, "Could not get interface address for %s",
                    rt->intf->name);

            frame_parent_free(frame);
            return -EADDRNOTAVAIL;
        }

        if (def_addr.ipv4 == 0) {
            LOG(LERR, "Interface %s has no address for IPv4",
                    rt->intf->name);

            frame_parent_free(frame);
            return -EADDRNOTAVAIL;
        }

        // Set source-address to address obtained from rt->intf
        saddr = def_addr.ipv4;
    }

    // TODO: Implement ARP cache locking
    addr_t nexthop_ip4 = { .proto = PROTO_IPV4, .ipv4 = nexthop };
    addr_t *dmac = arp_get_hwaddr(rt->intf, ARP_HW_ETHER, &nexthop_ip4);

    if (dmac == NULL) {
        struct log_trans trans = LOG_TRANS(LTRCE);
        LOGT(&trans, "call arp_request(%s, %s", rt->intf->name, fmtip4(saddr));
        LOGT(&trans, ", %s);", fmtip4(nexthop));
        LOG_COMMIT(&trans);
        // TODO: Rate limit ARP requests to prevent flooding
        arp_send_req(rt->intf, ARP_HW_ETHER, saddr, nexthop);

        frame_parent_free(frame);
        return -EHOSTUNREACH;
    }

    // Construct IPv4 header
    struct ipv4_hdr *hdr = frame_alloc(frame, sizeof(struct ipv4_hdr));
    hdr->hlen = 5;
    hdr->version = 4;
    hdr->tos = 0;
    hdr->len = htons((uint16_t) (ipv4_hdr_len(hdr) + frame_data_len(frame) -
            20));
    hdr->id  = htons(0);
    hdr->frag_ofs = htons(flags);
    // TODO: Make this user-configurable
    hdr->ttl = IPV4_DEF_TTL;
    hdr->proto = proto;
    hdr->saddr = htonl(saddr);
    hdr->daddr = htonl(daddr);
    hdr->csum = 0;
    hdr->csum = in_csum(hdr, (size_t) sizeof(struct ipv4_hdr), 0);

    switch(rt->intf->proto) {
        case PROTO_IP:
        case PROTO_IPV4:
            // Frame successfully made it to the bottom of the stack
            // Dispatch it to the interface and return
            return intf_dispatch(frame);
        case PROTO_ETHER:
            return ether_send(frame, ETH_P_IP, dmac->ether);
        default:
            return 0;
    }
}

