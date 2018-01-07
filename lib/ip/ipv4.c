#include <stdio.h>
#include <errno.h>

#include <netinet/in.h>

#include <netstack/eth/arp.h>
#include <netstack/ip/ipv4.h>
#include <netstack/ip/icmp.h>
#include <netstack/ip/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

bool ipv4_log(struct pkt_log *log, struct frame *frame) {
    struct ipv4_hdr *hdr = ipv4_hdr(frame);
    uint16_t hdr_len = (uint16_t) ipv4_hdr_len(hdr);
    frame->data += hdr_len;
    frame->tail = frame->data + (ntohs(hdr->len) - hdr_len);
    struct log_trans *trans = &log->t;

    // Print IPv4 total size
    LOGT(trans, "length %hu ", ntohs(hdr->len));

    // Print and check checksum
    uint16_t pkt_csum = hdr->csum;
    uint16_t calc_csum = in_csum(frame->head, (size_t) ipv4_hdr_len(hdr), 0)
                         + hdr->csum;
    LOGT(trans, "csum 0x%04x", ntohs(pkt_csum));
    if (pkt_csum != calc_csum)
        LOGT(trans, " (invalid 0x%04x)", ntohs(calc_csum));
    LOGT(trans, ", ");

    // TODO: Change to `if (!ipv4_should_accept(frame))` to accept other packets
    // Only log IPv4 packets sent by/destined for us
    addr_t sip = {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->saddr)};
    addr_t dip = {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->daddr)};
    if (!intf_has_addr(frame->intf, &sip)
        && !intf_has_addr(frame->intf, &dip)) {
        return false;
    }

    struct frame *child_frame = frame_child_copy(frame);
    switch (hdr->proto) {
        case IP_P_TCP: {
            uint16_t sport = htons(tcp_hdr(child_frame)->sport);
            uint16_t dport = htons(tcp_hdr(child_frame)->dport);
            LOGT(trans, "%s:%d > ", fmtip4(ntohl(hdr->saddr)), sport);
            LOGT(trans, "%s:%d ", fmtip4(ntohl(hdr->daddr)), dport);
            LOGT(trans, "TCP ");
            return tcp_log(log, child_frame, tcp_ipv4_csum(hdr));
        }
        case IP_P_ICMP:
            LOGT(trans, "%s > ", fmtip4(ntohl(hdr->saddr)));
            LOGT(trans, "%s ", fmtip4(ntohl(hdr->daddr)));
            LOGT(trans, "ICMP ");
            return icmp_log(log, child_frame);
        case IP_P_UDP:
            LOGT(trans, "%s > ", fmtip4(ntohl(hdr->saddr)));
            LOGT(trans, "%s ", fmtip4(ntohl(hdr->daddr)));
            LOGT(trans, "UDP ");
            LOGT(trans, "unimpl %s ", fmt_ipproto(hdr->proto));
            return false;
        default:
            LOGT(trans, "%s > ", fmtip4(ntohl(hdr->saddr)));
            LOGT(trans, "%s ", fmtip4(ntohl(hdr->daddr)));
            LOGT(trans, "unsupported %s ", fmt_ipproto(hdr->proto));
            break;
    }

    return true;
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

    // TODO: Change to `if (!ipv4_should_accept(frame))` to accept other packets
    // such as multicast, broadcast etc.
    addr_t ip = {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->daddr)};
    if (!intf_has_addr(frame->intf, &ip)) {
        return;
    }

    struct frame *child_frame = frame_child_copy(frame);
    switch (hdr->proto) {
        case IP_P_TCP: {
            struct tcp_hdr *tcp_hdr = tcp_hdr(child_frame);
            uint16_t sport = htons(tcp_hdr->sport);
            uint16_t dport = htons(tcp_hdr->dport);
            addr_t saddr = {.proto=PROTO_IPV4, .ipv4 = ntohl(hdr->saddr)};
            addr_t daddr = {.proto=PROTO_IPV4, .ipv4 = ntohl(hdr->daddr)};
            struct tcp_sock *sock = tcp_sock_lookup(&saddr, &daddr,
                                                    sport, dport);

            /* Pass initial network csum as TCP packet csum seed */
            tcp_recv(child_frame, sock, tcp_ipv4_csum(hdr));
            return;
        }
        case IP_P_ICMP:
            icmp_recv(child_frame);
            return;
        case IP_P_UDP:
        default:
            return;
    }
}

int ipv4_send(struct frame *child, uint8_t proto, uint16_t flags,
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
        LOGT_COMMIT(&trans);
        // TODO: Rate limit ARP requests to prevent flooding
        arp_send_req(rt->intf, ARP_HW_ETHER, saddr, nexthop);

        frame_parent_free(frame);
        return -EHOSTUNREACH;
    }

    // Construct IPv4 header
    struct ipv4_hdr *hdr = frame_head_alloc(frame, sizeof(struct ipv4_hdr));
    hdr->hlen = 5;
    hdr->version = 4;
    hdr->tos = 0;
    hdr->len = htons((uint16_t) (ipv4_hdr_len(hdr) + frame_data_len(frame)));
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

