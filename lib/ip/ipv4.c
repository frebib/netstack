#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/in.h>

#define NETSTACK_LOG_UNIT "IPv4"
#include <netstack/eth/arp.h>
#include <netstack/ip/ipv4.h>
#include <netstack/ip/icmp.h>
#include <netstack/ip/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>


bool ipv4_log(struct pkt_log *log, struct frame *frame) {
    struct ipv4_hdr *hdr = ipv4_hdr(frame);
    uint16_t hdr_len = (uint16_t) ipv4_hdr_len(hdr);
    frame->data = frame->head + hdr_len;
    frame->tail = frame->head + ntohs(hdr->len);
    struct log_trans *trans = &log->t;

    // Print IPv4 total size
    LOGT(trans, "length %hu ", frame_pkt_len(frame));

    // Print and check checksum
    uint16_t pkt_csum = hdr->csum;
    uint16_t calc_csum = in_csum(frame->head, (size_t) ipv4_hdr_len(hdr), 0)
                         + hdr->csum;
    LOGT(trans, "csum 0x%04x", ntohs(pkt_csum));
    if (pkt_csum != calc_csum)
        LOGT(trans, " (invalid 0x%04x)", ntohs(calc_csum));
    LOGT(trans, ", ");

    // Print flags if any are present
    uint16_t flags = ntohs(hdr->frag_ofs);
    if (flags != 0) {
        LOGT(trans, "flags [");

        if (flags & IP_DF)
            LOGT(trans, "DF");

        LOGT(trans, "] ");
    }

    // TODO: Change to `if (!ipv4_should_accept(frame))` to accept other packets
    // Only log IPv4 packets sent by/destined for us
    addr_t sip = {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->saddr)};
    addr_t dip = {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->daddr)};
    addr_t brd = {.proto = PROTO_IPV4, .ipv4 = 0xFFFFFFFF};
    addr_t zro = {.proto = PROTO_IPV4};
    if (!intf_has_addr(frame->intf, &sip)
        && !intf_has_addr(frame->intf, &dip)
        && !addreq(&dip, &brd)
        && !addreq(&sip, &zro)) {
        return false;
    }

    frame->head = frame->data;
    switch (hdr->proto) {
        case IP_P_TCP: {
            uint16_t sport = htons(tcp_hdr(frame)->sport);
            uint16_t dport = htons(tcp_hdr(frame)->dport);
            LOGT(trans, "%s:%d > ", fmtip4(ntohl(hdr->saddr)), sport);
            LOGT(trans, "%s:%d ", fmtip4(ntohl(hdr->daddr)), dport);
            LOGT(trans, "TCP ");
            return tcp_log(log, frame, inet_ipv4_csum(hdr), sip, dip);
        }
        case IP_P_ICMP:
            LOGT(trans, "%s > ", fmtip4(ntohl(hdr->saddr)));
            LOGT(trans, "%s ", fmtip4(ntohl(hdr->daddr)));
            LOGT(trans, "ICMP ");
            return icmp_log(log, frame);
        case IP_P_UDP:
            LOGT(trans, "%s > ", fmtip4(ntohl(hdr->saddr)));
            LOGT(trans, "%s ", fmtip4(ntohl(hdr->daddr)));
            LOGT(trans, "UDP ");
            LOGT(trans, "unimpl %s ", fmt_ipproto(hdr->proto));
            return false;
        default:
            LOGT(trans, "%s > ", fmtip4(ntohl(hdr->saddr)));
            LOGT(trans, "%s ", fmtip4(ntohl(hdr->daddr)));
            LOGT(trans, "unsupported %s (%d) ", fmt_ipproto(hdr->proto),
                 hdr->proto);
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
        LOG(LWARN, "packet header is too short!");
        return;
    }

    if (hdr->version != 4) {
        LOG(LWARN, "packet version is wrong: %d", hdr->version);
        return;
    }

    // TODO: Take options into account here

    if (in_csum(frame->head, (size_t) hdr_len, 0) != 0) {
        LOG(LWARN, "packet checksum is corrupt");
        return;
    }

    // TODO: Other integrity checks

    // TODO: Change to `if (!ipv4_should_accept(frame))` to accept other packets
    // such as multicast, broadcast etc.
    addr_t ip = {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->daddr)};
    if (!intf_has_addr(frame->intf, &ip)) {
        return;
    }

    // Push IP into protocol stack
    frame_layer_push(frame, PROTO_IPV4);

    frame->remaddr = (addr_t) {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->saddr)};
    frame->locaddr = (addr_t) {.proto = PROTO_IPV4, .ipv4 = ntohl(hdr->daddr)};

    frame->head = frame->data;
    switch (hdr->proto) {
        case IP_P_TCP:
            tcp_ipv4_recv(frame, hdr);
            return;
        case IP_P_ICMP:
            icmp_recv(frame);
            return;
        case IP_P_UDP:
        default:
            return;
    }
}

int ipv4_send(struct frame *frame, uint8_t proto, uint16_t flags,
              ip4_addr_t daddr, ip4_addr_t saddr, addr_t *hwaddr) {

    frame_lock(frame, SHARED_RW);

    // Construct IPv4 header
    // TODO: Dynamically allocate IPv4 header space
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

    switch(hwaddr->proto) {
        case PROTO_IP:
        case PROTO_IPV4:
            // Frame successfully made it to the bottom of the stack
            // Dispatch it to the interface and return
            return intf_dispatch(frame);
        case PROTO_ETHER:
            return ether_send(frame, ETH_P_IP, hwaddr->ether);
        default:
            return -ENODEV;
    }
}

