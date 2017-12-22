#include <stdio.h>

#include <netinet/in.h>
#include <netstack/frame.h>
#include <netstack/ip/ipv4.h>
#include <netstack/ip/icmp.h>
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
        fprintf(stderr, "Error: IPv4 packet header is too short!");
        return;
    }

    if (hdr->version != 4) {
        fprintf(stderr, "Error: IPv4 packet version is wrong: %d\n",
                hdr->version);
        return;
    }

    // TODO: Take options into account here

    if (in_csum(frame->head, (size_t) hdr_len, 0) != 0) {
        fprintf(stderr, "Error: IPv4 packet checksum is corrupt\n");
        return;
    }

    // TODO: Other integrity checks

    /* Fix network endianness in header */
    hdr = ipv4_ntoh(frame->head);

    char ssaddr[16], sdaddr[16];
    fmt_ipv4(hdr->saddr, ssaddr);
    fmt_ipv4(hdr->daddr, sdaddr);

    // TODO: Change to if (!ipv4_should_accept(frame)) to accept other packets
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

            /* Pass initial network csum as TCP packet csum seed */
            tcp_recv(child_frame, ipv4_csum);
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
