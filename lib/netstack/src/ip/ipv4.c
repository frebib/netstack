#include <stdio.h>

#include <netinet/in.h>
#include <netstack/frame.h>
#include <netstack/ip/ipv4.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

struct ipv4_hdr *parse_ipv4(void *data) {
    struct ipv4_hdr *hdr = (struct ipv4_hdr *) data;

    hdr->frag_ofs = ntohs(hdr->frag_ofs);
    hdr->saddr = ntohl(hdr->saddr);
    hdr->daddr = ntohl(hdr->daddr);
    hdr->len = ntohs(hdr->len);
    hdr->id = ntohs(hdr->id);

    return hdr;
}

void recv_ipv4(struct intf *intf, struct frame *frame) {

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
    hdr = parse_ipv4(frame->head);

    char ssaddr[16], sdaddr[16];
    fmt_ipv4(hdr->saddr, ssaddr);
    fmt_ipv4(hdr->daddr, sdaddr);
    printf(" %s > %s", ssaddr, sdaddr);

    struct frame *child_frame = frame_child_copy(frame);
    switch (hdr->proto) {
        case IP_P_TCP: {
            printf(" TCP");

            /* Calculate TCP pseudo-header checksum */
            struct tcp_ipv4_phdr pseudo_hdr;
            pseudo_hdr.saddr = htonl(hdr->saddr);
            pseudo_hdr.daddr = htonl(hdr->daddr);
            pseudo_hdr.len   = htons(payload_len);
            pseudo_hdr.proto = hdr->proto;
            pseudo_hdr.rsvd  = 0;
            uint16_t ipv4_csum = ~in_csum(&pseudo_hdr, sizeof(pseudo_hdr), 0);

            /* Pass initial network csum as TCP packet csum seed */
            recv_tcp(intf, child_frame, ipv4_csum);
            return;
        }
        case IP_P_UDP:
        case IP_P_ICMP:
            printf(" unimpl %s", fmt_ipproto(hdr->proto));
            /*
            fprintf(stderr, "IPv4: Unimplemented packet type %s\n",
                    fmt_ipproto(hdr->proto));
            */
            return;
        default:
            printf(" unsupported %s", fmt_ipproto(hdr->proto));
            /*
            fprintf(stderr, "IPv4: Unsupported packet type: %s\n",
                    fmt_ipproto(hdr->proto));
            */
            return;
    }
}
