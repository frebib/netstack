#include <stdio.h>

#include <netinet/in.h>
#include <libnet/frame.h>
#include <libnet/ip/ipv4.h>
#include <libnet/tcp/tcp.h>


struct ipv4_hdr *parse_ipv4(void *data) {
    struct ipv4_hdr *hdr = (struct ipv4_hdr *) data;

    hdr->frag_ofs = ntohs(hdr->frag_ofs);
    hdr->saddr = ntohl(hdr->saddr);
    hdr->daddr = ntohl(hdr->daddr);
    hdr->len = ntohs(hdr->len);
    hdr->id = ntohs(hdr->id);

    return hdr;
}

void recv_ipv4(struct interface *intf, struct frame *frame) {

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

    // TODO: Check checksum & other integrity checks

    // TODO: Take options into account here

    /* Fix network endianness in header */
    hdr = parse_ipv4(frame->head);

    struct frame *child_frame = frame_child_copy(frame);
    switch (hdr->proto) {
        case IP_P_TCP:
            return recv_tcp(intf, child_frame);
        case IP_P_UDP:
        case IP_P_ICMP:
            fprintf(stderr, "IPv4: Unimplemented packet type %s\n",
                    fmt_ipproto(hdr->proto));
            return;
        default:
            fprintf(stderr, "IPv4: Unsupported packet type: %s\n",
                    fmt_ipproto(hdr->proto));
            return;
    }
}