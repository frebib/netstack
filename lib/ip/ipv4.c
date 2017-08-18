#include <stdio.h>
#include <netinet/in.h>
#include <libnet/frame.h>
#include <libnet/ip/ipv4.h>

struct ipv4_hdr *recv_ipv4(struct frame *frame) {

    struct ipv4_hdr *hdr = (struct ipv4_hdr *) frame->head;

    hdr->saddr = ntohl(hdr->saddr);
    hdr->daddr = ntohl(hdr->daddr);
    hdr->len = ntohs(hdr->len);
    hdr->id = ntohs(hdr->id);

    if (hdr->version != 4) {
        fprintf(stderr, "Warning: IPv4 packet version is wrong: %d\n",
                hdr->version);
    }

    // TODO: Check checksum & other integrity checks
    // TODO: Drop the packet if it's invalid

    // TODO: Take options into account here
    frame->data += sizeof(struct ipv4_hdr);

    return hdr;
}