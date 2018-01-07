#include <netinet/in.h>

#include <netstack/ip/ipv4.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

uint16_t tcp_ipv4_csum(struct ipv4_hdr *hdr) {
    struct tcp_ipv4_phdr pseudo_hdr;
    pseudo_hdr.saddr = hdr->saddr;
    pseudo_hdr.daddr = hdr->daddr;
    pseudo_hdr.hlen  = hdr->len - htons((uint16_t) ipv4_hdr_len(hdr));
    pseudo_hdr.proto = hdr->proto;
    pseudo_hdr.rsvd  = 0;
    return ~in_csum(&pseudo_hdr, sizeof(pseudo_hdr), 0);
}

