#ifndef NETD_IPV4_H
#define NETD_IPV4_H

#include <stdint.h>

/*
    Source: https://tools.ietf.org/html/rfc791#page-11

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct ipv4_hdr {
    // TODO: Take endianness into account here
    uint8_t     hdr_len:4,  /* Internet header length (# of 32bit words) */
                version:4;  /* Always 4 for IPv4 */
    uint8_t     dscp:6,
                ecn:2;
    uint16_t    len,        /* Size of header + data in bytes */
                id;         /* packet identification number */
    uint8_t     flags:3;
    uint16_t    frag_ofs:13;
    uint8_t     ttl;
    uint8_t     proto;
    uint16_t    csum;
    uint32_t    saddr,
                daddr;
    /* Options are now specified, optionally of course */
}__attribute((packed));

/* Returns a struct ipv4_hdr from the frame->head */
struct ipv4_hdr *ipv4_hdr(struct frame *frame);

struct ipv4_hdr *recv_ipv4(struct frame *frame);

#define fmt_ipv4(ip, buff) \
    sprintf(buff, "%d.%d.%d.%d", \
        (ip >> 24) & 0xFF, \
        (ip >> 16) & 0xFF, \
        (ip >> 8) & 0xFF, \
        ip & 0xFF)

#endif //NETD_IPV4_H
