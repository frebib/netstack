#ifndef NETSTACK_IPV4_H
#define NETSTACK_IPV4_H

#include <stdint.h>
#include <linux/ip.h>
#include <netstack/intf/intf.h>

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

/* Returns a struct ipv4_hdr from the frame->head */
#define ipv4_hdr(frame) ((struct iphdr *) (frame)->head)

/* Returns the size in bytes of a header
 * hdr->hdr_len is 1 byte, soo 4x is 1 word size */
#define ipv4_hdr_len(hdr) ((hdr)->ihl * 4)

/* Given a network ipv4 packet buffer, this
 * mutates network values to host values */
struct iphdr *parse_ipv4(void *data);

/* Receives an ipv4 frame for processing in the network stack */
void recv_ipv4(struct intf *intf, struct frame *frame);

#define fmt_ipv4(ip, buff) \
    sprintf(buff, "%d.%d.%d.%d", \
        ((ip) >> 24) & 0xFF, \
        ((ip) >> 16) & 0xFF, \
        ((ip) >> 8) & 0xFF, \
        (ip) & 0xFF)

// Converts 4 bytes to a uint32_t IPv4 address
// e.g. num_ipv4(192, 168, 10, 1) represents 192.168.10.1
#define num_ipv4(a, b, c, d) (\
        ((a) << 24) + \
        ((b) << 16) + \
        ((c) << 8) + \
        (d) \
    )

/* Returns a matching `const char *` to a IP_P_* value */
static inline char const *fmt_ipproto(unsigned short proto) {
    switch (proto) {
        case IPPROTO_ICMP:  return "IP_P_ICMP";
        case IPPROTO_IGMP:  return "IP_P_IGMP";
        case IPPROTO_TCP:   return "IP_P_TCP";
        case IPPROTO_UDP:   return "IP_P_UDP";
        default:            return NULL;
    }
}

#endif //NETSTACK_IPV4_H
