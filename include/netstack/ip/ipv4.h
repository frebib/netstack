#ifndef NETSTACK_IPV4_H
#define NETSTACK_IPV4_H

#include <stdint.h>
#include <netstack/intf/intf.h>
#include <netstack/ip/ipproto.h>

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
    // TODO: Take endianness into account in ipv4_hdr
    uint8_t     hlen:4,     /* Internet header length (# of 32bit words) */
                version:4;  /* Always 4 for IPv4 */
    union {                 /* https://en.wikipedia.org/wiki/Type_of_service */
        struct {
            uint8_t dscp:6,
                    ecn:2;
        };
        uint8_t tos;
    };
    uint16_t    len,        /* Size of header + data in bytes */
                id;         /* packet identification number */
    uint16_t    frag_ofs;
    uint8_t     ttl;
    uint8_t     proto;
    uint16_t    csum;
    ip4_addr_t  saddr,
                daddr;
    /* Options are now specified, optionally of course */
}__attribute((packed));

#define IPV4_DEF_TTL 64

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

/* Returns a struct ipv4_hdr from the frame->head */
#define ipv4_hdr(frame) ((struct ipv4_hdr *) (frame)->head)

/* Returns the size in bytes of a header
 * hdr->hlen is 1 byte, soo 4x is 1 word size */
#define ipv4_hdr_len(hdr) ((hdr)->hlen * 4)

/* Given a network ipv4 packet buffer, this
 * mutates network values to host values */
struct ipv4_hdr *ipv4_ntoh(void *data);

/* Receives an ipv4 frame for processing in the network stack */
void ipv4_recv(struct frame *frame);

/*!
 * Constructs an IPv4 frame around the provided payload and sends it
 * @param frame IP payload to send
 * @param proto inner IP protocol (IP_P_*)
 * @param flags optionally, any IP flags such as IP_DF, otherwise 0
 * @param daddr destination IP address to send packet to
 * @param saddr optionally, the source address to send on the packet
 *              if not specified, the default interface address will be used
 * @return 0 on success or negative for errors (see errno(3))
 */
int send_ipv4(struct frame *child, uint8_t proto, uint16_t flags,
              ip4_addr_t daddr, ip4_addr_t saddr);


// Converts 4 bytes to a uint32_t IPv4 address
// e.g. num_ipv4(192, 168, 10, 1) represents 192.168.10.1
#define num_ipv4(a, b, c, d) (ip4_addr_t) (\
        ((a) << 24) + \
        ((b) << 16) + \
        ((c) << 8) + \
        (d) \
    )

#endif //NETSTACK_IPV4_H
