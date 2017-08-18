#ifndef NETD_TCP_H
#define NETD_TCP_H

#include <stdint.h>
#include <libnet/frame.h>

/*
    Source: https://tools.ietf.org/html/rfc793#page-15

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct tcp_hdr {
    // TODO: Take endianness into account here
    uint16_t    sport,          /* Source port */
                dport;          /* Destination port */
    uint32_t    seqn,           /* Sequence number */
                ackn;           /* Acknowledgement number */
    struct {
#if THE_HOST_IS_BIG_ENDIAN
    uint8_t     hdr_len:4,      /* Size of TCP header in 32-bit words */
                rsvd:4,         /* Empty reserved space for ctrl flags */
                /* Ignoring the experimental NS bit here: RFC 3540 */
                cwr:1,
                ece:1,
                urg:1,
                ack:1,           /* Various control bits */
                psh:1,
                rst:1,
                syn:1,
                fin:1;
#else
                /* Ignoring the experimental NS bit here: RFC 3540 */
    uint8_t     rsvd:4,         /* Empty reserved space for ctrl flags */
                hdr_len:4,      /* Size of TCP header in 32-bit words */
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,           /* Various control bits */
                urg:1,
                ece:1,
                cwr:1;
#endif
    } flags;
    uint16_t    wind,           /* Size of the receive window */
                csum,           /* Internet checksum */
                urg_ptr;        /* Urgent data pointer */

    /* Options go here */

}__attribute((packed));


/* Returns a struct tcp_hdr from the frame->head */
#define tcp_hdr(frame) ((struct tcp_hdr *) (frame)->head)

struct tcp_hdr *recv_tcp(struct frame *frame);


int fmt_tcp_flags(struct tcp_hdr* hdr, char* buffer);

#endif //NETD_TCP_H
