#ifndef NETSTACK_ICMP_H
#define NETSTACK_ICMP_H

#include <stdint.h>

#define ICMP_T_PONG     0       /* Echo reply */
#define ICMP_T_PING     8       /* Echo request */

#define ICMP_T_DESTUNR  3

#define ICMP_C_DESTUNR_NET      0
#define ICMP_C_DESTUNR_HOST     1
#define ICMP_C_DESTUNR_PROT     2
#define ICMP_C_DESTUNR_PORT     3
#define ICMP_C_DESTUNR_FRAG     4
#define ICMP_C_DESTUNR_SRCRT    5
#define ICMP_C_DESTUNR_NETUNKN  6
#define ICMP_C_DESTUNR_HSTUNKN  7
#define ICMP_C_DESTUNR_SRCISOL  8

/*
    Source: https://tools.ietf.org/html/rfc792

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Rest of header                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct icmp_hdr {
    uint8_t  type,
             code;
    uint16_t csum;
};

struct icmp_echo {
    uint16_t ident,
             seq;
    uint32_t payload;
};

/* Returns a struct icmp_hdr from the frame->head */
#define icmp_hdr(frame) ((struct icmp_hdr *) (frame)->head)

/* Returns a struct icmp_echo from the frame->data */
#define icmp_echo(frame) ((struct icmp_echo *) (frame)->data)

#endif //NETSTACK_ICMP_H
