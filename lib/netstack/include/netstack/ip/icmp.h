#ifndef NETSTACK_ICMP_H
#define NETSTACK_ICMP_H

#include <stdint.h>
#include <netstack/frame.h>
#include <netstack/intf/intf.h>

#define ICMP_T_ECHORPLY         0       /* Echo reply */
#define ICMP_T_ECHOREQ          8       /* Echo request */

#define ICMP_T_DESTUNR          3

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
    uint8_t     type,
                code;
    uint16_t    csum;
}__attribute((packed));

struct icmp_echo {
    uint16_t    id,
                seq;
    uint32_t    payload;
}__attribute((packed));

/* Returns a struct icmp_hdr from the frame->head */
#define icmp_hdr(frame) ((struct icmp_hdr *) (frame)->head)

/* Receives an icmp frame for processing in the network stack */
void icmp_recv(struct intf *intf, struct frame *frame);

/* Converts network to host values in header */
struct icmp_echo *icmp_echo(void *data);

/* Generates and dispatches an ICMP echo packet */
void send_icmp_reply(struct intf *intf, struct frame *frame);

#endif //NETSTACK_ICMP_H
