#ifndef NETSTACK_TCP_H
#define NETSTACK_TCP_H

#include <stdint.h>
#include <stddef.h>
#include <netstack/log.h>
#include <netstack/llist.h>
#include <netstack/intf/intf.h>

// Global TCP states list
extern struct llist tcp_sockets;

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
    // TODO: Take endianness into account in tcp_hdr
    uint16_t    sport,          /* Source port */
                dport;          /* Destination port */
    uint32_t    seqn,           /* Sequence number */
                ackn;           /* Acknowledgement number */
#if THE_HOST_IS_BIG_ENDIAN
    uint8_t     hlen:4,      /* Size of TCP header in 32-bit words */
                rsvd:4;         /* Empty reserved space for ctrl flags */
    struct {
                /* Ignoring the experimental NS bit here: RFC 3540 */
    uint8_t     cwr:1,
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
                hlen:4;         /* Size of TCP header in 32-bit words */
    struct {
        uint8_t fin:1,
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

/*
    Pseudo-header for calculating TCP checksum

      0         1         2         3
      0 2 4 6 8 0 2 4 6 8 0 2 4 6 8 0 2
    +--------+--------+--------+--------+
    |           Source Address          |
    +--------+--------+--------+--------+
    |         Destination Address       |
    +--------+--------+--------+--------+
    |  zero  |  proto |   TCP Length    |
    +--------+--------+--------+--------+
*/
struct tcp_ipv4_phdr {
    uint32_t saddr,
             daddr;
    uint8_t  rsvd,
             proto;
    uint16_t hlen;              /* Total length of TCP header */
}__attribute((packed));


enum tcp_state {
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_CLOSED,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
};

struct tcp_sock {
    addr_t saddr;
    addr_t daddr;
    uint16_t sport;
    uint16_t dport;
    enum tcp_state state;
};


/* Returns a string of characters/dots representing a set/unset TCP flag */
static inline const int fmt_tcp_flags(struct tcp_hdr *hdr, char *buffer) {
    if (hdr == NULL) {
        return -1;
    }

    buffer[0] = (char) (hdr->flags.fin ? 'F' : '.');
    buffer[1] = (char) (hdr->flags.syn ? 'S' : '.');
    buffer[2] = (char) (hdr->flags.rst ? 'R' : '.');
    buffer[3] = (char) (hdr->flags.psh ? 'P' : '.');
    buffer[4] = (char) (hdr->flags.ack ? 'A' : '.');
    buffer[5] = (char) (hdr->flags.urg ? 'U' : '.');
    buffer[6] = (char) (hdr->flags.ece ? 'E' : '.');
    buffer[7] = (char) (hdr->flags.cwr ? 'C' : '.');
    buffer[8] = 0;

    return 0;
}


/* Returns a struct tcp_hdr from the frame->head */
#define tcp_hdr(frame) ((struct tcp_hdr *) (frame)->head)

/* Returns the size in bytes of a header
 * hdr->hlen is 1 byte, soo 4x is 1 word size */
#define tcp_hdr_len(hdr) ((uint8_t) (hdr->hlen * 4))

bool tcp_log(struct pkt_log *log, struct frame *frame);

/* Receives a tcp frame for processing in the network stack */
void tcp_recv(struct frame *frame, struct tcp_sock *sock, uint16_t net_csum);

struct tcp_sock *tcp_sock_lookup(addr_t *saddr, addr_t *daddr,
                                 uint16_t sport, uint16_t dport);

/*
 * TCP Input
 */
int tcp_seg_arr(struct frame *frame, struct tcp_sock *sock);

#endif //NETSTACK_TCP_H
