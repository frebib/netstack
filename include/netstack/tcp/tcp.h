#ifndef NETSTACK_TCP_H
#define NETSTACK_TCP_H

#include <stdint.h>
#include <stddef.h>
#include <netstack/log.h>
#include <netstack/llist.h>
#include <netstack/ip/ipv4.h>
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
    uint8_t     hlen:4,         /* Size of TCP header in 32-bit words */
                rsvd:4;         /* Empty reserved space for ctrl flags */
    union {
        struct tcp_flags {
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
    union {
        struct tcp_flags {
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
        uint8_t flagval;
    };
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
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  rsvd;
    uint8_t  proto;
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

// TODO: Fix endianness in tcp.h
#if THE_HOST_IS_BIG_ENDIAN
#define TCP_FLAG_CWR    0x01
#define TCP_FLAG_ECE    0x02
#define TCP_FLAG_URG    0x04
#define TCP_FLAG_ACK    0x08
#define TCP_FLAG_PSH    0x10
#define TCP_FLAG_RST    0x20
#define TCP_FLAG_SYN    0x40
#define TCP_FLAG_FIN    0x80
#else
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80
#endif

struct tcp_sock {
    addr_t locaddr;
    addr_t remaddr;
    uint16_t locport;
    uint16_t remport;
    enum tcp_state state;
    struct tcp_tcb {
        uint32_t irs;       // initial receive sequence number
        uint32_t iss;       // initial send sequence number
        // Send Sequence Variables
        struct tcb_snd {
            uint32_t una;   // send unacknowledged
            uint32_t nxt;   // send next
            uint16_t wnd;   // send window
            uint16_t up;    // send urgent pointer
            uint32_t wl1;   // segment sequence number used for last window update
            uint32_t wl2;   // segment acknowledgment number used for last window update
        } snd;
        // Receive Sequence Variables
        struct tcb_rcv {
            uint32_t nxt;   // receive next
            uint16_t wnd;   // receive window
            uint16_t up;    // receive urgent pointer
        } rcv;
    } tcb;
};


#define TCP_DEF_MSS 536


/* Returns a string of characters/dots representing a set/unset TCP flag */
static inline char *fmt_tcp_flags(struct tcp_hdr *hdr, char *buffer) {
    if (buffer == NULL) {
        return NULL;
    }
    if (hdr == NULL) {
        buffer[0] = '\0';
        return buffer;
    }

    uint8_t count = 0;
    if (hdr->flags.fin) buffer[count++] = 'F';
    if (hdr->flags.syn) buffer[count++] = 'S';
    if (hdr->flags.rst) buffer[count++] = 'R';
    if (hdr->flags.psh) buffer[count++] = 'P';
    if (hdr->flags.ack) buffer[count++] = 'A';
    if (hdr->flags.urg) buffer[count++] = 'U';
    if (hdr->flags.ece) buffer[count++] = 'E';
    if (hdr->flags.cwr) buffer[count++] = 'C';
    buffer[count] = '\0';

    return buffer;
}


/* Returns a struct tcp_hdr from the frame->head */
#define tcp_hdr(frame) ((struct tcp_hdr *) (frame)->head)

/* Returns the size in bytes of a header
 * hdr->hlen is 1 byte, soo 4x is 1 word size */
#define tcp_hdr_len(hdr) ((uint16_t) ((hdr)->hlen * 4))

bool tcp_log(struct pkt_log *log, struct frame *frame, uint16_t net_csum);

/* Receives a tcp frame for processing in the network stack */
void tcp_recv(struct frame *frame, struct tcp_sock *sock, uint16_t net_csum);

struct tcp_sock *tcp_sock_lookup(addr_t *remaddr, addr_t *daddr,
                                 uint16_t remport, uint16_t locport);

/*
 * TCP Internet functions
 */

/*!
 * Calculates the IPv4 network checksum for the TCP checksum initial value
 * @param hdr IPv4 header of TCP parent packet
 * @return IPv4 network checksum using TCP/IPv4 pseudo-header
 */
uint16_t tcp_ipv4_csum(struct ipv4_hdr *hdr);


/*
 * TCP Input
 * See: tcpin.c
 */
int tcp_seg_arr(struct frame *frame, struct tcp_sock *sock);


/*
 * TCP Output
 * See: tcpout.c
 */
int tcp_send(struct tcp_sock *sock, struct frame *frame);

int tcp_send_ack(struct tcp_sock *sock);

int tcp_send_synack(struct tcp_sock *sock);

#endif //NETSTACK_TCP_H
