#ifndef NETSTACK_TCP_H
#define NETSTACK_TCP_H

#include <stdint.h>
#include <stddef.h>
#include <netstack/intf/intf.h>
#include <netinet/tcp.h>

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
    uint8_t rsvd,
            proto;
    uint16_t len;               /* Total length of TCP header */
}__attribute((packed));


/* Returns a struct tcphdr from the frame->head */
#define tcp_hdr(frame) ((struct tcphdr *) (frame)->head)

/* Returns the size in bytes of a header
 * hdr->hdr_len is 1 byte, soo 4x is 1 word size */
#define tcp_hdr_len(hdr) ((uint8_t) ((hdr)->th_off * 4))

/* Given a network tcp packet buffer, this
 * mutates network values to host values */
struct tcphdr *parse_tcp(void *data);

/* Receives a tcp frame for processing in the network stack */
void recv_tcp(struct intf *intf, struct frame *frame, uint16_t net_csum);


/* Returns a string of characters/dots representing a set/unset TCP flag */
static inline const int fmt_tcp_flags(struct tcphdr *hdr, char *buffer) {
    if (hdr == NULL) {
        return -1;
    }

    buffer[0] = (char) (hdr->th_flags & TH_FIN  ? 'F' : '.');
    buffer[1] = (char) (hdr->th_flags & TH_SYN  ? 'S' : '.');
    buffer[2] = (char) (hdr->th_flags & TH_RST  ? 'R' : '.');
    buffer[3] = (char) (hdr->th_flags & TH_PUSH ? 'P' : '.');
    buffer[4] = (char) (hdr->th_flags & TH_ACK  ? 'A' : '.');
    buffer[5] = (char) (hdr->th_flags & TH_URG  ? 'U' : '.');
    buffer[6] = 0;

    return 0;
}

#endif //NETSTACK_TCP_H
