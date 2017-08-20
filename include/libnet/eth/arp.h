#ifndef NETD_ARP_H
#define NETD_ARP_H

#include <stdint.h>
#include "ether.h"

#define ARP_HDR_LEN sizeof(struct arp_hdr)

/* ARP supported hardware types */
#define ARP_HW_ETHER        0x001
#define ARP_HW_IEEE_802     0x006
#define ARP_HW_ARCNET       0x007
#define ARP_HW_FRM_RLY      0x00F
#define ARP_HW_ATM16        0x010
#define ARP_HW_HDLC         0x011
#define ARP_HW_FIB_CH       0x012
#define ARP_HW_ATM19        0x013
#define ARP_HW_SERIAL       0x014

/* ARP operation types */
#define ARP_OP_REQUEST      0x001
#define ARP_OP_REPLY        0x002

static inline const char const *fmt_arp_op(unsigned short op) {
    switch (op) {
        case ARP_OP_REQUEST:    return "ARP_OP_REQUEST";
        case ARP_OP_REPLY:      return "ARP_OP_REPLY";
        default:                return NULL;
    }
}

/* ARP message header */
struct arp_hdr {
    uint16_t hw_type,
             prot_type;
    uint8_t  hlen,
             plen;
    uint16_t op;
}__attribute((packed));

/* ARP IPv4 payload */
struct arp_ipv4 {
    uint8_t  saddr[ETH_ADDR_LEN];
    uint32_t sipv4;
    uint8_t  daddr[ETH_ADDR_LEN];
    uint32_t dipv4;
}__attribute((packed));

/* Returns a struct arp_hdr from the frame->head */
#define arp_hdr(frame) ((struct arp_hdr *) (frame)->head)

/* Given a network arp message buffer, this
 * mutates network values to host values */
struct arp_hdr *parse_arp(void *data);

/* Receives an arp frame for processing in the network stack */
void recv_arp(struct interface *intf, struct frame *frame);

#endif //NETD_ARP_H
