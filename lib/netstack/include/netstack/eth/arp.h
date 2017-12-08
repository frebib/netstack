#ifndef NETSTACK_ARP_H
#define NETSTACK_ARP_H

#include <stdint.h>
#include <stdbool.h>

#include <netstack/eth/ether.h>

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

static inline char const *fmt_arp_op(unsigned short op) {
    switch (op) {
        case ARP_OP_REQUEST:    return "ARP_OP_REQUEST";
        case ARP_OP_REPLY:      return "ARP_OP_REPLY";
        default:                return NULL;
    }
}

/* ARP message header */
struct arp_hdr {
    uint16_t hwtype,
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

#define arp_entry_ipv4_len(hwlen) \
    (sizeof(struct arp_entry_ipv4) + (hwlen) - 1)

/* Returns a struct arp_hdr from the frame->head */
#define arp_hdr(frame) ((struct arp_hdr *) (frame)->head)

/* Given a network arp message buffer, this
 * mutates network values to host values */
struct arp_hdr *parse_arp(void *data);

/* Receives an arp frame for processing in the network stack */
void recv_arp(struct intf *intf, struct frame *frame);

/* Retrieve a hwaddress from ARP cache, or NULL of no cache hit */
/* Does NOT send ARP requests for cache misses.. */
uint8_t *arp_ipv4_get_hwaddr(struct intf *intf, uint8_t hwtype, uint32_t ipv4);

/* ARP table cache */

/* ARP cache validity */
#define ARP_UNKNOWN         0x000
#define ARP_PENDING         0x001
#define ARP_RESOLVED        0x002

static inline char const *fmt_arp_state(uint8_t state) {
    switch (state) {
        case ARP_UNKNOWN:  return "Unknown";
        case ARP_PENDING:  return "Pending";
        case ARP_RESOLVED: return "Resolved";
        default:           return "?";
    }
}

struct arp_entry_ipv4 {
    uint16_t hwtype;
    uint8_t  state;
    uint32_t ip;
    uint8_t  hwlen;
    // Not enough space allocated for hw address.
    uint8_t  hwaddr;
    // Use arp_entry_len() to allocate the correct size buffer
};

#define arp_entry_len(type, entry) \
    (sizeof(type) + (entry)->hwlen - 1)

/* Add ethernet/IPv4 entries to the ARP table */
/* Returns true if a new entry was inserted, false if an old updated */
bool arp_cache_ipv4(struct intf *intf, struct arp_hdr *hdr,
                    struct arp_ipv4 *req);

#endif //NETSTACK_ARP_H
