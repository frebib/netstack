#ifndef NETSTACK_ARP_H
#define NETSTACK_ARP_H

#include <stdint.h>
#include <stdbool.h>

#include <netstack/log.h>
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
    uint16_t hwtype,    /* Hardware type */
             proto;     /* Protocol type */
    uint8_t  hlen,      /* Hardware address length */
             plen;      /* Protocol address length */
    uint16_t op;        /* ARP operation (ARP_OP_*) */
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

bool arp_log(struct pkt_log *log, struct frame *frame);

/* Receives an arp frame for processing in the network stack */
void arp_recv(struct frame *frame);

// TODO: reduce redundant arguments passed to arp_send_req/reply
// TODO: infer interface and hwtype based on routing rules
int arp_send_req(struct intf *intf, uint16_t hwtype,
                 uint32_t saddr, uint32_t daddr);

int arp_send_reply(struct intf *intf, uint8_t hwtype, uint32_t sip,
                   uint32_t dip, uint8_t *daddr);

/* Retrieve a hwaddress from ARP cache, or NULL of no cache hit */
/* Does NOT send ARP requests for cache misses.. */
addr_t *arp_get_hwaddr(struct intf *intf, uint16_t hwtype, addr_t *protoaddr);

/* ARP table cache */

/* ARP cache validity */
#define ARP_UNKNOWN         0x001
#define ARP_PENDING         0x002
#define ARP_RESOLVED        0x004
#define ARP_PERMANENT       0x008

static inline char const *fmt_arp_state(uint8_t state) {
    switch (state) {
        case ARP_UNKNOWN:  return "Unknown";
        case ARP_PENDING:  return "Pending";
        case ARP_RESOLVED: return "Resolved";
        default:           return "?";
    }
}

struct arp_entry {
    uint8_t state;
    addr_t  protoaddr;
    addr_t  hwaddr;
};

/*!
 * Prints the ARP table to the log with the specified level
 * @param intf interface to read ARP table from
 * @param file file to write ARP table to
 */
void arp_log_tbl(struct intf *intf, loglvl_t level);

/*!
 * Attempt to update an existing protocol address entry
 * @param intf interface to add mapping to
 * @param hwaddr new hardware type & address
 * @param protoaddr protocol address to update
 * @return true if an existing entry was updated, false otherwise
 */
bool arp_update_entry(struct intf *intf, addr_t *hwaddr, addr_t *protoaddr);

/*!
 * Add new protocol/hardware pair to the ARP cache
 * @param intf interface to add mapping to
 * @param hwaddr hardware type and address
 * @param protoaddr protocol type and address
 * @return true if a new entry was inserted, false otherwise
 */
bool arp_cache_entry(struct intf *intf, addr_t *hwaddr, addr_t *protoaddr);

#endif //NETSTACK_ARP_H
