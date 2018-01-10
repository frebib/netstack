#ifndef NETSTACK_ETHER_H
#define NETSTACK_ETHER_H

#include <stdint.h>
#include <linux/types.h>

#include <netstack/log.h>
#include <netstack/intf/intf.h>
#include <netstack/eth/ethertype.h>


static eth_addr_t ETH_BRD_ADDR = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static eth_addr_t ETH_NUL_ADDR = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


/* Ethernet frame header */
struct eth_hdr {
    eth_addr_t daddr;   /* Destination address */
    eth_addr_t saddr;   /* Source address */
    uint16_t ethertype;   /* Frame payload type, see ethertype.h */

}__attribute((packed));
struct eth_hdr_vlan {
    eth_addr_t daddr;   /* Destination address */
    eth_addr_t saddr;   /* Source address */
    uint16_t tpid;      /* Value of ETH_P_VLAN */
    uint16_t vlan;      /* 802.11Q VLAN tag*/
    uint16_t ethertype;   /* Frame payload type, see ethertype.h */
}__attribute((packed));


/* Returns a struct eth_hdr from the frame->head */
#define eth_hdr(frame) ((struct eth_hdr *) (frame)->head)

/* Calculates ethernet header length, taking 802.11Q VLAN tags into account */
#define ether_hdr_len(f)  sizeof(struct eth_hdr) + \
                        (ntohs(eth_hdr(f)->ethertype) == ETH_P_VLAN ? 6 : 0)

bool ether_log(struct pkt_log *log, struct frame *frame);

/* Receives an ether frame for processing in the network stack */
void ether_recv(struct frame *frame);

int ether_send(struct frame *child, uint16_t ethertype, eth_addr_t mac);

bool ether_should_accept(struct eth_hdr *hdr, struct intf *intf);

#endif //NETSTACK_ETHER_H
