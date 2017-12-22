#ifndef NETSTACK_ETHER_H
#define NETSTACK_ETHER_H

#include <stdint.h>
#include <linux/types.h>

#include <netstack/intf/intf.h>

#include "ethertype.h"

#define ETH_HDR_LEN  sizeof(struct eth_hdr)

static eth_addr_t ETH_BRD_ADDR = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


/* Ethernet frame header */
struct eth_hdr {
    eth_addr_t daddr;   /* Destination address */
    eth_addr_t saddr;   /* Source address */
    __be16 ethertype;   /* Frame payload type, see ethertype.h */
}__attribute((packed));


/* Returns a struct eth_hdr from the frame->head */
#define eth_hdr(frame) ((struct eth_hdr *) (frame)->head)

/* Given a network ether frame buffer, this
 * mutates network values to host values */
struct eth_hdr *ether_ntoh(void *data);

/* Receives an ether frame for processing in the network stack */
void ether_recv(struct frame *frame);

int ether_send(struct frame *frame, uint16_t ethertype,
               eth_addr_t mac);

bool ether_should_accept(struct eth_hdr *hdr, struct intf *intf);

/* Formats a MAC address from an uint8_t[6] into a character buffer.
   WARNING: `buff` must be at least 18 characters in size as this macro
            does no bounds checking! */
#define fmt_mac(a, buff) \
    sprintf((buff), "%02X:%02X:%02X:%02X:%02X:%02X", \
        (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5])

#endif //NETSTACK_ETHER_H
