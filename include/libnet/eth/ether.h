#ifndef NETD_ETHER_H
#define NETD_ETHER_H

#include <stdint.h>
#include <linux/types.h>

#include <libnet/interface.h>

#include "ethertype.h"

#define ETH_HDR_LEN  sizeof(struct eth_hdr)
#define ETH_ADDR_LEN 6      /* # of octets per address */

/* Temporary define constant values for debugging */
#define INTF_NAME "enp3s0"
#define ETH_ADDR ((uint8_t[6]){ 0x44, 0x8A, 0x5B, 0x9F, 0x50, 0x5A })


/* Ethernet frame header */
struct eth_hdr {
    uint8_t daddr[ETH_ADDR_LEN];  /* Destination address */
    uint8_t saddr[ETH_ADDR_LEN];  /* Source address */
    __be16 ethertype;   /* Frame payload type, see ethertype.h */
}__attribute((packed));


/* Returns a struct eth_hdr from the frame->head */
#define eth_hdr(frame) ((struct eth_hdr *) (frame)->head)

/* Given a network ether frame buffer, this
 * mutates network values to host values */
struct eth_hdr *parse_ether(void *data);

/* Receives an ether frame for processing in the network stack */
void recv_ether(struct interface *intf, struct frame *frame);


/* Formats a MAC address from an uint8_t[6] into a character buffer.
   WARNING: `buff` must be at least 18 characters in size as this macro
            does no bounds checking! */
#define fmt_mac(a, buff) \
    sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X", \
        (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5])

#endif //NETD_ETHER_H
