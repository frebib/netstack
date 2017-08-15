#ifndef NETD_ETHER_H
#define NETD_ETHER_H

#include <stdint.h>
#include <linux/types.h>

#include <libnet/frame.h>

#include "ethertype.h"

#define ETH_HDR_LEN  sizeof(struct eth_hdr)
#define ETH_ADDR_LEN 6      /* # of octets per address */

/* Ethernet frame header */
struct eth_hdr {
    uint8_t saddr[ETH_ADDR_LEN];  /* Source address */
    uint8_t daddr[ETH_ADDR_LEN];  /* Destination address */
    __be16 ethertype;   /* Frame payload type, see ethertype.h */
}__attribute((packed));


/* Returns a struct eth_hdr from the frame->head */
struct eth_hdr *eth_hdr(struct frame *frame);

struct eth_hdr *recv_ether(struct frame *frame);

/* String formatting functions */

/* Formats a MAC address from an uint8_t[6] into a character buffer.
   WARNING: `buff` must be at least 18 characters in size as this macro
            does no bounds checking! */
#define fmt_mac(a, buff) \
    sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X", \
        a[0], a[1], a[2], a[3], a[4], a[5])

#endif //NETD_ETHER_H
