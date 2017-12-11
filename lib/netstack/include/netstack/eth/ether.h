#ifndef NETSTACK_ETHER_H
#define NETSTACK_ETHER_H

#include <stdint.h>
#include <linux/types.h>
#include <linux/if_ether.h>

#include <netstack/intf/intf.h>

#define ETH_HDR_LEN  sizeof(struct ethhdr)

static uint8_t ETH_BRD_ADDR[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* Returns a struct ethhdr from the frame->head */
#define eth_hdr(frame) ((struct ethhdr *) (frame)->head)

/* Given a network ether frame buffer, this
 * mutates network values to host values */
struct ethhdr *parse_ether(void *data);

/* Receives an ether frame for processing in the network stack */
void recv_ether(struct intf *intf, struct frame *frame);


/* Formats a MAC address from an uint8_t[6] into a character buffer.
   WARNING: `buff` must be at least 18 characters in size as this macro
            does no bounds checking! */
#define fmt_mac(a, buff) \
    sprintf((buff), "%02X:%02X:%02X:%02X:%02X:%02X", \
        (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5])

/* Returns a matching `const char *` to a ETH_P_* value */
static inline char const *fmt_ethertype(uint16_t ethertype) {
    switch (ethertype) {
        case ETH_P_IP:      return "ETH_P_IP";
        case ETH_P_IPV6:    return "ETH_P_IPV6";
        case ETH_P_ARP:     return "ETH_P_ARP";
        default:            return "ETH_P_?";
    }
}

#endif //NETSTACK_ETHER_H
