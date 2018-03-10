#ifndef NETSTACK_ROUTE_H
#define NETSTACK_ROUTE_H

#include <stdint.h>
#include <pthread.h>
#include <netstack/intf/intf.h>

/* Global route table, for all interfaces */
extern llist_t route_tbl;

/*
 *  IP Routing Table entry
 *
 * e.g.
 *   ip route add 192.168.100.1/24 via 10.123.5.24 dev eth0 metric 50
 *
 *      daddr   -> 192.168.100.1        (required)
 *      netmask -> 255.255.255.0 (/24)  (required else /32 assumed)
 *      gwaddr  -> 10.123.5.24          (optional)
 *      metric  -> 50                   (optional, assumed highest metric)
 *      intf    -> (ptr to) eth0        (required)
 */

struct route_entry {
    addr_t      daddr;      /* Address of route (host addr) */
    addr_t      gwaddr;     /* Address of route gateway */
    addr_t      netmask;    /* Mask (CIDR) denoting route span */
    uint32_t    metric;     /* Route priority*/
    uint8_t     flags;
    struct intf *intf;      /* Corresponding route interface */
};

#define RT_GATEWAY      0x001  /* Route is a gateway */


/*!
 * Given a destination address, find the routable destination address to
 * either deliver the packet directly or be forwarded on to the destination
 * @param addr  packet destination address to find routing address for
 * @return      destination of the next routable hop for addr
 */
struct route_entry *route_lookup(addr_t *addr);

#endif //NETSTACK_ROUTE_H
