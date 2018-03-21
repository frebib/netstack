#ifndef NETSTACK_NEIGH_H
#define NETSTACK_NEIGH_H

#include <fcntl.h>

#include <netstack/addr.h>
#include <netstack/col/llist.h>
#include <netstack/lock/retlock.h>
#include <netstack/time/timer.h>

/*
 * Neighbour provides functionality to dispatch internet protocol packets
 * onto an IP network, routing them appropriately. It also handles resolving
 * the hardware addresses and dispatching queued packets to those devices as
 * hardware addresses are resolved.
 *
 *   Neighbour: An immediately connected device (within the same subnet) that
 *   is zero hops away. This is usually either the destination device or the
 *   local gateway router.
 */

struct queued_pkt {
    retlock_t retwait;
    atomic_uchar refcount;
    timeout_t timeout;
    struct frame *frame;
    addr_t saddr;
    addr_t daddr;
    addr_t nexthop;
    uint8_t proto;
    uint16_t flags;
    uint16_t sock_flags;
};

/*!
 * Stores intermediary routing information for a given destination address,
 * optional source address and interface. This can be used to pre-determine
 * routing information before actually sending the packet, removing the
 * duplicated route lookup
 */
struct neigh_route {
    struct intf *intf;      /* Routable interface of next-hop */
    addr_t nexthop;         /* IP address of neighbouring host next-hop */
    addr_t saddr;           /* Source address of route */
    addr_t daddr;           /* Destination address of route*/
    uint8_t flags;          /* Route flags: see <netstack/inet/route.h> */
};

/*!
 * Resolves the route to the next-hop for a given destination address.
 * Pass a pointer to a neigh_route struct with at least the daddr field set to
 * the destination address of the route.
 * Optionally, the intf and saddr fields can be filled out with supporting
 * detail to persuade the route choice.
 * Most importantly the intf and nexthop addresses are completed which are
 * the bare minimum required for correctly routing a packet.
 * @return the neigh_route struct, `out`, fully completed with route details.
 */
int neigh_find_route(struct neigh_route *out);

/*!
 * Sends an IP packet to a neighbour, being the next-hop in the route.
 * Given a destination address, a route is found and hardware address
 * looked-up and the packet is forwarded on.
 * Directly calls neigh_find_route() and then neigh_send_to()
 */
int neigh_send(struct frame *frame, uint8_t proto, uint16_t flags,
               uint16_t sock_flags, addr_t *daddr, addr_t *saddr);

/*!
 * Sends an IP packet to a neighbour, as per the neigh_route structure.
 * Packets that cannot be dispatched straight away will be queued and sent as
 * soon as the required lower-layer information is available.
 * @param rt    route information about nexthop
 * @param frame frame to send or queue
 * @param proto IP header protocol field
 * @param flags IP flags
 * @return 0 on success, otherwise if error
 */
int neigh_send_to(struct neigh_route *rt, struct frame *frame, uint8_t proto,
                  uint16_t flags, uint16_t sock_flags);

/*!
 * Updates the neighbour processing of a hardware address update that can be
 * used to send queued packets
 * @param intf   interface the hwaddr relates to
 * @param daddr  IP address that the hwaddr relates to
 * @param hwaddr the hwaddr that has updated
 */
void neigh_update_hwaddr(struct intf *intf, addr_t *daddr, addr_t *hwaddr);

/*!
 * Timeout handler function for cleaning up expired queued packets.
 * @param pending pending packet to cleanup and deallocate
 */
void neigh_queue_expire(struct queued_pkt *pending);

void neigh_queue_cancel(struct intf *intf);

#define neigh_queued_lock(qd) \
    do { \
        atomic_fetch_add(&(qd)->refcount, 1); \
        retlock_lock(&(qd)->retwait); \
    } while (0)

#define neigh_queued_unlock(qd) \
    do { \
        atomic_fetch_sub(&(qd)->refcount, 1); \
        retlock_unlock(&(qd)->retwait); \
    } while (0)

#define neigh_queued_free(qd) \
    do { \
        if (atomic_fetch_sub(&(qd)->refcount, 2) <= 2) { \
            retlock_unlock(&(qd)->retwait); \
            free(qd); \
        } else { \
            retlock_unlock(&(qd)->retwait); \
        } \
    } while (0)

#endif //NETSTACK_NEIGH_H
