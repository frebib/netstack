#include <stdio.h>

#define NETSTACK_LOG_UNIT "ROUTE"
#include <netstack/log.h>
#include <netstack/ip/route.h>

llist_t route_tbl = LLIST_INITIALISER;

inline static uint8_t *bitwise_and(uint8_t *out, const uint8_t *a,
                                   const uint8_t *b, const size_t len) {
    for (uint16_t i = 0; i < len; ++i)
        out[i] = a[i] & b[i];
    return out;
}

struct route_entry *route_lookup(addr_t *addr) {
    struct route_entry *bestrt = NULL;

    pthread_mutex_lock(&route_tbl.lock);

    for_each_llist(&route_tbl) {
        struct route_entry *rt = llist_elem_data();

        // Get length of address for comparison
        size_t len = addrlen(addr->proto);
        uint8_t addrnet[len], daddrnet[len];
        // Bitwise AND (addr & rt->netmask) and (addr & rt->daddr)
        bitwise_and(addrnet, &addr->address, &rt->netmask.address, len);
        bitwise_and(daddrnet, &rt->daddr.address, &rt->netmask.address, len);

        // Check for route matching 'addr'
        if (memcmp(addrnet, daddrnet, len) == 0) {
            // TODO: Define how routes with the same metric should behave?
            // Ensure the route is first or lowest metric
            if (bestrt == NULL || (rt->metric < bestrt->metric))
                bestrt = rt;
        }
    }

    // Return a route if one is found
    if (bestrt != NULL) {
        pthread_mutex_unlock(&route_tbl.lock);
        return bestrt;
    }

    // Look instead for default routes
    for_each_llist(&route_tbl) {
        struct route_entry *rt = llist_elem_data();

        // Find any routes marked as gateway
        if (rt->flags & RT_GATEWAY) {
            if (bestrt == NULL || (rt->metric < bestrt->metric)) {
                bestrt = rt;
            }
        }
    }
    pthread_mutex_unlock(&route_tbl.lock);

    return bestrt;
}
