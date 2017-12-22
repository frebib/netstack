#include <stdio.h>
#include <netstack/ip/route.h>
#include <netstack/ip/ipv4.h>

// TODO: Lock route table for writing
struct llist route_tbl = LLIST_INITIALISER;
pthread_mutex_t route_lck = PTHREAD_MUTEX_INITIALIZER;

struct route_entry *route_lookup(uint32_t addr) {
    struct route_entry *bestrt = NULL;

    for_each_llist(&route_tbl) {
        struct route_entry *rt = llist_elem_data();

        // Check for route matching 'addr'
        if ((addr & rt->netmask) == (rt->daddr & rt->netmask)) {
            // Ensure the route is first or lowest metric
            // TODO: Define how routes with the same metric should behave?
            if (bestrt == NULL || (rt->metric < bestrt->metric)) {
                bestrt = rt;
            }
            continue;
        }
    }

    // Return a route if one is found
    if (bestrt != NULL)
        return bestrt;

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
    return bestrt;
}
