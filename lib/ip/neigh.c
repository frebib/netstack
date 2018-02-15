#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <netstack/eth/arp.h>
#include <netstack/ip/route.h>
#include <netstack/ip/ipv4.h>
#include <netstack/ip/neigh.h>
#include <netstack/timer.h>


int neigh_find_route(struct neigh_route *out) {
    
    if (out == NULL || addrzero(&out->daddr))
        return -EINVAL;

    // TODO: Take source address into route calculation
    LOGFN(LVERB, "Finding route to %s", straddr(&out->daddr));
    struct route_entry *rt = route_lookup(&out->daddr);
    if (!rt) {
        // If no route found, return DESTUNREACHABLE error
        LOGFN(LNTCE, "No route to %s found", straddr(&out->daddr));
        return -EHOSTUNREACH;
    }

    struct log_trans t = LOG_TRANS(LTRCE);
    LOGT(&t, "Route found:  daddr %s", straddr(&rt->daddr));
    LOGT(&t, " gwaddr %s", straddr(&rt->gwaddr));
    LOGTFN(&t, " nmask %s", straddr(&rt->netmask));
    LOGT_COMMITFN(&t);

    // TODO: Perform correct route/hardware address lookups when appropriate
    if (rt->intf == NULL) {
        LOGFN(LERR, "Route interface is null for %p", (void *) rt);
        return -EINVAL;
    }

    // Use interface specified in frame, regardless of route, if it is set
    // This may seem strange, however there is likely a reason it has been
    // overridden, even if it is an invalid/different intf for the route/daddr
    if (out->intf != NULL) {
        if (out->intf != rt->intf) {
            LOGFN(LWARN, "[ROUTE] route interface differs from the one in the "
                    "sending packet (%s != %s", rt->intf->name, out->intf->name);
        }
    } else {
        // Update interface now it is known from route
        out->intf = rt->intf;
    }

    // If route is a gateway, send to the gateway, otherwise send directly
    out->nexthop = (rt->flags & RT_GATEWAY) ? rt->gwaddr : out->daddr;
    out->flags = rt->flags;

    // TODO: Make ARP/NDP request now, instead of later to reduce waiting time

    return 0;
}

int neigh_send(struct frame *frame, uint8_t proto, uint16_t flags,
               uint16_t sock_flags, addr_t *daddr, addr_t *saddr) {

    struct neigh_route rt = {
            .daddr = *daddr,
            .intf = frame->intf
    };
    if (saddr != NULL)
        rt.saddr = *saddr;

    return neigh_find_route(&rt) ||
           neigh_send_to(&rt, frame, proto, flags, sock_flags);
}

int neigh_send_to(struct neigh_route *rt, struct frame *frame, uint8_t proto,
                  uint16_t flags, uint16_t sock_flags) {

    struct intf *intf = rt->intf;

    // If the source-address is non-zero (set to a value), use it
    if (!addrzero(&rt->saddr)) {
        // Ensure the saddr passed is valid for the sending interface
        if (!intf_has_addr(intf, &rt->saddr)) {
            LOGFN(LWARN, "The requested address %s is invalid for "
                    "interface %s", straddr(&rt->saddr), intf->name);

            // It is not an error to send a packet with a mis-matched address,
            // however strange it may seem, though, yes, it _is_ stupid.
            //return -EADDRNOTAVAIL;
        }
    }
    else {
        // Find the default address of the interface matching daddr->proto
        addr_t def_addr = {.proto = rt->daddr.proto};
        if (!intf_get_addr(intf, &def_addr)) {
            LOG(LERR, "Could not get interface address for %s", intf->name);
            return -EADDRNOTAVAIL;
        }
        if (def_addr.address == 0) {
            LOG(LERR, "Interface %s has no address for IPv4", intf->name);
            return -EADDRNOTAVAIL;
        }

        // Set source-address to address obtained from rt->intf
        rt->saddr = def_addr;
    }


    // Don't assume ARP. IPv6 uses NDP for neighbour discovery
    switch (rt->daddr.proto) {
        case PROTO_IPV4:
            LOGFN(LTRCE, "Finding %s addr for nexthop: %s",
                  strproto(rt->nexthop.proto), straddr(&rt->nexthop));

            struct arp_entry *entry;
            entry = arp_get_entry(&intf->arptbl, intf->proto, &rt->nexthop);

            if (entry != NULL) {
                LOGFN(LTRCE, "ARP entry matching %s found", straddr(&rt->nexthop));

                // Entry is resolved, send the frame!
                if (entry->state & ARP_RESOLVED) {
                    LOGFN(LTRCE, "ARP entry is resolved. Sending frame");

                    // Take a copy of the hwaddr so we can release the lock
                    addr_t hwaddr = entry->hwaddr;
                    // Unlock entry after accessing it
                    pthread_mutex_unlock(&entry->lock);

                    // Route and hardware address obtained, send the packet and ret
                    int ret = ipv4_send(frame, proto, flags, rt->daddr.ipv4,
                                     rt->saddr.ipv4, &hwaddr);

                    return ret;
                } else {
                    // Unlock anyway
                    pthread_mutex_unlock(&entry->lock);
                }
            }

            // No existing ARP entry found. Request one
            
            // Increase the refcount so other threads can use frame
            frame_incref(frame);

            // Enqueue the outgoing packet and request the hardware address
            struct queued_pkt *pending = malloc(sizeof(struct queued_pkt));
            pending->retwait = (retlock_t) RETLOCK_INITIALISER;
            pending->retwait.val = -1; // Start with initial error value
            pending->frame = frame;
            pending->saddr = rt->saddr;
            pending->daddr = rt->daddr;
            pending->nexthop = rt->nexthop;
            pending->proto = proto;
            pending->flags = flags;
            pending->sock_flags = sock_flags;

            // Lock retlock atomically with respect to 'pending'
            retlock_lock(&pending->retwait);
            LOGFN(LDBUG, "Queuing packet for later sending");
            llist_append(&intf->neigh_outqueue, pending);

            // TODO: Rate limit ARP requests to prevent flooding

            // Convert proto_t value to ARP_HW_* for transmission
            uint16_t arphw = arp_proto_hw(intf->proto);
            int err = arp_send_req(intf, arphw, &rt->saddr, &rt->nexthop);
            if (err) {
                LOGE(LNTCE, "arp_send_req");
                return err;
            }

            // TODO: Use inet_socket for passing options to neighbour

            int ret = 0;
            struct timespec to = {.tv_sec = ARP_WAIT_TIMEOUT};

            // If NONBLOCK flag is set, don't wait, just set the expiry timer
            if (sock_flags & O_NONBLOCK) {
                // Set the timeout to destroy the
                void *fn = (void (*)(void *)) neigh_queue_expire;
                timeout_set(&pending->timeout, fn, pending, to.tv_sec, to.tv_nsec);

                retlock_unlock(&pending->retwait);

                // Indicate that the packet was queued
                ret = -EWOULDBLOCK;
            } else {
                LOGFN(LDBUG, "Requesting hwaddr for %s, (wait %lds)",
                      straddr(&rt->nexthop), to.tv_sec);

                // Unlock the frame before pausing thread to prevent deadlock
                frame_unlock(frame);

                // Wait for packet to be sent, or timeout to occur
                err = retlock_timedwait_nolock(&pending->retwait, &to, &ret);

                LOG(LDBUG, "retlock_timed_wait returned %d", ret);

                // Handle timeout
                if (err == ETIMEDOUT)
                    ret = -EHOSTUNREACH;
                // Handle other generic errors
                else if (err)
                    ret = -err;

                // Deallocate dynamic memory
                free(pending);

                frame_lock(frame, SHARED_RD);
            }

            return ret;

        default:
            return -EPROTONOSUPPORT;
    }
}

void neigh_update_hwaddr(struct intf *intf, addr_t *daddr, addr_t *hwaddr) {
    pthread_mutex_lock(&intf->neigh_outqueue.lock);

    if (intf->neigh_outqueue.length > 0)
        LOG(LVERB, "Attempting to process %zu queued packets for %s",
            intf->neigh_outqueue.length, intf->name);

    for_each_llist(&intf->neigh_outqueue) {
        struct queued_pkt *tosend = llist_elem_data();

        // Lock the tosend entry to check address
        retlock_lock(&tosend->retwait);

        // Found entry to update and send
        if (addreq(&tosend->nexthop, daddr)) {

            // Cancel the timeout (asap) if one is pending
            if (tosend->sock_flags & O_NONBLOCK) {
                LOG(LDBUG, "Clearing neigh_queue_expire timeout");
                timeout_clear(&tosend->timeout);
            }

            struct log_trans trans = LOG_TRANS(LDBUG);
            LOGT(&trans, "Sending queued packet to %s",
                 straddr(&tosend->nexthop));
            LOGT(&trans, " with hwaddr %s", straddr(hwaddr));
            LOGT_COMMIT(&trans);

            // Remove queued packet from queue and unlock list
            llist_remove_nolock(&intf->neigh_outqueue, tosend);
            pthread_mutex_unlock(&intf->neigh_outqueue.lock);

            // Lock the frame for writing so it can be written to
            frame_lock(tosend->frame, SHARED_RW);

            // Send the queued frame!
            int ret = ipv4_send(tosend->frame, tosend->proto, tosend->flags,
                                tosend->daddr.ipv4, tosend->saddr.ipv4, hwaddr);

            // Now that the frame has been dispatched, we can deref it
            frame_decref(tosend->frame);

            LOG(LDBUG, "Queued packet sent to %s", straddr(&tosend->nexthop));

            // Signal all waiting threads with the return value
            int err;
            if ((err = retlock_broadcast_nolock(&tosend->retwait, ret)))
                LOGSE(LERR, "retlock_broadcast_nolock", -err);

            return;
        }
        // Unlock regardless and continue
        retlock_unlock(&tosend->retwait);
    }

    pthread_mutex_unlock(&intf->neigh_outqueue.lock);
}

void neigh_queue_expire(struct queued_pkt *pending) {
    // Obtain the lock before attempting to clear any values
    retlock_lock(&pending->retwait);

    LOG(LNTCE, "Queued packet for %s expired. Destroying it",
        straddr(&pending->daddr));

    // Remove pending frame from queue
    struct intf *intf = pending->frame->intf;
    llist_remove(&intf->neigh_outqueue, pending);
    frame_decref(pending->frame);

    retlock_unlock(&pending->retwait);
    // Tough doo-doo if you manage to lock the queued packet now, sorry

    // Deallocate memory
    timeout_clear(&pending->timeout);
    free(pending);
}