#ifndef NETSTACK_INET_H
#define NETSTACK_INET_H

#include <stdint.h>
#include <netstack/addr.h>

struct inet_sock {
    addr_t locaddr;
    addr_t remaddr;
    uint16_t locport;
    uint16_t remport;
};

/*!
 * Finds a matching socket, including listening and closed sockets.
 * Will return wildcard address sockets for any match (0.0.0.0 or equiv
 * addrs) if any are found (e.g. TCP_LISTEN should be source: 0.0.0.0:0)
 *
 * Note: Some socket objects should be treated as immutable, such as those
 * with TCP_LISTEN and a new one inserted specific to the connection.
 *
 * Courtesy of @Steamlined: https://i.giphy.com/media/czwo5mMtaknhC/200.gif
 *
 * @param remaddr remote address
 * @param locaddr local address
 * @param remport remote port
 * @param locport local port
 * @return a matching inet_sock object, or NULL if no matches found
 */
static struct inet_sock *inet_sock_lookup(struct llist *socks,
                                   addr_t *remaddr, addr_t *locaddr,
                                   uint16_t remport, uint16_t locport) {
    // TODO: Use hashtbl instead of list to lookup sockets
    // TODO: Lock llist socks for concurrent access

    for_each_llist(socks) {
        struct inet_sock *sock = llist_elem_data();
        if (!sock) {
            LOG(LWARN, "tcp_sockets contains a NULL element!");
            continue;
        }


        // struct log_trans t = LOG_TRANS(LDBUG);
        // LOGT(&t, "remote: %s:%hu ", straddr(remaddr), remport);
        // LOGT(&t, "local: %s:%hu ", straddr(locaddr), locport);
        // LOGT_COMMIT(&t);

        // Check matching saddr assuming it's non-zero
        if (!addrzero(&sock->remaddr) && !addreq(remaddr, &sock->remaddr)) {
            // LOG(LDBUG, "Remote address %s doesn't match", straddr(remaddr));
            // LOG(LDBUG, "   compared to %s", straddr(&sock->remaddr));
            continue;
        }
        // Check matching remport assuming it's non-zero
        if (sock->remport != 0 && sock->remport != remport) {
            // LOG(LDBUG, "Remote port %hu doesn't match %hu", sock->remport, remport);
            continue;
        }

        // Check matching daddr assuming it's non-zero
        if (!addrzero(&sock->locaddr) && !addreq(locaddr, &sock->locaddr)) {
            // LOG(LDBUG, "Local address %s doesn't match", straddr(remaddr));
            // LOG(LDBUG, "  compared to %s", straddr(&sock->remaddr));
            continue;
        }
        if (locport != sock->locport) {
            // LOG(LDBUG, "Local port %hu doesn't match %hu", sock->locport, remport);
            continue;
        }

        // t = (struct log_trans) LOG_TRANS(LDBUG);
        // LOGT(&t, "Found matching tcp_sock\t");
        // LOGT(&t, "\tsource: %s:%hu ", straddr(&sock->remaddr), sock->remport);
        // LOGT(&t, "\tdest: %s:%hu ", straddr(&sock->locaddr), sock->locport);
        // LOGT_COMMIT(&t);

        // Passed all matching checks
        return sock;
    }

    return NULL;
}

#endif //NETSTACK_INET_H
