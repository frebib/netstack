#ifndef NETSTACK_INET_H
#define NETSTACK_INET_H

#include <stdint.h>
#include <netstack/addr.h>
#include <netstack/inet/ipv4.h>
#include <netstack/intf/intf.h>

struct inet_sock {
    addr_t locaddr;
    addr_t remaddr;
    uint16_t locport;
    uint16_t remport;
    struct intf *intf;      /* Interface is fixed per-socket as the address/port
                              pairs define the socket, and thus the interface */
    uint16_t flags;         /* Socket-level options */
};

/*
    Pseudo-header for calculating TCP/UDP checksum

      0         1         2         3
      0 2 4 6 8 0 2 4 6 8 0 2 4 6 8 0 2
    +--------+--------+--------+--------+
    |           Source Address          |
    +--------+--------+--------+--------+
    |         Destination Address       |
    +--------+--------+--------+--------+
    |  zero  |  proto |     Length      |
    +--------+--------+--------+--------+
*/
struct inet_ipv4_phdr {
    ip4_addr_t saddr;
    ip4_addr_t daddr;
    uint8_t    rsvd;
    uint8_t    proto;
    uint16_t   hlen;
}__attribute((packed));


struct ipv4_hdr;
uint16_t inet_ipv4_csum(struct ipv4_hdr *hdr);

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
struct inet_sock *inet_sock_lookup(llist_t *socks,
                                   addr_t *remaddr, addr_t *locaddr,
                                   uint16_t remport, uint16_t locport);

#endif //NETSTACK_INET_H
