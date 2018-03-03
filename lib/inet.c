#include <netinet/in.h>

#define NETSTACK_LOG_UNIT "INET"
#include <netstack/ip/ipv4.h>
#include <netstack/tcp/tcp.h>
#include <netstack/checksum.h>

uint16_t inet_ipv4_csum(struct ipv4_hdr *hdr) {
    struct inet_ipv4_phdr pseudo_hdr;
    pseudo_hdr.saddr = hdr->saddr;
    pseudo_hdr.daddr = hdr->daddr;
    pseudo_hdr.hlen  = htons(ntohs(hdr->len) - (uint16_t) ipv4_hdr_len(hdr));
    pseudo_hdr.proto = hdr->proto;
    pseudo_hdr.rsvd  = 0;
    return ~in_csum(&pseudo_hdr, sizeof(pseudo_hdr), 0);
}

struct inet_sock *inet_sock_lookup(llist_t *socks,
                                   addr_t *remaddr, addr_t *locaddr,
                                   uint16_t remport, uint16_t locport) {
    // TODO: Use hashtbl instead of list to lookup sockets

    pthread_mutex_lock(&socks->lock);

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
        pthread_mutex_unlock(&socks->lock);
        return sock;
    }

    pthread_mutex_unlock(&socks->lock);
    return NULL;
}
