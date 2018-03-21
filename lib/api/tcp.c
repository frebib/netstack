#include <malloc.h>

#include <netstack/api/tcp.h>
#include <netstack/tcp/tcp.h>
#include <netstack/col/alist.h>

#include <netinet/tcp.h>
#include <netstack/inet/route.h>


int socket_tcp(int domain, int type, int protocol) {
    // elem is a pointer to the list element
    struct inet_sock **elem = NULL, *sock;
    int fd = (int) alist_add(&ns_sockets, (void **) &elem);
    fd += NS_MIN_FD;

    *elem = calloc(1, sizeof(struct tcp_sock));
    sock = *elem;
    sock->locaddr.proto = PROTO_IPV4;
    sock->remaddr.proto = PROTO_IPV4;
    tcp_sock_init((struct tcp_sock *) sock);
    LOG(LVERB, "creating new TCP/IPv4 socket %p (fd %d)", sock, fd);

    // Append optional socket flags if specified in type
    if (type & SOCK_CLOEXEC)
        sock->flags |= O_CLOEXEC;
    if (type & SOCK_NONBLOCK)
        sock->flags |= O_NONBLOCK;

    sock->type = SOCK_STREAM;

    return fd;
}

ssize_t recv_tcp(struct inet_sock *inet, void *buf, size_t len, int flags) {
    struct tcp_sock *sock = (struct tcp_sock *) inet;

    retns(tcp_user_recv(sock, buf, len, flags));
}

ssize_t send_tcp(struct inet_sock *inet, const void *buf, size_t len, int flags) {
    struct tcp_sock *sock = (struct tcp_sock *) inet;

    retns(tcp_user_send(sock, buf, len, flags));
}

int connect_tcp(struct inet_sock *inet, const struct sockaddr *addr,
                socklen_t len) {

    struct tcp_sock *sock = (struct tcp_sock *) inet;

    // Store remote address in sock->inet
    addr_from_sa(&inet->remaddr, &inet->remport, addr);

    // Look up route and find local address to use
    struct route_entry *rt = route_lookup(&inet->remaddr);
    
    if (rt == NULL)
        returnerr(EHOSTUNREACH);
    
    addr_t *locaddr = (addr_t *) llist_peek(&rt->intf->inet);
    if (locaddr == NULL)
        returnerr(EADDRNOTAVAIL);

    inet->intf = rt->intf;
    inet->locaddr = *locaddr;

    // Extract the local port
    addr_from_sa(NULL, &inet->locport, addr);
    // Choose a random outgoing port if one isn't specified
    if (inet->locport == 0)
        inet->locport = tcp_randomport();

    // TODO: Ensure chosen outgoing TCP port isn't in use already

    retns(tcp_user_open(sock));
}

int getsockopt_tcp(struct inet_sock *inet, int level, int opt, void *val,
                   socklen_t *restrict len) {

    struct tcp_sock *sock = (struct tcp_sock *) inet;

    // See tcp(7) for descriptions of these options
    switch (opt) {
        case TCP_CONGESTION:
        case TCP_CORK:
        case TCP_DEFER_ACCEPT:
        case TCP_KEEPCNT:
        case TCP_KEEPIDLE:
        case TCP_KEEPINTVL:
        case TCP_LINGER2:
        case TCP_MAXSEG:
        case TCP_INFO:
        case TCP_USER_TIMEOUT:
        case TCP_WINDOW_CLAMP:
        default:
            // These options are not implemented so just throw an error
            returnerr(ENOPROTOOPT);
        case TCP_NODELAY:
            // Is always disabled
            val = 0;
            break;
    }
    return 0;
}

int setsockopt_tcp(struct inet_sock *inet, int level, int opt, const void *val,
                   socklen_t len) {

    struct tcp_sock *sock = (struct tcp_sock *) inet;

    // See tcp(7) for descriptions of these options
    switch (opt) {
        case TCP_CONGESTION:
        case TCP_CORK:
        case TCP_DEFER_ACCEPT:
        case TCP_KEEPCNT:
        case TCP_KEEPIDLE:
        case TCP_KEEPINTVL:
        case TCP_LINGER2:
        case TCP_MAXSEG:
        case TCP_INFO:
        case TCP_USER_TIMEOUT:
        case TCP_WINDOW_CLAMP:
        default:
            // These options are not implemented so just throw an error
            returnerr(ENOPROTOOPT);
        case TCP_NODELAY:
            // Disables TCP Nagle's algorithm
            // Return success as there's nothing to turn off
            return 0;
    }
}

int shutdown_tcp(struct inet_sock *inet, int how) {

    struct tcp_sock *sock = (struct tcp_sock *) inet;

    if (how == SHUT_WR || how == SHUT_RDWR) {
        retns(tcp_user_close(sock));
    }

    // TODO: Handle SHUT_RD in shutdown_tcp

    return 0;
}
