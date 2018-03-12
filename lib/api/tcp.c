#include <malloc.h>

#include <netstack/api/tcp.h>
#include <netstack/tcp/tcp.h>
#include <netstack/col/alist.h>

#include <netinet/tcp.h>

void addr_from_sa(addr_t *pAddr, const struct sockaddr *pSockaddr);

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

int connect_tcp(struct inet_sock *inet, const struct sockaddr *addr,
                socklen_t len) {

    // Store remote address in sock->inet
    addr_from_sa(&inet->remaddr, addr);

    // TODO: Look up route and find local address to use

    int ret = tcp_user_open((struct tcp_sock *) inet);

    if (ret < 0)
        returnerr(-ret);
    else
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
            returnerr(EOPNOTSUPP);
        case TCP_NODELAY:
            // Disables TCP Nagle's algorithm
            // Return success as there's nothing to turn off
            return 0;
    }
}
