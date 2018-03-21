#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/param.h>

#include <netstack/api/tcp.h>
#include <netstack/api/socket.h>
#include <netstack/tcp/tcp.h>

// Global list of sockets visible to this netstack instance
ns_socket_t ns_sockets;

int socket(int domain, int type, int protocol) {
    LOG(LNTCE, "%s", __func__);

    // Prevent optional flags breaking type match
    switch (type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) {
        // Handle TCP
        case SOCK_STREAM:
            if (protocol != 0 && protocol != IPPROTO_TCP)
                returnerr(EINVAL);

            switch (domain) {
                case AF_INET:
                    return socket_tcp(domain, type, protocol);
                default:
                    // Only AF_INET is supported currently
                    returnerr(EAFNOSUPPORT);
            }
        default:
            // For anything we can't handle, pass on to the default function
            return sys_socket(domain, type, protocol);
    }
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    ns_check_sock(fd, sock, {
        return sys_connect(fd, addr, len);
    });

    // connect() on SOCK_DGRAM is valid: https://stackoverflow.com/a/9741966
    switch (sock->type) {
        case SOCK_STREAM:
            return connect_tcp(sock, addr, len);
        default:
            returnerr(ESOCKTNOSUPPORT);
    }
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    ns_check_sock(fd, sock, {
        return sys_bind(fd, addr, len);
    });

    switch (sock->locaddr.proto) {
        case PROTO_IPV4:
            addr_from_sa(&sock->locaddr, &sock->locport, addr);
            return 0;
        default:
            returnerr(ESOCKTNOSUPPORT);
    }
}

int listen(int fd, int backlog) {
    ns_check_sock(fd, sock, {
        return sys_listen(fd, backlog);
    });

    switch (sock->type) {
        case SOCK_STREAM:
            retns(tcp_user_listen((struct tcp_sock *) sock, (int) backlog));
        default:
            returnerr(ESOCKTNOSUPPORT);
    }
}

int accept(int fd, struct sockaddr *restrict addr, socklen_t *restrict len) {
    ns_check_sock(fd, sock, {
        return sys_accept(fd, addr, len);
    });

    switch (sock->type) {
        case SOCK_STREAM: {
            struct tcp_sock *client;
            int ret = tcp_user_accept((struct tcp_sock *) sock, &client);
            if (ret < 0)
                returnerr(-ret);

            struct tcp_sock **elem = NULL;
            int fd = (int) alist_add(&ns_sockets, (void **) &elem);
            fd += NS_MIN_FD;

            *elem = client;

            return fd;
        }
        default:
            returnerr(ESOCKTNOSUPPORT);
    }
}

#ifdef _GNU_SOURCE
int accept4(int fd, struct sockaddr *restrict addr, socklen_t *restrict len,
            int flags) {
    LOG(LNTCE, "%s", __func__);
    return sys_accept(fd, addr, len);
}
#endif

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    ns_check_sock(fd, sock, {
        return sys_recv(fd, buf, len, flags);
    });

    switch (sock->type) {
        case SOCK_STREAM:
            return recv_tcp(sock, buf, len, flags);
        default:
            returnerr(ESOCKTNOSUPPORT);
    }
}

ssize_t read(int fd, void *buf, size_t count) {
    LOG(LNTCE, "%s", __func__);
    return sys_read(fd, buf, count);
}

ssize_t recvfrom(int fd, void *restrict buf, size_t len, int flags,
                 struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    LOG(LNTCE, "%s", __func__);
    return sys_recvfrom(fd, buf, len, flags, addr, addrlen);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    LOG(LNTCE, "%s", __func__);
    return sys_recvmsg(fd, msg, flags);
}

ssize_t write(int fd, const void *buf, size_t count) {
    LOG(LNTCE, "%s", __func__);
    return sys_write(fd, buf, count);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    ns_check_sock(fd, sock, {
        return sys_send(fd, buf, len, flags);
    });

    LOG(LNTCE, "%s(fd = %d (sock %p), ..)", __func__, fd, sock);

    switch (sock->type) {
        case SOCK_STREAM:
            return send_tcp(sock, buf, len, flags);
        default:
            returnerr(ESOCKTNOSUPPORT);
    }
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr * addr, socklen_t addrlen) {
    LOG(LNTCE, "%s", __func__);
    return sys_sendto(fd, buf, len, flags, addr, addrlen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    LOG(LNTCE, "%s", __func__);
    return sys_sendmsg(fd, msg, flags);
}

int poll(struct pollfd fds[], nfds_t nfds, int timeout) {
    LOG(LNTCE, "%s", __func__);
    return sys_poll(fds, nfds, timeout);
}

int select(int nfds, fd_set *restrict readfds, fd_set *restrict writefds,
                  fd_set *restrict errorfds,
                  struct timeval *restrict timeout) {
    LOG(LNTCE, "%s", __func__);
    return sys_select(nfds, readfds, writefds, errorfds, timeout);
}

int getpeername(int fd, struct sockaddr *restrict addr, socklen_t *restrict len) {
    LOG(LNTCE, "%s", __func__);
    return sys_getpeername(fd, addr, len);
}

int getsockname(int fd, struct sockaddr *restrict addr, socklen_t *restrict len) {
    LOG(LNTCE, "%s", __func__);
    return sys_getsockname(fd, addr, len);
}

int getsockopt_sock(struct inet_sock *inet, int level, int opt, void *val,
                    socklen_t *restrict len);
int getsockopt(int fd, int level, int opt, void *val, socklen_t *restrict len) {
    ns_check_sock(fd, sock, {
        return sys_getsockopt(fd, level, opt, val, len);
    });

    LOG(LNTCE, "%s on sock %p: %d = ?", __func__, sock, opt);

    switch (level) {
        case SOL_SOCKET:
            return getsockopt_sock(sock, level, opt, val, len);
        case SOL_TCP:
            if (sock->type != SOCK_STREAM)
                returnerr(ENOPROTOOPT);
            return getsockopt_tcp(sock, level, opt, val, len);
        default:
            returnerr(ENOPROTOOPT);
    }
}
int getsockopt_sock(struct inet_sock *sock, int level, int opt, void *val,
                    socklen_t *restrict len) {

    switch (opt) {
        case SO_ERROR:
            if (sock->type == SOCK_STREAM) {
                // Get TCP error for TCP sockets
                struct tcp_sock *tcp_sock = (struct tcp_sock *) sock;
                size_t size = MIN((size_t) len, sizeof(tcp_sock->error));
                memcpy(val, &tcp_sock->error, size);
                return 0;
            }
        default:
            returnerr(ENOPROTOOPT);
    }
}

int setsockopt_sock(struct inet_sock *inet, int level, int opt, const void *val,
                    socklen_t len);
int setsockopt(int fd, int level, int opt, const void *val, socklen_t len) {
    ns_check_sock(fd, sock, {
        return sys_setsockopt(fd, level, opt, val, len);
    });

    LOG(LNTCE, "%s on sock %p: %d = %d", __func__, sock, opt, *(int *)val);

    switch (level) {
        case SOL_SOCKET:
            return setsockopt_sock(sock, level, opt, val, len);
        case SOL_TCP:
            if (sock->type != SOCK_STREAM)
                returnerr(ENOPROTOOPT);
            return setsockopt_tcp(sock, level, opt, val, len);
        default:
            returnerr(ENOPROTOOPT);
    }
}

int setsockopt_sock(struct inet_sock *sock, int level, int opt, const void *val,
                    socklen_t len) {
    returnerr(ENOPROTOOPT);
}

int fcntl(int fd, int cmd, ...) {
    va_list args;
    void *arg;
    va_start(args, cmd);
    arg = va_arg(args, void *);
    va_end(args);

    ns_check_sock(fd, sock, {
        return sys_fcntl(fd, cmd, arg);
    });

    int val;
    va_start(args, cmd);
    val = va_arg(args, int);
    va_end(args);

    va_end(args);
    switch (cmd) {
        case F_DUPFD:
        case F_DUPFD_CLOEXEC: {
            struct inet_sock **elem = NULL;
            int dupfd = (int) alist_add(&ns_sockets, (void **) &elem);
            *elem = sock;
            if (sock->type == SOCK_STREAM)
                tcp_sock_incref((struct tcp_sock *) sock);
            return dupfd + NS_MIN_FD;
        }
        case F_GETFL:
            return sock->flags;
        case F_SETFL:
            sock->flags = (uint16_t) val;
            return 0;
        case F_GETFD:
        case F_SETFD:
        case F_GETOWN:
        case F_SETOWN:
        case F_GETLK:
        case F_SETLK:
        case F_SETLKW:
        default:
            returnerr(EINVAL);
            break;
    }

    returnerr(EINVAL);
}

int shutdown(int fd, int how) {
    ns_check_sock(fd, sock, {
        return sys_shutdown(fd, how);
    });

    LOG(LNTCE, "%s(fd = %d (sock %p), ..)", __func__, fd, sock);

    switch (sock->type) {
        case SOCK_STREAM:
            return shutdown_tcp(sock, how);
        default:
            returnerr(ENOTCONN);
    }
}

int sockatmark(int fd) {
    LOG(LNTCE, "%s", __func__);
    return sys_sockatmark(fd);
}
