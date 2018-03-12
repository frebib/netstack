#include <errno.h>

#include <netstack/api/tcp.h>
#include <netstack/api/socket.h>

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

    LOG(LNTCE, "%s(fd = %d (sock %p), ..)", __func__, fd, sock);

    // connect() on SOCK_DGRAM is valid: https://stackoverflow.com/a/9741966
    switch (sock->type) {
        case SOCK_STREAM:
            return connect_tcp(sock, addr, len);
        default:
            returnerr(ESOCKTNOSUPPORT);
    }
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    LOG(LNTCE, "%s", __func__);
    return sys_bind(fd, addr, len);
}

int listen(int fd, int backlog) {
    LOG(LNTCE, "%s", __func__);
    return sys_listen(fd, backlog);
}

int accept(int fd, struct sockaddr *restrict addr, socklen_t *restrict len) {
    LOG(LNTCE, "%s", __func__);
    return sys_accept(fd, addr, len);
}

#ifdef _GNU_SOURCE
int accept4(int fd, struct sockaddr *restrict addr, socklen_t *restrict len,
            int flags) {
    LOG(LNTCE, "%s", __func__);
    return sys_accept(fd, addr, len);
}
#endif

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    LOG(LNTCE, "%s", __func__);
    return sys_recv(fd, buf, len, flags);
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
    LOG(LNTCE, "%s", __func__);
    return sys_send(fd, buf, len, flags);
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

int getpeername(int fd, struct sockaddr *restrict addr, socklen_t *restrict len) {
    LOG(LNTCE, "%s", __func__);
    return sys_getpeername(fd, addr, len);
}

int getsockname(int fd, struct sockaddr *restrict addr, socklen_t *restrict len) {
    LOG(LNTCE, "%s", __func__);
    return sys_getsockname(fd, addr, len);
}

int getsockopt(int fd, int level, int opt, void *val, socklen_t *restrict len) {
    LOG(LNTCE, "%s", __func__);
    return sys_getsockopt(fd, level, opt, val, len);
}

int setsockopt_sock(struct inet_sock *inet, int level, int opt, const void *val,
                    socklen_t len);
int setsockopt(int fd, int level, int opt, const void *val, socklen_t len) {
    ns_check_sock(fd, sock, {
        return sys_setsockopt(fd, level, opt, val, len);
    });

    LOG(LNTCE, "%s on sock %p: %d = %p", __func__, sock, opt, val);

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

int shutdown(int fd, int how) {
    LOG(LNTCE, "%s", __func__);
    return sys_shutdown(fd, how);
}

int sockatmark(int fd) {
    LOG(LNTCE, "%s", __func__);
    return sys_sockatmark(fd);
}
