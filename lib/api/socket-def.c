#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stddef.h>
#include <dlfcn.h>

#include <netstack/api/socket.h>

/*
 * This file contains permanent definitions for function pointers defined in
 * <netstack/api/socket.h> to provide constant reference to the same in-memory
 * pointer between compilation units.
 */

int (*sys_socket)(int, int, int) = NULL;

int (*sys_connect)(int, const struct sockaddr *, socklen_t) = NULL;

int (*sys_bind)(int, const struct sockaddr *, socklen_t) = NULL;

int (*sys_listen)(int, int) = NULL;

int (*sys_accept)(int, struct sockaddr *restrict, socklen_t *restrict) = NULL;

#ifdef _GNU_SOURCE
int (*sys_accept4)(int fd, struct sockaddr *restrict addr,
                   socklen_t *restrict len, int flags) = NULL;
#endif

int (*sys_getpeername)(int, struct sockaddr *restrict, socklen_t *restrict) = NULL;

int (*sys_getsockname)(int, struct sockaddr *restrict, socklen_t *restrict) = NULL;

int (*sys_getsockopt)(int, int, int, void *restrict, socklen_t *restrict) = NULL;

int (*sys_setsockopt)(int, int, int, const void *, socklen_t) = NULL;

int (*sys_fcntl)(int fd, int cmd, ...) = NULL;

int (*sys_shutdown)(int, int) = NULL;

int (*sys_sockatmark)(int) = NULL;

ssize_t (*sys_recv)(int, void *, size_t, int) = NULL;

ssize_t (*sys_recvfrom)(int, void *restrict, size_t, int, struct sockaddr *restrict,
                        socklen_t *restrict) = NULL;

ssize_t (*sys_recvmsg)(int, struct msghdr *, int) = NULL;

ssize_t (*sys_send)(int, const void *, size_t, int) = NULL;

ssize_t (*sys_sendto)(int, const void *, size_t, int, const struct sockaddr *,
                      socklen_t) = NULL;

ssize_t (*sys_sendmsg)(int, const struct msghdr *, int) = NULL;

int (*sys_ioctl)(int __fd, unsigned long int __request, ...) = NULL;

int (*sys_poll)(struct pollfd fds[], nfds_t nfds, int timeout) = NULL;

int (*sys_select)(int nfds, fd_set *restrict readfds, fd_set *restrict writefds,
                  fd_set *restrict errorfds,
                  struct timeval *restrict timeout) = NULL;

ssize_t (*sys_read)(int fd, void *buf, size_t count) = NULL;

ssize_t (*sys_write)(int fd, const void *buf, size_t count) = NULL;

ssize_t (*sys_close)(int fd) = NULL;

ssize_t (*sys_sendfile)(int out_fd, int in_fd, off_t *offset, size_t count) = NULL;


int ns_api_init() {
    alist_init(&ns_sockets, 4);

    sys_socket = dlsym(RTLD_NEXT, "socket");
    sys_connect = dlsym(RTLD_NEXT, "connect");
    sys_bind = dlsym(RTLD_NEXT, "bind");
    sys_listen = dlsym(RTLD_NEXT, "listen");
    sys_accept = dlsym(RTLD_NEXT, "accept");
#ifdef _GNU_SOURCE
    sys_accept4 = dlsym(RTLD_NEXT, "accept4");
#endif
    sys_getpeername = dlsym(RTLD_NEXT, "getpeername");
    sys_getsockname = dlsym(RTLD_NEXT, "getsockname");
    sys_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    sys_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    sys_fcntl = dlsym(RTLD_NEXT, "fcntl");
    // recv'ing
    sys_read = dlsym(RTLD_NEXT, "read");
    sys_recv = dlsym(RTLD_NEXT, "recv");
    sys_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    sys_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    // send'ing
    sys_write = dlsym(RTLD_NEXT, "write");
    sys_send = dlsym(RTLD_NEXT, "send");
    sys_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    sys_sendto = dlsym(RTLD_NEXT, "sendto");
    // closing
    sys_close = dlsym(RTLD_NEXT, "close");
    sys_shutdown = dlsym(RTLD_NEXT, "shutdown");
    sys_sockatmark = dlsym(RTLD_NEXT, "sockatmark");
    // waiting
    sys_poll = dlsym(RTLD_NEXT, "poll");
    sys_select = dlsym(RTLD_NEXT, "select");
    sys_ioctl = dlsym(RTLD_NEXT, "ioctl");

    return 0;
}
