#ifndef NETSTACK_API_SOCKET_H
#define NETSTACK_API_SOCKET_H

/*!
 * <netstack/api/socket.h> aims to emulate <sys/socket.h> in the operation of
 * the functions it defines with ns_* prefixed functions. For any protocol or
 * case it can handle, netstack will process the socket, otherwise it will be
 * handed off to the original implementations of the respective function
 * (using dlsym(3)).
 *
 * For detail on how any of these functions are supposed to work, consult
 * the documentation for sys/socket.h (man sys_socket.h on Linux)
*/

#include <stdint.h>

#include <netstack/addr.h>

#include <netstack/inet.h>
#include <netstack/col/alist.h>

// Global netstack socket list
ARRAYLIST_DEFINE(ns_socket, struct inet_sock *);
extern ns_socket_t ns_sockets;

/*!
 * Initialises the house-keeping for netstack socket API as well as the
 * sys_* calls for real system calls to the kernel for the socket API.
 * @return
 */
int ns_api_init();



/*!
 * <netstack/api/socket.h> also provides access to the original system calls of
 * the BSD socket API with the sys_* prefix. These are provided for use by
 * netstack internally so it can connect to the real lower-layers/kernel.
 */

#include <stddef.h>

/*
 * sys/socket.h functions
 */
#include <sys/socket.h>

extern int (*sys_socket)(int, int, int);

extern int (*sys_connect)(int, const struct sockaddr *, socklen_t);

extern int (*sys_bind)(int, const struct sockaddr *, socklen_t);

extern int (*sys_listen)(int, int);

extern int (*sys_accept)(int, struct sockaddr *restrict, socklen_t *restrict);

extern int (*sys_getpeername)(int, struct sockaddr *restrict, socklen_t *restrict);

extern int (*sys_getsockname)(int, struct sockaddr *restrict, socklen_t *restrict);

extern int (*sys_getsockopt)(int, int, int, void *restrict, socklen_t *restrict);

extern int (*sys_setsockopt)(int, int, int, const void *, socklen_t);

extern int (*sys_shutdown)(int, int);

extern int (*sys_sockatmark)(int);

extern ssize_t (*sys_recv)(int, void *, size_t, int);

extern ssize_t (*sys_recvfrom)(int, void *restrict, size_t,
                               int, struct sockaddr *restrict,
                               socklen_t *restrict);

extern ssize_t (*sys_recvmsg)(int, struct msghdr *, int);

extern ssize_t (*sys_send)(int, const void *, size_t, int);

extern ssize_t (*sys_sendto)(int, const void *, size_t, int,
                             const struct sockaddr *, socklen_t);

extern ssize_t (*sys_sendmsg)(int, const struct msghdr *, int);


/*
 * Standard I/O functions
*/
#include <sys/ioctl.h>

extern int (*sys_ioctl)(int __fd, unsigned long int __request, ...);

#include <poll.h>

extern int (*sys_poll)(struct pollfd fds[], nfds_t nfds, int timeout);

#include <sys/select.h>

extern int (*sys_select)(int nfds, fd_set *restrict readfds, fd_set *restrict writefds,
              fd_set *restrict errorfds, struct timeval *restrict timeout);

#include <unistd.h>

extern ssize_t (*sys_read)(int fd, void *buf, size_t count);

extern ssize_t (*sys_write)(int fd, const void *buf, size_t count);

extern ssize_t (*sys_close)(int fd);

#include <sys/sendfile.h>

extern ssize_t (*sys_sendfile)(int out_fd, int in_fd, off_t *offset, size_t count);

// TODO: Handle readv../writev.. and fread/fwrite


#endif //NETSTACK_API_SOCKET_H
