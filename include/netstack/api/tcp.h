#ifndef NETSTACK_API_TCP_H
#define NETSTACK_API_TCP_H

#include <netinet/tcp.h>
#include <netstack/api/socket.h>

int socket_tcp(int domain, int type, int protocol);

int connect_tcp(struct inet_sock *inet, const struct sockaddr *addr,
                socklen_t len);

int setsockopt_tcp(struct inet_sock *inet, int level, int opt, const void *val,
                   socklen_t len);

#endif //NETSTACK_API_TCP_H
