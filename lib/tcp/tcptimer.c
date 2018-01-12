#include <netstack/tcp/tcp.h>

void tcp_timewait_expire(struct tcp_sock *sock) {
    LOG(LINFO, "[TCP] TIME-WAIT expired. Closing connection");
    tcp_setstate(sock, TCP_CLOSED);
    tcp_free_sock(sock);
}
