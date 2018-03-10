#define NETSTACK_LOG_UNIT "TCP"
#include <netstack/tcp/tcp.h>
#include <netstack/time/timer.h>

void tcp_timewait_expire(struct tcp_sock *sock) {
    LOG(LINFO, "TIME-WAIT expired. Closing connection");
    tcp_setstate(sock, TCP_CLOSED);
    tcp_sock_destroy(sock);
}
