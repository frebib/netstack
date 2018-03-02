#include <netstack/tcp/tcp.h>
#include <netstack/time/timer.h>

void tcp_timewait_expire(struct tcp_sock *sock) {
    LOG(LINFO, "[TCP] TIME-WAIT expired. Closing connection");
    tcp_setstate(sock, TCP_CLOSED);
    // Clear this timeout
    tcp_timewait_cancel(sock);
    tcp_sock_destroy(sock);
}
