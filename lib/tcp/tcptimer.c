#include <netstack/timer.h>
#include <netstack/tcp/tcp.h>

void tcp_timewait_expire(struct tcp_sock *sock) {
    LOG(LINFO, "[TCP] TIME-WAIT expired. Closing connection");
    tcp_setstate(sock, TCP_CLOSED);
    // Clear this timeout
    tcp_timewait_cancel(sock);
    tcp_destroy_sock(sock);
}
