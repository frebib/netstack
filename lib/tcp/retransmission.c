#include <stdlib.h>

#define NETSTACK_LOG_UNIT "TCP/RT"
#include <netstack/log.h>
#include <netstack/tcp/retransmission.h>

void tcp_retransmission_timeout(void *arg) {
    struct tcp_rto_data *data = arg;
    struct tcp_sock *sock = data->sock;
    struct tcb *tcb = &sock->tcb;

    LOG(LVERB, "retransmission timeout for sock (%u, %hu) available %ld",
        data->seq - tcb->iss, data->len, seqbuf_available(&sock->sndbuf, data->seq));

    // https://tools.ietf.org/html/rfc6298

    tcp_sock_lock(sock);

    uint32_t una = tcb->snd.una;
    uint32_t end = data->seq + data->len - 1;

    // Retransmit a new segment starting from the latest un-acked data
    if (tcp_seq_leq(una, end)) {
        LOG(LDBUG, "RETRANSMITTING SEQ %u-%u", data->seq - tcb->iss, end - tcb->iss);
        tcp_sock_unlock(sock);

        // Retransmit the first bytes in the retransmission queue
        // TODO: Optionally only send the missing bytes instead of just a full segment worth
        int ret;
        if ((ret = tcp_send_data(sock, una, 0)) <= 0)
            LOGSE(LWARN, "retransmitting with tcp_send_data(%u)", -ret, una - tcb->iss);

        // Relock the socket
        tcp_sock_lock(sock);
    }

    if (sock->unacked.length > 0) {
        // Update the next unacknowledged segment for retransmit timeout
        struct tcp_seq_data *unacked = llist_peek(&sock->unacked);
        data->seq = unacked->seq;
        data->len = unacked->len;

        // Restart the rto
        LOG(LTRCE, "restarting rto for seq %u", data->seq - tcb->iss);
        sock->rto_event = contimer_queue_rel(&sock->rtimer, &sock->rto,
                                             data, sizeof(struct tcp_rto_data));

        // Unlock but continue to hold reference for next timeout
        tcp_sock_unlock(sock);
    } else {
        // Decrement held reference from when rto was started
        tcp_sock_decref_unlock(sock);
    }
}

void tcp_update_rtq(struct tcp_sock *sock) {

    pthread_mutex_lock(&sock->unacked.lock);

    // Consume all acknowledged bytes from send buffer
    seqbuf_consume_to(&sock->sndbuf, sock->tcb.snd.una);

    LOG(LVERB, "checking %zu unacked segments", sock->unacked.length);
    for_each_llist(&sock->unacked) {
        struct tcp_seq_data *data = llist_elem_data();

        uint32_t iss = sock->tcb.iss;
        uint32_t end = data->seq + data->len - 1;

        if (tcp_seq_gt(sock->tcb.snd.una, end)) {
            LOG(LTRCE, "removing acknowledged segment %u-%u",
                data->seq - iss, end - iss);
            llist_remove_nolock(&sock->unacked, data);
            free(data);
        }
    }

    // Cancel the rto if there are no unacked segments left
    if (sock->unacked.length < 1) {

        LOG(LINFO, "No unacked segments outstanding. Cancelling the rto");

        // Ensure we don't decref the socket if no event was cancelled
        if (contimer_cancel(&sock->rtimer, sock->rto_event) == 0) {
            // Unlock then decrement held reference
            pthread_mutex_unlock(&sock->unacked.lock);
            tcp_sock_decref(sock);
        }

        // Just unlock. No event was cancelled
        pthread_mutex_unlock(&sock->unacked.lock);

    } else {
        // Just release lock. The timer is still running
        pthread_mutex_unlock(&sock->unacked.lock);
    }
}
