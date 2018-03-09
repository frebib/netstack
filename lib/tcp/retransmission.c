#include <stdlib.h>
#include <sys/param.h>

#define NETSTACK_LOG_UNIT "TCP/RT"
#include <netstack/log.h>
#include <netstack/time/util.h>
#include <netstack/tcp/retransmission.h>


void tcp_syn_retransmission_timeout(void *arg) {
    struct tcp_rto_data *data = arg;
    struct tcp_sock *sock = data->sock;

    tcp_sock_lock(sock);

    // Sanity check
    if (sock->state != TCP_SYN_SENT)
        return;

    // If the backoff has hit the retry count, give up and claim ETIMEDOUT
    if (sock->backoff >= TCP_SYN_COUNT - 1) {
        tcp_setstate(sock, TCP_CLOSED);
        retlock_broadcast_bare(&sock->wait, -ETIMEDOUT);
        tcp_sock_unlock(sock);
        return;
    }

    // A different timeout value is used for SYN.
    // Just increment the backoff
    sock->backoff++;

    tcp_send_syn(sock);

    // Re-arm the connect timeout with double timeout
    struct timespec timeout;
    timespecns(&timeout, TCP_SYN_RTO << sock->backoff);
    LOG(LVERB, "setting sock connect timeout %.3fs", tstosec(&timeout, float));

    void *cb = tcp_syn_retransmission_timeout;
    sock->rto_event = contimer_queue_rel(&sock->rtimer, &timeout, cb,
                                         data, sizeof(struct tcp_rto_data));

    tcp_sock_unlock(sock);
}

void tcp_start_rto(struct tcp_sock *sock, uint16_t count, uint8_t flags) {

    struct tcp_rto_data rtd = {
            .sock = sock,
            .seq = sock->tcb.snd.nxt,
            .len = count,
            .flags = flags
    };

    // Hold another reference to the socket to prevent it being free'd
    tcp_sock_incref(sock);

    // Use the sock->lasttime storage as contimer_queue_rel() will fill it
    // with the absolute start time of the timeout upon return
    sock->lasttime.tv_sec  = nstosec(sock->rtt);
    sock->lasttime.tv_nsec = sock->rtt % NSPERSEC;

    LOG(LVERB, "starting rtimer for sock %p (%u, %i)", sock, rtd.seq, count);
    sock->rto_event = contimer_queue_rel(&sock->rtimer, &sock->lasttime,
                                         NULL, &rtd, sizeof(rtd));
}

void tcp_retransmission_timeout(void *arg) {
    struct tcp_rto_data *data = arg;
    struct tcp_sock *sock = data->sock;
    struct tcb *tcb = &sock->tcb;

    tcp_sock_lock(sock);

    // https://tools.ietf.org/html/rfc6298
    // Maximum value MAY be placed on RTO, provided it is at least 60 seconds
    if (tstosec(&sock->rto, float) < 60)
        sock->backoff++;

    uint32_t seq = data->seq;
    uint32_t una = tcb->snd.una;
    uint32_t end = data->seq + data->len - 1;

    LOG(LVERB, "retransmission timeout for sock (%u, %hu) available %ld",
        seq - tcb->iss, data->len, seqbuf_available(&sock->sndbuf, seq));

    // Retransmit a new segment starting from the latest un-acked data
    if (tcp_seq_leq(una, end)) {
        LOG(LCRIT, "RETRANSMITTING SEQ %u-%u", seq - tcb->iss, end - tcb->iss);

        // Always exponentially backoff every time a segment has to be
        // retransmitted. This is reset to 0 every time a valid ACK arrives
        sock->backoff++;
        
        tcp_sock_unlock(sock);

        // Retransmit the first bytes in the retransmission queue
        // TODO: Optionally only send the missing bytes instead of just a full segment worth
        int ret;
        if (data->len > 0) {
            if ((ret = tcp_send_data(sock, una, data->len, data->flags)) <= 0)
                LOGSE(LWARN, "retransmitting with tcp_send_data(%u)", -ret, una - tcb->iss);
        } else {
            if ((ret = tcp_send_empty(sock, una, data->len, data->flags)) <= 0)
                LOGSE(LWARN, "retransmitting with tcp_send_empty(%u)", -ret, una - tcb->iss);
        }

        // Relock the socket
        tcp_sock_lock(sock);
    }

    pthread_mutex_lock(&sock->unacked.lock);

    if (sock->unacked.length > 0) {
        // Update the next unacknowledged segment for retransmit timeout
        struct tcp_seq_data *unacked = llist_peek_nolock(&sock->unacked);
        data->seq = unacked->seq;
        data->len = unacked->len;
        data->flags = unacked->flags;

        LOG(LTRCE, "restarting rto for seq %u", unacked->seq - tcb->iss);
        pthread_mutex_unlock(&sock->unacked.lock);

        // Back-off the retransmission timeout exponentially by the backoff value.
        // This ensures successive retransmissions of the same missing segment
        // are spread further and further apart. When an ACK is received, the
        // backoff is reset and later retransmissions start backing-off again
        // from the rto instead of from the backed-off rto from here.
        struct timespec timeout;
        timespecns(&timeout, tstons(&sock->rto, uint64_t) << sock->backoff);
        float msec = tstoms(&timeout, float);
        LOG(LVERB, "backing-off the next retransmission to %.3fms", msec);

        // Strictly speaking, this is a violation of the specification, as per
        // RFC 6298. The RTO value should be incremented for each retransmission
        // and persist after the recovery however it seems to do more harm than
        // good from my testing. -frebib ~2018

        // Restart the rto
        sock->rto_event = contimer_queue_rel(&sock->rtimer, &timeout, NULL,
                                             data, sizeof(struct tcp_rto_data));

        // Unlock but continue to hold reference for next timeout
        tcp_sock_unlock(sock);
    } else {
        pthread_mutex_unlock(&sock->unacked.lock);
        // Decrement held reference from when rto was started
        tcp_sock_decref_unlock(sock);
    }
}

void tcp_update_rtq(struct tcp_sock *sock) {

    pthread_mutex_lock(&sock->unacked.lock);

    uint32_t unacked = sock->tcb.snd.una;
    switch (sock->state) {
        case TCP_SYN_SENT:
            break;
        default:
            // Ensure we don't try to consume the non-existent ACK byte for our FIN
            if (tcp_fin_was_acked(sock))
                unacked--;

            // Consume all acknowledged bytes from send buffer
            seqbuf_consume_to(&sock->sndbuf, unacked);
            break;
    }

    struct tcp_seq_data latest = {0};
    LOG(LVERB, "checking %zu unacked segments", sock->unacked.length);
    for_each_llist(&sock->unacked) {
        struct tcp_seq_data *data = llist_elem_data();

        uint32_t iss = sock->tcb.iss;
        uint32_t end = data->seq + data->len - 1;

        if (tcp_seq_gt(sock->tcb.snd.una, end)) {
            LOG(LTRCE, "removing acknowledged segment %u-%u",
                data->seq - iss, end - iss);

            // Store the latest ACKed segment for updating the rtt
            // Retransmitted segments should NOT be used for rtt calculation
            if (sock->backoff < 1)
                latest = *data;

            llist_remove_nolock(&sock->unacked, data);
            free(data);
        }
    }

    // Update the round-trip time with the latest ACK received
    if (latest.seq != 0 && latest.len != 0) {
        uint32_t iss = sock->tcb.iss;
        uint32_t end = latest.seq + latest.len - 1;
        LOG(LVERB, "updating rtt with latest acked segment %u-%u",
            latest.seq - iss, end - iss);

        tcp_update_rtt(sock, &latest);
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

void tcp_update_rtt(struct tcp_sock *sock, struct tcp_seq_data *acked) {

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    LOG(LVERB, "now (%ld.%.9ld) - sent (%ld.%.9ld)", now.tv_sec, now.tv_nsec,
        acked->when.tv_sec, acked->when.tv_nsec);
    timespecsub(&now, &acked->when);

    // Ensure the rtt is positive ( > 0 )
    if (tstons(&now, int64_t) < 0) {
        uint32_t seq = acked->seq - sock->tcb.iss;
        uint32_t end = acked->seq + acked->len - 1 - sock->tcb.iss;
        LOG(LWARN, "segment %u-%u was sent in the future?", seq, end);
        return;
    }

    // Raw round-trip time
    uint64_t r = tstons(&now, uint64_t);

    LOG(LTRCE, "segment response time %.3fms (%ldns)", nstoms((float) r), r);

    // RFC 6298: Computing TCP's Retransmission Timer
    // https://tools.ietf.org/html/rfc6298

    // If SRTT is 0, make the initial measurement
    if (sock->srtt == 0) {
        sock->srtt = r;
        sock->rttvar = r >> 1U;  // r / 2
    } else {
        // RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
        // SRTT <- (1 - alpha) * SRTT + alpha * R'
        const double beta = 0.25;
        const double alpha = 0.125;
        sock->rttvar = (uint64_t) ((1 - beta) * sock->rttvar + beta *
                                        labs((int64_t) (sock->srtt - r)));
        sock->srtt = (uint64_t) ((1 - alpha) * sock->srtt + alpha * r);
    }

    // K <- 4
    // RTO <- SRTT + (K*RTTVAR)
    uint64_t rto = sock->srtt + (sock->rttvar << 2U);
    rto = MAX(rto, TCP_RTO_MIN);
    timespecns(&sock->rto, rto);

    LOG(LVERB, "sock %p RTO <- %.3fms", sock, nstoms((float) rto));
}