#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include <sys/param.h>
#include <netinet/in.h>

#define NETSTACK_LOG_UNIT "TCP"
#include <netstack/tcp/tcp.h>
#include <netstack/tcp/retransmission.h>


void expand_escapes(char *dest, const char *src, size_t len) {
    char c;
    while (len-- > 0) {
        c = *(src++);
        switch(c) {
            case '\a': *(dest++) = '\\'; *(dest++) = 'a';
                break;
            case '\b': *(dest++) = '\\'; *(dest++) = 'b';
                break;
            case '\t': *(dest++) = '\\'; *(dest++) = 't';
                break;
            case '\n': *(dest++) = '\\'; *(dest++) = 'n';
                break;
            case '\v': *(dest++) = '\\'; *(dest++) = 'v';
                break;
            case '\f': *(dest++) = '\\'; *(dest++) = 'f';
                break;
            case '\r': *(dest++) = '\\'; *(dest++) = 'r';
                break;
            case '\\': *(dest++) = '\\'; *(dest++) = '\\';
                break;
            case '\"': *(dest++) = '\\'; *(dest++) = '\"';
                break;
            case '\0': *(dest++) = '\\'; *(dest++) = '0';
                break;
            default:   *(dest++) = isprint(c) ? c : '?';
        }
    }
    *dest = '\0'; /* Ensure NULL terminator */
}

void tcp_recv_closed(struct frame *frame, struct tcp_hdr *seg) {

    // If the state is CLOSED (i.e., TCB does not exist) then
    struct log_trans t = LOG_TRANS(LDBUG);
    LOGT(&t, "Reached TCP_CLOSED on ");
    LOGT(&t, "%s:%hu -> ", straddr(&frame->remaddr), frame->remport);
    LOGT(&t, "%s:%hu", straddr(&frame->locaddr), frame->locport);
    LOGT_COMMIT(&t);

    // all data in the incoming segment is discarded.  An incoming
    // segment containing a RST is discarded.  An incoming segment not
    // containing a RST causes a RST to be sent in response.  The
    // acknowledgment and sequence field values are selected to make the
    // reset sequence acceptable to the TCP that sent the offending
    // segment.

    // TODO: Optionally don't send TCP RST packets

    // tcp_send_* functions only use sock->inet
    struct tcp_sock sock = { .inet = {
            .locport = frame->locport,
            .locaddr = frame->locaddr,
            .remport = frame->remport,
            .remaddr = frame->remaddr,
            .flags = O_NONBLOCK,
            .type = SOCK_STREAM,
            .intf = frame->intf
    } };

    if (seg->flags.ack != 1) {
        // If the ACK bit is off, sequence number zero is used,
        // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
        LOG(LDBUG, "Sending RST/ACK");
        tcp_send_rstack(&sock, 0, ntohl(seg->seqn) + frame_data_len(frame) + 1);
    } else {
        // If the ACK bit is on,
        // <SEQ=SEG.ACK><CTL=RST>
        LOG(LDBUG, "Sending RST");
        tcp_send_rst(&sock, ntohl(seg->ackn));
    }
}

void tcp_recv_listen(struct frame *frame, struct tcp_sock *parent,
                     struct tcp_hdr *seg) {

    LOG(LDBUG, "Reached TCP_LISTEN on %s:%hu",
          straddr(&frame->remaddr), frame->remport);

    // tcp_send_* functions only use sock->inet
    struct tcp_sock sock = { .inet = {
            .locport = frame->locport,
            .locaddr = frame->locaddr,
            .remport = frame->remport,
            .remaddr = frame->remaddr,
            .flags = O_NONBLOCK,
            .type = SOCK_STREAM,
            .intf = frame->intf
    } };

    /*
      first check for an RST

        An incoming RST should be ignored.  Return.
    */
    if (seg->flags.rst == 1) {
        return;
    }
    /*
      second check for an ACK

        Any acknowledgment is bad if it arrives on a connection still in
        the LISTEN state.  An acceptable reset segment should be formed
        for any arriving ACK-bearing segment.  The RST should be
        formatted as follows:

          <SEQ=SEG.ACK><CTL=RST>

        Return.
    */
    if (seg->flags.ack == 1) {
        LOG(LDBUG, "Sending RST");
        tcp_send_rst(&sock, ntohl(seg->ackn));
        return;
    }
    /*
      third check for a SYN

        If the SYN bit is set, check the security.  If the
        security/compartment on the incoming segment does not exactly
        match the security/compartment in the TCB then send a reset and
        return.

          <SEQ=SEG.ACK><CTL=RST>
    */
    if (seg->flags.syn != 1) {
        return;
    }


    // Incoming 'frame' is SYN frame

    // TODO: Implement TCP/IPv4 precedence, IPv6 has no security/precedence

    /*
        If the SEG.PRC is greater than the TCB.PRC then if allowed by
        the user and the system set TCB.PRC<-SEG.PRC, if not allowed
        send a reset and return.

          <SEQ=SEG.ACK><CTL=RST>

        If the SEG.PRC is less than the TCB.PRC then continue.

        Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other
        control or text should be queued for processing later.  ISS
        should be selected and a SYN segment sent of the form:

          <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

        SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
        state should be changed to SYN-RECEIVED.  Note that any other
        incoming control or data (combined with SYN) will be processed
        in the SYN-RECEIVED state, but processing of SYN and ACK should
        not be repeated.  If the listen was not fully specified (i.e.,
        the foreign socket was not fully specified), then the
        unspecified fields should be filled in now.
    */

    uint32_t iss = ntohl(tcp_seqnum());
    uint32_t seg_seq = ntohl(seg->seqn);

    struct tcp_sock *client = tcp_sock_init(calloc(1, sizeof(struct tcp_sock)));
    client->inet.locport = frame->locport;
    client->inet.locaddr = frame->locaddr;
    client->inet.remport = frame->remport;
    client->inet.remaddr = frame->remaddr;
    // Un-accepted connections should be non-blocking
    // as to not cause deadlocks
    client->inet.flags = O_NONBLOCK;
    client->inet.type = SOCK_STREAM;
    client->inet.intf = frame->intf;
    client->mss = 1460;
    client->tcb = (struct tcb) {
            .irs = seg_seq,
            .iss = iss,
            .snd = {
                    .una = iss,
                    .nxt = iss + 1,
                    .wnd = ntohs(seg->wind)
            },
            .rcv = {
                    .nxt = seg_seq + 1,
                    .wnd = UINT16_MAX
            }
    };
    tcp_setstate(client, TCP_SYN_RECEIVED);
    client->parent = parent;
    llist_push(&tcp_sockets, client);
    llist_append(&parent->passive->backlog, client);

    // Send SYN/ACK and drop incoming segment
    LOG(LDBUG, "Sending SYN/ACK");
    tcp_send_synack(client);

    /*
      fourth other text or control

        Any other control or text-bearing segment (not containing SYN)
        must have an ACK and thus would be discarded by the ACK
        processing.  An incoming RST segment could not be valid, since
        it could not have been sent in response to anything sent by this
        incarnation of the connection.  So you are unlikely to get here,
        but if you do, drop the segment, and return.
     */
}

/*
 * Initial TCP input routine, after packet sanity checks in tcp_recv()
 *
 * Follows 'SEGMENT ARRIVES'
 * https://tools.ietf.org/html/rfc793#page-65
 * https://github.com/romain-jacotin/quic/blob/master/doc/TCP.md#-segment-arrives
 *
 * See RFC793, bottom of page 52: https://tools.ietf.org/html/rfc793#page-52
 */
int tcp_seg_arr(struct frame *frame, struct tcp_sock *sock) {
    int ret = -1;

    // Don't allow NULL sockets because it provides no address to send RST to
    if (sock == NULL)
        return ret;

    // Ensure we always hold the frame as long as we need it
    frame_incref(frame);
    tcp_sock_lock(sock);
    tcp_sock_incref(sock);

    struct tcb *tcb = &sock->tcb;
    struct inet_sock *inet = &sock->inet;
    struct tcp_hdr *seg = tcp_hdr(frame);
    uint32_t seg_seq = ntohl(seg->seqn);
    uint32_t seg_ack = ntohl(seg->ackn);
    uint16_t seg_len = frame_data_len(frame);
    uint32_t seg_end = seg_seq + MAX(seg_len - 1, 0);

    if (sock->inet.intf == NULL)
        // Use incoming interface as known intf for socket
        sock->inet.intf = frame->intf;

    // A segment is "in-order" if the sequence number is
    // the next one we expect to receive
    bool in_order = (seg_seq == tcb->rcv.nxt);
    bool ack_acceptable = tcp_ack_acceptable(tcb, seg_ack);

    if (sock->state == TCP_SYN_SENT) {
        LOG(LDBUG, "Reached SYN-SENT on %s:%hu",
              straddr(&inet->remaddr), inet->remport);
        /*
          first check the ACK bit

            If the ACK bit is set

              If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
              the RST bit is set, if so drop the segment and return)

                <SEQ=SEG.ACK><CTL=RST>

              and discard the segment.  Return.

              If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
        */
        if (seg->flags.ack == 1) {
            if (tcp_seq_lt(seg_ack, tcb->iss) ||
                tcp_seq_gt(seg_ack, tcb->snd.nxt)) {
                if (seg->flags.rst != 1) {
                    LOG(LDBUG, "Sending RST");
                    ret = tcp_send_rst(sock, seg_ack);
                }
                goto drop_pkt;
            }
        }
        /*
          second check the RST bit
          If the RST bit is set

              If the ACK was acceptable then signal the user "error:
              connection reset", drop the segment, enter CLOSED state,
              delete TCB, and return.  Otherwise (no ACK) drop the segment
              and return.

        */
        if (seg->flags.rst == 1) {
            if (ack_acceptable) {
                tcp_setstate(sock, TCP_CLOSED);
                tcp_wake_error(sock, -ECONNREFUSED);
                tcp_sock_decref(sock);
            }
            goto drop_pkt;
        }

        // TODO: Implement TCP/IPv4 precedence, IPv6 has no security/precedence
        /*
          third check the security and precedence

            If the security/compartment in the segment does not exactly
            match the security/compartment in the TCB, send a reset

              If there is an ACK

                <SEQ=SEG.ACK><CTL=RST>

              Otherwise

                <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

            If there is an ACK

              The precedence in the segment must match the precedence in the
              TCB, if not, send a reset

                <SEQ=SEG.ACK><CTL=RST>

            If there is no ACK

              If the precedence in the segment is higher than the precedence
              in the TCB then if allowed by the user and the system raise
              the precedence in the TCB to that in the segment, if not
              allowed to raise the prec then send a reset.

                <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

              If the precedence in the segment is lower than the precedence
              in the TCB continue.

            If a reset was sent, discard the segment and return.
        */

        /*
          fourth check the SYN bit

            This step should be reached only if the ACK is ok, or there is
            no ACK, and if the segment did not contain a RST.

            If the SYN bit is on and the security/compartment and precedence
            are acceptable then, RCV.NXT is set to SEG.SEQ+1, IRS is set to
            SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
            is an ACK), and any segments on the retransmission queue which
            are thereby acknowledged should be removed.
        */
        if (seg->flags.syn == 1) {
            tcb->rcv.nxt = seg_seq + 1;
            tcb->irs = seg_seq;
            if (ack_acceptable)
                tcb->snd.una = seg_ack;

            tcp_update_rtq(sock);

            /*
                If SND.UNA > ISS (our SYN has been ACKed), change the connection
                state to ESTABLISHED, form an ACK segment

                  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

                and send it.  Data or controls which were queued for
                transmission may be included.  If there are other controls or
                text in the segment then continue processing at the sixth step
                below where the URG bit is checked, otherwise return.
            */
            if (tcb->snd.una > tcb->iss) {

                // TODO: Parse incoming TCP options for MSS value
                sock->mss = 1460;

                // RFC 1122: Section 4.2.2.20 (c)
                // TCP event processing corrections
                // https://tools.ietf.org/html/rfc1122#page-94
                tcp_update_wnd(tcb, seg);

                // Initialise established connection
                tcp_established(sock, seg_seq + 1);

                LOG(LDBUG, "Sending ACK");
                if (seqbuf_available(&sock->sndbuf, seg_ack))
                    ret = tcp_send_data(sock, seg_seq + 1, 0, 0);
                else
                    ret = tcp_send_ack(sock);

                // Signal the open() call if it's waiting for us
                if (tcp_wake_waiters(sock)) {
                    LOGERR("pthread_cond_signal");
                }

                goto drop_pkt;
            }
        }
        /*
            Otherwise enter SYN-RECEIVED, form a SYN,ACK segment

              <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

            and send it.  If there are other controls or text in the
            segment, queue them for processing after the ESTABLISHED state
            has been reached, return.
        */
        tcp_setstate(sock, TCP_SYN_RECEIVED);
        LOG(LDBUG, "Sending SYN/ACK");
        ret = tcp_send_synack(sock);

        // TODO: If there are other controls or text in the segment,
        // queue them for processing after the ESTABLISHED state is reached
        goto drop_pkt;
        /*
          fifth, if neither of the SYN or RST bits is set then drop the
          segment and return.
        */
    }

    /*
    Otherwise,

    first check sequence number

      SYN-RECEIVED STATE
      ESTABLISHED STATE
      FIN-WAIT-1 STATE
      FIN-WAIT-2 STATE
      CLOSE-WAIT STATE
      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT STATE

        Segments are processed in sequence.  Initial tests on arrival
        are used to discard old duplicates, but further processing is
        done in SEG.SEQ order.  If a segment's contents straddle the
        boundary between old and new, only the new parts should be
        processed.

        There are four cases for the acceptability test for an incoming
        segment:

        Segment Receive  Test
        Length  Window
        ------- -------  -------------------------------------------

           0       0     SEG.SEQ = RCV.NXT

           0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

          >0       0     not acceptable

          >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                      or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

        If the RCV.WND is zero, no segments will be acceptable, but
        special allowance should be made to accept valid ACKs, URGs and
        RSTs.
    */
    bool valid = true;
    if (seg_len > 0 && tcb->rcv.wnd == 0) {
        valid = false;
        LOG(LINFO, "data sent but RCV.WND is 0");
    }
    if (!tcp_seq_inwnd(seg_seq, tcb->rcv.nxt, tcb->rcv.wnd) ||
            !tcp_seq_inwnd(seg_end, tcb->rcv.nxt, tcb->rcv.wnd)) {
        valid = false;
        LOG(LINFO, "Recv'd out-of-sequence segment: SEQ %u < RCV.NXT %u",
            seg_seq, tcb->rcv.nxt);
    }
    if (!tcp_seq_inwnd(seg_end, tcb->rcv.nxt, tcb->rcv.wnd)) {
        valid = false;
        LOG(LINFO, "more data was sent than can fit in RCV.WND: "
                    "SEQ %u, END %u, LEN %hu, RCV.NXT %u, RCV.WND %hu",
            seg_seq, seg_end, seg_len, tcb->rcv.nxt, tcb->rcv.wnd);
    }
    /*
        If an incoming segment is not acceptable, an acknowledgment
        should be sent in reply (unless the RST bit is set, if so drop
        the segment and return):

          <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        After sending the acknowledgment, drop the unacceptable segment
        and return.
    */
    if (!valid) {
        // TODO: Handle duplicate incoming segments in TIME-WAIT
        if (seg->flags.rst == 0 && sock->state != TCP_TIME_WAIT) {
            LOG(LDBUG, "Sending ACK");
            ret = tcp_send_ack(sock);
        }
        goto drop_pkt;
    }
    /*
        In the following it is assumed that the segment is the idealized
        segment that begins at RCV.NXT and does not exceed the window.
        One could tailor actual segments to fit this assumption by
        trimming off any portions that lie outside the window (including
        SYN and FIN), and only processing further if the segment then
        begins at RCV.NXT.  Segments with higher beginning sequence
        numbers may be held for later processing.

    // TODO: Store out-of-order segments that are >RCV.NXT for later processing

    second check the RST bit,

    */
    switch(sock->state) {
    /*
      SYN-RECEIVED STATE

        If the RST bit is set

          If this connection was initiated with a passive OPEN (i.e.,
          came from the LISTEN state), then return this connection to
          LISTEN state and return.  The user need not be informed.  If
          this connection was initiated with an active OPEN (i.e., came
          from SYN-SENT state) then the connection was refused, signal
          the user "connection refused".  In either case, all segments
          on the retransmission queue should be removed.  And in the
          active OPEN case, enter the CLOSED state and delete the TCB,
          and return.
    */
        case TCP_SYN_RECEIVED:
            if (seg->flags.rst == 1) {
                // If backlog list is NULL, socket is ACTIVE open
                if (sock->passive == NULL) {
                    tcp_wake_error(sock, -ECONNREFUSED);
                    contimer_stop(&sock->rtimer);
                    ret = -ECONNREFUSED;
                }
                tcp_sock_decref(sock);
                goto drop_pkt;
            }
            break;
    /*
      ESTABLISHED
      FIN-WAIT-1
      FIN-WAIT-2
      CLOSE-WAIT

        If the RST bit is set then, any outstanding RECEIVEs and SEND
        should receive "reset" responses.  All segment queues should be
        flushed.  Users should also receive an unsolicited general
        "connection reset" signal.  Enter the CLOSED state, delete the
        TCB, and return.

    */
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSE_WAIT:
            if (seg->flags.rst == 1) {
                tcp_setstate(sock, TCP_CLOSED);
                tcp_wake_error(sock, -ECONNRESET);
                tcp_sock_decref(sock);
                goto drop_pkt;
            }
            break;
    /*
      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT

        If the RST bit is set then, enter the CLOSED state, delete the
        TCB, and return.
    */
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            if (seg->flags.rst == 1) {
                tcp_setstate(sock, TCP_CLOSED);
                tcp_wake_error(sock, -ECONNRESET);
                tcp_sock_decref(sock);
                goto drop_pkt;
            }
            break;

        default:
            break;
    }
    /*
    third check security and precedence

      SYN-RECEIVED

        If the security/compartment and precedence in the segment do not
        exactly match the security/compartment and precedence in the TCB
        then send a reset, and return.

      ESTABLISHED STATE

        If the security/compartment and precedence in the segment do not
        exactly match the security/compartment and precedence in the TCB
        then send a reset, any outstanding RECEIVEs and SEND should
        receive "reset" responses.  All segment queues should be
        flushed.  Users should also receive an unsolicited general
        "connection reset" signal.  Enter the CLOSED state, delete the
        TCB, and return.

      Note this check is placed following the sequence check to prevent
      a segment from an old connection between these ports with a
      different security or precedence from causing an abort of the
      current connection.

    fourth, check the SYN bit,

      SYN-RECEIVED
      ESTABLISHED STATE
      FIN-WAIT STATE-1
      FIN-WAIT STATE-2
      CLOSE-WAIT STATE
      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT STATE

        If the SYN is in the window it is an error, send a reset, any
        outstanding RECEIVEs and SEND should receive "reset" responses,
        all segment queues should be flushed, the user should also
        receive an unsolicited general "connection reset" signal, enter
        the CLOSED state, delete the TCB, and return.

        If the SYN is not in the window this step would not be reached
        and an ack would have been sent in the first step (sequence
        number check).
    */
    switch (sock->state) {
        case TCP_SYN_RECEIVED:
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSE_WAIT:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            // If SYN is set and iff seg->seqn is outside the rcv.wnd
            if (seg->flags.syn == 1 && (seg_seq < tcb->rcv.nxt ||
                                        seg_seq > tcb->rcv.nxt + tcb->rcv.wnd)) {

                tcp_wake_error(sock, -ECONNRESET);
                LOG(LDBUG, "Sending RST");
                ret = tcp_send_rst(sock, seg_ack);
                contimer_stop(&sock->rtimer);
                tcp_sock_decref(sock);
                // TODO: Implement RFC 5961 Section 4: Blind Reset Attack on SYN
                // https://tools.ietf.org/html/rfc5961#page-9
                ret = -ECONNRESET;
                goto drop_pkt;
            }
            break;

        default:
            break;
    }
    /*

    fifth check the ACK field,

      if the ACK bit is off drop the segment and return
    */
    if (seg->flags.ack != 1)
        goto drop_pkt;
    /*

      if the ACK bit is on
    */
    switch (sock->state) {
    /*
        SYN-RECEIVED STATE

          If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
          and continue processing.

            If the segment acknowledgment is not acceptable, form a
            reset segment,

              <SEQ=SEG.ACK><CTL=RST>

            and send it.
    */
        case TCP_SYN_RECEIVED:
            if (ack_acceptable) {
                tcp_established(sock, seg_seq);
            } else {
                LOG(LDBUG, "Sending RST");
                ret = tcp_send_rst(sock, seg_ack);

                // SYN-RECEIVED is always PASSIVE_OPEN
//                tcp_restore_listen(sock);
            }
            break;
    /*
        ESTABLISHED STATE

          If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
          Any segments on the retransmission queue which are thereby
          entirely acknowledged are removed.  Users should receive
          positive acknowledgments for buffers which have been SENT and
          fully acknowledged (i.e., SEND buffer should be returned with
          "ok" response).  If the ACK is a duplicate
          (SEG.ACK < SND.UNA), it can be ignored.  If the ACK acks
          something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
          drop the segment, and return.

          If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be
          updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
          SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
          SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.

          Note that SND.WND is an offset from SND.UNA, that SND.WL1
          records the sequence number of the last segment used to update
          SND.WND, and that SND.WL2 records the acknowledgment number of
          the last segment used to update SND.WND.  The check here
          prevents using old segments to update the window.
    */
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSE_WAIT:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
            // RFC 1122: Section 4.2.2.20 (g)
            // TCP event processing corrections
            // https://tools.ietf.org/html/rfc1122#page-94
            if (ack_acceptable) {

                // Update send buffer
                tcb->snd.una = seg_ack;

                // Remove any segments from the rtq that are ack'd
                tcp_update_rtq(sock);

                // Exponential backoff should be reset upon receiving a valid ACK
                // It should happen _AFTER_ updating the rtt/rtq so that segments
                // acknowledged by this ACK segment aren't used to calculate the
                // updated RTO. See: https://tools.ietf.org/html/rfc6298#page-4
                sock->backoff = 0;

                // Wakeup tcp_user_send() now as there might be space in the snd.wnd
                pthread_cond_broadcast(&sock->waitack);

                if (tcp_seq_gt(seg_ack, tcb->snd.nxt) &&
                    !tcp_seq_lt(seg_ack, tcb->snd.una)) {
                    // TODO: Is sending an ACK here necessary?
                    LOG(LDBUG, "ACK received for something not yet sent");
                    LOG(LDBUG, "Sending ACK");
                    ret = tcp_send_ack(sock);
                    goto drop_pkt;
                }
            }
            // If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK))
            if (tcp_seq_lt(tcb->snd.wl1, seg_seq) ||
                (tcb->snd.wl1 == seg_seq &&
                 tcp_seq_leq(tcb->snd.wl2, seg_ack))) {
                tcp_update_wnd(tcb, seg);
            } else {
                // Just update send window
                tcb->snd.wnd = ntohs(seg->wind);
            }

        default:
            break;
    }

    if (in_order && tcp_fin_was_acked(sock)) {
        switch (sock->state) {
    /*
        FIN-WAIT-1 STATE

          In addition to the processing for the ESTABLISHED state, if
          our FIN is now acknowledged then enter FIN-WAIT-2 and continue
          processing in that state.
    */
            case TCP_FIN_WAIT_1:
                tcp_setstate(sock, TCP_FIN_WAIT_2);
                break;
    /*
        FIN-WAIT-2 STATE

          In addition to the processing for the ESTABLISHED state, if
          the retransmission queue is empty, the user's CLOSE can be
          acknowledged ("ok") but do not delete the TCB.
    */
            case TCP_FIN_WAIT_2:
                // TODO: Send success to waiting close() calls
                tcp_wake_error(sock, 0);
                break;
    /*
        CLOSING STATE

          In addition to the processing for the ESTABLISHED state, if
          the ACK acknowledges our FIN then enter the TIME-WAIT state,
          otherwise ignore the segment.
    */
            case TCP_CLOSING:
                tcp_setstate(sock, TCP_TIME_WAIT);
                tcp_timewait_start(sock);

                // Notify waiting close() calls that the connection is closed
                tcp_wake_error(sock, 0);

                break;
    /*
        LAST-ACK STATE

          The only thing that can arrive in this state is an
          acknowledgment of our FIN.  If our FIN is now acknowledged,
          delete the TCB, enter the CLOSED state, and return.
    */
            case TCP_LAST_ACK:
                tcp_setstate(sock, TCP_CLOSED);
                tcp_wake_waiters(sock);
                tcp_sock_decref(sock);
                goto drop_pkt;
    /*
        TIME-WAIT STATE

          The only thing that can arrive in this state is a
          retransmission of the remote FIN.  Acknowledge it, and restart
          the 2 MSL timeout.
    */
            case TCP_TIME_WAIT:
                tcp_send_ack(sock);
                tcp_timewait_restart(sock);
                break;
            default:
                break;
        }
    }
    /*
    sixth, check the URG bit,

      ESTABLISHED STATE
      FIN-WAIT-1 STATE
      FIN-WAIT-2 STATE

        If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and signal
        the user that the remote side has urgent data if the urgent
        pointer (RCV.UP) is in advance of the data consumed.  If the
        user has already been signaled (or is still in the "urgent
        mode") for this continuous sequence of urgent data, do not
        signal the user again.

      CLOSE-WAIT STATE
      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT

        This should not occur, since a FIN has been received from the
        remote side.  Ignore the URG.
    */

    /*
    seventh, process the segment text,
    */
    switch (sock->state) {
    /*
      ESTABLISHED STATE
      FIN-WAIT-1 STATE
      FIN-WAIT-2 STATE

        Once in the ESTABLISHED state, it is possible to deliver segment
        text to user RECEIVE buffers.  Text from segments can be moved
        into buffers until either the buffer is full or the segment is
        empty.  If the segment empties and carries an PUSH flag, then
        the user is informed, when the buffer is returned, that a PUSH
        has been received.

        When the TCP takes responsibility for delivering the data to the
        user it must also acknowledge the receipt of the data.

        Once the TCP takes responsibility for the data it advances
        RCV.NXT over the data accepted, and adjusts RCV.WND as
        apporopriate to the current buffer availability.  The total of
        RCV.NXT and RCV.WND should not be reduced.

        Please note the window management suggestions in section 3.7.

        Send an acknowledgment of the form:

          <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        This acknowledgment should be piggybacked on a segment being
        transmitted if possible without incurring undue delay.
    */
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2: {

            if (seg_len < 1)
                break;

            // We keep segment text for any segments that have arrived,
            // regardless of whether they are out-of-order, to reduce
            // future retransmissions

            // Reorder segments
            frame_incref(frame);
            pthread_mutex_lock(&sock->recvqueue.lock);

            // Insert the segment into the queue, ordered
            llist_insert_sorted_nolock(&sock->recvqueue, frame,
                                (int (*)(void *, void *)) &tcp_seg_cmp);

            // Regardless of whether the segment was in-order, it takes up
            // space in the recvqueue so adjust the window accordingly
            tcb->rcv.wnd -= seg_len;
            uint32_t irs = tcb->irs;

            // For debug purposes, print queued segments in recvqueue
            //tcp_log_recvqueue(sock);

            // Before unlocking the recvqueue, count the amount of contiguous
            // bytes available locally in the queue from RCV.NXT
            tcb->rcv.nxt = tcp_recvqueue_contigseq(sock, tcb->rcv.nxt);

            pthread_mutex_unlock(&sock->recvqueue.lock);

            if (tcp_seq_gt(sock->recvptr, sock->tcb.rcv.nxt))
                LOG(LERR, "You dun goofed: recvptr (%u) > RCV.NXT (%u)",
                      sock->recvptr - irs, sock->tcb.rcv.nxt - irs);

            // Always send an ACK for the largest contiguous segment we've queued.
            LOG(LDBUG, "Sending ACK");
            ret = tcp_send_ack(sock);

            // Signal pending recv() calls with a >0 value to indicate data
            if (in_order)
                tcp_wake_waiters(sock);

            break;
        }
    /*
      CLOSE-WAIT STATE
      CLOSING STATE
      LAST-ACK STATE
      TIME-WAIT STATE

        This should not occur, since a FIN has been received from the
        remote side.  Ignore the segment text.
    */
        default:
            break;
    }

    /*
    eighth, check the FIN bit,

      Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
      since the SEG.SEQ cannot be validated; drop the segment and
      return.
    */
    if (seg->flags.fin != 1) {
        switch (sock->state) {
            case TCP_CLOSED:
            case TCP_LISTEN:
            case TCP_SYN_SENT:
                goto drop_pkt;
            default:
                break;
        }
    } else {
        if (seg_seq != tcb->rcv.nxt) {
            LOG(LWARN, "Recv'd out-of-order FIN. Dropping");
            LOG(LWARN, "SEQ %u, RCV.NXT %u", seg_seq, tcb->rcv.nxt);
            goto drop_pkt;
        }
    /*
      If the FIN bit is set, signal the user "connection closing" and
      return any pending RECEIVEs with same message, advance RCV.NXT
      over the FIN, and send an acknowledgment for the FIN.  Note that
      FIN implies PUSH for any segment text not yet delivered to the
      user.
    */
        switch (sock->state) {
    /*
        SYN-RECEIVED STATE
        ESTABLISHED STATE

          Enter the CLOSE-WAIT state.
    */
            case TCP_SYN_RECEIVED:
            case TCP_ESTABLISHED:
                tcp_setstate(sock, TCP_CLOSE_WAIT);
                break;
    /*
        FIN-WAIT-1 STATE

          If our FIN has been ACKed (perhaps in this segment), then
          enter TIME-WAIT, start the time-wait timer, turn off the other
          timers; otherwise enter the CLOSING state.

    */
            case TCP_FIN_WAIT_1:
                if (tcp_fin_was_acked(sock)) {
                    tcp_setstate(sock, TCP_TIME_WAIT);
                    tcp_timewait_start(sock);

                    // Stop retransmission timer
                    // TODO: stop other TCP timers in FIN-WAIT-2
                    contimer_stop(&sock->rtimer);
                } else {
                    // Just enter CLOSING and wait for ACK
                    tcp_setstate(sock, TCP_CLOSING);
                }
                break;
    /*
        FIN-WAIT-2 STATE

          Enter the TIME-WAIT state.  Start the time-wait timer, turn
          off the other timers.
    */
            case TCP_FIN_WAIT_2:
                tcp_setstate(sock, TCP_TIME_WAIT);
                tcp_timewait_start(sock);

                 // TODO: stop other TCP timers in FIN-WAIT-2
                // Stop retransmission timer
                contimer_stop(&sock->rtimer);
                break;
    /*
        TIME-WAIT STATE

          Remain in the TIME-WAIT state.  Restart the 2 MSL time-wait
          timeout.
    */
            case TCP_TIME_WAIT:
                tcp_timewait_restart(sock);
                break;
    /*
        CLOSE-WAIT STATE

          Remain in the CLOSE-WAIT state.

        CLOSING STATE

          Remain in the CLOSING state.

        LAST-ACK STATE

          Remain in the LAST-ACK state.
    */
            default:
                break;
        }

        // Send 0 to pending recv() calls indicating EOF
        tcp_wake_waiters(sock);

        tcb->rcv.nxt = seg_seq + 1;
        LOG(LDBUG, "Sending ACK");
        ret = tcp_send_ack(sock);
    }

drop_pkt:
    tcp_sock_decref_unlock(sock);
    frame_decref(frame);
    return ret;
}

void tcp_update_wnd(struct tcb *tcb, struct tcp_hdr *seg) {
    tcb->snd.wnd = ntohs(seg->wind);
    tcb->snd.wl1 = ntohl(seg->seqn);
    tcb->snd.wl2 = ntohl(seg->ackn);
}
