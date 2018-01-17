#ifndef NETSTACK_TCP_H
#define NETSTACK_TCP_H

#include <stdint.h>
#include <stddef.h>

// Ring buffer library
#include <rbuf.h>

#include <netstack/log.h>
#include <netstack/llist.h>
#include <netstack/timer.h>
#include <netstack/inet.h>
#include <netstack/ip/ipv4.h>
#include <netstack/intf/intf.h>

// Global TCP states list
extern struct llist tcp_sockets;

/*
    Source: https://tools.ietf.org/html/rfc793#page-15

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct tcp_hdr {
    // TODO: Take endianness into account in tcp_hdr
    uint16_t    sport,          /* Source port */
                dport;          /* Destination port */
    uint32_t    seqn,           /* Sequence number */
                ackn;           /* Acknowledgement number */
#if THE_HOST_IS_BIG_ENDIAN
    uint8_t     hlen:4,         /* Size of TCP header in 32-bit words */
                rsvd:4;         /* Empty reserved space for ctrl flags */
    union {
        struct tcp_flags {
                    /* Ignoring the experimental NS bit here: RFC 3540 */
        uint8_t     cwr:1,
                    ece:1,
                    urg:1,
                    ack:1,           /* Various control bits */
                    psh:1,
                    rst:1,
                    syn:1,
                    fin:1;
#else
    /* Ignoring the experimental NS bit here: RFC 3540 */
    uint8_t     rsvd:4,         /* Empty reserved space for ctrl flags */
                hlen:4;         /* Size of TCP header in 32-bit words */
    union {
        struct tcp_flags {
            uint8_t fin:1,
                    syn:1,
                    rst:1,
                    psh:1,
                    ack:1,           /* Various control bits */
                    urg:1,
                    ece:1,
                    cwr:1;
#endif
        } flags;
        uint8_t flagval;
    };
    uint16_t    wind,           /* Size of the receive window */
                csum,           /* Internet checksum */
                urg_ptr;        /* Urgent data pointer */

    /* Options go here */

}__attribute((packed));

struct tcb {
    uint32_t irs;       // initial receive sequence number
    uint32_t iss;       // initial send sequence number
    // Send Sequence Variables
    struct tcb_snd {
        uint32_t una;   // send unacknowledged
        uint32_t nxt;   // send next
        uint32_t wnd;   // send window (what it is: https://tools.ietf.org/html/rfc793#page-20)
        uint16_t up;    // send urgent pointer
        uint32_t wl1;   // segment sequence number used for last window update
        uint32_t wl2;   // segment acknowledgment number used for last window update
    } snd;
    // Receive Sequence Variables
    struct tcb_rcv {
        uint32_t nxt;   // receive next
        uint16_t wnd;   // receive window
        uint16_t up;    // receive urgent pointer
    } rcv;
};

enum tcp_state {
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_CLOSED,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
};
static const char *tcp_strstate(enum tcp_state state) {
    switch (state) {
        case TCP_LISTEN:        return "LISTEN";
        case TCP_SYN_SENT:      return "SYN-SENT";
        case TCP_SYN_RECEIVED:  return "SYN-RECEIVED";
        case TCP_ESTABLISHED:   return "ESTABLISHED";
        case TCP_FIN_WAIT_1:    return "FIN-WAIT-1";
        case TCP_FIN_WAIT_2:    return "FIN-WAIT-2";
        case TCP_CLOSE_WAIT:    return "CLOSE-WAIT";
        case TCP_CLOSING:       return "CLOSING";
        case TCP_CLOSED:        return "CLOSED";
        case TCP_LAST_ACK:      return "LAST-ACK";
        case TCP_TIME_WAIT:     return "TIME-WAIT";
        default:                return NULL;
    }
}

struct tcp_sock {
    struct inet_sock inet;
    enum tcp_state state;
    bool opentype;      // Either TCP_ACTIVE_OPEN or TCP_PASSIVE_OPEN
    struct tcb tcb;

    // Data buffers
    rbuf sndbuf;
    rbuf rcvbuf;

    // TCP timers
    timeout_t timewait;

    // Thread wait locks
    pthread_cond_t openwait;
    pthread_mutex_t openlock;
    size_t openret;
};


// TODO: Fix endianness in tcp.h
#if THE_HOST_IS_BIG_ENDIAN
#define TCP_FLAG_CWR    0x01
#define TCP_FLAG_ECE    0x02
#define TCP_FLAG_URG    0x04
#define TCP_FLAG_ACK    0x08
#define TCP_FLAG_PSH    0x10
#define TCP_FLAG_RST    0x20
#define TCP_FLAG_SYN    0x40
#define TCP_FLAG_FIN    0x80
#else
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80
#endif


#define TCP_ACTIVE_OPEN     0x0
#define TCP_PASSIVE_OPEN    0x1

#define TCP_DEF_MSS     536
#define TCP_MSL         60      // Maximum Segment Lifetime (in seconds)


/* Returns a string of characters/dots representing a set/unset TCP flag */
static inline char *fmt_tcp_flags(struct tcp_hdr *hdr, char *buffer) {
    if (buffer == NULL) {
        return NULL;
    }
    if (hdr == NULL) {
        buffer[0] = '\0';
        return buffer;
    }

    uint8_t count = 0;
    if (hdr->flags.fin) buffer[count++] = 'F';
    if (hdr->flags.syn) buffer[count++] = 'S';
    if (hdr->flags.rst) buffer[count++] = 'R';
    if (hdr->flags.psh) buffer[count++] = 'P';
    if (hdr->flags.ack) buffer[count++] = 'A';
    if (hdr->flags.urg) buffer[count++] = 'U';
    if (hdr->flags.ece) buffer[count++] = 'E';
    if (hdr->flags.cwr) buffer[count++] = 'C';
    buffer[count] = '\0';

    return buffer;
}


/* Returns a struct tcp_hdr from the frame->head */
#define tcp_hdr(frame) ((struct tcp_hdr *) (frame)->head)

/* Returns the size in bytes of a header
 * hdr->hlen is 1 byte, soo 4x is 1 word size */
#define tcp_hdr_len(hdr) ((uint16_t) ((hdr)->hlen * 4))

bool tcp_log(struct pkt_log *log, struct frame *frame, uint16_t net_csum);

/* Receives a tcp frame for processing in the network stack */
void tcp_recv(struct frame *frame, struct tcp_sock *sock, uint16_t net_csum);

/*!
 * Sets the state of the TCP connection
 * Checks and performs queued actions on the socket
 * @param sock  socket to change state of
 * @param state state to set
 */
void tcp_setstate(struct tcp_sock *sock, enum tcp_state state);

/*!
 * Called on a newly established connection. It allocates required buffers
 * for data transmission
 * @param sock  socket to initialise
 * @param seg   incoming tcp_hdr segment that established the connection
 */
void tcp_established(struct tcp_sock *sock, struct tcp_hdr *seg);

/*!
 * Finds a matching tcp_sock with address/port quad, including matching
 * against wildcard addresses and ports.
 * @see inet_sock_lookup
 * @return a tcp_sock instance, or NULL if no matches found
 */
static inline struct tcp_sock *tcp_sock_lookup(addr_t *remaddr, addr_t *locaddr,
                                               uint16_t remport, uint16_t locport) {
    return (struct tcp_sock *)
            inet_sock_lookup(&tcp_sockets, remaddr, locaddr, remport, locport);
}

/*!
 * Removes a socket from the global socket list
 * Should be called before tcp_free_sock() to avoid race conditions
 */
#define tcp_untrack_sock(sock) llist_remove(&tcp_sockets, (sock))

/*!
 * Removes a TCP socket from the global socket list and deallocates it
 * @param sock socket to free
 */
void tcp_free_sock(struct tcp_sock *sock);

/*!
 * Deallocates a socket. Does NOT remove it from the global socket list
 * @param sock socket to free
 */
void tcp_destroy_sock(struct tcp_sock *sock);

/*!
 * Cleans up incomplete operations such as still-open connections, waiting
 * send/recv calls and calls tcp_free_sock()
 * @param sock
 */
void tcp_sock_cleanup(struct tcp_sock *sock);


/*
 * TCP Internet functions
 */

/*!
 * Returns a new random open outgoing TCP port
 * @return a random port number
 */
uint16_t tcp_randomport();

/*!
 * Returns a new random initial sequence/acknowledgement number
 * @return a random seq/ack number
 */
uint32_t tcp_seqnum();


/*
 * TCP Input
 * See: tcpin.c
 */
#define tcp_ack_acceptable(tcb, seg) (tcb)->snd.una <= ntohl((seg)->ackn) && \
                                        ntohl((seg)->ackn) <= (tcb)->snd.nxt

int tcp_seg_arr(struct frame *frame, struct tcp_sock *sock);

/*!
 * Updates the TCP send window from an incoming segment
 */
void tcp_update_wnd(struct tcb *tcb, struct tcp_hdr *seg);

/*!
 * Restores a previously LISTENing socket to LISTEN state
 * Use this function when an TCP_PASSIVE_OPEN connection attempt fails and
 * the socket should be reset to allow other connections.
 * @param sock
 */
void tcp_restore_listen(struct tcp_sock *sock);

/*
 * TCP Output
 * See: tcpout.c
 */

/*!
 *
 * @param sock
 * @param frame
 * @return
 */
int tcp_send(struct tcp_sock *sock, struct frame *frame);

int tcp_send_empty(struct tcp_sock *sock, uint32_t seqn, uint32_t ackn,
                   uint8_t flags);

int tcp_send_data(struct tcp_sock *sock, uint8_t flags);

/*!
 * Send a TCP ACK segment in the form
 *    <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
 */
#define tcp_send_ack(sock) \
    tcp_send_empty((sock), (sock)->tcb.snd.nxt, (sock)->tcb.rcv.nxt, \
        TCP_FLAG_ACK)

/*!
 * Send a TCP SYN segment in the form
 *    <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
 */
#define tcp_send_syn(sock) \
    tcp_send_empty((sock), (sock)->tcb.iss, 0, TCP_FLAG_SYN)

/*!
 * Send a TCP SYN/ACK segment in the form
 *    <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
 */
#define tcp_send_synack(sock) \
    tcp_send_empty((sock), (sock)->tcb.iss, (sock)->tcb.rcv.nxt, \
        TCP_FLAG_SYN | TCP_FLAG_ACK)

/*!
 * Send a TCP FIN/ACK segment in the form
 *    <SEQ=SND.NXT><ACK=RCV.NXT><CTL=FIN,ACK>
 */
#define tcp_send_finack(sock) \
    tcp_send_empty((sock), (sock)->tcb.snd.nxt++, (sock)->tcb.rcv.nxt, \
        TCP_FLAG_FIN | TCP_FLAG_ACK)

/*!
 * Sends a TCP RST segment given a socket, in the form
 *    <SEQ={seqn}><CTL=RST>
 */
#define tcp_send_rst(sock, seq) \
    tcp_send_empty((sock), (seq), 0, TCP_FLAG_RST)

/*!
 * Sends a TCP RST/ACK segment given a socket, in the form
 *    <SEQ={seqn}><ACK={ackn}><CTL=RST,ACK>
 */
#define tcp_send_rstack(sock, seq, ack) \
    tcp_send_empty((sock), (seq), (ack), TCP_FLAG_RST | TCP_FLAG_ACK)


/*
 * TCP User (calls)
 * See: tcpuser.c
 */
int tcp_user_open(struct tcp_sock *sock);
int tcp_user_accept(struct tcp_sock *sock);
int tcp_user_send(struct tcp_sock *sock, void *data, size_t len);
int tcp_user_recv();
int tcp_user_close(struct tcp_sock *sock);
int tcp_user_abort();
int tcp_user_status();


/*
 * TCP timers
 */
void tcp_timewait_expire(struct tcp_sock *sock);

#define tcp_timewait_start(sock) \
    timeout_set(&(sock)->timewait, (void(*)(void *)) tcp_timewait_expire, \
        (void *) (sock), TCP_MSL * 2, 0)

#define tcp_timewait_restart(sock) timeout_restart(&(sock)->timewait, -1, -1)

#define tcp_timewait_cancel(sock) timeout_clear(&(sock)->timewait)

#endif //NETSTACK_TCP_H
