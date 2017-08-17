#include <stdlib.h>
#include <netinet/in.h>

#include <libnet/tcp/tcp.h>

struct tcp_hdr *tcp_hdr(struct frame *frame) {
    return (struct tcp_hdr *) frame->head;
}

struct tcp_hdr *recv_tcp(struct frame *frame) {
    struct tcp_hdr *tcp_hdr = (struct tcp_hdr *) frame->data;

    tcp_hdr->sport = ntohs(tcp_hdr->sport);
    tcp_hdr->dport = ntohs(tcp_hdr->dport);
    tcp_hdr->seqn = ntohl(tcp_hdr->seqn);
    tcp_hdr->ackn = ntohl(tcp_hdr->ackn);
    tcp_hdr->wind = ntohs(tcp_hdr->wind);
    tcp_hdr->csum = ntohs(tcp_hdr->csum);
    tcp_hdr->urg_ptr = ntohs(tcp_hdr->urg_ptr);

    return tcp_hdr;
}

int fmt_tcp_flags(struct tcp_hdr *hdr, char *buffer) {
    if (hdr == NULL) {
        return -1;
    }

    buffer[0] = (char) (hdr->flags.fin ? 'F' : '.');
    buffer[1] = (char) (hdr->flags.syn ? 'S' : '.');
    buffer[2] = (char) (hdr->flags.rst ? 'R' : '.');
    buffer[3] = (char) (hdr->flags.psh ? 'P' : '.');
    buffer[4] = (char) (hdr->flags.ack ? 'A' : '.');
    buffer[5] = (char) (hdr->flags.urg ? 'U' : '.');
    buffer[6] = (char) (hdr->flags.ece ? 'E' : '.');
    buffer[7] = (char) (hdr->flags.cwr ? 'C' : '.');
    buffer[8] = 0;

    return 0;
}

