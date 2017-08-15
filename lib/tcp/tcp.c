#include <stddef.h>
#include <libnet/tcp/tcp.h>

int fmt_tcp_flags(struct tcp_hdr *hdr, char *buffer) {
    if (hdr == NULL) {
        return -1;
    }

    buffer[0] = (char) (hdr->fin ? 'F' : '.');
    buffer[1] = (char) (hdr->syn ? 'S' : '.');
    buffer[2] = (char) (hdr->rst ? 'R' : '.');
    buffer[3] = (char) (hdr->psh ? 'P' : '.');
    buffer[4] = (char) (hdr->ack ? 'A' : '.');
    buffer[5] = (char) (hdr->urg ? 'U' : '.');
    buffer[6] = (char) (hdr->ece ? 'E' : '.');
    buffer[7] = (char) (hdr->cwr ? 'C' : '.');
    buffer[8] = 0;

    return 0;
}

