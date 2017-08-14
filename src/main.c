#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>

#include <sys/capability.h>
#include <linux/if_ether.h>
#include "../libnet/src/eth/ether.h"

int main(int argc, char **argv) {

    // Check for effective CAP_NET_RAW capability
    cap_flag_value_t hasRaw = CAP_CLEAR;
    if (cap_get_flag(cap_get_proc(), CAP_NET_RAW, CAP_EFFECTIVE, &hasRaw)) {
        perror("Error checking capabilities");
    }
    if (hasRaw != CAP_SET) {
        fprintf(stderr, "You don't have the CAP_NET_RAW capability.\n"
                "Use 'setcap cap_net_raw+ep %s' or run as root\n", argv[0]);
        exit(1);
    }

    // Open a raw socket (raw layer 2/3 frames)
    // Use SOCK_DGRAM to remove ethernet header
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        printf("Error: %s\n", strerror(errno));
        return -1;
    }

    // Count is raw eth packet size (inc eth + ip headers)
    ssize_t count = 0;
    socklen_t sl = 0;
    uint8_t buffer[65536];
    struct sockaddr sa = {0};

    // Read data into the buffer
    while ((count = recvfrom(sock, buffer, 65535, 0, &sa, &sl)) != -1) {
        // Format and print time the same as tcpdump for comparison
        struct timespec ts;
        timespec_get(&ts, TIME_UTC);
        char buf[15];
        strftime(buf, sizeof(buf), "%T", gmtime(&ts.tv_sec));
        snprintf(buf + 8, 8, ".%ld", ts.tv_nsec);
        // Print time received and payload size
        printf("%s Received a frame of %5lu bytes\t\n", buf, count);

        struct eth_hdr *eth_hdr = (struct eth_hdr *) buffer;
        // Convert network endianess to host
        eth_hdr->ethertype = ntohs(eth_hdr->ethertype);

        char ssaddr[18], sdaddr[18];
        fmt_mac(eth_hdr->saddr, ssaddr);
        fmt_mac(eth_hdr->daddr, sdaddr);
        printf("\tSource: %s\n\tDest:   %s\n\tType:   0x%04X > %s\n",
               ssaddr, sdaddr, eth_hdr->ethertype,
               fmt_ethertype(eth_hdr->ethertype));
    }

    printf("Error: %s\n", strerror(errno));

    return 0;
}
