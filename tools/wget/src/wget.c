#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char **argv) {

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <port>\n", basename(argv[0]));
        return EXIT_FAILURE;
    }
    
    int fd, ret;
    struct addrinfo *info, hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    if ((ret = getaddrinfo(argv[1], argv[2], &hints, &info)) != 0)
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));

    if ((fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol)) < 0)
        perror("socket");
    if (connect(fd, info->ai_addr, info->ai_addrlen))
        perror("connect");

    freeaddrinfo(info);

    char *get1 = "GET / HTTP/1.0\r\nHost: ";
    char *get2 = "\r\nConnection: close\r\n\r\n";

    send(fd, get1, strlen(get1), MSG_MORE);
    send(fd, argv[1], strlen(argv[1]), MSG_MORE);
    send(fd, get2, strlen(get2), 0);

    ssize_t count;
    uint total = 0;
    const size_t len = 8192;
    char data[len];

    while ((count = recv(fd, data, len, 0)) > 0) {
        total += count;
        write(STDOUT_FILENO, data, (size_t) count);
    }

    if (count < 0)
        perror("recv");

    fprintf(stderr, "total bytes %u\n", total);

    close(fd);
}
