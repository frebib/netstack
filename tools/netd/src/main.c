#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>

#include <sys/wait.h>

#define NETSTACK_LOG_UNIT "NETD"
#include <netstack.h>
#include <netstack/log.h>
#include <netstack/inet/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/intf/rawsock.h>

// TODO: Add many configurable interfaces
// TODO: Add loopback interface
static struct netstack instance;


int main(int argc, char **argv) {

    // Initialise config & netstack internals
    netstack_init(&instance);

    // Check for effective CAP_NET_RAW,CAP_NET_ADMIN capabilities
    if (netstack_checkcap(argv[0]))
        exit(EXIT_FAILURE);

    // TODO: Take interface etc. configuration from config file

    // Create a INTF_RAWSOCK interface for sending/recv'ing data
    int err;
    struct intf *intf = calloc(sizeof(struct intf), 1);
    if (rawsock_new(intf) != 0) {
        LOG(LCRIT, "Could not create INTF_RAWSOCK");
        exit(EXIT_FAILURE);
    }
    llist_append(&instance.interfaces, intf);

    // Create interface send/recv threads
    intf_init(intf);

    // Initialise signal handling
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGHUP);
    sigaddset(&sigs, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigs, NULL) != 0) {
        perror("pthread_sigmask");
    }

    // Main thread captures signals, waiting for program termination
    int signum;
    while (sigwait(&sigs, &signum) == 0) {
        LOG(LINFO, "Caught signal: %s", strsignal(signum));

        switch (signum) {
            // Cleanup and exit, responsibly
            case SIGINT:
            case SIGHUP:
            case SIGQUIT:

                llist_iter(&instance.interfaces, neigh_queue_cancel);

                // Cleanup TCP states
                LOG(LNTCE, "Cleaning up %zu TCP sockets", tcp_sockets.length);
                llist_iter(&tcp_sockets, tcp_sock_incref);
                llist_iter(&tcp_sockets, tcp_sock_abort);
                llist_iter(&tcp_sockets, tcp_sock_destroy);
                llist_clear(&tcp_sockets);

                LOG(LNTCE, "Stopping threads for %s", intf->name);
                // Cleanup threads
                // Send all terminations first, before waiting
                for (int i = 0; i < INTF_THR_MAX; i++) {
                    if (intf->threads[i]) {
                        // pthread_cancel(id) will invoke cleanup procedures
                        pthread_cancel(intf->threads[i]);
                    }
                }
                // Wait for each thread to finish terminating
                for (int i = 0; i < INTF_THR_MAX; i++) {
                    if (intf->threads[i]) {
                        pthread_join(intf->threads[i], NULL);
                    }
                }

                netstack_cleanup(&instance);

                return EXIT_SUCCESS;
            default:
                // Do nothing, it doesn't concern us
                continue;
        }
    }
    perror("Signal error");
}
