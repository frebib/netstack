#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <signal.h>
#include <sysexits.h>

#include <sys/socket.h>

#include <netstack.h>

#define premain __attribute__((constructor)) premain

void premain(int, char *[]);
void segvhandler(int);
void postexit(void);

struct netstack instance;

void premain(int argc, char *argv[]) {
    // Register error/exit handlers
    signal(SIGSEGV, segvhandler);
    atexit(postexit);

    // TODO: Parse config based on argv/configuration file

    // Initialise the netstack instance
    netstack_init(&instance);

    LOG(LINFO, "netstack v%s loaded, via libnshook", NETSTACK_VERSION);
}

/*!
 * Runs at the event of a SIGSEGV, then raises another SIGSEGV
 * @param num signal value. Set to 11 for SIGSEGV
 */
void segvhandler(int num) {
    LOG(LINFO, "netstack exiting");

    netstack_cleanup(&instance);

    // Unbind this/all SIGSEGV handlers to prevent infinite loop
    signal(SIGSEGV, SIG_DFL);
    // Re-trigger the segfault
    raise(num);
}

/*!
 * Runs after the process exits successfully
 */
void postexit(void) {
    LOG(LINFO, "netstack exiting");
    netstack_cleanup(&instance);
}
