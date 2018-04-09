# netstack: TCP/IP network stack implementation in userland
[![Build Status](https://drone.spritsail.io/api/badges/frebib/netstack/status.svg)](https://drone.spritsail.io/frebib/netstack)

The homepage for this project is hosted on GitHub: [https://github.com/frebib/netstack](https://github.com/frebib/netstack)

**IF YOU ARE USING THIS CODE FOR ANY PURPOSE, PLEASE USE THE LATEST CODE FROM GITHUB ABOVE**
PRs and issues are always accepted and I'm happy to help with squashing on of the millions of bugs I left lying around :)

* **libnetstack**  - A full userspace network stack implementation in a library
* **libnshook**    - A bootstrap library to inject netstack into a dynamic executable at runtime
* **netstack-run** - A bootstrap script to preload libnshook and libnetstack at runtime, for convenience
* **httpget**      - A basic GET request tool given a host and port
* **netd**         - A network daemon to process and control network communications, using libnetstack

_It should be noted that until a far distant time, there is no guarantee of API or ABI stability. Most things can and likely will change, until a stable release (if ever)._

## Building

### GNU Make
```bash
# Build everything
make
# Install to the local filesystem
sudo make install PREFIX=/usr/local
```

Available targets are as follows:

* `libnetstack.so`  - Network stack library
* `libnshook.so  `  - Injection library
* `netd`            - Main binary, will also build `libnetstack.so`
* `build`           - Same as `netd`
* `doc`             - Builds man-pages and documentation
* `install`         - Installs everything into the filesystem

### CMake
```
mkdir build
cd build
cmake ..
make
```

### Optional features

Until such time that automated detection of extra features is added through autotools/autoconf, they have to be specified manually for now.

GNU extensions such as named pthreads can be enabled with 
```sh
CFLAGS=-D_GNU_SOURCE make ..
```
