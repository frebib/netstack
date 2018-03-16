# netstack: TCP/IP network stack implementation in userland
[![Build Status](https://drone.spritsail.io/api/badges/frebib/netstack/status.svg)](https://drone.spritsail.io/frebib/netstack)

The homepage for this project is hosted on GitHub: [https://github.com/frebib/netstack](https://github.com/frebib/netstack)

This is made up of two integral parts:

* **netd** - A network daemon to process and control network communications, using libnetstack
* **libnetstack** - A full userspace network stack implementation in a library

_It should be noted that until a far distant time, there is no guarantee of API or ABI stability. Most things can and likely will change, until a stable release (if ever)._

## Building

### GNU Make
```bash
# Build binary, library and documentation
make all
# Install to the local filesystem
sudo make install PREFIX=/usr/local
```

Available targets are as follows:

* `libnetstack.so`  - Network stack library
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

## Testing

There are several bundled unit tests to test various parts of core code. They depend on [`libcheck`](https://github.com/libcheck/check).
These can be run with
```
make test
```

## Debugging

Memory leaks can be discovered with valgind, using something similar to the following:
```sh
valgrind --vgdb=yes --leak-check=full --show-reachable=yes --track-origins=yes ./netd
```
