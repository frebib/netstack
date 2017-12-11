# A complete TCP & networking stack in userland
[![Build Status](https://drone.adam-ant.co.uk/api/badges/frebib/netd/status.svg)](https://drone.adam-ant.co.uk/frebib/netd)

This is made up of two integral parts:

* **netd** - A network daemon to process and control network communications, using libnetstack
* **libnetstack** - A full userspace network stack implementation in a library

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

## Testing

There are several bundled unit tests to test various parts of core code. They depend on [`libcheck`](https://github.com/libcheck/check).
These can be run with
```
make test
```
