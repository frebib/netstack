# libnshook: Inject netstack into any binary
[![Build Status](https://drone.adam-ant.co.uk/api/badges/frebib/netd/status.svg)](https://drone.adam-ant.co.uk/frebib/netd)

libnshook is an injection library that replaces the standard BSD `socket(7)` API at runtime of any dynamically-linked binary using libdl and libc.
It can be used to test and play with netstack with no requirement to modify or recompile existing code.

This library can be loaded into any program at runtime using the following syntax:

```shell
LD_PRELOAD=path/to/libnshook.so program args ..
```

for example,
```shell
LD_PRELOAD=./libnshook.so curl github.com/frebib/netstack
```


## Notices

On Linux, libnshook relies upon the non-portable `RTLD_NEXT` feature provided by libdl and `dlsym(3)`.

It may not work on specific libc implementations. _(uClibc?)_ Glibc is known to work, musl should work also.

It likely will not work on other *nix systems although alternative functionality probably exists and can be implemented. Open an issue and we'll see what we can do.

It will _not_ work on static binaries, recompilation against libnetstack is required for that to work.

