FROM debian:stretch-slim as builder

WORKDIR /tmp/netstack

ARG CC=gcc
ARG CFLAGS=-D_GNU_SOURCE
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update && \
    apt-get -y install make gcc $CC libcap-dev

ADD . /tmp/netstack
WORKDIR /tmp/netstack

RUN make install PREFIX=/usr DESTDIR=/output && \
    cp /lib/$(gcc --print-multiarch)/libcap.so* /output/usr/lib

# ~~~~~~~~~~~~~~~~~~

FROM spritsail/busybox

COPY --from=builder /output /

CMD [ "/usr/bin/netd" ]
