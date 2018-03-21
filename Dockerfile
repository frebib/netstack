FROM debian:stretch-slim as builder

WORKDIR /tmp/netstack

ARG CFLAGS=-D_GNU_SOURCE
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update && \
    apt-get -y install git make gcc libcap-dev && \
    git clone https://github.com/frebib/netstack.git . && \
    make install PREFIX=/usr DESTDIR=/output && \
    cp /lib/$(gcc --print-multiarch)/libgcc_s.so* /output/usr/lib && \
    cp /lib/$(gcc --print-multiarch)/libcap.so* /output/usr/lib

# ~~~~~~~~~~~~~~~~~~

FROM spritsail/busybox

COPY --from=builder /output /

CMD [ "/usr/bin/netd" ]
