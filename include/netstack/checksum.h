#ifndef NETSTACK_CHECKSUM_H
#define NETSTACK_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

#if _WORDSIZE == 32
uint16_t in_csum(const void *ptr, size_t len, uint32_t initial);
#else
uint16_t in_csum(const void *ptr, size_t len, uint64_t initial);
#endif

#endif //NETSTACK_CHECKSUM_H
