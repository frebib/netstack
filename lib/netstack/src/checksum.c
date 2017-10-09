#include <netstack/checksum.h>

/* Source: https://tools.ietf.org/html/rfc1071#section-4.1 */
#if _WORDSIZE == 32
uint16_t in_csum(const uint8_t *ptr, size_t len, uint16_t initial) {

    uint32_t sum = initial;
    uint16_t *data = (uint16_t *) ptr;

    while (len > 1) {
        /*  This is the inner loop */
        sum += *data++;
        len -= 2;
    }

    /*  Add left-over byte, if any */
    if (len > 0)
        sum += *(uint8_t *) data;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t) ~sum;
}
#else
uint16_t in_csum(const void *ptr, size_t len, uint64_t initial) {

    uint64_t sum = initial;
    const uint64_t *data = (const uint64_t *) ptr;

    uint32_t t1, t2;
    uint16_t t3, t4;

    /* Main loop - 8 bytes at a time */
    while (len >= sizeof(uint64_t)) {
        uint64_t s = *data++;
        sum += s;
        if (sum < s) sum++;
        len -= sizeof(uint64_t);
    }

    /* Handle tail less than 8-bytes long */
    uint8_t* tail = (uint8_t *) data;
    if (len & 4) {
        uint32_t s = *(uint32_t *) tail;
        sum += s;
        if (sum < s) sum++;
        tail += 4;
    }

    if (len & 2) {
        uint16_t s = *(uint16_t *) tail;
        sum += s;
        if (sum < s) sum++;
        tail += 2;
    }

    if (len & 1) {
        uint8_t s = *tail;
        sum += s;
        if (sum < s) sum++;
    }

    /* Fold down to 16 bits */
    t1 = (uint32_t) sum;
    t2 = (uint32_t) (sum >> 32);
    t1 += t2;
    if (t1 < t2) t1++;
    t3 = (uint16_t) t1;
    t4 = (uint16_t) (t1 >> 16);
    t3 += t4;
    if (t3 < t4) t3++;

    return ~t3;
}
#endif
