#include <check.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <netstack/col/seqbuf.h>

START_TEST (read_write)
    {
        size_t testlen = 300;
        uint8_t testdata[testlen];
        int fd = open("/dev/urandom", O_RDONLY);
        read(fd, testdata, testlen);

        srandom(time(NULL));
        size_t start = (size_t) random() % UINT16_MAX;

        seqbuf_t buf;
        ck_assert_int_eq(seqbuf_init(&buf, random() % 87, start), 0);

        ck_assert_int_eq(seqbuf_write(&buf, testdata + 000, 100), 100);
        ck_assert_int_eq(buf.count, 100);
        ck_assert_int_eq(seqbuf_write(&buf, testdata + 100, 100), 100);
        ck_assert_int_eq(buf.count, 200);
        ck_assert_int_eq(seqbuf_write(&buf, testdata + 200, 100), 100);
        ck_assert_int_eq(buf.count, 300);

        // Ensure all bytes are available
        ck_assert_int_eq(testlen, seqbuf_available(&buf, start));

        uint8_t outdata[testlen];
        ck_assert_int_eq(seqbuf_read(&buf, start, outdata, 300), 300);

        // Ensure data is identical
        ck_assert_mem_eq(testdata, outdata, 300);

        // Ensure no bytes have been consumed
        ck_assert_int_eq(seqbuf_available(&buf, start), 300);

        size_t consume_amt = 100;
        size_t newstart = start + consume_amt;
        seqbuf_consume(&buf, consume_amt);
        ck_assert_int_eq(seqbuf_available(&buf, newstart), testlen - consume_amt);

        seqbuf_consume(&buf, (size_t) seqbuf_available(&buf, newstart));
        ck_assert_int_eq(seqbuf_available(&buf, newstart + (testlen - consume_amt)), 0);
    }
END_TEST

Suite *llist_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Sequential Buffer");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, read_write);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int fails;
    SRunner *sr = srunner_create(llist_suite());
    srunner_run_all(sr, CK_NORMAL);
    fails = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (fails == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
