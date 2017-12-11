#include <check.h>
#include <stdlib.h>

#include <netstack/queue.h>

START_TEST (empty_queue)
    {
        struct queue q;
        queue_init(&q);
        ck_assert_ptr_null(queue_pop(&q));
    }
END_TEST

START_TEST (single_push)
    {
        struct queue qs, *q;
        q = &qs;
        queue_init(q);
        queue_push(q, (void *) 1);
        ck_assert_ptr_nonnull(q->head);
        ck_assert_ptr_eq(q->head, q->tail);
        ck_assert_ptr_eq(queue_pop(q), (void *)1);
        ck_assert_ptr_null(queue_pop(q));
    }
END_TEST

START_TEST (dual_push)
    {
        struct queue qs, *q;
        q = &qs;
        queue_init(q);
        queue_push(q, (void *) 1);
        queue_push(q, (void *) 2);
        ck_assert_ptr_nonnull(q->head->next);
        ck_assert_ptr_nonnull(q->head->next->prev);
    }
END_TEST

START_TEST (multi_push)
    {
        struct queue qs, *q;
        q = &qs;
        queue_init(q);
        queue_push(q, (void *) 1);
        queue_push(q, (void *) 2);
        queue_push(q, (void *) 3);
        ck_assert_ptr_eq(q->head->data, (void *)1);
        ck_assert_ptr_nonnull(q->head->next);
        ck_assert_ptr_eq(q->head->next->data, (void *)2);
        ck_assert_ptr_nonnull(q->head->next->next);
        ck_assert_ptr_eq(q->head->next->next->data, (void *)3);
        ck_assert_ptr_null(q->head->next->next->next);
    }
END_TEST

START_TEST (multi_push_pop)
    {
        struct queue qs, *q;
        q = &qs;
        queue_init(q);
        queue_push(q, (void *) 1);
        queue_push(q, (void *) 2);
        queue_push(q, (void *) 3);
        ck_assert_ptr_eq(queue_pop(q), (void *)1);
        queue_push(q, (void *) 4);
        ck_assert_ptr_eq(queue_pop(q), (void *)2);
        ck_assert_ptr_eq(queue_pop(q), (void *)3);
        queue_push(q, (void *) 5);
        ck_assert_ptr_eq(queue_pop(q), (void *)4);
        ck_assert_ptr_eq(queue_pop(q), (void *)5);
        ck_assert_ptr_null(queue_pop(q));
    }
END_TEST

Suite *queue_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Queue");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, empty_queue);
    tcase_add_test(tc_core, single_push);
    tcase_add_test(tc_core, dual_push);
    tcase_add_test(tc_core, multi_push);
    tcase_add_test(tc_core, multi_push_pop);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int fails;
    SRunner *sr = srunner_create(queue_suite());
    srunner_run_all(sr, CK_NORMAL);
    fails = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (fails == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
