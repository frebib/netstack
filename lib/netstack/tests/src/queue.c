#include <check.h>
#include <stdlib.h>

#include <netstack/llist.h>

START_TEST (empty_llist)
    {
        struct llist q = LLIST_INITIALISER;
        ck_assert_ptr_null(llist_pop(&q));
    }
END_TEST

START_TEST (single_append)
    {
        struct llist qs = LLIST_INITIALISER, *q = &qs;
        llist_append(q, (void *) 1);
        ck_assert_ptr_nonnull(q->head);
        ck_assert_ptr_eq(q->head, q->tail);
        ck_assert_ptr_null(q->head->prev);
        ck_assert_ptr_null(q->head->next);
        ck_assert_ptr_eq(llist_pop(q), (void *)1);
        ck_assert_ptr_null(llist_pop(q));
        ck_assert_ptr_null(q->head);
    }
END_TEST

START_TEST (dual_append)
    {
        struct llist qs = LLIST_INITIALISER, *q = &qs;
        llist_append(q, (void *) 1);
        llist_append(q, (void *) 2);
        ck_assert_ptr_null(q->head->prev);
        ck_assert_ptr_nonnull(q->head->next);
        ck_assert_ptr_nonnull(q->head->next->prev);
        ck_assert_ptr_null(q->head->next->next);
        ck_assert_ptr_eq(q->head->next, q->tail);
        ck_assert_ptr_eq(q->head, q->tail->prev);
        ck_assert_ptr_eq(llist_pop(q), (void *)1);
        ck_assert_ptr_nonnull(q->head);
        ck_assert_ptr_eq(q->head, q->tail);
        ck_assert_ptr_null(q->head->next);
        ck_assert_ptr_null(q->head->prev);
        ck_assert_ptr_eq(llist_pop(q), (void *)2);
        ck_assert_ptr_null(q->head);
    }
END_TEST

START_TEST (multi_append)
    {
        struct llist qs = LLIST_INITIALISER, *q = &qs;
        llist_append(q, (void *) 1);
        llist_append(q, (void *) 2);
        llist_append(q, (void *) 3);
        ck_assert_ptr_eq(q->head->data, (void *)1);
        ck_assert_ptr_nonnull(q->head->next);
        ck_assert_ptr_eq(q->head->next->data, (void *)2);
        ck_assert_ptr_nonnull(q->head->next->next);
        ck_assert_ptr_eq(q->head->next->next->data, (void *)3);
        ck_assert_ptr_null(q->head->next->next->next);
    }
END_TEST

START_TEST (multi_append_pop)
    {
        struct llist qs = LLIST_INITIALISER, *q = &qs;
        llist_append(q, (void *) 1);
        llist_append(q, (void *) 2);
        llist_append(q, (void *) 3);
        ck_assert_ptr_eq(llist_pop(q), (void *)1);
        llist_append(q, (void *) 4);
        ck_assert_ptr_eq(llist_pop(q), (void *)2);
        ck_assert_ptr_eq(llist_pop(q), (void *)3);
        llist_append(q, (void *) 5);
        ck_assert_ptr_eq(llist_pop(q), (void *)4);
        ck_assert_ptr_eq(llist_pop(q), (void *)5);
        ck_assert_ptr_null(llist_pop(q));
    }
END_TEST

Suite *llist_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Queue");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, empty_llist);
    tcase_add_test(tc_core, single_append);
    tcase_add_test(tc_core, dual_append);
    tcase_add_test(tc_core, multi_append);
    tcase_add_test(tc_core, multi_append_pop);
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
