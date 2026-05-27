/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "shared.h"
#include "remoted.h"

static void test_ar_extract_sized_module_and_payload_keeps_first_payload_byte(void **state)
{
    (void)state;

    unsigned char buffer[] = {
        's','y','s','c','o','l','l','e','c','t','o','r','_','v','d','_','r','u','n','t','i','m','e','_','j','a','v','a','_','f','u','l','l','_','s','y','n','c',' ',
        0x7c, 0x01, 0x02, 0x03
    };
    char *module_name = NULL;
    char *payload_start = NULL;

    assert_int_equal(0, ar_extract_sized_module_and_payload((char *)buffer, &module_name, &payload_start));
    assert_string_equal(module_name, "syscollector_vd_runtime_java_full_sync");
    assert_ptr_equal(payload_start, (char *)buffer + strlen("syscollector_vd_runtime_java_full_sync") + 1);
    assert_int_equal((unsigned char)payload_start[0], 0x7c);
    assert_int_equal((unsigned char)payload_start[1], 0x01);
}

static void test_ar_has_complete_sized_payload_accepts_exact_payload(void **state)
{
    (void)state;

    unsigned char buffer[] = {
        's','y','s','c','o','l','l','e','c','t','o','r','_','v','d','_','s','y','n','c',' ',
        0x7c, 0x01, 0x02, 0x03
    };
    char *module_name = NULL;
    char *payload_start = NULL;

    assert_int_equal(0, ar_extract_sized_module_and_payload((char *)buffer, &module_name, &payload_start));
    assert_int_equal(1, ar_has_complete_sized_payload((char *)buffer,
                                                      payload_start,
                                                      sizeof(buffer),
                                                      4));
}

static void test_ar_has_complete_sized_payload_rejects_truncated_payload(void **state)
{
    (void)state;

    unsigned char buffer[] = {
        's','y','s','c','o','l','l','e','c','t','o','r','_','v','d','_','s','y','n','c',' ',
        0x7c, 0x01
    };
    char *module_name = NULL;
    char *payload_start = NULL;

    assert_int_equal(0, ar_extract_sized_module_and_payload((char *)buffer, &module_name, &payload_start));
    assert_int_equal(0, ar_has_complete_sized_payload((char *)buffer,
                                                      payload_start,
                                                      sizeof(buffer),
                                                      4));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ar_extract_sized_module_and_payload_keeps_first_payload_byte),
        cmocka_unit_test(test_ar_has_complete_sized_payload_accepts_exact_payload),
        cmocka_unit_test(test_ar_has_complete_sized_payload_rejects_truncated_payload),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
