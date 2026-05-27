/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "rc.h"

typedef bool (*syscollector_parse_response_func)(const unsigned char* data, size_t length);
typedef bool (*syscollector_parse_response_vd_func)(const unsigned char* data, size_t length);
typedef bool (*syscollector_parse_response_runtime_java_full_vd_func)(const unsigned char* data, size_t length);

extern int wm_sync_message(const char* command, size_t command_len);
extern unsigned int enable_synchronization;
extern bool shutdown_process_started;
extern syscollector_parse_response_func syscollector_parse_response_ptr;
extern syscollector_parse_response_vd_func syscollector_parse_response_vd_ptr;
extern syscollector_parse_response_runtime_java_full_vd_func syscollector_parse_response_runtime_java_full_vd_ptr;

static size_t regular_calls = 0;
static size_t vd_calls = 0;
static size_t runtime_java_full_calls = 0;
static const unsigned char* last_payload = NULL;
static size_t last_payload_len = 0;

static bool regular_parser(const unsigned char* data, size_t length)
{
    ++regular_calls;
    last_payload = data;
    last_payload_len = length;
    return true;
}

static bool vd_parser(const unsigned char* data, size_t length)
{
    ++vd_calls;
    last_payload = data;
    last_payload_len = length;
    return true;
}

static bool runtime_java_full_parser(const unsigned char* data, size_t length)
{
    ++runtime_java_full_calls;
    last_payload = data;
    last_payload_len = length;
    return true;
}

static void reset_state(void)
{
    enable_synchronization = 1;
    shutdown_process_started = false;
    syscollector_parse_response_ptr = regular_parser;
    syscollector_parse_response_vd_ptr = vd_parser;
    syscollector_parse_response_runtime_java_full_vd_ptr = runtime_java_full_parser;
    regular_calls = 0;
    vd_calls = 0;
    runtime_java_full_calls = 0;
    last_payload = NULL;
    last_payload_len = 0;
}

static void build_sync_command(char* buffer,
                               size_t buffer_size,
                               const char* header,
                               const unsigned char* payload,
                               size_t payload_len,
                               size_t* command_len)
{
    const size_t header_len = strlen(header);

    assert_non_null(buffer);
    assert_non_null(header);
    assert_non_null(command_len);
    assert_true(header_len + payload_len <= buffer_size);

    memcpy(buffer, header, header_len);

    if (payload && payload_len > 0)
    {
        memcpy(buffer + header_len, payload, payload_len);
    }

    *command_len = header_len + payload_len;
}

static void test_wm_sync_message_routes_regular_sync(void **state)
{
    (void)state;
    static const unsigned char payload[] = {0x01, 0x02, 0x03};
    char command[128];
    size_t command_len = 0;

    reset_state();
    build_sync_command(command, sizeof(command), SYSCOLECTOR_SYNC_HEADER, payload, sizeof(payload), &command_len);

    assert_int_equal(wm_sync_message(command, command_len), 0);
    assert_int_equal(regular_calls, 1);
    assert_int_equal(vd_calls, 0);
    assert_int_equal(runtime_java_full_calls, 0);
    assert_ptr_equal(last_payload, (const unsigned char*)command + strlen(SYSCOLECTOR_SYNC_HEADER));
    assert_int_equal(last_payload_len, sizeof(payload));
}

static void test_wm_sync_message_routes_vd_sync(void **state)
{
    (void)state;
    static const unsigned char payload[] = {0x10, 0x20};
    char command[128];
    size_t command_len = 0;

    reset_state();
    build_sync_command(command, sizeof(command), SYSCOLECTOR_VD_SYNC_HEADER, payload, sizeof(payload), &command_len);

    assert_int_equal(wm_sync_message(command, command_len), 0);
    assert_int_equal(regular_calls, 0);
    assert_int_equal(vd_calls, 1);
    assert_int_equal(runtime_java_full_calls, 0);
    assert_ptr_equal(last_payload, (const unsigned char*)command + strlen(SYSCOLECTOR_VD_SYNC_HEADER));
    assert_int_equal(last_payload_len, sizeof(payload));
}

static void test_wm_sync_message_routes_runtime_java_full_sync_to_dedicated_parser(void **state)
{
    (void)state;
    static const unsigned char payload[] = {0xAA, 0xBB, 0xCC, 0xDD};
    char command[160];
    size_t command_len = 0;

    reset_state();
    build_sync_command(command,
                       sizeof(command),
                       SYSCOLECTOR_VD_RUNTIME_JAVA_FULL_SYNC_HEADER,
                       payload,
                       sizeof(payload),
                       &command_len);

    assert_int_equal(wm_sync_message(command, command_len), 0);
    assert_int_equal(regular_calls, 0);
    assert_int_equal(vd_calls, 0);
    assert_int_equal(runtime_java_full_calls, 1);
    assert_ptr_equal(last_payload,
                     (const unsigned char*)command + strlen(SYSCOLECTOR_VD_RUNTIME_JAVA_FULL_SYNC_HEADER));
    assert_int_equal(last_payload_len, sizeof(payload));
}

static void test_wm_sync_message_rejects_unknown_syscollector_sync_header(void **state)
{
    (void)state;
    static const unsigned char payload[] = {0xAB};
    char command[160];
    size_t command_len = 0;

    reset_state();
    build_sync_command(command,
                       sizeof(command),
                       "syscollector_vx_sync ",
                       payload,
                       sizeof(payload),
                       &command_len);

    assert_int_equal(wm_sync_message(command, command_len), -1);
    assert_int_equal(regular_calls, 0);
    assert_int_equal(vd_calls, 0);
    assert_int_equal(runtime_java_full_calls, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wm_sync_message_routes_regular_sync),
        cmocka_unit_test(test_wm_sync_message_routes_vd_sync),
        cmocka_unit_test(test_wm_sync_message_routes_runtime_java_full_sync_to_dedicated_parser),
        cmocka_unit_test(test_wm_sync_message_rejects_unknown_syscollector_sync_header),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
