/*
 * Bowie — P2P Internet Sharing Tool (Repo: bowie)
 * Copyright (C) 2026 ASBM Team
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * ============================================================================
 * BOWIE — ENGINE UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the engine declared in engine/engine.h.
 *
 * These tests exercise the state machine: a new engine is
 * stopped, a started engine is started, a connected engine is
 * running, and a disconnected engine is started again. They
 * do not exercise the DHT or the NAT layer, because those
 * modules are not yet implemented.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No network.
 *   - No DHT or NAT. Those modules are not yet implemented.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The tests use the real engine, with a placeholder tunnel
 * (NULL is not allowed; the tests pass a dummy pointer that
 * the engine does not dereference).
 *
 * The state machine is deterministic. Every test runs in one
 * thread; the engine's lock is not exercised across threads.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>               test framework
 *   <string.h>              memset
 *   "bowie/types.h"         types
 *   "bowie/err.h"           errors
 *   "engine/engine.h"       declarations
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "engine/engine.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static bowie_engine_t *make_engine(void)
{
    bowie_engine_config_t cfg;
    bowie_engine_t       *e = NULL;
    bowie_error_t         rc;

    bowie_engine_default_config(&cfg);

    rc = bowie_engine_new(&cfg, &e);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_ptr_nonnull(e);

    return e;
}

static bowie_peer_id_t make_peer_id(void)
{
    bowie_peer_id_t id;

    memset(&id, 0xAA, sizeof(id));

    return id;
}

/*
 * A dummy tunnel pointer. The engine only stores it; it does
 * not dereference it in the current placeholder implementation.
 */
static bowie_tun_t *dummy_tun(void)
{
    return (bowie_tun_t *)0x1;
}

/*
 * ============================================================================
 * CONFIG
 * ============================================================================
 */

START_TEST(test_engine_default_config)
{
    bowie_engine_config_t cfg;

    memset(&cfg, 0xFF, sizeof(cfg));
    bowie_engine_default_config(&cfg);

    ck_assert_uint_eq(cfg.dht_port, 0);
    ck_assert_uint_eq(cfg.nat_port, 0);
    ck_assert_int_eq(cfg.allow_server, 0);
    ck_assert_ptr_null(cfg.stun_host);
    ck_assert_uint_eq(cfg.stun_port, 0);
    ck_assert_ptr_null(cfg.turn_host);
    ck_assert_uint_eq(cfg.turn_port, 0);
    ck_assert_ptr_null(cfg.turn_user);
    ck_assert_ptr_null(cfg.turn_pass);
    ck_assert_uint_eq(cfg.tunnel_mtu, 0);
}
END_TEST

START_TEST(test_engine_default_config_null)
{
    bowie_engine_default_config(NULL);
}
END_TEST

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_engine_new_null_cfg)
{
    bowie_engine_t *e = NULL;
    bowie_error_t   rc;

    rc = bowie_engine_new(NULL, &e);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
    ck_assert_ptr_null(e);
}
END_TEST

START_TEST(test_engine_new_null_out)
{
    bowie_engine_config_t cfg;

    bowie_engine_default_config(&cfg);

    {
        bowie_error_t rc = bowie_engine_new(&cfg, NULL);
        ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
    }
}
END_TEST

START_TEST(test_engine_new_ok)
{
    bowie_engine_t *e = make_engine();

    ck_assert_int_eq(bowie_engine_get_state(e),
                     BOWIE_ENGINE_STOPPED);

    bowie_engine_free(e);
}
END_TEST

START_TEST(test_engine_free_null)
{
    bowie_engine_free(NULL);
}
END_TEST

/*
 * ============================================================================
 * START / STOP
 * ============================================================================
 */

START_TEST(test_engine_start_null)
{
    bowie_error_t rc = bowie_engine_start(NULL, dummy_tun());

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_engine_start_null_tun)
{
    bowie_engine_t *e = make_engine();
    bowie_error_t   rc;

    rc = bowie_engine_start(e, NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);

    bowie_engine_free(e);
}
END_TEST

START_TEST(test_engine_start_ok)
{
    bowie_engine_t *e = make_engine();
    bowie_error_t   rc;

    rc = bowie_engine_start(e, dummy_tun());

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_int_eq(bowie_engine_get_state(e),
                     BOWIE_ENGINE_STARTED);

    bowie_engine_free(e);
}
END_TEST

START_TEST(test_engine_start_twice)
{
    bowie_engine_t *e = make_engine();
    bowie_error_t   rc;

    rc = bowie_engine_start(e, dummy_tun());
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_engine_start(e, dummy_tun());
    ck_assert_int_eq(rc, BOWIE_ERR_STATE);

    bowie_engine_free(e);
}
END_TEST

START_TEST(test_engine_stop_null)
{
    bowie_error_t rc = bowie_engine_stop(NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_engine_stop_not_started)
{
    bowie_engine_t *e = make_engine();
    bowie_error_t   rc;

    rc = bowie_engine_stop(e);

    ck_assert_int_eq(rc, BOWIE_ERR_NOT_STARTED);

    bowie_engine_free(e);
}
END_TEST

START_TEST(test_engine_stop_ok)
{
    bowie_engine_t *e = make_engine();
    bowie_error_t   rc;

    rc = bowie_engine_start(e, dummy_tun());
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_engine_stop(e);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_int_eq(bowie_engine_get_state(e),
                     BOWIE_ENGINE_STOPPED);

    bowie_engine_free(e);
}
END_TEST

/*
 * ============================================================================
 * CONNECT / DISCONNECT
 * ============================================================================
 */

START_TEST(test_engine_connect_null)
{
    bowie_peer_id_t peer;
    bowie_error_t   rc;

    peer = make_peer_id();

    rc = bowie_engine_connect(NULL, &peer, 100);
    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_engine_connect_not_started)
{
    bowie_engine_t *e = make_engine();
    bowie_peer_id_t peer;
    bowie_error_t   rc;

    peer = make_peer_id();

    rc = bowie_engine_connect(e, &peer, 100);
    ck_assert_int_eq(rc, BOWIE_ERR_NOT_STARTED);

    bowie_engine_free(e);
}
END_TEST

START_TEST(test_engine_connect_ok)
{
    bowie_engine_t *e = make_engine();
    bowie_peer_id_t peer;
    bowie_error_t   rc;

    peer = make_peer_id();

    rc = bowie_engine_start(e, dummy_tun());
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_engine_connect(e, &peer, 100);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_int_eq(bowie_engine_get_state(e),
                     BOWIE_ENGINE_RUNNING);

    bowie_engine_free(e);
}
END_TEST

START_TEST(test_engine_connect_busy)
{
    bowie_engine_t *e = make_engine();
    bowie_peer_id_t peer;
    bowie_error_t   rc;

    peer = make_peer_id();

    rc = bowie_engine_start(e, dummy_tun());
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_engine_connect(e, &peer, 100);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_engine_connect(e, &peer, 100);
    ck_assert_int_eq(rc, BOWIE_ERR_BUSY);

    bowie_engine_free(e);
}
END_TEST

START_TEST(test_engine_disconnect_null)
{
    bowie_error_t rc = bowie_engine_disconnect(NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_engine_disconnect_not_running)
{
    bowie_engine_t *e = make_engine();
    bowie_error_t   rc;

    rc = bowie_engine_disconnect(e);
    ck_assert_int_eq(rc, BOWIE_ERR_STATE);

    bowie_engine_free(e);
}
END_TEST

START_TEST(test_engine_disconnect_ok)
{
    bowie_engine_t *e = make_engine();
    bowie_peer_id_t peer;
    bowie_error_t   rc;

    peer = make_peer_id();

    rc = bowie_engine_start(e, dummy_tun());
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_engine_connect(e, &peer, 100);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_engine_disconnect(e);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_int_eq(bowie_engine_get_state(e),
                     BOWIE_ENGINE_STARTED);

    bowie_engine_free(e);
}
END_TEST

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

START_TEST(test_engine_state_name_stopped)
{
    const char *s = bowie_engine_state_name(BOWIE_ENGINE_STOPPED);
    ck_assert_str_eq(s, "STOPPED");
}
END_TEST

START_TEST(test_engine_state_name_started)
{
    const char *s = bowie_engine_state_name(BOWIE_ENGINE_STARTED);
    ck_assert_str_eq(s, "STARTED");
}
END_TEST

START_TEST(test_engine_state_name_running)
{
    const char *s = bowie_engine_state_name(BOWIE_ENGINE_RUNNING);
    ck_assert_str_eq(s, "RUNNING");
}
END_TEST

START_TEST(test_engine_state_name_unknown)
{
    const char *s = bowie_engine_state_name((bowie_engine_state_t)99);
    ck_assert_str_eq(s, "UNKNOWN");
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *engine_suite(void)
{
    Suite *s;
    TCase *tc_config;
    TCase *tc_lifecycle;
    TCase *tc_start_stop;
    TCase *tc_connect;
    TCase *tc_state;

    s = suite_create("Engine");

    tc_config = tcase_create("Config");
    tcase_add_test(tc_config, test_engine_default_config);
    tcase_add_test(tc_config, test_engine_default_config_null);
    suite_add_tcase(s, tc_config);

    tc_lifecycle = tcase_create("Lifecycle");
    tcase_add_test(tc_lifecycle, test_engine_new_null_cfg);
    tcase_add_test(tc_lifecycle, test_engine_new_null_out);
    tcase_add_test(tc_lifecycle, test_engine_new_ok);
    tcase_add_test(tc_lifecycle, test_engine_free_null);
    suite_add_tcase(s, tc_lifecycle);

    tc_start_stop = tcase_create("StartStop");
    tcase_add_test(tc_start_stop, test_engine_start_null);
    tcase_add_test(tc_start_stop, test_engine_start_null_tun);
    tcase_add_test(tc_start_stop, test_engine_start_ok);
    tcase_add_test(tc_start_stop, test_engine_start_twice);
    tcase_add_test(tc_start_stop, test_engine_stop_null);
    tcase_add_test(tc_start_stop, test_engine_stop_not_started);
    tcase_add_test(tc_start_stop, test_engine_stop_ok);
    suite_add_tcase(s, tc_start_stop);

    tc_connect = tcase_create("Connect");
    tcase_add_test(tc_connect, test_engine_connect_null);
    tcase_add_test(tc_connect, test_engine_connect_not_started);
    tcase_add_test(tc_connect, test_engine_connect_ok);
    tcase_add_test(tc_connect, test_engine_connect_busy);
    tcase_add_test(tc_connect, test_engine_disconnect_null);
    tcase_add_test(tc_connect, test_engine_disconnect_not_running);
    tcase_add_test(tc_connect, test_engine_disconnect_ok);
    suite_add_tcase(s, tc_connect);

    tc_state = tcase_create("State");
    tcase_add_test(tc_state, test_engine_state_name_stopped);
    tcase_add_test(tc_state, test_engine_state_name_started);
    tcase_add_test(tc_state, test_engine_state_name_running);
    tcase_add_test(tc_state, test_engine_state_name_unknown);
    suite_add_tcase(s, tc_state);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = engine_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
