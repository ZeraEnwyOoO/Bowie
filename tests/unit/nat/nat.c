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
 * BOWIE — NAT UNIT TESTS
 * ============================================================================
 *
 * Unit tests for the NAT interface and the libjuice backend.
 *
 * These tests exercise the contract: argument validation,
 * lifecycle transitions, state reporting, callback
 * installation, and the capabilities report. They do not
 * exercise a real network connection; that is an integration
 * test and belongs in tests/integration/.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No real connection. bowie_nat_connect() is not called
 *     with a real peer that answers; the one test that calls
 *     it with a signal callback installed expects a timeout,
 *     because no peer answers.
 *   - No real data transfer. bowie_nat_send() and
 *     bowie_nat_recv() are only checked for their NULL and
 *     state contracts.
 *   - No server. No STUN or TURN server is contacted in a
 *     way that is expected to succeed.
 *   - No threading test. The callbacks are installed and
 *     removed; they are not invoked except by the timeout
 *     test, where the signal callback is invoked by libjuice
 *     with no peer on the other end.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Every test follows the same shape: set up, call, assert,
 * tear down. A test that creates an instance frees it before
 * it returns, so a failing test does not leak.
 *
 * The suite is split into six cases:
 *
 *   contract   — NULL arguments and invalid values
 *   lifecycle  — new, start, stop, free
 *   connect    — connection contract
 *   state      — get_state, set_state_cb, state_name
 *   callbacks  — set_recv, set_signal
 *   caps       — capabilities
 *
 * The connect case has three tests:
 *
 *   test_connect_not_started         — no start, expect error
 *   test_connect_no_signal           — no signal, expect error
 *   test_connect_with_signal_timeout — signal installed, no
 *                                      peer, expect timeout
 *
 * The timeout test blocks for the timeout it passes, so the
 * timeout is short (100 ms). It exercises the real libjuice
 * path: gathering, candidate production, and waiting for a
 * peer that never answers.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>               test framework
 *   <stdlib.h>              NULL
 *   <string.h>              memset
 *   "bowie/types.h"         bowie_addr_t
 *   "bowie/err.h"           bowie_error_t and codes
 *   "nat/nat.h"             public NAT contract
 * ============================================================================
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "nat/nat.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_peer_addr(bowie_addr_t *addr)
{
    memset(addr, 0, sizeof(*addr));

    addr->family  = BOWIE_AF_INET;
    addr->addr[0] = 127;
    addr->addr[1] = 0;
    addr->addr[2] = 0;
    addr->addr[3] = 1;
    addr->port    = 12345;
}

/*
 * ============================================================================
 * CONTRACT — NULL AND INVALID ARGUMENTS
 * ============================================================================
 */

START_TEST(test_default_config_null)
{
    bowie_nat_default_config(NULL);
    /* no crash is the assertion */
}
END_TEST

START_TEST(test_default_config_values)
{
    bowie_nat_config_t cfg;

    memset(&cfg, 0xFF, sizeof(cfg));

    bowie_nat_default_config(&cfg);

    ck_assert_ptr_null(cfg.stun_server_host);
    ck_assert_uint_eq(cfg.stun_server_port, 0);
    ck_assert_ptr_null(cfg.turn_server_host);
    ck_assert_uint_eq(cfg.turn_server_port, 0);
    ck_assert_ptr_null(cfg.turn_username);
    ck_assert_ptr_null(cfg.turn_password);
    ck_assert_uint_eq(cfg.connect_timeout_ms, 10000);
    ck_assert_uint_eq(cfg.keepalive_ms, 0);
    ck_assert_int_eq(cfg.allow_server, 0);
}
END_TEST

START_TEST(test_new_null_cfg)
{
    bowie_nat_t  *nat = NULL;
    bowie_error_t rc;

    rc = bowie_nat_new(NULL, &nat);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
    ck_assert_ptr_null(nat);
}
END_TEST

START_TEST(test_new_null_out)
{
    bowie_nat_config_t cfg;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_new_invalid_allow_server)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);
    cfg.allow_server = 2;

    rc = bowie_nat_new(&cfg, &nat);

    ck_assert_int_eq(rc, BOWIE_ERR_INVAL);
    ck_assert_ptr_null(nat);
}
END_TEST

START_TEST(test_start_null)
{
    bowie_error_t rc;

    rc = bowie_nat_start(NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_stop_null)
{
    bowie_error_t rc;

    rc = bowie_nat_stop(NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_free_null)
{
    bowie_nat_free(NULL);
    /* no crash is the assertion */
}
END_TEST

START_TEST(test_connect_null_nat)
{
    bowie_addr_t  peer;
    bowie_error_t rc;

    make_peer_addr(&peer);

    rc = bowie_nat_connect(NULL, &peer, 1000);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_connect_null_peer)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_ptr_nonnull(nat);

    rc = bowie_nat_connect(nat, NULL, 1000);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_disconnect_null)
{
    bowie_error_t rc;

    rc = bowie_nat_disconnect(NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_send_null_nat)
{
    uint8_t buf[8] = {0};
    long    rc;

    rc = bowie_nat_send(NULL, buf, sizeof(buf));

    ck_assert_int_eq((bowie_error_t)rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_send_null_buf)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;
    long               lrc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    lrc = bowie_nat_send(nat, NULL, 8);

    ck_assert_int_eq((bowie_error_t)lrc, BOWIE_ERR_NULL_ARG);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_send_zero_len)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;
    long               lrc;
    uint8_t            buf[8] = {0};

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    lrc = bowie_nat_send(nat, buf, 0);

    ck_assert_int_eq((bowie_error_t)lrc, BOWIE_ERR_INVAL);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_recv_null_nat)
{
    uint8_t buf[8];
    long    rc;

    rc = bowie_nat_recv(NULL, buf, sizeof(buf));

    ck_assert_int_eq((bowie_error_t)rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_recv_null_buf)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;
    long               lrc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    lrc = bowie_nat_recv(nat, NULL, 8);

    ck_assert_int_eq((bowie_error_t)lrc, BOWIE_ERR_NULL_ARG);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_recv_zero_cap)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;
    long               lrc;
    uint8_t            buf[8];

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    lrc = bowie_nat_recv(nat, buf, 0);

    ck_assert_int_eq((bowie_error_t)lrc, BOWIE_ERR_INVAL);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_set_recv_null)
{
    bowie_error_t rc;

    rc = bowie_nat_set_recv(NULL, NULL, NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_set_signal_null)
{
    bowie_error_t rc;

    rc = bowie_nat_set_signal(NULL, NULL, NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_signal_recv_null_nat)
{
    uint8_t       data[8] = {0};
    bowie_error_t rc;

    rc = bowie_nat_signal_recv(NULL, data, sizeof(data));

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_signal_recv_null_data)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_signal_recv(nat, NULL, 8);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_signal_recv_zero_len)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;
    uint8_t            data[8] = {0};

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_signal_recv(nat, data, 0);

    ck_assert_int_eq(rc, BOWIE_ERR_INVAL);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_set_state_cb_null)
{
    bowie_error_t rc;

    rc = bowie_nat_set_state_cb(NULL, NULL, NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_capabilities_null_nat)
{
    bowie_nat_caps_t caps;
    bowie_error_t    rc;

    rc = bowie_nat_capabilities(NULL, &caps);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_capabilities_null_out)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_capabilities(nat, NULL);

    ck_assert_int_eq(rc, BOWIE_ERR_NULL_ARG);

    bowie_nat_free(nat);
}
END_TEST

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

START_TEST(test_new_ok)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_ptr_nonnull(nat);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_new_allow_server_ok)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);
    cfg.allow_server     = 1;
    cfg.stun_server_host = "stun.cloudflare.com";
    cfg.stun_server_port = 3478;

    rc = bowie_nat_new(&cfg, &nat);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_ptr_nonnull(nat);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_start_ok)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_start(nat);

    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_start_twice)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_start(nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_start(nat);
    ck_assert_int_eq(rc, BOWIE_ERR_STATE);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_stop_ok)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_start(nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_stop(nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_stop_not_started)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_stop(nat);

    ck_assert_int_eq(rc, BOWIE_ERR_NOT_STARTED);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_start_stop_start)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_start(nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_stop(nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_start(nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_free_started)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_start(nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    /* free must stop first; no crash is the assertion */
    bowie_nat_free(nat);
}
END_TEST

/*
 * ============================================================================
 * CONNECT — CONTRACT ONLY
 * ============================================================================
 */

START_TEST(test_connect_not_started)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_addr_t       peer;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    make_peer_addr(&peer);

    rc = bowie_nat_connect(nat, &peer, 100);

    ck_assert_int_eq(rc, BOWIE_ERR_NOT_STARTED);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_connect_no_signal)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_addr_t       peer;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_start(nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    make_peer_addr(&peer);

    /* No signal callback installed. */
    rc = bowie_nat_connect(nat, &peer, 100);

    ck_assert_int_eq(rc, BOWIE_ERR_NOT_INITIALIZED);

    bowie_nat_free(nat);
}
END_TEST

/*
 * ============================================================================
 * CONNECT — SIGNAL INSTALLED, NO PEER ANSWERS
 * ============================================================================
 *
 * This test exercises the real libjuice path: gathering runs,
 * a candidate is produced, and the signal callback is invoked
 * with an SDP blob. No peer answers, so the connect call
 * blocks until the timeout and then returns BOWIE_ERR_TIMEOUT.
 *
 * The timeout is short so the test does not slow the suite
 * noticeably. It is deliberately not zero: zero would mean
 * "use the backend default", which is 10 seconds.
 */

static bowie_error_t dummy_signal_send(void                  *ctx,
                                       const bowie_peer_id_t *peer,
                                       const uint8_t         *data,
                                       size_t                 len)
{
    (void)ctx;
    (void)peer;
    (void)data;
    (void)len;

    return BOWIE_OK;
}

START_TEST(test_connect_with_signal_timeout)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_addr_t       peer;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_start(nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_set_signal(nat, dummy_signal_send, NULL);
    ck_assert_int_eq(rc, BOWIE_OK);

    make_peer_addr(&peer);

    rc = bowie_nat_connect(nat, &peer, 100);

    ck_assert_int_eq(rc, BOWIE_ERR_TIMEOUT);

    bowie_nat_free(nat);
}
END_TEST

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

START_TEST(test_get_state_null)
{
    bowie_nat_state_t state;

    state = bowie_nat_get_state(NULL);

    ck_assert_int_eq(state, BOWIE_NAT_STATE_DISCONNECTED);
}
END_TEST

START_TEST(test_get_state_initial)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;
    bowie_nat_state_t  state;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    state = bowie_nat_get_state(nat);

    ck_assert_int_eq(state, BOWIE_NAT_STATE_DISCONNECTED);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_state_name_disconnected)
{
    const char *name;

    name = bowie_nat_state_name(BOWIE_NAT_STATE_DISCONNECTED);

    ck_assert_ptr_nonnull(name);
    ck_assert_str_eq(name, "DISCONNECTED");
}
END_TEST

START_TEST(test_state_name_gathering)
{
    const char *name;

    name = bowie_nat_state_name(BOWIE_NAT_STATE_GATHERING);

    ck_assert_ptr_nonnull(name);
    ck_assert_str_eq(name, "GATHERING");
}
END_TEST

START_TEST(test_state_name_connecting)
{
    const char *name;

    name = bowie_nat_state_name(BOWIE_NAT_STATE_CONNECTING);

    ck_assert_ptr_nonnull(name);
    ck_assert_str_eq(name, "CONNECTING");
}
END_TEST

START_TEST(test_state_name_connected)
{
    const char *name;

    name = bowie_nat_state_name(BOWIE_NAT_STATE_CONNECTED);

    ck_assert_ptr_nonnull(name);
    ck_assert_str_eq(name, "CONNECTED");
}
END_TEST

START_TEST(test_state_name_completed)
{
    const char *name;

    name = bowie_nat_state_name(BOWIE_NAT_STATE_COMPLETED);

    ck_assert_ptr_nonnull(name);
    ck_assert_str_eq(name, "COMPLETED");
}
END_TEST

START_TEST(test_state_name_failed)
{
    const char *name;

    name = bowie_nat_state_name(BOWIE_NAT_STATE_FAILED);

    ck_assert_ptr_nonnull(name);
    ck_assert_str_eq(name, "FAILED");
}
END_TEST

START_TEST(test_state_name_unknown)
{
    const char *name;

    name = bowie_nat_state_name((bowie_nat_state_t)99);

    ck_assert_ptr_nonnull(name);
    ck_assert_str_eq(name, "UNKNOWN");
}
END_TEST

/*
 * ============================================================================
 * CALLBACKS — INSTALL AND REMOVE
 * ============================================================================
 */

static void dummy_recv(void          *ctx,
                       const uint8_t *data,
                       size_t         len)
{
    (void)ctx;
    (void)data;
    (void)len;
}

static void dummy_state(void              *ctx,
                        bowie_nat_state_t  state)
{
    (void)ctx;
    (void)state;
}

START_TEST(test_set_signal_install_remove)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_set_signal(nat, dummy_signal_send, NULL);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_set_signal(nat, NULL, NULL);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_set_recv_install_remove)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_set_recv(nat, dummy_recv, NULL);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_set_recv(nat, NULL, NULL);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_set_state_cb_install_remove)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_set_state_cb(nat, dummy_state, NULL);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_set_state_cb(nat, NULL, NULL);
    ck_assert_int_eq(rc, BOWIE_OK);

    bowie_nat_free(nat);
}
END_TEST

/*
 * ============================================================================
 * CAPABILITIES
 * ============================================================================
 */

START_TEST(test_capabilities_default)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_nat_caps_t   caps;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_capabilities(nat, &caps);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_ptr_nonnull(caps.name);
    ck_assert_str_eq(caps.name, "libjuice");
    ck_assert_int_eq(caps.performs_nat_traversal, 1);
    ck_assert_int_eq(caps.uses_server, 0);
    ck_assert_int_eq(caps.can_relay, 0);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_capabilities_with_stun)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_nat_caps_t   caps;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);
    cfg.allow_server     = 1;
    cfg.stun_server_host = "stun.cloudflare.com";
    cfg.stun_server_port = 3478;

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_capabilities(nat, &caps);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_int_eq(caps.uses_server, 1);
    ck_assert_int_eq(caps.can_relay, 0);

    bowie_nat_free(nat);
}
END_TEST

START_TEST(test_capabilities_with_turn)
{
    bowie_nat_config_t cfg;
    bowie_nat_t       *nat = NULL;
    bowie_nat_caps_t   caps;
    bowie_error_t      rc;

    bowie_nat_default_config(&cfg);
    cfg.allow_server     = 1;
    cfg.stun_server_host = "stun.cloudflare.com";
    cfg.stun_server_port = 3478;
    cfg.turn_server_host = "127.0.0.1";
    cfg.turn_server_port = 3478;
    cfg.turn_username    = "bowie";
    cfg.turn_password    = "bowietest";

    rc = bowie_nat_new(&cfg, &nat);
    ck_assert_int_eq(rc, BOWIE_OK);

    rc = bowie_nat_capabilities(nat, &caps);

    ck_assert_int_eq(rc, BOWIE_OK);
    ck_assert_int_eq(caps.uses_server, 1);
    ck_assert_int_eq(caps.can_relay, 1);

    bowie_nat_free(nat);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *nat_suite(void)
{
    Suite *s;
    TCase *tc_contract;
    TCase *tc_lifecycle;
    TCase *tc_connect;
    TCase *tc_state;
    TCase *tc_callbacks;
    TCase *tc_caps;

    s = suite_create("Nat");

    tc_contract = tcase_create("Contract");
    tcase_add_test(tc_contract, test_default_config_null);
    tcase_add_test(tc_contract, test_default_config_values);
    tcase_add_test(tc_contract, test_new_null_cfg);
    tcase_add_test(tc_contract, test_new_null_out);
    tcase_add_test(tc_contract, test_new_invalid_allow_server);
    tcase_add_test(tc_contract, test_start_null);
    tcase_add_test(tc_contract, test_stop_null);
    tcase_add_test(tc_contract, test_free_null);
    tcase_add_test(tc_contract, test_connect_null_nat);
    tcase_add_test(tc_contract, test_connect_null_peer);
    tcase_add_test(tc_contract, test_disconnect_null);
    tcase_add_test(tc_contract, test_send_null_nat);
    tcase_add_test(tc_contract, test_send_null_buf);
    tcase_add_test(tc_contract, test_send_zero_len);
    tcase_add_test(tc_contract, test_recv_null_nat);
    tcase_add_test(tc_contract, test_recv_null_buf);
    tcase_add_test(tc_contract, test_recv_zero_cap);
    tcase_add_test(tc_contract, test_set_recv_null);
    tcase_add_test(tc_contract, test_set_signal_null);
    tcase_add_test(tc_contract, test_signal_recv_null_nat);
    tcase_add_test(tc_contract, test_signal_recv_null_data);
    tcase_add_test(tc_contract, test_signal_recv_zero_len);
    tcase_add_test(tc_contract, test_set_state_cb_null);
    tcase_add_test(tc_contract, test_capabilities_null_nat);
    tcase_add_test(tc_contract, test_capabilities_null_out);
    suite_add_tcase(s, tc_contract);

    tc_lifecycle = tcase_create("Lifecycle");
    tcase_add_test(tc_lifecycle, test_new_ok);
    tcase_add_test(tc_lifecycle, test_new_allow_server_ok);
    tcase_add_test(tc_lifecycle, test_start_ok);
    tcase_add_test(tc_lifecycle, test_start_twice);
    tcase_add_test(tc_lifecycle, test_stop_ok);
    tcase_add_test(tc_lifecycle, test_stop_not_started);
    tcase_add_test(tc_lifecycle, test_start_stop_start);
    tcase_add_test(tc_lifecycle, test_free_started);
    suite_add_tcase(s, tc_lifecycle);

    tc_connect = tcase_create("Connect");
    tcase_add_test(tc_connect, test_connect_not_started);
    tcase_add_test(tc_connect, test_connect_no_signal);
    tcase_add_test(tc_connect, test_connect_with_signal_timeout);
    suite_add_tcase(s, tc_connect);

    tc_state = tcase_create("State");
    tcase_add_test(tc_state, test_get_state_null);
    tcase_add_test(tc_state, test_get_state_initial);
    tcase_add_test(tc_state, test_state_name_disconnected);
    tcase_add_test(tc_state, test_state_name_gathering);
    tcase_add_test(tc_state, test_state_name_connecting);
    tcase_add_test(tc_state, test_state_name_connected);
    tcase_add_test(tc_state, test_state_name_completed);
    tcase_add_test(tc_state, test_state_name_failed);
    tcase_add_test(tc_state, test_state_name_unknown);
    suite_add_tcase(s, tc_state);

    tc_callbacks = tcase_create("Callbacks");
    tcase_add_test(tc_callbacks, test_set_signal_install_remove);
    tcase_add_test(tc_callbacks, test_set_recv_install_remove);
    tcase_add_test(tc_callbacks, test_set_state_cb_install_remove);
    suite_add_tcase(s, tc_callbacks);

    tc_caps = tcase_create("Capabilities");
    tcase_add_test(tc_caps, test_capabilities_default);
    tcase_add_test(tc_caps, test_capabilities_with_stun);
    tcase_add_test(tc_caps, test_capabilities_with_turn);
    suite_add_tcase(s, tc_caps);

    return s;
}

int main(void)
{
    Suite   *s;
    SRunner *sr;
    int      failed;

    s  = nat_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
