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
 * BOWIE — PEER TESTS
 * ============================================================================
 *
 * Unit tests for src/net/peer.c.
 *
 * Every public function declared in net/peer.h is covered
 * here. The NULL contract of each pointer-taking function is
 * tested, because it is part of the declared contract and not
 * an accident of the implementation.
 *
 * The peer struct is a value type. The tests check that a
 * value is copied correctly, that equality is based on the
 * peer ID only, and that a peer with no capabilities reports
 * no capabilities.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memset
 *   "net/peer.h"                 the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "net/peer.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void make_peer_id(bowie_peer_id_t *id, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_PEER_ID_LEN; i++) {
        id->bytes[i] = (uint8_t)(seed + i);
    }
}

static void make_public_id(bowie_public_id_t *id, uint8_t seed)
{
    for (size_t i = 0u; i < BOWIE_PUBLIC_ID_LEN; i++) {
        id->bytes[i] = (uint8_t)(seed + i);
    }
}

static void make_endpoint(bowie_endpoint_t *ep, uint8_t seed)
{
    memset(ep, 0, sizeof(*ep));
    ep->addr.family = BOWIE_AF_INET;
    ep->addr.addr[0] = 192u;
    ep->addr.addr[1] = 168u;
    ep->addr.addr[2] = 1u;
    ep->addr.addr[3] = seed;
    ep->addr.port = (uint16_t)(1000u + seed);
    ep->transport = 1u;
}

/*
 * ============================================================================
 * CLEAR
 * ============================================================================
 */

START_TEST(test_clear_zeroes_every_field)
{
    bowie_peer_t peer;
    make_peer_id(&peer.peer_id, 1u);
    make_public_id(&peer.public_id, 2u);
    make_endpoint(&peer.endpoint, 3u);
    peer.capabilities = BOWIE_CAP_ALL;
    peer.last_seen_ms = 12345u;

    bowie_peer_clear(&peer);

    ck_assert(bowie_peer_id_is_zero(&peer.peer_id));
    ck_assert(bowie_public_id_is_zero(&peer.public_id));
    ck_assert_int_eq(peer.endpoint.addr.family, BOWIE_AF_UNSPEC);
    ck_assert_uint_eq(peer.endpoint.addr.port, 0u);
    ck_assert_uint_eq(peer.endpoint.transport, 0u);
    ck_assert_uint_eq(peer.capabilities, 0u);
    ck_assert_uint_eq(peer.last_seen_ms, 0u);
}
END_TEST

START_TEST(test_clear_null_is_noop)
{
    bowie_peer_clear(NULL);
}
END_TEST

/*
 * ============================================================================
 * IS_SET
 * ============================================================================
 */

START_TEST(test_is_set_null)
{
    ck_assert(!bowie_peer_is_set(NULL));
}
END_TEST

START_TEST(test_is_set_zeroed_peer)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    ck_assert(!bowie_peer_is_set(&peer));
}
END_TEST

START_TEST(test_is_set_with_id)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    make_peer_id(&peer.peer_id, 1u);
    ck_assert(bowie_peer_is_set(&peer));
}
END_TEST

START_TEST(test_is_set_after_clear)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    make_peer_id(&peer.peer_id, 1u);
    ck_assert(bowie_peer_is_set(&peer));

    bowie_peer_clear(&peer);
    ck_assert(!bowie_peer_is_set(&peer));
}
END_TEST

/*
 * ============================================================================
 * EQUAL
 * ============================================================================
 */

START_TEST(test_equal_null_null)
{
    ck_assert(bowie_peer_equal(NULL, NULL));
}
END_TEST

START_TEST(test_equal_null_unset)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    ck_assert(bowie_peer_equal(NULL, &peer));
    ck_assert(bowie_peer_equal(&peer, NULL));
}
END_TEST

START_TEST(test_equal_null_set)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    make_peer_id(&peer.peer_id, 1u);
    ck_assert(!bowie_peer_equal(NULL, &peer));
    ck_assert(!bowie_peer_equal(&peer, NULL));
}
END_TEST

START_TEST(test_equal_same_id)
{
    bowie_peer_t a;
    bowie_peer_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    make_peer_id(&a.peer_id, 1u);
    make_peer_id(&b.peer_id, 1u);
    ck_assert(bowie_peer_equal(&a, &b));
}
END_TEST

START_TEST(test_equal_same_id_different_endpoint)
{
    /*
     * Equality is based on the peer ID only. A peer that has
     * moved to a different address is still the same peer.
     */
    bowie_peer_t a;
    bowie_peer_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    make_peer_id(&a.peer_id, 1u);
    make_peer_id(&b.peer_id, 1u);
    make_endpoint(&a.endpoint, 1u);
    make_endpoint(&b.endpoint, 2u);
    ck_assert(bowie_peer_equal(&a, &b));
}
END_TEST

START_TEST(test_equal_same_id_different_capabilities)
{
    bowie_peer_t a;
    bowie_peer_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    make_peer_id(&a.peer_id, 1u);
    make_peer_id(&b.peer_id, 1u);
    a.capabilities = (uint32_t)BOWIE_CAP_SOURCE;
    b.capabilities = (uint32_t)BOWIE_CAP_CLIENT;
    ck_assert(bowie_peer_equal(&a, &b));
}
END_TEST

START_TEST(test_equal_same_id_different_last_seen)
{
    bowie_peer_t a;
    bowie_peer_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    make_peer_id(&a.peer_id, 1u);
    make_peer_id(&b.peer_id, 1u);
    a.last_seen_ms = 100u;
    b.last_seen_ms = 200u;
    ck_assert(bowie_peer_equal(&a, &b));
}
END_TEST

START_TEST(test_equal_different_id)
{
    bowie_peer_t a;
    bowie_peer_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    make_peer_id(&a.peer_id, 1u);
    make_peer_id(&b.peer_id, 2u);
    ck_assert(!bowie_peer_equal(&a, &b));
}
END_TEST

START_TEST(test_equal_two_unset_peers)
{
    bowie_peer_t a;
    bowie_peer_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    ck_assert(bowie_peer_equal(&a, &b));
}
END_TEST

/*
 * ============================================================================
 * HAS_CAP
 * ============================================================================
 */

START_TEST(test_has_cap_null)
{
    ck_assert(!bowie_peer_has_cap(NULL, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_peer_has_cap(NULL, BOWIE_CAP_CLIENT));
    ck_assert(!bowie_peer_has_cap(NULL, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_has_cap_none)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    ck_assert(!bowie_peer_has_cap(&peer, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_peer_has_cap(&peer, BOWIE_CAP_CLIENT));
    ck_assert(!bowie_peer_has_cap(&peer, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_has_cap_source)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.capabilities = (uint32_t)BOWIE_CAP_SOURCE;
    ck_assert(bowie_peer_has_cap(&peer, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_peer_has_cap(&peer, BOWIE_CAP_CLIENT));
    ck_assert(!bowie_peer_has_cap(&peer, BOWIE_CAP_GATEWAY));
}
END_TEST

START_TEST(test_has_cap_combined)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.capabilities = (uint32_t)BOWIE_CAP_SOURCE
                      | (uint32_t)BOWIE_CAP_GATEWAY;
    ck_assert(bowie_peer_has_cap(&peer, BOWIE_CAP_SOURCE));
    ck_assert(!bowie_peer_has_cap(&peer, BOWIE_CAP_CLIENT));
    ck_assert(bowie_peer_has_cap(&peer, BOWIE_CAP_GATEWAY));
}
END_TEST

/*
 * ============================================================================
 * SET_ID
 * ============================================================================
 */

START_TEST(test_set_id_copies)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));

    bowie_peer_id_t id;
    make_peer_id(&id, 42u);

    bowie_peer_set_id(&peer, &id);

    ck_assert(bowie_peer_id_equal(&peer.peer_id, &id));
}
END_TEST

START_TEST(test_set_id_null_peer)
{
    bowie_peer_id_t id;
    make_peer_id(&id, 1u);
    bowie_peer_set_id(NULL, &id);
}
END_TEST

START_TEST(test_set_id_null_id)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    bowie_peer_set_id(&peer, NULL);
    ck_assert(!bowie_peer_is_set(&peer));
}
END_TEST

/*
 * ============================================================================
 * SET_PUBLIC_ID
 * ============================================================================
 */

START_TEST(test_set_public_id_copies)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));

    bowie_public_id_t id;
    make_public_id(&id, 7u);

    bowie_peer_set_public_id(&peer, &id);

    ck_assert(bowie_public_id_equal(&peer.public_id, &id));
}
END_TEST

START_TEST(test_set_public_id_null_peer)
{
    bowie_public_id_t id;
    make_public_id(&id, 1u);
    bowie_peer_set_public_id(NULL, &id);
}
END_TEST

START_TEST(test_set_public_id_null_id)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    bowie_peer_set_public_id(&peer, NULL);
    ck_assert(bowie_public_id_is_zero(&peer.public_id));
}
END_TEST

/*
 * ============================================================================
 * SET_ENDPOINT
 * ============================================================================
 */

START_TEST(test_set_endpoint_copies)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));

    bowie_endpoint_t ep;
    make_endpoint(&ep, 5u);

    bowie_peer_set_endpoint(&peer, &ep);

    ck_assert_int_eq(peer.endpoint.addr.family, ep.addr.family);
    ck_assert_uint_eq(peer.endpoint.addr.port, ep.addr.port);
    ck_assert_uint_eq(peer.endpoint.transport, ep.transport);
    ck_assert_uint_eq(peer.endpoint.addr.addr[3], 5u);
}
END_TEST

START_TEST(test_set_endpoint_null_peer)
{
    bowie_endpoint_t ep;
    make_endpoint(&ep, 1u);
    bowie_peer_set_endpoint(NULL, &ep);
}
END_TEST

START_TEST(test_set_endpoint_null_endpoint)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    bowie_peer_set_endpoint(&peer, NULL);
    ck_assert_int_eq(peer.endpoint.addr.family, BOWIE_AF_UNSPEC);
}
END_TEST

/*
 * ============================================================================
 * SET_CAPABILITIES
 * ============================================================================
 */

START_TEST(test_set_capabilities)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));

    bowie_peer_set_capabilities(&peer,
                                (uint32_t)BOWIE_CAP_SOURCE);

    ck_assert_uint_eq(peer.capabilities,
                      (uint32_t)BOWIE_CAP_SOURCE);
}
END_TEST

START_TEST(test_set_capabilities_overwrites)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.capabilities = (uint32_t)BOWIE_CAP_SOURCE;

    bowie_peer_set_capabilities(&peer,
                                (uint32_t)BOWIE_CAP_CLIENT);

    ck_assert_uint_eq(peer.capabilities,
                      (uint32_t)BOWIE_CAP_CLIENT);
}
END_TEST

START_TEST(test_set_capabilities_null_peer)
{
    bowie_peer_set_capabilities(NULL, (uint32_t)BOWIE_CAP_SOURCE);
}
END_TEST

/*
 * ============================================================================
 * SET_LAST_SEEN
 * ============================================================================
 */

START_TEST(test_set_last_seen)
{
    bowie_peer_t peer;
    memset(&peer, 0, sizeof(peer));

    bowie_peer_set_last_seen(&peer, 987654u);

    ck_assert_uint_eq(peer.last_seen_ms, 987654u);
}
END_TEST

START_TEST(test_set_last_seen_null_peer)
{
    bowie_peer_set_last_seen(NULL, 1u);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *peer_suite(void)
{
    Suite *s = suite_create("Peer");

    TCase *tc_clear = tcase_create("Clear");
    tcase_add_test(tc_clear, test_clear_zeroes_every_field);
    tcase_add_test(tc_clear, test_clear_null_is_noop);
    suite_add_tcase(s, tc_clear);

    TCase *tc_set = tcase_create("IsSet");
    tcase_add_test(tc_set, test_is_set_null);
    tcase_add_test(tc_set, test_is_set_zeroed_peer);
    tcase_add_test(tc_set, test_is_set_with_id);
    tcase_add_test(tc_set, test_is_set_after_clear);
    suite_add_tcase(s, tc_set);

    TCase *tc_eq = tcase_create("Equal");
    tcase_add_test(tc_eq, test_equal_null_null);
    tcase_add_test(tc_eq, test_equal_null_unset);
    tcase_add_test(tc_eq, test_equal_null_set);
    tcase_add_test(tc_eq, test_equal_same_id);
    tcase_add_test(tc_eq, test_equal_same_id_different_endpoint);
    tcase_add_test(tc_eq, test_equal_same_id_different_capabilities);
    tcase_add_test(tc_eq, test_equal_same_id_different_last_seen);
    tcase_add_test(tc_eq, test_equal_different_id);
    tcase_add_test(tc_eq, test_equal_two_unset_peers);
    suite_add_tcase(s, tc_eq);

    TCase *tc_cap = tcase_create("HasCap");
    tcase_add_test(tc_cap, test_has_cap_null);
    tcase_add_test(tc_cap, test_has_cap_none);
    tcase_add_test(tc_cap, test_has_cap_source);
    tcase_add_test(tc_cap, test_has_cap_combined);
    suite_add_tcase(s, tc_cap);

    TCase *tc_id = tcase_create("SetId");
    tcase_add_test(tc_id, test_set_id_copies);
    tcase_add_test(tc_id, test_set_id_null_peer);
    tcase_add_test(tc_id, test_set_id_null_id);
    suite_add_tcase(s, tc_id);

    TCase *tc_pub = tcase_create("SetPublicId");
    tcase_add_test(tc_pub, test_set_public_id_copies);
    tcase_add_test(tc_pub, test_set_public_id_null_peer);
    tcase_add_test(tc_pub, test_set_public_id_null_id);
    suite_add_tcase(s, tc_pub);

    TCase *tc_ep = tcase_create("SetEndpoint");
    tcase_add_test(tc_ep, test_set_endpoint_copies);
    tcase_add_test(tc_ep, test_set_endpoint_null_peer);
    tcase_add_test(tc_ep, test_set_endpoint_null_endpoint);
    suite_add_tcase(s, tc_ep);

    TCase *tc_sc = tcase_create("SetCapabilities");
    tcase_add_test(tc_sc, test_set_capabilities);
    tcase_add_test(tc_sc, test_set_capabilities_overwrites);
    tcase_add_test(tc_sc, test_set_capabilities_null_peer);
    suite_add_tcase(s, tc_sc);

    TCase *tc_ls = tcase_create("SetLastSeen");
    tcase_add_test(tc_ls, test_set_last_seen);
    tcase_add_test(tc_ls, test_set_last_seen_null_peer);
    suite_add_tcase(s, tc_ls);

    return s;
}

int main(void)
{
    Suite *s = peer_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
