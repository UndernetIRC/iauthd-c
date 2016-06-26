/* iauth_sar.c - Test harness for inaddr manipulations
 *
 * Copyright 2016 Michael Poole <mdpoole@troilus.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Functional specification:
 *
 * This should verify common use cases for sar_pton() and sar_ntop().
 * Eventually, it should provide complete branch coverage for those
 * functions (including supporting implementation functions) and for
 * the other functions declared in sar.h.
 */

#include "tests/tests.h"

/** Structure describing a test for IP address parsing and formatting. */
struct address_test {
    const char *text;      /**< Text address to parse. */
    const char *canonical; /**< Canonical form of address. */
    union {
        uint8_t v4[4];     /**< IPv4 representation. */
        uint16_t v6[8];    /**< IPv6 representation. */
    } expected;            /**< Parsed address. */
    int x_pton  : 8;       /**< Bytes used from #text. */
    int x_nbits : 8;       /**< Bits used in #expected. */
    unsigned int is_ipv4     : 1; /**< Is it an IPv4 address? */
};

/** IP address test cases. */
static const struct address_test addrs[] = {
    { "0::", "::",  { .v6 = { 0, 0, 0, 0, 0, 0, 0, 0 } }, -1, -1, 0 },
    { "::0", "::",  { .v6 = { 0, 0, 0, 0, 0, 0, 0, 0 } }, -1, -1, 0 },
    { "::1", "::1", { .v6 = { 0, 0, 0, 0, 0, 0, 0, 1 } }, -1, -1, 0 },
    { "127.0.0.1", "127.0.0.1", { .v4 = { 127, 0, 0, 1 } }, -1, -1, 1 },
    { "::ffff:127.0.0.3", "::ffff:127.0.0.3", { .v6 = { 0, 0, 0, 0, 0, 65535, 0x7f00, 3 } }, -1, -1, 0 },
    { "::127.0.0.2", "::127.0.0.2", { .v6 = { 0, 0, 0, 0, 0, 0, 0x7f00, 2 } }, -1, -1, 0 },
    { NULL, NULL, { .v4 = { 0, 0, 0, 0 } }, -1, -1, 1 }
};
const int n_addrs = sizeof(addrs) / sizeof(addrs[0]) - 1;
const int tests_per_addr = 6;

static void test_address(const struct address_test *addr)
{
    struct sockaddr_storage ss;
    struct sockaddr       *sa = (struct sockaddr *)&ss;
    struct sockaddr_in   *sin = (struct sockaddr_in *)&ss;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
    unsigned short ipv6[8];
    int x_pton, x_nbits;
    unsigned int ii, len, val, nbits;
    char text[SAR_NTOP_MAX];

    /* Supply defaults for pton and nbits. */
    if ((x_pton = addr->x_pton) < 0)
        x_pton = strlen(addr->text);
    if ((x_nbits = addr->x_nbits) < 0)
        x_nbits = addr->is_ipv4 ? 32 : 128;

    /* Check that parsing works as expected. */
    len = sar_pton(sa, sizeof(ss), &nbits, addr->text);
    cmp_ok(len, "==", x_pton, "did sar_pton() consume everything");
    cmp_ok(nbits, "==", x_nbits, "was sar_pton()'s nbits expected?");
    skip(len == 0, 3, "sar_pton() failed");
    if (addr->is_ipv4) {
        cmp_ok(ss.ss_family, "==", AF_INET, "address should be IPv4");
        cmp_mem(&sin->sin_addr, &addr->expected.v4, 4, "check IPv4 address");
        len = sizeof(*sin);
    } else {
        cmp_ok(ss.ss_family, "==", AF_INET6, "address should be IPv6");
        for (ii = 0; ii < 8; ++ii)
            ipv6[ii] = htons(addr->expected.v6[ii]);
        cmp_mem(&sin6->sin6_addr, &ipv6, 16, "check IPv6 address");
        len = sizeof(*sin6);
    }

    /* Check conversion back to text. */
    val = sar_ntop(text, sizeof(text), sa, len);
    cmp_ok(val, "==", strlen(addr->canonical), "is sar_ntop() length right?");
    is(text, addr->canonical, "is sar_ntop() text right?");
    end_skip;
}

static void test_inaddr(void)
{
    int ii;

    for (ii = 0; ii < n_addrs; ++ii)
        test_address(&addrs[ii]);
}

void module_constructor(UNUSED_ARG(const char name[]))
{
    module_depends("tests", NULL);
    plan(test_inaddr, n_addrs * tests_per_addr);
}
