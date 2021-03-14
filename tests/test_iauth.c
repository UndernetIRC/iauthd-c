/* test_iauth.c - Test harness for miscellaneous IAuth functions
 *
 * Copyright 2021 Michael Poole <mdpoole@troilus.org>
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

#include "tests/tests.h"
#include "modules/iauth.h"

static void test_iauth_ipv4(void)
{
	char text[IRC_NTOP_MAX];
	irc_inaddr addr, addr_2;
	unsigned int used, bits;

	used = irc_pton(&addr, &bits, "::127.0.0.1", 0);
	cmp_ok(used, "==", 11, "irc_pton('::127.0.0.1') == 11");

	irc_ntop(text, sizeof text, &addr);
	is(text, "127.0.0.1", "irc_ntop for 127.0.0.1");

	used = irc_pton(&addr_2, &bits, "127.0.0.1/32", 1);
	cmp_ok(used, "==", 12, "irc_pton('127.0.0.1/32') == 12");
	cmp_ok(bits, "==", 128, "irc_pton('127.0.0.1/32') 'uses' 128 bits");
	addr.in6[5] = 65535;
	cmp_ok(irc_inaddr_cmp(&addr, &addr_2), "==", 0, "127.0.0.1 is invariant");

	used = irc_pton(&addr, &bits, ".1.2.3", 1);
	cmp_ok(used, "==", 0, "irc_pton('.1.2.3') fails");

	used = irc_pton(&addr, &bits, "1.2.3", 1);
	cmp_ok(used, "==", 0, "irc_pton('1.2.3') fails");

	used = irc_pton(&addr, &bits, "1.2.3..4", 1);
	cmp_ok(used, "==", 0, "irc_pton('1.2.3..4') fails");

	used = irc_pton(&addr, &bits, "127.*", 1);
	cmp_ok(used, "==", 5, "irc_pton('127.*') == 5");
	cmp_ok(bits, "==", 104, "irc_pton('127.*') 'uses' 104 bits");

	used = irc_pton(&addr, &bits, "127.*.1", 1);
	cmp_ok(used, "==", 0, "irc_pton('127.*.1') fails");

	used = irc_pton(&addr, &bits, "255.255.255.255", 1);
	cmp_ok(used, "==", 15, "irc_pton('255.255.255.255') == 15");

	used = irc_pton(&addr, &bits, "255.255.255.256", 1);
	cmp_ok(used, "==", 0, "irc_pton('255.255.255.256') fails");

	used = irc_pton(&addr, NULL, "127.0.0.0/24", 0);
	cmp_ok(used, "==", 0, "irc_pton('127.0.0.0/24') fails without allow_trailing");

	used = irc_pton(&addr, NULL, "127.0.0.0/24", 1);
	cmp_ok(used, "==", 9, "irc_pton('127.0.0.0/24') with bits == NULL ignores /24");

	used = irc_pton(&addr, &bits, "127.0.0.0/33", 1);
	cmp_ok(used, "==", 0, "irc_pton('127.0.0.0/33') fails");
}

static void test_iauth_ipv6(void)
{
	char text[IRC_NTOP_MAX];
	irc_inaddr addr, addr_2;
	unsigned int used, bits;

	used = irc_pton(&addr, &bits, "f00d:b33f::cafe", 0);
	cmp_ok(used, "==", 15, "irc_pton('f00d:b33f::cafe') == 15");

	irc_ntop(text, sizeof text, &addr);
	is(text, "f00d:b33f::cafe", "irc_ntop() for f00d:b33f::cafe");

	used = irc_pton(&addr_2, &bits, "aaaa:0:0:bbbb::", 0);
	cmp_ok(used, "==", 15, "irc_pton('aaaa:0:0:bbbb::') == 15");

	irc_ntop(text, sizeof text, &addr_2);
	is(text, "aaaa:0:0:bbbb::", "irc_ntop() for aaaa:0:0:bbbb::");

	used = irc_pton(&addr, &bits, "***", 0);
	cmp_ok(used, "==", 3, "irc_pton('***') == 3");
	cmp_ok(bits, "==", 0, "irc_pton('***') 'uses' 0 bits");

	used = irc_pton(&addr, &bits, ":aaaa:bbbb/128", 1);
	cmp_ok(used, "==", 0, "irc_pton(':aaaa:bbbb/128') fails");

	used = irc_pton(&addr, &bits, "aaaa:bbbb:*", 1);
	cmp_ok(used, "==", 11, "irc_pton('aaaa:bbbb:*') == 11");
	cmp_ok(bits, "==", 32, "irc_pton('aaaa:bbbb:*') 'uses' 32 bits");

	used = irc_pton(&addr, &bits, "ffff:eeee::/32", 1);
	cmp_ok(used, "==", 14, "irc_pton('ffff:eeee::/32') == 14");
	cmp_ok(bits, "==", 32, "irc_pton('ffff:eeee::/32') 'uses' 32 bits");

	used = irc_pton(&addr, &bits, "10000::", 0);
	cmp_ok(used, "==", 0, "irc_pton('10000::') fails");

	used = irc_pton(&addr, &bits, "aaaa::bbbb::cccc", 0);
	cmp_ok(used, "==", 0, "irc_pton('aaaa::bbbb::cccc') fails");

	used = irc_pton(&addr, &bits, "::1/129", 1);
	cmp_ok(used, "==", 0, "irc_pton('::1/129') fails");

	used = irc_pton(&addr, &bits, "::1/a", 0);
	cmp_ok(used, "==", 0, "irc_pton('::1/a') fails");

	used = irc_pton(&addr, &bits, "::1/a", 1);
	cmp_ok(used, "==", 3, "irc_pton('::1/a') has trailing text");

	used = irc_pton(&addr, &bits, "a::b::*", 1);
	cmp_ok(used, "==", 0, "irc_pton('a::b::*') fails");

	used = irc_pton(&addr, &bits, "1:corp", 1);
	cmp_ok(used, "==", 0, "irc_pton('1:corp') fails");

	used = irc_pton(&addr, &bits, "::ffff:.1.2.3", 0);
	cmp_ok(used, "==", 0, "irc_pton('::ffff:.1.2.3') fails");

	used = irc_pton(&addr, &bits, "1:2:3:4:5:6:7:127.0.0.1", 0);
	cmp_ok(used, "==", 0, "irc_pton('1:2:3:4:5:6:7:127.0.0.1') fails");

	used = irc_pton(&addr, &bits, "a::b:*", 1);
	cmp_ok(used, "==", 0, "irc_pton('a::b:*') fails");

	memset(addr.in6_8, 0xff, sizeof addr.in6_8);
	memcpy(&addr_2, &addr, sizeof addr_2);
	addr_2.in6_8[15] = 0xf0;
	cmp_ok(irc_check_mask(&addr, &addr_2, 124), "==", 1, "irc_check_mask() matches");
	cmp_ok(irc_check_mask(&addr, &addr_2, 126), "==", 0, "irc_check_mask() mismatches");
}

void module_constructor(UNUSED_ARG(const char name[]))
{
	module_depends("tests", "iauth", NULL);
	plan(test_iauth_ipv4, 16);
	plan(test_iauth_ipv6, 23);
}
