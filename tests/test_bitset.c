/* test_bitset.c - Test harness for bitset code
 *
 * Copyright 2020 Michael Poole <mdpoole@troilus.org>
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

static void test_bitset(void)
{
	struct dyn_bitset *a, *b, *c;
	unsigned int ii;
	int res;

	a = dyn_bitset_alloc(128);
	cmp_ok(bitset_count(a->bits, BITSET_WORD_NUM(128)), "==", 0, "bitset_count(a) == 0");

	b = dyn_bitset_alloc(128);
	bitset_set(b->bits, 0, 18, -1);
	cmp_ok(bitset_count(b->bits, BITSET_WORD_NUM(128)), "==", 2, "bitset_count(b) == 2");

	bitset_clear(b->bits, 18, -1);
	cmp_ok(bitset_count(b->bits, BITSET_WORD_NUM(128)), "==", 1, "bitset_count(b) == 1");

#if UINT_WIDTH > 32
	for (ii = 0; ii <= BITSET_BITS_PER_WORD; ii += 32) {
		a->bits[0] = (a->bits[0] << 32) | 0xaaaaaaaa;
		b->bits[0] = (b->bits[0] << 32) | 0x55555555;
	}
#else
		a->bits[0] = 0xaaaaaaaa;
		b->bits[0] = 0x55555555;
#endif
	for (ii = 1; ii <= BITSET_WORD_NUM(127); ii += 1) {
		a->bits[ii] = a->bits[0];
		b->bits[ii] = b->bits[0];
	}

	c = dyn_bitset_alloc(128);
	res = bitset_and(c->bits, a->bits, b->bits, BITSET_WORD_NUM(128));
	ok(!res, "bitset_and() between disjoint sets");

	res = bitset_andnot(c->bits, a->bits, b->bits, BITSET_WORD_NUM(128));
	ok(res, "bitset_andnot() between complementary sets");

	res = bitset_h_andnot(a->bits, b->bits, BITSET_WORD_NUM(128));
	cmp_ok(res, "==", 1, "bitset_h_andnot(a, b)");

	ii = bitset_count(c->bits, BITSET_WORD_NUM(128));
	cmp_ok(ii, "==", 64, "bitset_count() of a & ~b");

	bitset_or(c->bits, a->bits, b->bits, BITSET_WORD_NUM(128));
	ii = bitset_count(c->bits, BITSET_WORD_NUM(128));
	cmp_ok(ii, "==", 128, "bitset_count() of a | b");

	res = bitset_and(c->bits, a->bits, c->bits, BITSET_WORD_NUM(128));
	cmp_ok(res, "!=", 0, "bitset_and() of c & a was non-zero");

	res = bitset_h_andnot(a->bits, a->bits, BITSET_WORD_NUM(128));
	cmp_ok(res, "==", 0, "bitset_h_andnot(a, a) == 0");

	dyn_bitset_free(c);
	dyn_bitset_free(b);
	dyn_bitset_free(a);
}

void module_constructor(UNUSED_ARG(const char name[]))
{
	module_depends("tests", NULL);
	plan(test_bitset, 10);
}
