/* test_accum.c - Test harness for accumulator utilities
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

static void test_accum(void)
{
	struct variance v;

	variance_init(&v);
	variance_tick(&v, 0.0);
	variance_tick(&v, 1.0);
	variance_tick(&v, 2);
	variance_tick(&v, 0);
	variance_tick(&v, 2);

	near(v.n, 5, "v.n ~= 5");
	near(variance_mean(&v), 1, "variance_mean(&v) ~= 1");
	near(variance_stdev(&v, 1), 1.0, "variance_stdev(&v, 1) ~= 1.0");
}

void module_constructor(UNUSED_ARG(const char name[]))
{
	module_depends("tests", NULL);
	plan(test_accum, 3);
}
