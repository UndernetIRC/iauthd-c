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

static void test_char_vector(void)
{
	struct char_vector cv;
	const char *buf;

	char_vector_wipe(&cv);
	char_vector_append_printf(&cv, "hello %s world", "extra long");
	is(cv.vec, "hello extra long world", "char_vector_append_printf can grow vector");
	char_vector_clear(&cv);

	char_vector_init(&cv, 16);
	cv.used = 0;
	char_vector_append_string(&cv, "abcdef");
	cmp_ok(cv.used, "==", 6, "'abcdef'.used == 6");

	buf = "0000000000000000";
	char_vector_append_count(&cv, buf, 10);
	cmp_ok(cv.used, "==", 16, "('abcdef'+'0000000000').used == 16");

	char_vector_append_printf(&cv, " hello %s", "world");
	is(cv.vec, "abcdef0000000000 hello world", "triple concatenated contents");

	strlcpy(cv.vec, "extra long hello world", 16);
	is(cv.vec, "extra long hell", "extra long hello world truncated");

	strlcpy(cv.vec, "extra long hello world", cv.size);
	is(cv.vec, "extra long hello world", "extra long hello world copied");

	char_vector_clear(&cv);
}

static void test_uint_vector(void)
{
	struct uint_vector uv;
	unsigned int ii;

	uint_vector_init(&uv, 8);
	for (ii = 0; ii < 12; ++ii)
		uint_vector_append(&uv, ii);
	cmp_ok(uv.used, "==", 12, "uint vector has 12 elements");

	uint_vector_clear(&uv);
}

static void test_string_vector(void)
{
	struct string_vector sv, sv_copy;

	string_vector_init(&sv, 4);
	string_vector_append(&sv, xstrdup("Hello world"));

	string_vector_init(&sv_copy, 4);
	string_vector_append(&sv_copy, xstrdup("Goodbye world"));
	string_vector_copy(&sv_copy, &sv);
	test_ok(!strcmp(sv_copy.vec[0], "Hello world"),
		"string_vector_copy() replaces destination strings");

	string_vector_clear_int(&sv_copy);
	string_vector_clear_int(&sv);
}

void module_constructor(UNUSED_ARG(const char name[]))
{
	module_depends("tests", NULL);
	plan(test_char_vector, 6);
	plan(test_uint_vector, 1);
	plan(test_string_vector, 1);
}

void module_post_init(UNUSED_ARG(struct module *self))
{
}
