/* tests.h - Declarations of common test helper functions
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

#if !defined(TESTS_H_af53d9e6_cfff_4801_a3e9_f92ca98dc107)

/** Multiple-inclusion guard for "tests/tests.h". */
#define TESTS_H_af53d9e6_cfff_4801_a3e9_f92ca98dc107

#include "src/common.h"

/* This API closely follows that of the Perl TAP or C libtap.
 *
 * The major differences are that plan() takes the test function
 * before the number of tests -- so that multiple loadable modules can
 * each run tests (while using the module dependency framework), and
 * that not all test functions are supported.
 */

typedef void (*test_func)(void);

void diag(const char *fmt, ...) PRINTF_LIKE(1, 2);
void BAIL_OUT(const char *fmt, ...) __attribute__((noreturn));
void test_plan(test_func fn, int count, const char *fmt, ...);
void test_ok(int val, const char *fmt, ...);
void test_is(const char *got, const char *expected, const char *fmt, ...);
void test_isnt(const char *got, const char *unexpected, const char *fmt, ...);
void test_cmp(int a, const char *op, int b, const char *fmt, ...);
void test_memcmp(const void *got, const void *expected, size_t n, const char *fmt, ...);
void test_skip(int n, const char *fmt, ...);

#define NO_PLAN -1
#define SKIP_ALL -2
#define plan(...) test_plan(__VA_ARGS__, NULL)
#define ok(...) test_ok((int) __VA_ARGS__, NULL)
#define is(...) test_is(__VA_ARGS__, NULL)
#define isnt(...) test_isnt(__VA_ARGS__, NULL)
#define cmp_ok(...) test_cmp(__VA_ARGS__, NULL)
#define cmp_mem(...) test_memcmp(__VA_ARGS__, NULL)
#define pass(...) ok(1, "" __VA_ARGS__)
#define fail(...) ok(0, "" __VA_ARGS__)
#define skip(val, count, ...) do { if (val) { test_skip(count, __VA_ARGS__, NULL); break; }
#define end_skip } while(0)

#endif /* !defined(TESTS_H_af53d9e6_cfff_4801_a3e9_f92ca98dc107) */
