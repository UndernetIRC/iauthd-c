/* tests.c - Definitions of common test helper functions
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

#include "tests/tests.h"
#include <math.h>
#include <setjmp.h>

DECLARE_VECTOR(test_list, test_func);

static jmp_buf test_jmp_buf;
static struct test_list test_list;
static int test_id;
static int test_count;
static int test_no_plan;
static int test_skip_all;
static int test_fails;

DEFINE_VECTOR(test_list, test_func);

void test_bail_out(int ignore, const char *fmt, ...);
void test_ok(int test, const char *fmt, ...);
void test_is(const char *got, const char *expected, const char *fmt, ...);
void test_isnt(const char *got, const char *unexpected, const char *fmt, ...);
void test_cmp(int a, const char *op, int b, const char *fmt, ...);

static void pfx_print(const char *prefix, const char *sep, const char *fmt, va_list args)
{
    fputs(prefix, stdout);
    if (fmt) {
        fputs(sep, stdout);
        vfprintf(stdout, fmt, args);
    }
    putc('\n', stdout);
    fflush(stdout);
}

void test_plan(test_func fn, int count, const char *fmt, ...)
{
    test_list_append(&test_list, fn);

    if (count == SKIP_ALL)
        test_skip_all = 1;
    else if (count < 0)
        test_no_plan = 1;
    else
        test_count += count;

    if (count == SKIP_ALL) {
        if (!test_skip_all) {
            va_list args;

            va_start(args, fmt);
            pfx_print("1..0 # SKIP", " ", fmt, args);
            va_end(args);
        }
        test_skip_all = 1;
    }
}

void BAIL_OUT(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    pfx_print("Bail out!", " ", fmt, args);
    va_end(args);

    longjmp(test_jmp_buf, 1);
}

static void test_vok(int test, const char *fmt, va_list args)
{
    if (!test) {
        ++test_fails;
        fputs("not ", stdout);
    }
    printf("ok %d", ++test_id);
    pfx_print("", " - ", fmt, args);
}

void diag(const char *fmt, ...)
{
    va_list args;

    fputs("# ", stdout);
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

void test_ok(int val, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    test_vok(val, fmt, args);
    va_end(args);
}

void test_is(const char *got, const char *expected, const char *fmt, ...)
{
    va_list args;
    int val;

    val = got && expected && !strcmp(got, expected);
    va_start(args, fmt);
    test_vok(val, fmt, args);
    va_end(args);
    if (!val) {
        printf("#      got: '%s'\n", got);
        printf("# expected: '%s'\n", expected);
    }
}

void test_isnt(const char *got, const char *unexpected, const char *fmt, ...)
{
    va_list args;
    int val;

    val = got && unexpected && strcmp(got, unexpected);
    va_start(args, fmt);
    test_vok(val, fmt, args);
    va_end(args);
    if (!val) {
        printf("#        got: '%s'\n", got);
        printf("# unexpected: '%s'\n", unexpected);
    }
}

void test_cmp(int a, const char *op, int b, const char *fmt, ...)
{
    va_list args;
    int val;

    if (!strcmp(op, "<"))
        val = (a < b);
    else if (!strcmp(op, "<="))
        val = (a <= b);
    else if (!strcmp(op, "=="))
        val = (a == b);
    else if (!strcmp(op, ">="))
        val = (a >= b);
    else if (!strcmp(op, ">"))
        val = (a > b);
    else if (!strcmp(op, "!="))
        val = (a != b);
    else
        BAIL_OUT("invalid operator for cmp_ok(%d, \"%s\", %d, ...)", a, op, b);

    va_start(args, fmt);
    test_vok(val, fmt, args);
    va_end(args);
    if (!val) {
        printf("# %d %s %d\n", a, op, b);
    }
}

void test_memcmp(const void *got, const void *expected, size_t n, const char *fmt, ...)
{
    va_list args;
    int val;

    val = memcmp(got, expected, n);
    va_start(args, fmt);
    test_vok(val == 0, fmt, args);
    va_end(args);
    if (val) {
        const unsigned char *e = expected;
        const unsigned char *g = got;
        size_t ii, jj, kk;

        for (ii = 0; ii < n; ++ii) {
            if (e[ii] != g[ii])
                break;
        }

        kk = (ii < 4) ? 0 : (ii - 4);
        printf("#      got (@%zu):", kk);
        for (jj = 0; jj < 12; ++jj)
            printf(" %02x", g[kk+jj]);
        printf("\n# expected (@%zu):", kk);
        for (jj = 0; jj < 12; ++jj)
            printf(" %02x", e[kk+jj]);
        putc('\n', stdout);
    }
}

void test_near(double a, double b, const char *fmt, ...)
{
    double diff = a - b;
    double margin = b * 1e-9;
    int val = fabs(diff) < margin;
    va_list args;

    va_start(args, fmt);
    test_vok(val, fmt, args);
    va_end(args);
    if (!val) {
        printf("# %f ~= %f\n", a, b);
    }
}

void test_skip(int n, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    if (n > 0) {
        printf("ok %d # skip ", ++test_id);
        if (fmt)
            vfprintf(stdout, fmt, args);
        putc('\n', stdout);
    }
    va_end(args);
    while (n-- > 1)
        printf("ok %d # skip\n", ++test_id);
}

static void tests_execute(UNUSED_ARG(int fd), UNUSED_ARG(short evt), UNUSED_ARG(void *arg))
{
    clean_exit = 1;

    flockfile(stdout);
    if (setjmp(test_jmp_buf)) {
        clean_exit = 0;
    } else {
        unsigned int ii;

        if (test_skip_all) {
            event_loopbreak();
            return;
        } else if (test_count && !test_no_plan) {
            printf("1..%d\n", test_count);
        }

        for (ii = 0; ii < test_list.used; ++ii) {
            test_list.vec[ii]();
        }

        if (!test_count || test_no_plan)
            printf("1..%d\n", test_id);
        else if (test_id != test_count)
            BAIL_OUT("saw %d tests, expected %d", test_id, test_count);

        if (test_fails) {
            printf("# Looks like you failed %d tests of %d run\n", test_fails, test_id);
            clean_exit = 0;
        }
    }
    funlockfile(stdout);

    event_loopbreak();
}

void module_constructor(UNUSED_ARG(const char name[]))
{
    struct timeval tv_zero = { 0, 0 };

    module_is_backend();
    event_once(-1, EV_TIMEOUT, tests_execute, NULL, &tv_zero);
}
