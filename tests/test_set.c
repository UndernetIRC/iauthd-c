/* test_set.c - Test harness for splay tree dictionary
 *
 * Copyright 2019 Michael Poole <mdpoole@troilus.org>
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
 * This should test various permutations of insertion and removal for
 * sets.  (Because removal in this binary tree implementation, as in
 * many others, first involves a lookup, there is not a separate set of
 * lookup tests.)
 */

#include "tests/tests.h"

static int ints[] = {
	-8, -6, -4, -2, 0, 2, 4, 6, 8
};
static const size_t n_ints = ARRAY_LENGTH(ints);

static int idxs[9] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
static struct set *int_set;

static struct set_node *insert_int_node(int value)
{
	struct set_node *n;

	n = set_node_alloc(sizeof(int));
	*(int *)set_node_data(n) = value;
	set_insert(int_set, n);

	return n;
}

static void g_perms(int n, const char * (*visit)(void), const char *description)
{
	static int cc[9];
	const char *msg;
	int ii;
	int jj = 0;

	for (ii = 0; ii < n; ++ii) {
		idxs[ii] = ii;
		cc[ii] = 0;
	}

	msg = visit();
	if (msg != NULL) {
		fail("%s (first perm: %s)", description, msg);
		return;
	}
	++jj;

	for (ii = 0; ii < n; ) {
		if (cc[ii] < ii) {
#define swap(A, B) do { int a = idxs[A]; idxs[A] = idxs[B]; idxs[B] = a; } while (0)
			if (ii & 1)
				swap(cc[ii], ii);
			else
				swap(0, ii);
#undef swap
			msg = visit();
			if (msg != NULL) {
				fail("%s (perm %d: %s)", description, jj, msg);
				return;
			}
			++jj;
			++cc[ii];
			ii = 0;
		} else {
			cc[ii] = 0;
			++ii;
		}
	}

	pass("%s", description);
}

/* test_ints_a uses idxs[] to control the insertion order, and its
 * static dir variable to control removal order.
 */
static const char *test_ints_a(void)
{
	static int dir = 1;
	size_t ii;
	int datum;

	for (ii = 0; ii < n_ints; ++ii) {
		insert_int_node(ints[idxs[ii]]);

		if (set_size(int_set) != ii + 1)
			return "wrong set_size() after insert";
	}

	for (ii = 0; ii < n_ints; ++ii) {
		datum = (dir > 0) ? ints[ii] : ints[n_ints-1-ii];
		set_remove(int_set, &datum, 0);
		if (set_size(int_set) != n_ints-1-ii)
			return "wrong set_size() after remove";
	}
	dir = -dir;

	if (set_size(int_set) != 0)
		return "final set_size() != 0";
	if (int_set->root != NULL)
		return "final set->root != NULL";

	return NULL;
}

/* test_ints_b uses its static dir variable to control the insertion
 * order, and idxs[] to control removal order.
 */
static const char *test_ints_b(void)
{
	static int dir = 1;
	size_t ii;
	int idx, datum;

	for (ii = 0; ii < n_ints; ++ii) {
		idx = (dir > 0) ? ii : (n_ints-1-ii);
		insert_int_node(ints[idx]);
		if (set_size(int_set) != ii + 1)
			return "wrong set_size() after insert";
	}
	dir = -dir;

	for (ii = 0; ii < n_ints; ++ii) {
		datum = ints[idxs[ii]];
		set_remove(int_set, &datum, 0);
		if (set_size(int_set) != n_ints-1-ii)
			return "wrong set_size() after remove";
	}

	if (set_size(int_set) != 0)
		return "final set_size() != 0";
	if (int_set->root != NULL)
		return "final set->root != NULL";

	return NULL;
}

static void test_set(void)
{
	struct set_node *n_5, *n_8, *n;
	int datum;

	int_set = set_alloc(set_compare_int, NULL);
	g_perms(n_ints, test_ints_a, "randomized insertion of ints");
	g_perms(n_ints, test_ints_b, "randomized removal of ints");
	set_clear(int_set, 0);

	insert_int_node(2);
	insert_int_node(5);
	n_8 = insert_int_node(8);
	n_5 = insert_int_node(5);
	cmp_ok(set_size(int_set), "==", 3, "set_size() after duplicate insert");

	datum = 4;
	n = set_lower(int_set, &datum);
	ok((n == n_5), "expect set_lower(int_set, &4) == n_5_2");

	datum = 8;
	n = set_lower(int_set, &datum);
	ok((n == n_8), "expect set_lower(int_set, &8) == n_8");

	set_clear(int_set, 0);
}

void module_constructor(UNUSED_ARG(const char name[]))
{
    module_depends("tests", NULL);
    plan(test_set, 5);
}

void module_destructor(void)
{
	free(int_set);
}
