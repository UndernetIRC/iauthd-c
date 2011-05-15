/* set.h - Splay tree set
 *
 * Copyright 2004, 2011 Michael Poole <mdpoole@troilus.org>
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

#if !defined(SRVX_SET_H)
#define SRVX_SET_H

/** Element destruction function.  It must dereference any memory
 * pointed to by the data element pointed to, but must not free the
 * element itself.
 */
typedef void set_cleanup_f(void*);

/** Set comparison function type.  It works like the function passed
 * to qsort(), and must return a number less than, equal to or greater
 * than zero if the first argument is less than, equal to or greater
 * (respectively) than the second argument.  The second argument is
 * always an element of the set; the first argument may or may not be
 * in the set.
 */
typedef int set_compare_f(const void*, const void*);

struct set_node
{
    struct set_node *l, *r, *prev, *next;
};

struct set
{
    set_compare_f *compare;
    set_cleanup_f *cleanup;
    struct set_node *root;
    unsigned int count;
};

#define set_node(DATUM) (((struct set_node*)(DATUM))-1)
#define set_node_data(NODE) ((void*)((NODE)+1))
#define set_node_alloc(SIZE) ((struct set_node*)xmalloc(sizeof(struct set_node) + (SIZE)))
#define set_prev(NODE) ((NODE)->prev)
#define set_next(NODE) ((NODE)->next)

struct set *set_alloc(set_compare_f *compare, set_cleanup_f *cleanup) MALLOC_LIKE;
#define set_size(SET) ((SET)->count)
void set_insert(struct set *set, struct set_node *node);
void *set_find(struct set *set, const void *datum);
struct set_node *set_first(struct set *set);
struct set_node *set_lower(struct set *set, const void *datum);
int set_remove(struct set *set, void *datum, int no_dispose);
void set_clear(struct set *set);

/* Functions you might use for set cleanup or compare. */
int set_compare_charp(const void *a_, const void *b_);
int set_compare_int(const void *a_, const void *b_);
int set_compare_ptr(const void *a_, const void *b_);

#endif /* !defined(SRVX_SET_H) */
