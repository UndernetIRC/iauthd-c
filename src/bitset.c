/* bitset.c - Fixed-length bit vector type
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

#include "src/common.h"

int bitset_and(bitset_page_t *out, const bitset_page_t *in1, const bitset_page_t *in2, unsigned int count)
{
    unsigned int ii;
    int non_zero;

    for (ii = non_zero = 0; ii < count; ++ii) {
        out[ii] = in1[ii] & in2[ii];
        if (out[ii])
            non_zero++;
    }
    return non_zero;
}

int bitset_andnot(bitset_page_t *out, const bitset_page_t *in1, const bitset_page_t *in2, unsigned int count)
{
    unsigned int ii;
    int non_zero;

    for (ii = non_zero = 0; ii < count; ++ii) {
        out[ii] = in1[ii] & ~in2[ii];
        if (out[ii])
            non_zero++;
    }
    return non_zero;
}

int bitset_or(bitset_page_t *out, const bitset_page_t *in1, const bitset_page_t *in2, unsigned int count)
{
    unsigned int ii;
    int non_zero;

    for (ii = non_zero = 0; ii < count; ++ii) {
        out[ii] = in1[ii] | in2[ii];
        if (out[ii])
            non_zero++;
    }
    return non_zero;
}

/** Horizontal (or "wire") and-not operation.
 *
 * \param[in] in1 Array of bitset pages.
 * \param[in] in2 Array of bitset pages.
 * \return Zero if every bit that is set in \a in1 is also set in \a
 *   in2, non-zero if any bit is set in \a in1 but cleared in \a in2.
 */
int bitset_h_andnot(const bitset_page_t *in1, const bitset_page_t *in2, unsigned int count)
{
    unsigned int ii;
    int non_zero;

    for (ii = non_zero = 0; ii < count; ++ii) {
        if (in1[ii] & ~in2[ii])
            return 1;
    }
    return 0;
}

unsigned int bitset_count(const bitset_page_t *in, unsigned int count)
{
    static const int counts[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
    unsigned int ii, accum;
    bitset_page_t tmp;

    for (ii = accum = 0; ii < count; ++ii)
        for (tmp = in[ii]; tmp; tmp >>= 4)
            accum += counts[tmp & 15];
    return accum;
}

void bitset_clear(bitset_page_t *set, ...)
{
    va_list args;
    int bit;

    va_start(args, set);
    while ((bit = va_arg(args, int)) >= 0)
        set[BITSET_WORD_NUM(bit)] &= ~BITSET_WORD_MASK(bit);
    va_end(args);
}

void bitset_set(bitset_page_t *set, ...)
{
    va_list args;
    int bit;

    va_start(args, set);
    while ((bit = va_arg(args, int)) >= 0)
        set[BITSET_WORD_NUM(bit)] |= BITSET_WORD_MASK(bit);
    va_end(args);
}

struct dyn_bitset *dyn_bitset_alloc(unsigned int len)
{
    struct dyn_bitset *dbs;

    dbs = xmalloc(sizeof(*dbs) + sizeof(bitset_page_t) * BITSET_WORD_NUM(len + BITSET_BITS_PER_WORD - 1));
    dbs->bits = (bitset_page_t*)(dbs + 1);
    return dbs;
}

void dyn_bitset_free(struct dyn_bitset *dbs)
{
    xfree(dbs);
}
