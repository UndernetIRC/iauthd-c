/* bitset.h - Fixed-length bit vector type
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

#if !defined(BITSET_H_a2df050b_7e6f_4c85_970a_372c535e4c64)

/** Multiple-inclusion guard for "src/bitset.h". */
#define BITSET_H_a2df050b_7e6f_4c85_970a_372c535e4c64

typedef unsigned int bitset_page_t;
#define BITSET_BITS_PER_WORD (CHAR_BIT * sizeof(bitset_page_t))
#define BITSET_WORD_NUM(NN)  ((NN) / BITSET_BITS_PER_WORD)
#define BITSET_WORD_MASK(NN) (1 << ((NN) % BITSET_BITS_PER_WORD))
#define DECLARE_BITSET(STRUCTNAME,NUMBITS) struct STRUCTNAME {\
    bitset_page_t bits[(NUMBITS + BITSET_BITS_PER_WORD - 1) / BITSET_BITS_PER_WORD];\
}
#define BITSET_GET(SET, NN) ((SET).bits[BITSET_WORD_NUM(NN)] & BITSET_WORD_MASK(NN))
#define BITSET_SET(SET, NN) ((SET).bits[BITSET_WORD_NUM(NN)] |= BITSET_WORD_MASK(NN))
#define BITSET_CLEAR(SET, NN) ((SET).bits[BITSET_WORD_NUM(NN)] &= ~BITSET_WORD_MASK(NN))
#define BITSET_ZERO(SET) memset((SET).bits, 0, sizeof((SET).bits))
#define BITSET_COPY(OUT, IN) memcpy((OUT).bits, (IN).bits, sizeof((OUT).bits))
#define BITSET_AND(OUT, IN1, IN2) bitset_and((OUT).bits, (IN1).bits, (IN2).bits, ARRAY_LENGTH((OUT).bits))
#define BITSET_OR(OUT, IN1, IN2) bitset_or((OUT).bits, (IN1).bits, (IN2).bits, ARRAY_LENGTH((OUT).bits))
#define BITSET_COUNT(SET) bitset_count((SET).bits, ARRAY_LENGTH((SET).bits))
#define BITSET_H_ANDNOT(IN1, IN2) bitset_h_andnot((IN1).bits, (IN2).bits, ARRAY_LENGTH((IN1).bits))
#define BITSET_MULTI_CLEAR(SET, ...) bitset_clear((SET).bits, __VA_ARGS__, -1)
#define BITSET_MULTI_SET(SET, ...) bitset_set((SET).bits, __VA_ARGS__, -1)

int bitset_and(bitset_page_t *out, const bitset_page_t *in1, const bitset_page_t *in2, unsigned int count);
int bitset_or(bitset_page_t *out, const bitset_page_t *in1, const bitset_page_t *in2, unsigned int count);
int bitset_h_andnot(const bitset_page_t *in1, const bitset_page_t *in2, unsigned int count);
unsigned int bitset_count(const bitset_page_t *in, unsigned int count);
void bitset_clear(bitset_page_t *set, ...);
void bitset_set(bitset_page_t *set, ...);

struct dyn_bitset {
    bitset_page_t *bits;
};

struct dyn_bitset *dyn_bitset_alloc(unsigned int len) MALLOC_LIKE;
void dyn_bitset_free(struct dyn_bitset *dbs);

#endif /* !defined(a2df050b_7e6f_4c85_970a_372c535e4c64) */
