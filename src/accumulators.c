/* accumulators.c - Statistical accumulation structures
 *
 * Copyright 2015 Michael Poole <mdpoole@troilus.org>
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

#include "src/accumulators.h"
#include <math.h>

void variance_init(struct variance *accum)
{
    accum->n = 0;
    accum->mean = 0;
    accum->M2 = 0;
}

void variance_tick(struct variance *accum, double x)
{
    double delta = x - accum->mean;
    accum->n += 1;
    accum->mean += delta / accum->n;
    accum->M2 += delta * (x - accum->mean);
}

double variance_stdev(struct variance *accum, int sample)
{
    double n = accum->n - (sample ? 1 : 0);
    return (n <= 0) ? 0 : sqrt(accum->M2 / n);
}
