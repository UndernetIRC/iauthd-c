/* accumulators.h - Statistical accumulation structures
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

#if !defined(ACCUMULATORS_H_789cc736_9452_48d8_9795_59a72bd79b0d)
#define ACCUMULATORS_H_789cc736_9452_48d8_9795_59a72bd79b0d

struct variance {
    double n;
    double mean;
    double M2;
};

void variance_init(struct variance *accum);
void variance_tick(struct variance *accum, double x);
#define variance_mean(ACCUM) ((ACCUM)->mean)
double variance_stdev(struct variance *accum, int sample);

#endif /* !defined(ACCUMULATORS_H_789cc736_9452_48d8_9795_59a72bd79b0d) */
