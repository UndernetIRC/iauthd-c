/* common.h - Widely used declarations and definitions
 *
 * Copyright 2011 Michael Poole <mdpoole@troilus.org>
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

#if !defined(COMMON_H_423c4b78_b463_4c5c_bd2f_f48559e8a1ee)

/** Multiple-inclusion guard for "src/common.h". */
#define COMMON_H_423c4b78_b463_4c5c_bd2f_f48559e8a1ee

#include "src/compat.h"

/** Evaluates to the length of an array \a x. */
#define ARRAY_LENGTH(x) (sizeof(x)/sizeof(x[0]))

/** Global variable containing fully qualified revision name. */
extern const char iauthd_version[];

#endif /* !defined(COMMON_H_423c4b78_b463_4c5c_bd2f_f48559e8a1ee) */
