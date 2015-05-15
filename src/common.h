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

/* Include the libevent headers. */
#include <evdns.h>
#include <event.h>

/** Evaluates to the length of an array \a x. */
#define ARRAY_LENGTH(x) (sizeof(x)/sizeof(x[0]))

/** Points to a structure of type \a TYPE that contains \a PFIELD as
 * \a FIELDNAME.
 */
#define ENCLOSING_STRUCT(PFIELD, TYPE, FIELDNAME) ((TYPE*)((char*)(PFIELD)-offsetof(TYPE, FIELDNAME)))

/** Helper typedef for functions that get called before the program exits. */
typedef void (*exit_func_t)(void);

void reg_exit_func(exit_func_t handler);
void call_exit_funcs(void);

/** Global variable containing fully qualified revision name. */
extern const char iauthd_version[];

/* Wrappers around memory allocators that terminate on failure. */

void *xmalloc(unsigned int size) MALLOC_LIKE;
char *xstrdup(const char *str);
void *xrealloc(void *ptr, unsigned int size);
#define xfree(PTR) free(PTR)

/* <ctype.h>-like helpers. */

extern uint8_t char_types[256];
#define CHAR_XDIGIT 32
#define CHAR_TOKEN 16
#define ct_get(CH) (char_types[(unsigned char)(CH)])
#define ct_isxdigit(CH) (ct_get(CH) & CHAR_XDIGIT)
#define ct_istoken(CH) (ct_get(CH) & CHAR_TOKEN)
#define ct_xdigit_val(CH) (ct_get(CH) & 15)

void ctype_init(void);

/* Define commonly used types. */

#include "src/bitset.h"
#include "src/set.h"
#include "src/vector.h"

DECLARE_VECTOR(char_vector, char);
void char_vector_append_string(struct char_vector *cv, const char *string);
void char_vector_append_count(struct char_vector *cv, const char *data, unsigned int count);
void char_vector_append_printf(struct char_vector *cv, const char *format, ...) PRINTF_LIKE(2, 3);
void char_vector_append_vprintf(struct char_vector *cv, const char *format, va_list args);

DECLARE_VECTOR(uint_vector, unsigned int);

DECLARE_VECTOR(string_vector, char *);
void string_vector_clear_int(struct string_vector *sv);
void string_vector_copy(struct string_vector *dest, const struct string_vector *src);

DECLARE_VECTOR(const_string_vector, const char *);
void const_string_vector_remove(struct const_string_vector *sv, const char *string);

/* Include the declarations for other iauthd core functionality. */

#include "src/accumulators.h"
#include "src/config.h"
#include "src/log.h"
#include "src/module.h"
#include "src/sar.h"

#endif /* !defined(COMMON_H_423c4b78_b463_4c5c_bd2f_f48559e8a1ee) */
