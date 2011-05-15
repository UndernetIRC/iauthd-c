/* common.c - Definitions of widely used functions
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

#include "src/common.h"

DEFINE_VECTOR(char_vector, char)
DEFINE_VECTOR(string_vector, char *)
DEFINE_VECTOR(const_string_vector, const char *)

uint8_t char_types[256];

/** Initializes the character-type table, char_types[]. */
void ctype_init(void)
{
    static const char token_chars[] = "abcdefghijklmnopqrstuvwxyz-._#";
    static const char hex_digits[] = "0123456789abcdef";
    int ii;

    for (ii = 0; token_chars[ii] != '\0'; ++ii)
    {
        char_types[toupper(token_chars[ii])] = CHAR_TOKEN;
        char_types[tolower(token_chars[ii])] = CHAR_TOKEN;
    }
    for (ii = 0; hex_digits[ii] != '\0'; ++ii)
    {
        int val = CHAR_TOKEN | CHAR_XDIGIT | ii;
        char_types[toupper(hex_digits[ii])] = val;
        char_types[tolower(hex_digits[ii])] = val;
    }
}

void *xmalloc(unsigned int size)
{
    void *res;
    res = calloc(1, size);
    if (!res)
        log_message(log_core, LOG_FATAL, "Unable to allocate %u bytes.", size);
    return res;
}

char *xstrdup(const char *str)
{
    char *res;
    if (!str)
        return NULL;
    res = strdup(str);
    if (!res)
        log_message(log_core, LOG_FATAL, "Unable to duplicate %u-byte string.", (unsigned int)strlen(str));
    return res;
}

void *xrealloc(void *ptr, unsigned int size)
{
    void *res = realloc(ptr, size);
    if (!res)
        log_message(log_core, LOG_FATAL, "Unable to resize %p to %u bytes.", ptr, size);
    return res;
}

static exit_func_t *ef_list;
static unsigned int ef_size, ef_used;

void reg_exit_func(exit_func_t handler)
{
    if (ef_used == ef_size) {
        if (ef_size) {
            ef_size <<= 1;
            ef_list = xrealloc(ef_list, ef_size*sizeof(exit_func_t));
        } else {
            ef_size = 8;
            ef_list = xmalloc(ef_size*sizeof(exit_func_t));
        }
    }
    ef_list[ef_used++] = handler;
}

void call_exit_funcs(void)
{
    unsigned int ii;

    module_close_all();
    for (ii = ef_used; ii > 0; )
        ef_list[--ii]();
    xfree(ef_list);
    ef_used = ef_size = 0;
}

void char_vector_reserve(struct char_vector *cv, unsigned int total_size)
{
    char *new_vec;
    if (total_size <= cv->size)
        return;
    new_vec = malloc(total_size);
    if (!new_vec)
        return;
    memcpy(new_vec, cv->vec, cv->used);
    xfree(cv->vec);
    cv->vec = new_vec;
    cv->size = total_size;
}

void char_vector_append_count(struct char_vector *cv, const char *data, unsigned int count)
{
    size_t len = cv->used + count;
    char_vector_reserve(cv, len);
    if (cv->size < len)
        return;
    memcpy(cv->vec + cv->used, data, count);
    cv->used = len;
}

void char_vector_append_string(struct char_vector *cv, const char *string)
{
    size_t len = cv->used + strlen(string) + 1;
    char_vector_reserve(cv, len);
    if (cv->size < len)
        return;
    memcpy(cv->vec + cv->used, string, len - cv->used);
    cv->used = len - 1;
}

void char_vector_append_vprintf(struct char_vector *cv, const char *format, va_list args)
{
    va_list working;
    size_t len;
    int ret;

    va_copy(working, args);
    len = strlen(format);
    if (!cv->vec || (cv->size < cv->used + len))
        char_vector_reserve(cv, cv->used + len);
    ret = vsnprintf(cv->vec + cv->used, cv->size - cv->used, format, working);
    va_end(working);
    if (ret <= 0) {
        va_copy(working, args);
        while ((ret = vsnprintf(cv->vec + cv->used, cv->size - cv->used, format, working)) <= 0) {
            char_vector_reserve(cv, cv->size + len);
            va_end(working);
            va_copy(working, args);
        }
        cv->used += ret;
    } else if (cv->used + ret < cv->size) {
        /* hooray; it fit */
        cv->used += ret;
    } else {
        /* we now know exactly how much space we need */
        char_vector_reserve(cv, cv->used + ret + 1);
        va_copy(working, args);
        cv->used += vsnprintf(cv->vec + cv->used, cv->size - cv->used, format, working);
    }
}

void char_vector_append_printf(struct char_vector *cv, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    char_vector_append_vprintf(cv, format, args);
    va_end(args);
}

void string_vector_clear_int(struct string_vector *sv)
{
    unsigned int ii;
    for (ii = 0; ii < sv->used; ++ii)
        xfree(sv->vec[ii]);
    string_vector_clear(sv);
}

void string_vector_copy(struct string_vector *dest, const struct string_vector *src)
{
    char **new_vector;
    unsigned int ii;

    for (ii = 0; ii < dest->used; ++ii)
        xfree(dest->vec[ii]);
    if (dest->size < src->size) {
        new_vector = xmalloc(src->used * sizeof(*new_vector));
        xfree(dest->vec);
        dest->vec = new_vector;
        dest->size = src->used;
    }
    dest->used = src->used;
    for (ii = 0; ii < dest->used; ++ii)
        dest->vec[ii] = xstrdup(src->vec[ii]);
}

void const_string_vector_remove(struct const_string_vector *sv, const char *string)
{
    unsigned int ii, jj, limit;

    for (ii = jj = 0, limit = sv->used; ii < limit; ii++)
        if (strcasecmp(sv->vec[ii], string))
            sv->vec[jj++] = sv->vec[ii];
        else
            sv->used--;
}

#if !defined(HAVE_STRLCPY)

size_t
strlcpy(char *out, const char *in, size_t len)
{
    size_t in_len;

    in_len = strlen(in);
    if (in_len < --len)
        memcpy(out, in, in_len + 1);
    else
        memcpy(out, in, len), out[len] = '\0';
    return in_len;
}

#endif /* !defined(HAVE_STRLCPY) */
