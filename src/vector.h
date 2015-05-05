/* vector.h - generic vector type
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

#if !defined(VECTOR_H_1dd2ae1a_9e5c_4fa3_bf22_0f1dbd9b8d3a)

/** Multiple-inclusion guard for "src/vector.h". */
#define VECTOR_H_1dd2ae1a_9e5c_4fa3_bf22_0f1dbd9b8d3a

#define DECLARE_VECTOR(STRUCTNAME,ITEMTYPE) struct STRUCTNAME {\
  unsigned int used, size;\
  ITEMTYPE *vec;\
};\
void STRUCTNAME##_wipe(struct STRUCTNAME *vec);\
void STRUCTNAME##_init(struct STRUCTNAME *vec, unsigned int len);\
void STRUCTNAME##_reserve(struct STRUCTNAME *vec, unsigned int len);\
void STRUCTNAME##_append(struct STRUCTNAME *vec, ITEMTYPE new_item);\
void STRUCTNAME##_clear(struct STRUCTNAME *vec)

#define DEFINE_VECTOR(STRUCTNAME,ITEMTYPE) \
void STRUCTNAME##_wipe(struct STRUCTNAME *vec) {\
  vec->used = 0;\
  vec->size = 0;\
  vec->vec = NULL;\
}\
void STRUCTNAME##_init(struct STRUCTNAME *vec, unsigned int len) {\
  vec->used = 0;\
  vec->size = len;\
  vec->vec = xmalloc(vec->size * sizeof(vec->vec[0]));\
}\
void STRUCTNAME##_reserve(struct STRUCTNAME *vec, unsigned int len) {\
  while (vec->size < len)\
    vec->size <<= 1;\
  vec->vec = xrealloc(vec->vec, vec->size*sizeof(vec->vec[0]));\
}\
void STRUCTNAME##_append(struct STRUCTNAME *vec, ITEMTYPE new_item) {\
  if (vec->used == vec->size) {\
    vec->size = vec->size ? (vec->size << 1) : 4;\
    vec->vec = xrealloc(vec->vec, vec->size*sizeof(vec->vec[0]));\
  }\
  vec->vec[vec->used++] = new_item;\
}\
void STRUCTNAME##_clear(struct STRUCTNAME *vec) {\
  vec->used = vec->size = 0;\
  xfree(vec->vec);\
  vec->vec = NULL;\
}

#endif /* !defined(VECTOR_H_1dd2ae1a_9e5c_4fa3_bf22_0f1dbd9b8d3a) */
