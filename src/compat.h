/* compat.h - Stuff to paper over differences between systems
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

#if !defined(COMPAT_H_6f7b39aa_9c51_4b5a_8169_4e145da0e027)

/** Multiple-inclusion guard for "src/compat.h". */
#define COMPAT_H_6f7b39aa_9c51_4b5a_8169_4e145da0e027

#include "autoconf.h"

#define _POSIX_C_SOURCE 200809L
#if !defined(NDEBUG)
# define _FORTIFY_SOURCE 2
#endif

/* ANSI C89 headers -- every system should have them. */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#endif

#if defined(TIME_WITH_SYS_TIME)
# include <sys/time.h>
# include <time.h>
#elif defined(HAVE_SYS_TIME_H)
# include <sys/time.h>
#else
# include <time.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_REGEX_H
# include <regex.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_SYS_TIMES_H
# include <sys/times.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#if defined(HAVE_NETDB_H)
# include <netdb.h>
#endif

#if defined(HAVE_FNMATCH_H)
# include <fnmatch.h>
#endif

#if defined(HAVE_STRINGS_H)
# include <strings.h>
#endif

#if !defined(LINE_MAX)
/* Should be defined by Unix header files; Cygwin lacks it. */
# define LINE_MAX 4096
#endif

#if !defined(HAVE_GMTIME_R)
/* For a single-threaded application, this provides reentrant behavior. */
#define gmtime_r(CLOCK, RES) memcpy((RES), gmtime(CLOCK), sizeof(struct tm))
#endif

#if !defined(HAVE_FNMATCH)
# define FNM_NOESCAPE 1
# define FNM_PATHNAME 2
# define FNM_PERIOD   4
# define FNM_NOMATCH  1
# define FNM_R_DEPTH  2
int fnmatch(const char *pattern, const char *string, int flags);
#endif

#if !defined(HAVE_STRLCPY)
size_t strlcpy(char *out, const char *in, size_t len);
#endif

#if defined(HAVE_VA_COPY)
/* no action necessary */
#elif defined(HAVE___VA_COPY)
# define va_copy(d,s) __va_copy(d,s)
#else
# define va_copy(d,s) memcpy(&(d), &(s), sizeof(va_list))
#endif

#if __GNUC__ >= 2

# if __GNUC__ >= 4
#  define NULL_SENTINEL __attribute__((sentinel))
# endif

# define PRINTF_LIKE(M,N) __attribute__((format (printf, M, N)))
# define MALLOC_LIKE __attribute__((malloc))
# define FORMAT_ARG(ARG) __attribute__((format_arg (ARG)))
# define UNUSED_ARG(ARG) ARG __attribute__((unused))

#elif defined(S_SPLINT_S)

# define UNUSED_ARG(ARG) /*@unused@*/ ARG
# define const /*@observer@*/ /*@temp@*/

#endif

/* Provide defaults for lint-like macros. */

#if !defined(PRINTF_LIKE)
# define PRINTF_LIKE(M,N)
#endif

#if !defined(MALLOC_LIKE)
# define MALLOC_LIKE
#endif

#if !defined(FORMAT_ARG)
# define FORMAT_ARG(ARG)
#endif

#if !defined(NULL_SENTINEL)
# define NULL_SENTINEL
#endif

#if !defined(UNUSED_ARG)
# define UNUSED_ARG(ARG) ARG
#endif

#if !defined(HAVE_EVUTIL_SOCKET_T)
/* libevent1 needs this to be int; libevent2 uses intptr_t on Windows. */
typedef int evutil_socket_t;
#endif

#endif /* !defined(COMPAT_H_6f7b39aa_9c51_4b5a_8169_4e145da0e027) */
