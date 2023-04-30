# configure.ac - Configuration rules for iauthd-c.
#
# Copyright 2011 Michael Poole <mdpoole@troilus.org>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

dnl General initialization.
AC_PREREQ([2.63])
AC_INIT([iauthd-c], [1.0.5], [coder-com@undernet.org])
AC_CONFIG_AUX_DIR([autoconf])
AC_CONFIG_MACRO_DIR([autoconf])
AC_CONFIG_HEADERS([autoconf.h])
AC_CONFIG_SRCDIR([src/main.c])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([silent-rules])
AM_SILENT_RULES([yes])
AC_ENABLE_STATIC([no])
AC_ENABLE_SHARED([yes])
LT_INIT

dnl Check for toolchain utilities.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MKDIR_P
PKG_CHECK_MODULES([EVENT], [libevent >= 2.1])

dnl Compiler/runtime feature checks.
AC_C_CONST
AC_C_INLINE
AC_HEADER_STDC
AC_HEADER_TIME
AC_STRUCT_TM

dnl Check whether we might be running in a git working tree.
AC_CHECK_PROGS(GIT, [git])
AM_CONDITIONAL(HAS_GIT, test z$GIT != z -a -r ${srcdir}/.git)

dnl Check libraries.
AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(rt, clock_gettime)
AC_CHECK_LIB(socket, socket)
AC_CHECK_TYPE(evutil_socket_t,
  AC_DEFINE(HAVE_EVUTIL_SOCKET_T, 1, [Define if <evutil.h> defines evutil_socket_t]),, [#include <evutil.h>])

dnl More detailed system runtime feature checks.
AC_CHECK_HEADERS([arpa/inet.h dirent.h fcntl.h fnmatch.h inttypes.h netdb.h netinet/in.h regex.h stddef.h stdint.h strings.h sys/epoll.h sys/select.h sys/socket.h sys/stat.h sys/timeb.h sys/times.h sys/types.h sys/wait.h unistd.h])
AC_CHECK_FUNCS([atoi socket vsnprintf])
AC_CHECK_FUNCS([closedir fnmatch ftime gettimeofday gmtime gmtime_r opendir readdir regcomp regexec regfree sigaction strerror strlcpy strlcat strsignal strtok_r sysconf],,)
if test $ac_cv_func_gmtime_r = no -a $ac_cv_func_gmtime = no ; then
  AC_MSG_ERROR([gmtime_r or gmtime is required])
fi
if test $ac_cv_func_gettimeofday = no -a $ac_cv_func_ftime = no ; then
  AC_MSG_ERROR([ftime or gettimeofday is required])
fi

dnl How to copy one va_list to another?
AC_CACHE_CHECK([for va_copy], ac_cv_c_va_copy, [AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([#include <stdarg.h>], [va_list ap1, ap2; va_copy(ap1, ap2);])],
  [ac_cv_c_va_copy="yes"],
  [ac_cv_c_va_copy="no"]
)])
if test "$ac_cv_c_va_copy" = "yes" ; then
  AC_DEFINE(HAVE_VA_COPY, 1, [Define if we have va_copy])
fi
dnl (it may also have a pre-C99 name, __va_copy())
AC_CACHE_CHECK([for __va_copy], ac_cv_c___va_copy, [AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([#include <stdarg.h>], [va_list ap1, ap2; __va_copy(ap1, ap2);])],
  [ac_cv_c___va_copy="yes"],
  [ac_cv_c___va_copy="no"]
)])
if test "$ac_cv_c___va_copy" = "yes" ; then
  AC_DEFINE(HAVE___VA_COPY, 1, [Define if we have __va_copy])
fi

dnl Check for structure members that only exist on some platforms.
AC_CHECK_MEMBER([struct sockaddr.sa_len],
                [AC_DEFINE([HAVE_SOCKADDR_SA_LEN],,[Define if struct sockaddr has sa_len field])],
                [],[#include <sys/types.h>
#include <sys/socket.h>])
AC_CHECK_MEMBER([struct sockaddr_storage.ss_family],
                [AC_DEFINE([HAVE_STRUCT_SOCKADDR_STORAGE],,[Define if struct sockaddr_storage declared])],
                [],[#include <sys/types.h>
#include <sys/socket.h>])
AC_CHECK_MEMBER([struct addrinfo.ai_flags],
                [AC_DEFINE([HAVE_STRUCT_ADDRINFO],,[Define if struct addrinfo declared])],
                [],[#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>])

dnl Decide what CLFAGS we can use for strict compilation.
case `uname` in
Linux) STRICT_CFLAGS="-W -Wall -Werror" ;;
*) STRICT_CFLAGS="-W -Wall" ;;
esac

AC_SUBST(STRICT_CFLAGS)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
