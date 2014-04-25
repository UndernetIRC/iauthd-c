# Makefile.frag - -*- makefile -*- rules to build iauthd-c
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

# NOTE: automake and libtool (at least 1.7.9 and 1.5.6, respectively)
# sort of lose when you have conditional shared libraries.  So we
# define a bonus variable, EXTRA_LDFLAGS, that should be used with
# each conditional library.  The -rpath makes libtool generate a
# shared library instead of a static library.
EXTRA_LDFLAGS = $(AM_LDFLAGS) -rpath $(pkglibdir)

pkglib_LTLIBRARIES = \
	modules/iauth.la \
	modules/iauth_xquery.la

modules_iauth_la_SOURCES = \
	modules/iauth.h \
	modules/iauth_core.c \
	modules/iauth_misc.c
modules_iauth_la_LDFLAGS = $(EXTRA_LDFLAGS)

modules_iauth_xquery_la_SOURCES = \
	modules/iauth_xquery.c
modules_iauth_xquery_la_LDFLAGS = $(EXTRA_LDFLAGS)
