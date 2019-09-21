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

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/autoconf/tap-driver.sh
TEST_LDFLAGS = -module -rpath $(abs_top_builddir)

TESTS = \
	tests/test_all.sh

EXTRA_DIST += \
	tests/iauthd-c.conf \
	tests/test_all.sh

check_LTLIBRARIES = \
	tests/test_sar.la \
	tests/test_set.la \
	tests/tests.la

tests_test_sar_la_SOURCES = tests/test_sar.c
tests_test_sar_la_LDFLAGS = $(TEST_LDFLAGS)

tests_test_set_la_SOURCES = tests/test_set.c
tests_test_set_la_LDFLAGS = $(TEST_LDFLAGS)

tests_tests_la_SOURCES = \
	tests/tests.h \
	tests/tests.c
tests_tests_la_LDFLAGS = $(TEST_LDFLAGS)
