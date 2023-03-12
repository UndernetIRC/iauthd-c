# Makefile.am - top-level -*- makefile -*- to build iauthd-c
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

AUTOMAKE_OPTIONS = gnu dist-bzip2 subdir-objects nostdinc 1.6
ACLOCAL_AMFLAGS = -I autoconf

LOGDIR="$(localstatedir)/log"

STRICT_CFLAGS = @STRICT_CFLAGS@
AM_CFLAGS = $(STRICT_CFLAGS) $(EVENT_CFLAGS) -I$(top_srcdir) -I$(top_builddir)
AM_CPPFLAGS = -DSYSCONFDIR="\"$(sysconfdir)\"" -DMODULESDIR="\"$(pkglibdir)\"" -DLOGDIR="\"$(LOGDIR)\""
AM_LDFLAGS = -module -avoid-version -export-dynamic
EXTRA_DIST =

include $(srcdir)/doc/Makefile.frag
include $(srcdir)/src/Makefile.frag
include $(srcdir)/modules/Makefile.frag
include $(srcdir)/tests/Makefile.frag

install-data-local:
	$(MKDIR_P) "$(LOGDIR)"
