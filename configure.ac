# Autoconf script for MCAST
# To rebuild the `configure' script from this, execute the command
# 	autoconf
# in the directory containing this script.
#
# This software is a part of Mcast. A very simple traffic generator
# and analyzer especially tuned for IP multicast, although it is
# useful for unicast too.
# Mcast is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#  Mcast is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with Mcast; see the file COPYING.
#
AC_INIT(mcast.c)

# Default CFLAGS unless set by environment.
: ${CFLAGS="-O2"}

AC_SUBST(CC)
AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LIBS)
AC_SUBST(INCLUDES)
AC_SUBST(OBJ_SUFFIX)
AC_SUBST(EXE_SUFFIX)
AC_SUBST(HAVE_SIN_LEN)
#
AC_PROG_CC()
#AC_PROG_INSTALL
AC_PREFIX_DEFAULT(/usr/local)
#
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, main)
AC_CHECK_HEADERS(linux/sockios.h sys/sockio.h)
#
# Change if WIN32
EXE_SUFFIX=""
OBJ_SUFFIX=".o"
AR_SUFFIX=".a"
#
# ----------------------------
# check sin_len of sockaddr_in
# ----------------------------
AC_MSG_CHECKING(whether struct sockaddr_in has a sin_len field)
AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>
],[static struct sockaddr_in ac_i;int ac_j = sizeof (ac_i.sin_len);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SIN_LEN)],
 AC_MSG_RESULT(no))
#
AC_OUTPUT(Makefile,
	)
