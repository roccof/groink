dnl Process this file with autoconf to produce a configure script.

dnl Init Autoconf
AC_INIT([GroinK], [0.1BETA1], [decrew@indivia.net])

AC_PREREQ(2.64)

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AM_PROG_LIBTOOL

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADER([src/config.h])

AH_TOP([
#ifndef GROINK_CONFIG_H   
#define GROINK_CONFIG_H
])
AH_BOTTOM([
#endif /* GROINK_CONFIG_H */
])

dnl Checks for libraries
AC_CHECK_LIB([m], [sin], , [AC_MSG_ERROR([math library not found]);exit 1])
AC_CHECK_LIB([pthread], [pthread_create], , [AC_MSG_ERROR(["pthread library not found"]);exit 1])
dnl AC_CHECK_LIB([ncurses], [initscr], , [])
AC_CHECK_LIB([pcap], [pcap_open_live], , [AC_MSG_ERROR(["libpcap not found"]);exit 1])
PKG_CHECK_MODULES([LUA], [lua >= 5.1], , [AC_MSG_NOTICE(["Trying lua 5.1..."]) 
			 PKG_CHECK_MODULES([LUA], [lua5.1], , [AC_MSG_ERROR(["lua 5.1 not found"]);exit 1])
			 ])
AC_SUBST(LUA_CFLAGS)
AC_SUBST(LUA_LIBS)

dnl Checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h strings.h unistd.h stdlib.h stdarg.h string.h], , [AC_MSG_ERROR(["*** REQUIRED!! ***"]);exit 1])

dnl Checks for functions

dnl Check if there are new functions introduced in libpcap 1.0.0
AC_CHECK_FUNCS(pcap_create) 

dnl Checks for types
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INTMAX_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINTMAX_T

dnl Checks for compiler characteristics
dnl AC_PROG_CC
AM_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_GCC_TRADITIONAL
AC_C_CONST

dnl Checks for library functions
AC_FUNC_MALLOC
AC_CHECK_FUNCS(daemon)

dnl Save the path passed to configure
AC_PREFIX_DEFAULT([/usr/local])

if test "$prefix" = "NONE"; then
   prefix="/usr/local"
fi
if test "$exec_prefix" = "NONE"; then
   exec_prefix=$prefix
fi

AH_TEMPLATE(INSTALL_PREFIX, [the prefix passed by configure])
AC_DEFINE_UNQUOTED(INSTALL_PREFIX, "`eval echo $prefix`")

AH_TEMPLATE(INSTALL_DATADIR, [The directory for installing idiosyncratic read-only architecture-independent data])
AC_DEFINE_UNQUOTED(INSTALL_DATADIR, "`eval echo $datarootdir`")

dnl Check user defined --enable-FEATURE
AC_ARG_ENABLE(debug,
	AC_HELP_STRING([--enable-debug], [Enable debugging strings in the program execution.]),
	[debug=$enableval],[])

if test "$debug" = "yes"; then
   CFLAGS="$CFLAGS -DGROINK_DEBUG -rdynamic "
fi

CFLAGS="$CFLAGS -Wall"

AC_OUTPUT(Makefile src/Makefile tests/Makefile)

echo
echo "====================================="
echo
echo ' _____           _       _   __'
echo '|  __ \         (_)     | | / /'
echo '| |  \/_ __ ___  _ _ __ | |/ / '
echo "| | __| '__/ _ \| | '_ \|    \ "
echo '| |_\ \ | | (_) | | | | | |\  \'
echo ' \____/_|  \___/|_|_| |_\_| \_/'
echo -e "\t\t\tby DECrew"
echo
echo "====================================="
echo
echo ">> run 'make install' as r00t to compile"
echo