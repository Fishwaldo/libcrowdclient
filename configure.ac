#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libcrowdclient], [1.0], [http://jira.my-ho.st/jira/])
AC_CONFIG_AUX_DIR(autotools)
AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADER([include/config.h])
AC_CONFIG_MACRO_DIR(autotools)
AM_INIT_AUTOMAKE(silent-rules)
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE
AC_LIBTOOL_DLOPEN



# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_CHECK_PROG([PROG_WSDL2H], [wsdl2h], [wsdl2h])
if test x"$PROG_WSDL2H" = x"" ; then
	AC_MSG_ERROR(["Can't find wsdl2h program from the gsoap packge"])
fi
AC_SUBST([PROG_WSDL2H])
AC_CHECK_PROG([PROG_SOAPCPP2], [soapcpp2], [soapcpp2])
if test x"$PROG_SOAPCPP2" = x"" ; then
	AC_MSG_ERROR(["Can't find the soapcpp2 program from the gsoap package"])
fi
AC_SUBST([PROG_SOAPCPP2])

# Checks for libraries.
PKG_CHECK_MODULES([GSOAP], [gsoapssl++])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.

AC_CONFIG_FILES(Makefile src/Makefile src/soap/Makefile include/Makefile)
AC_OUTPUT
