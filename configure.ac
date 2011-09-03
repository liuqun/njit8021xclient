AC_INIT([njit8021xclient],[1.0],[njit8021xclient@googlegroups.com],[],[https://github.com/liuqun/njit8021xclient])

AC_MSG_CHECKING([program prefix for $PACKAGE_NAME]);
if test "x$program_prefix" = "x" || test $program_prefix = "NONE" ; then
	dnl 可执行文件前缀默认值
	program_prefix="njit-"
fi
AC_MSG_RESULT([$program_prefix])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_LBL_C_INIT_BEFORE_CC(V_CCOPT, V_INCLS)
AC_PROG_CC
AC_LBL_C_INIT(V_CCOPT, V_INCLS)
AC_LBL_C_INLINE
AC_LBL_LIBPCAP(V_PCAPDEP, V_INCLS)
AC_SUBST(V_CCOPT)
AC_SUBST(V_DEFS)
AC_SUBST(V_GROUP)
AC_SUBST(V_INCLS)
AC_SUBST(V_PCAPDEP)
PKG_CHECK_MODULES([libcrypto], [libcrypto])
dnl 配置GUI
gtk_version_required="2.0.0"
AM_PATH_GTK_2_0([$gtk_version_required], [have_gtk_2_0="yes"], [])
if test "x"$have_gtk_2_0 = "xyes" ; then
	AC_DEFINE([HAVE_GTK_2_0], [], [支持GTK+ 2.0用户界面])
	AC_CONFIG_SUBDIRS([src-gui])
else
	AC_MSG_WARN(["You need gtk >= $gtk_version_required to enable graphic user interface of $PACKAGE"])
fi
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT

