AC_INIT([njit8021xclient],[1.0],[njit8021xclient@googlegroups.com],[],[https://github.com/liuqun/njit8021xclient])
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
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT

