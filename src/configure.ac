dnl File: autoconf.ac
dnl -----------------

AC_PREREQ(2.57)
AC_INIT([njit8021xclient],[1.0],[njit8021xclient@googlegroups.com],[njit8021xclient-1.0.tar.gz],[http://github.com/liuqun/njit8021xclient])

AC_PROG_CC
PKG_PROG_PKG_CONFIG([0.15])

dnl 默认优先调用libcrypto的MD5算法, 预留libgcrypt作为备选项
AC_SUBST([libgcrypt_CFLAGS], [])
AC_SUBST([libgcrypt_LIBS], [])
AC_SUBST([libcrypto_CFLAGS], [])
AC_SUBST([libcrypto_LIBS], [])
AC_ARG_WITH([libgcrypt], AC_HELP_STRING([--with-libgcrypt], [use libgcrypt @<:@default=no@:>@ ]), [], [with_libgcrypt=no])
AC_ARG_WITH([libcrypto], AC_HELP_STRING([--with-libcrypto], [use libcrypto as a replacement for libgcrypt @<:@default=yes@:>@ ]), [], [with_libcrypto=yes])
if test "x$with_libgcrypt" = "xyes" || test "x$with_libgcrypt" = "xcheck" ; then
	lib=libgcrypt
	dnl 调用libgcrypt自带的libgcrypt-config脚本确定编译器参数
	AC_PATH_TOOL([LIBGCRYPT_CONFIG], [libgcrypt-config])
	if test -z $ac_pt_LIBGCRYPT_CONFIG; then
		AC_MSG_WARN([Cannot find libgcrypt-config script!])
	else
		AC_SUBST([libgcrypt_CFLAGS], `$ac_pt_LIBGCRYPT_CONFIG --cflags`)
		AC_SUBST([libgcrypt_LIBS], `$ac_pt_LIBGCRYPT_CONFIG --libs`)
	fi
elif test "x$with_libgcrypt" = "xno" ; then
	lib=libcrypto
	if test "x$with_libcrypto" = "xyes" || "x$with_libcrypto" = "xcheck" ; then
		dnl 利用pkg-config工具自动确定libcrypto的编译参数
		PKG_CHECK_MODULES([libcrypto], [libcrypto])
	elif test "x$with_libcrypto" = "xno" ; then
		AC_MSG_ERROR([Either "--with-libcrypto" or "--with-libgcrypt" should be chosen!])
	else
		AC_MSG_ERROR([Sorry, "--with-libcrypto=$with_libcrypto" is not supported yet!])
	fi
else
	AC_MSG_ERROR([Sorry, "--with-libgcrypt=$with_libgcrypt" is not supported yet!])
fi
AC_SUBST([md5lib], [$lib])


dnl 使用libpcap自带的pcap-config脚本确定编译器参数
AC_PATH_TOOL([PCAP_CONFIG], [pcap-config])
if test -z $ac_pt_PCAP_CONFIG; then
	AC_MSG_WARN([])
	AC_MSG_WARN([Cannot find pcap-config script!])
	AC_MSG_WARN([])
	AC_CHECK_HEADER([pcap.h], [], [AC_MSG_WARN(["Can not find pcap.h!"])])
	AC_SUBST([libpcap_CFLAGS], [])
	AC_SUBST([libpcap_LIBS], [])
else
	AC_SUBST([libpcap_CFLAGS], `$ac_pt_PCAP_CONFIG --cflags`)
	AC_SUBST([libpcap_LIBS], `$ac_pt_PCAP_CONFIG --libs`)
fi


AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

