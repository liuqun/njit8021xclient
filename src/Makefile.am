ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = client
client_SOURCES = \
		main.c \
		auth.c \
		ip.c   \
		fillmd5-libcrypto.c \
		njit8021xclient.c \
		njit8021xclient.h \
		debug.h
CCOPT = $(V_CCOPT)
DEFS  = $(V_DEFS)
INCLS = $(V_INCLS)
client_CFLAGS = $(CCOPT) $(DEFS) $(INCLS)
client_CFLAGS += $(libgcrypt_CFLAGS)
client_LDADD  = $(LBL_LIBS)
client_LDADD += $(libcrypto_LIBS)

