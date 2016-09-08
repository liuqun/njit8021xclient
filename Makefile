CC		= mips-openwrt-linux-uclibc-gcc
CFLAGS	= -O2
USE_LIB	= -lpcap
APP_NAME= h3cc_make
INCLUDE	= ~/openwrt/kamikaze/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/include
LIBS	= ~/openwrt/kamikaze/staging_dir/target-mips_r2_uClibc-0.9.33.2/usr/lib

h3cc_static: njit8021xclient.o auth.o \
			 main.c ip.c fillmd5-libcrypto.c \
			 libMD5Buildin.a libPatch.a
	echo 'Final Wave.'
	$(CC) main.c fillmd5-libcrypto.c ip.c \
		njit8021xclient.o auth.o \
		libMD5Buildin.a libPatch.a \
		-o $(APP_NAME) $(USE_LIB) -I $(INCLUDE) -L $(LIBS) $(CFLAGS) --static
	echo 'All done. Enjoy yourself.'

auth.o: auth.c debug.h
	$(CC) -c auth.c -I $(INCLUDE) -L $(LIBS)

njit8021xclient.o: njit8021xclient.c njit8021xclient.h
	$(CC) -c njit8021xclient.c

libPatch.a: ./patch/des.c ./patch/handleDES.c ./patch/desKey.h ./patch/SParray.h
	echo 'Building libPatch_ForNCEPU...'
	$(CC) -c patch/des.c patch/handleDES.c \
		  -I $(INCLUDE) -L $(LIBS)
	ar rcs libPatch.a des.o handleDES.o

libMD5Buildin.a: ./md5-buildin/md5_dgst.c ./md5-buildin/md5_one.c ./md5-buildin/mem_clr.c
	echo 'Building libMD5Buildin...'
	$(CC) -c md5-buildin/md5_dgst.c md5-buildin/md5_one.c md5-buildin/mem_clr.c \
		  -I $(INCLUDE) -L $(LIBS)
	ar rcs libMD5Buildin.a md5_dgst.o md5_one.o mem_clr.o

clean:
	rm -rf *.o
