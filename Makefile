CC := gcc
CFLAGS := -g -Wall -Wextra -I.
LDLIBS := -lpcap
CFLAGS += $(shell libgcrypt-config --cflags)
LDLIBS += $(shell libgcrypt-config --libs)

#------------------------------------
all: njit-client njit-RefreshIP


#------------------------------------
njit-client: main.o auth.o fillmd5.o fillbase64.o ip.o
	$(LINK.o) $^ $(LDLIBS) -o $@
%.o: %.c %.h
	$(COMPILE.c) $< -o $@
%.o: %.c
	$(COMPILE.c) $< -o $@
njit-RefreshIP:
	ln -s RefreshIP.sh $@
	chmod +x $@
#------------------------------------
# 可以使用make build.log收集编译信息
build.log: njit-client
	@echo "Build Date: " `date` > $@
	@echo "C Compiler: " `$(CC) --version | head -n 1`>> $@
	@echo "CFLAGS:     " $(CFLAGS) >> $@
	@echo "LDLIBS:     " $(LDLIBS) >> $@

