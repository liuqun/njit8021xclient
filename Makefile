CC := gcc
CFLAGS := -g -Wall -Wextra -I.
LDLIBS := -lpcap
CFLAGS += $(shell libgcrypt-config --cflags)
LDLIBS += $(shell libgcrypt-config --libs)

#------------------------------------
all: njit-client njit-RefreshIP Version.log


#------------------------------------
njit-client: main.o auth.o fillmd5.o fillbase64.o ip.o
	$(LINK.o) $^ $(LDLIBS) -o $@
%.o: %.c %.h
	$(COMPILE.c) $< -o $@
%.o: %.c
	$(COMPILE.c) $< -o $@
njit-RefreshIP: RefreshIP.sh
	cat $< > $@
	chmod +x $@
#------------------------------------
# 生成编译日志
Version.log: njit-client
	@echo "==========================================================" >  $@
	@echo "编译者：$(shell grep `whoami` /etc/passwd | cut -d : -f 5)" >> $@
	@echo "日  期：$(shell date '+%Y年%m月%d日')"                      >> $@
	@echo "----------------------------------------------------------" >> $@
	@echo "编译器：$(shell $(CC) --version | head -n 1)"               >> $@
	@echo "        CFLAGS = $(CFLAGS)"                                 >> $@
	@echo "        LDLIBS = $(LDLIBS)"                                 >> $@
	@echo "动态链接库："                                               >> $@
	@ldd  $<                                                           >> $@
	@echo "==========================================================" >> $@
	@cat $@
