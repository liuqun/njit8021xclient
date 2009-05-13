#-----------------------------------------------------------------------------
# 调用make命令的方法
#
# 1、一般情况下，只需在源代码目录下调用make命令即可完成编译
# 	make
#
# 2、通过给make命令添加前缀“env CC=编译器”，可以指定你想使用编译器，例如：
# 	env CC=gcc  make
#
# 3、除了通过变量CC设置编译器之外，还可以通过CFLAGS和LDFLAGS分别指定编译和链接选项。
#    一些常用的设置如下：
#    CFLAGS=-O2          设置编译器优化级别为-O2
#    CFLAGS="-D NDEBUG"  关闭所有assert()调试信息
#    LDFLAGS=-static     进行交叉编译时必须链接到静态链接库
#    可以在一条命令中同时指定多个选项，例如针对路由器进行交叉编译的make命令如下：
# 	env CC=/tools/dd/bin/misp-linux-gnu-gcc  CFLAGS="-O2 -D NDEBUG"  LDFLAGS=-static  make
#
#-----------------------------------------------------------------------------


# 如果没有从命令行指定编译选项，默认情况下将开启调试选项、关闭所有编译优化、优先链接动态链接库。
CFLAGS ?= -g -O0
#LDFLAGS?=

# 总是开启所有编译器警告选项
CFLAGS += -Wall -Wextra

# 配置libpcap
CFLAGS +=
LDLIBS += -lpcap

# 配置libgcrypt
CFLAGS += $(shell libgcrypt-config --cflags)
LDLIBS += $(shell libgcrypt-config --libs)

# 源文件
c_source_files := main.c auth.c fillmd5.c ip.c
c_header_files := debug.h
python_source_files := RefreshIP.py

# 输出文件
executable_files := njit-client njit-RefreshIP
object_files := $(patsubst %.c, %.o, $(c_source_files))
log_files := Build.log

#====================================
.PHONY: all
all: $(executable_files) $(log_files)
#------------------------------------
njit-client: $(object_files)
	$(LINK.o) $^ $(LDLIBS) -o $@
auth.o: auth.c debug.h
	$(COMPILE.c) $< -o $@
%.o: %.c
	$(COMPILE.c) $< -o $@
%.o: %.c %.h
	$(COMPILE.c) $< -o $@
#------------------------------------
njit-RefreshIP: RefreshIP.py
	cat $< > $@
	chmod +x $@
#------------------------------------
Build.log: njit-client
	@echo "==========================================================" >  $@
	@echo "编译者：$(shell grep `whoami` /etc/passwd | cut -d : -f 5)" >> $@
	@echo "日  期：$(shell date '+%Y年%m月%d日')"                      >> $@
	@echo "----------------------------------------------------------" >> $@
	@echo "编译器：$(shell $(CC) --version | head -n 1)"               >> $@
	@echo "        CFLAGS = $(CFLAGS)"                                 >> $@
	@echo "        LDFLAGS= $(LDFLAGS)"                                >> $@
	@echo "        LDLIBS = $(LDLIBS)"                                 >> $@
	@echo "动态链接库："                                               >> $@
	-@ldd  njit-client                                                 >> $@
	@echo "==========================================================" >> $@
	cat $@
#------------------------------------
# make clean
# 仅删除编译生成的.o文件，保留可执行文件和*.log
.PHONY: clean
clean:
	$(RM) $(object_files)
#------------------------------------
# make distclean
# 删除*.o、可执行文件以及*.log
.PHONY: distclean
distclean:
	$(RM) $(object_files)
	$(RM) $(executable_files)
	$(RM) $(log_files)

