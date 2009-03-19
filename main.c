/* File: main.c
 * ------------
 * 校园网客户端命令行入口函数
 */

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

/* 子函数声明 */
int ProcessAuthenticaiton_WiredEthernet(const char *UserName, const char *Password, const char *DeviceName);


/**
 * 函数：main()
 *
 * 检查程序的执行权限和命令行参数格式
 */
int main(int argc, char *argv[])
{
	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		fprintf(stderr, "Sorry, currently %s must be executed as root.\n", argv[0]);
		exit(-1);
	}

	/* 检查命令行参数格式 */
	if (argc != 3) {
		fprintf(stderr, "缺少命令行参数！\n");
		fprintf(stderr,	"Usage:\n");
		fprintf(stderr,	"    %s username password\n", argv[0]);
		exit(-1);
	}

	/* Process 802.1X authentication through wired Ethernet. */
	ProcessAuthenticaiton_WiredEthernet(argv[1], argv[2], "eth0");
	/* Note: 一般情况下使用eth0即可 */

	return (0);
}

