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
	char *DeviceName;

	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		fprintf(stderr, "Sorry, currently %s must be executed as root.\n", argv[0]);
		fprintf(stderr, "(RedHat/Fedora下使用su命令切换为root)\n");
		fprintf(stderr, "(Ubuntu/Debian下使用sudo)\n");
		exit(-1);
	}

	/* 检查命令行参数格式 */
	if (argc<3 || argc>4) {
		fprintf(stderr, "命令行参数错误！\n");
		fprintf(stderr,	"正确的调用格式为:\n");
		fprintf(stderr,	"    %s username password\n", argv[0]);
		fprintf(stderr,	"    %s username password eth0\n", argv[0]);
		fprintf(stderr,	"    %s username password eth1\n", argv[0]);
		fprintf(stderr, "(注：若不指明网卡设备，默认情况下将使用eth0)\n");
		exit(-1);
	} else if (argc == 4) {
		DeviceName = argv[3]; // 允许从命令行指定设备名
	} else {
		DeviceName = "eth0"; // 缺省情况下使用的设备
	}

	/* Process 802.1X authentication through wired Ethernet. */
	ProcessAuthenticaiton_WiredEthernet(argv[1], argv[2], DeviceName);

	return (0);
}

