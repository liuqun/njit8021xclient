/* File: auth.c
 * ------------
 * 注：核心函数为Authenticaiton()，由该函数执行801.1X认证
 */

int Authenticaiton(const char *UserName, const char *Password, const char *DeviceName);

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>

#include <pcap.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>


// 自定义常量
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20} EAP_Type;
typedef uint8_t EAP_ID;

// 子函数声明
static void SendStartPkt(pcap_t *adhandle, const uint8_t mac[]);
static void SendLogoffPkt(pcap_t *adhandle, const uint8_t mac[]);
static void SendResponseIdentity(pcap_t *adhandle,
			const uint8_t request[],
			const uint8_t ethhdr[],
			const uint8_t ip[4],
			const char    username[]);
static void SendResponseMD5(pcap_t *adhandle,
		const uint8_t request[],
		const uint8_t ethhdr[],
		const char username[],
		const char passwd[]);
static void SendResponseAvailable(pcap_t *adhandle,
		const uint8_t request[],
		const uint8_t ethhdr[],
		const uint8_t ip[4],
		const char    username[]);
static void SendResponseNotification(pcap_t *handle,
		const uint8_t request[],
		const uint8_t ethhdr[]);
static void GetMacFromDevice(uint8_t mac[6], const char *devicename);
// From fillmd5.c
extern void FillMD5Area(uint8_t digest[],
	       	uint8_t id, const char passwd[], const uint8_t srcMD5[]);
// From fillbase64.c
extern void FillBase64Area(char area[]);
// From ip.c
extern void GetIpFromDevice(uint8_t ip[4], const char DeviceName[]);

// 定义DPRINTF宏：输出调试信息
#define DPRINTF(...)	fprintf(stderr, __VA_ARGS__)


/**
 * 函数：Authenticaiton()
 *
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 */

int Authenticaiton(const char *UserName, const char *Password, const char *DeviceName)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*adhandle; // adapter handle
	uint8_t	MAC[6];
	char	FilterStr[100];
	struct bpf_program	fcode;
	const int DefaultTimeout=60000;//设置接收超时参数，单位ms

	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
	if (adhandle==NULL) {
		fprintf(stderr, "%s\n", errbuf); 
		exit(-1);
	}

	/* 查询本机MAC地址 */
	GetMacFromDevice(MAC, DeviceName);

	/*
	 * 设置过滤器：
	 * 初始情况下只捕获发往本机的802.1X认证会话，不接收多播信息（避免误捕获其他客户端发出的多播信息）
	 * 进入循环体前可以重设过滤器，那时再开始接收多播信息
	 */
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
							MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);


	START_AUTHENTICATION:
	{
		int retcode;
		struct pcap_pkthdr *header;
		const uint8_t	*captured;
		uint8_t	ethhdr[14]={0};
		uint8_t	ip[4]={0};

		/* 主动发起认证会话 */
		SendStartPkt(adhandle, MAC);
		DPRINTF("[ ] Client: Start.\n");

		/* 接收来自认证服务器的数据并应答 */

		// 接收第一个Request包
		retcode = pcap_next_ex(adhandle, &header, &captured);
		assert(retcode==1||retcode==0);
		if (retcode==0)
		{
			DPRINTF("Error: Pcap timeout!\n");
			DPRINTF("Press 'Enter' to reconnect; Press 'Ctrl-C' to quit.\n");
			fprintf(stderr, "njit-client: 错误！服务器无响应或响应超时。\n");
			fprintf(stderr, "             按Enter键重试，按Ctrl-C退出。\n");
			// Note: 也有可能是网线没插好
			while (getchar() != '\n')
				;
			goto START_AUTHENTICATION;
		}

		assert((EAP_Code)captured[18] == REQUEST);

		// 填写应答包的Ethernet Header（14字节），以后无须再修改
		memcpy(ethhdr+0, captured+6, 6);
		memcpy(ethhdr+6, MAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;

		// 若收到的第一个Request包是Notification，直接回答一个无附加内容的Notification包（iNode有附加内容）
		if ((EAP_Type)captured[22] == NOTIFICATION)
		{
			DPRINTF("[%d] Server: Request Notification!\n", captured[19]);
			SendResponseNotification(adhandle, captured, ethhdr);// 填写Notification包并发送
			DPRINTF("    Client: Response Notification.\n");

			// 继续接收下一个Request包
			retcode = pcap_next_ex(adhandle, &header, &captured);
			assert(retcode==1);
			assert((EAP_Code)captured[18] == REQUEST);
		}

		// 回答第一个Request Identity / Request AVAILABLE包时需要特殊处理
		// （都要回答Response Identity包）
		if ((EAP_Type)captured[22] == IDENTITY)
		{	// 南京工程学院目前使用的格式
			DPRINTF("[%d] Server: Request Identity!\n", captured[19]);
		}
		else if ((EAP_Type)captured[22] == AVAILABLE)
		{	// 中南财经政法大学目前使用的格式
			DPRINTF("[%d] Server: Request AVAILABLE!\n", captured[19]);
		}
		else
		{
			DPRINTF("[%d] Server: Request (type:%d)!\n", captured[19], (EAP_Type)captured[22]);
			DPRINTF("Error! Unexpected request type\n");
			exit(-1);
		}
		GetIpFromDevice(ip, DeviceName);
		SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
		DPRINTF("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);

		// 重设过滤器，只捕获华为802.1X认证设备发来的包（包括多播Request Identity / Request AVAILABLE）
		sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			captured[6],captured[7],captured[8],captured[9],captured[10],captured[11]);
		pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
		pcap_setfilter(adhandle, &fcode);

		// 进入循环体
		for (;;)
		{
			// 调用pcap_next_ex()函数捕获数据包
			while (pcap_next_ex(adhandle, &header, &captured) != 1)
			{
				DPRINTF("."); // 若捕获失败，则等1秒后重试
				sleep(1);     // 直到成功捕获到一个数据包后再跳出
			}

			// 根据收到的Request，回复相应的Response包
			if ((EAP_Code)captured[18] == REQUEST)
			{
				switch ((EAP_Type)captured[22])
				{
				 case IDENTITY:
					DPRINTF("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
					GetIpFromDevice(ip, DeviceName);
					SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
					DPRINTF("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);
					break;
				 case AVAILABLE:
					DPRINTF("[%d] Server: Request AVAILABLE!\n", (EAP_ID)captured[19]);
					GetIpFromDevice(ip, DeviceName);
					SendResponseAvailable(adhandle, captured, ethhdr, ip, UserName);
					DPRINTF("[%d] Client: Response AVAILABLE.\n", (EAP_ID)captured[19]);
					break;
				 case MD5:
					DPRINTF("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
					SendResponseMD5(adhandle, captured, ethhdr, UserName, Password);
					DPRINTF("[%d] Client: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
					break;
				 case NOTIFICATION:
					DPRINTF("[%d] Server: Request Notification!\n", captured[19]);
					SendResponseNotification(adhandle, captured, ethhdr);
					DPRINTF("     Client: Response Notification.\n");
					break;
				 default:
					DPRINTF("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
					DPRINTF("Error! Unexpected request type\n");
					exit(-1);
					break;
				}
			}
			else if ((EAP_Code)captured[18] == FAILURE)
			{	// 处理认证失败信息
				uint8_t errtype = captured[22];
				uint8_t msgsize = captured[23];
				const char *msg = (const char*) &captured[24];
				DPRINTF("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
				if (errtype==0x09 && msgsize>0)
				{	// 输出错误提示消息
					fprintf(stderr, "%s\n", msg);
					// 已知的几种错误如下
					// E2531:用户名不存在
					// E2542:该用户帐号已经在别处登录
					// E2547:接入时段限制
					// E2553:密码错误
					// E2602:认证会话不存在
					// E3137:客户端版本号无效
					exit(-1);
				}
				else if (errtype==0x08) // 可能网络无流量时服务器结束此次802.1X认证会话
				{	// 遇此情况客户端立刻发起新的认证会话
					goto START_AUTHENTICATION;
				}
				else
				{
					DPRINTF("errtype=0x%02x\n", errtype);
					exit(-1);
				}
			}
			else if ((EAP_Code)captured[18] == SUCCESS)
			{
				DPRINTF("[%d] Server: Success.\n", captured[19]);
				// TODO: 尚未实现“自动获取动态分配的IP地址”这一关键功能
			}
			else
			{
				DPRINTF("[%d] Server: (H3C data)\n", captured[19]);
				// TODO: 这里没有处理华为自定义数据包 
			}
		}
	}
	return (0);
}



static
void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{

	int	fd;
	int	err;
	struct ifreq	ifr;

	fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
	assert(fd != -1);

	assert(strlen(devicename) < IFNAMSIZ);
	strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	assert(err != -1);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	err = close(fd);
	assert(err != -1);
	return;
}


static
void SendStartPkt(pcap_t *handle, const uint8_t localmac[])
{
	const uint8_t MultcastAddr[6] = {
		0x01,0x80,0xc2,0x00,0x00,0x03
	};
	uint8_t packet[18];

	// Ethernet Header (14 Bytes)
	memcpy(packet, MultcastAddr, 6);
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x01;	// Type=Start
	packet[16] = packet[17] =0x00;// Length=0x0000

	// 发包
	pcap_sendpacket(handle, packet, sizeof(packet));
}


static
void SendResponseAvailable(pcap_t *handle, const uint8_t request[], const uint8_t ethhdr[], const uint8_t ip[4], const char username[])
{
	int i;
	uint16_t eaplen;
	int usernamelen;
	uint8_t response[128];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == AVAILABLE);

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
		response[14] = 0x1;	// 802.1X Version 1
		response[15] = 0x0;	// Type=0 (EAP Packet)
		//response[16~17]留空	// Length

		// Extensible Authentication Protocol
		// {
			response[18] = (EAP_Code) RESPONSE;	// Code
			response[19] = request[19];		// ID
			//response[20~21]留空			// Length
			response[22] = (EAP_Type) AVAILABLE;	// Type
			// Type-Data
			// {
				i = 23;
				response[i++] = 0x00;// 上报是否使用代理
				response[i++] = 0x15;	  // 上传IP地址
				response[i++] = 0x04;	  //
				memcpy(response+i, ip, 4);//
				i += 4;			  //
				response[i++] = 0x06;		  // 携带版本号
				response[i++] = 0x07;		  //
				FillBase64Area((char*)response+i);//
				i += 28;			  //
				response[i++] = ' '; // 两个空格符
				response[i++] = ' '; //
				usernamelen = strlen(username);
				memcpy(response+i, username, usernamelen);//
				i += usernamelen;			  //
			// }
		// }
	// }
	
	// 补填前面留空的两处Length
	eaplen = htons(i-18);
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));

	// 发送
	pcap_sendpacket(handle, response, i);
}


static
void SendResponseIdentity(pcap_t *adhandle, const uint8_t request[], const uint8_t ethhdr[], const uint8_t ip[4], const char username[])
{
	uint8_t	response[128];
	size_t i;
	uint16_t eaplen;
	int usernamelen;

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == IDENTITY
	     ||(EAP_Type)request[22] == AVAILABLE); // 兼容中南财经政法大学情况

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
		response[14] = 0x1;	// 802.1X Version 1
		response[15] = 0x0;	// Type=0 (EAP Packet)
		//response[16~17]留空	// Length

		// Extensible Authentication Protocol
		// {
			response[18] = (EAP_Code) RESPONSE;	// Code
			response[19] = request[19];		// ID
			//response[20~21]留空			// Length
			response[22] = (EAP_Type) IDENTITY;	// Type
			// Type-Data
			// {
				i = 23;
				response[i++] = 0x15;	  // 上传IP地址
				response[i++] = 0x04;	  //
				memcpy(response+i, ip, 4);//
				i += 4;			  //
				response[i++] = 0x06;		  // 携带版本号
				response[i++] = 0x07;		  //
				FillBase64Area((char*)response+i);//
				i += 28;			  //
				response[i++] = ' '; // 两个空格符
				response[i++] = ' '; //
				usernamelen = strlen(username); //末尾添加用户名
				memcpy(response+i, username, usernamelen);
				i += usernamelen;
				assert(i <= sizeof(response));
			// }
		// }
	// }
	
	// 补填前面留空的两处Length
	eaplen = htons(i-18);
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));

	// 发送
	pcap_sendpacket(adhandle, response, i);
	return;
}


static
void SendResponseMD5(pcap_t *handle, const uint8_t request[], const uint8_t ethhdr[], const char username[], const char passwd[])
{
	uint16_t eaplen;
	size_t   usernamelen;
	size_t   packetlen;
	uint8_t  response[128];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == MD5);

	usernamelen = strlen(username);
	eaplen = htons(22+usernamelen);
	packetlen = 14+4+22+usernamelen; // ethhdr+EAPOL+EAP+usernamelen

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
		response[14] = 0x1;	// 802.1X Version 1
		response[15] = 0x0;	// Type=0 (EAP Packet)
		memcpy(response+16, &eaplen, sizeof(eaplen));	// Length

		// Extensible Authentication Protocol
		// {
		response[18] = (EAP_Code) RESPONSE;// Code
		response[19] = request[19];	// ID
		response[20] = response[16];	// Length
		response[21] = response[17];	//
		response[22] = (EAP_Type) MD5;	// Type
		response[23] = 16;		// Value-Size: 16 Bytes
		FillMD5Area(response+24, request[19], passwd, request+24);
		memcpy(response+40, username, usernamelen);
		// }
	// }

	pcap_sendpacket(handle, response, packetlen);
}


static
void SendLogoffPkt(pcap_t *handle, const uint8_t localmac[])
{
	const uint8_t MultcastAddr[6] = {
		0x01,0x80,0xc2,0x00,0x00,0x03
	};
	uint8_t packet[18];

	// Ethernet Header (14 Bytes)
	memcpy(packet, MultcastAddr, 6);
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x02;	// Type=Logoff
	packet[16] = packet[17] =0x00;// Length=0x0000

	// 发包
	pcap_sendpacket(handle, packet, sizeof(packet));
}

static
void SendResponseNotification(pcap_t *handle, const uint8_t request[], const uint8_t ethhdr[])
{
	uint8_t	response[23];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == NOTIFICATION);

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
		response[14] = 0x1;	// 802.1X Version 1
		response[15] = 0x0;	// Type=0 (EAP Packet)
		response[16] = 0x00;	// Length
		response[17] = 0x05;	//

		// Extensible Authentication Protocol
		// {
		response[18] = (EAP_Code) RESPONSE;	// Code
		response[19] = (EAP_ID) request[19];	// ID
		response[20] = response[16];		// Length
		response[21] = response[17];		//
		response[22] = (EAP_Type) NOTIFICATION;	// Type
		// }
	// }

	pcap_sendpacket(handle, response, sizeof(response));
}


