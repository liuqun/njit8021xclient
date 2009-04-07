/* File: auth.c
 * ------------
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>

#include <pcap.h>

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>


// 自定义常量
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20} EAP_Type;
typedef uint8_t EAP_ID;

// 函数声明
int ProcessAuthenticaiton_WiredEthernet(const char *UserName, const char *Password, const char *DeviceName);
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
static int GetErrorCode(const uint8_t captured[]);
static void DumpFailurePkt(const uint8_t captured[]);
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
 * 函数：ProcessAuthenticaiton_WiredEthernet()
 *
 * Process 802.1X authentication through wired Ethernet
 * 使用以太网进行802.1X认证
 */

int ProcessAuthenticaiton_WiredEthernet(const char *UserName, const char *Password, const char *DeviceName)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*adhandle;
	uint8_t	MAC[6];
	char	FilterStr[100];
	struct bpf_program	fcode;


	/* 打开适配器 */
	const int DefaultTimeOut=60000;//设置接收超时参数，单位ms
	adhandle = pcap_open_live(DeviceName,65536,1,DefaultTimeOut,errbuf);
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
			uint8_t response[128]={0};
			memcpy(response, ethhdr, 14);
			DPRINTF("[%d] Server: Request Notification!\n", captured[19]);
			// 填写Notification包并发送
			response[14] = 0x01;
			response[15] = 0x00;
			response[16] = 0x00;
			response[17] = 0x05;
			response[18] = (EAP_Code) RESPONSE;
			response[19] = (EAP_ID) captured[19];
			response[20] = 0x00;
			response[21] = 0x05;
			response[22] = (EAP_Type) NOTIFICATION;
			pcap_sendpacket(adhandle, response, 23);
			DPRINTF("[%d] Client: Response Notification.\n", response[19]);

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
		// 循环应答，另外处理认证失败信息和其他H3C自定义数据格式
		for (;;)
		{
			while((retcode=pcap_next_ex(adhandle, &header, &captured)) != 1)
			{
				// 遇到捕获失败的情况，分析错误原因
				DPRINTF("Warning: Failed to capture next packet\n");
				DPRINTF("the return code of pcap_next_ex() is %d\n", retcode);
				DPRINTF("Analizing: %s\n", pcap_lib_version());
				if (retcode==0)//超时
				{
					DPRINTF("Return code 0 stands for timeout\n");
					DPRINTF("We will ignore this case and continue to capture the next packet\n");
					continue; // 继续捕获后续数据包
				}
				else if (retcode==-1)
				{
					DPRINTF("Return code -1 stands for a pcap error\n");
					fprintf(stderr, "Pcap error: %s\n", errbuf);
					exit(-1);
				}
				else
				{
					fprintf(stderr, "Unexpected return code %d\n", retcode);
					exit(-1);
				}
			}

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
				 default:
					DPRINTF("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
					DPRINTF("Error! Unexpected request type\n");
					exit(-1);
					break;
				}
			}
			else if ((EAP_Code)captured[18] == FAILURE)
			{
				int	errcode;
				DPRINTF("[%d] Server: Failure.\n", captured[19]);
				errcode = GetErrorCode(captured);
				switch (errcode)
				{
				 case -1: // 被服务器踢下线后自动重连
					goto START_AUTHENTICATION;
					break;
				 case -2:
					DumpFailurePkt(captured);
					exit(-1);
					break;
				 case 2531: // 用户名不存在
				 case 2542: // 在线用户数量限制
				 case 2547: // 接入时段限制
				 case 2553: // 密码错误
				 case 2602: // Session does not exist
				 case 3137: // 客户端版本号错误
				 default:   // 其他错误码
					fprintf(stderr, "%s\n", captured+24);
					exit(-1);
					break;
				}
			}
			else if ((EAP_Code)captured[18] == SUCCESS)
			{
				DPRINTF("[%d] Server: Success.\n", captured[19]);
			}
			else
			{
				DPRINTF("[%d] Server: (H3C data)\n", captured[19]);
				// TODO: Examine H3C data packet
			}
		}
	}
	return (0);
}


static
int GetErrorCode(const uint8_t captured[])
{
	int errcode;

	if (captured[22]==0x09)
	{
		sscanf((char*)captured+24, "E%4d: ", &errcode);
		return (errcode);
	}
       	else if (captured[22]==0x08 && captured[23]==0x01)
	{
		return (-1);
	}
	else
	{
		return (-2);
	}
}


static
void DumpFailurePkt(const uint8_t captured[])
{
	int i;
	uint16_t len;// length of H3C extra data in the 'Failure' packet

	assert((EAP_Code)captured[18] == FAILURE);

	memcpy(&len, captured+20, sizeof(len));
	len = ntohs(len);
	len -= 4;

	fprintf(stderr, "Received 'Failure' packet with extra data %d Bytes:\n", len);
	fprintf(stderr, " %02x %02x\n", captured[22], captured[23]);
	for (i=2; i<len; i++)
	{
		fprintf(stderr, " %02x", captured[22+i]);
	}
	fprintf(stderr, "\n");
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
				response[i++] = 0x15;	  // 上传IP地址
				response[i++] = 0x04;	  //
				memcpy(response+i, ip, 4);//
				i += 4;			  //
				response[i++] = 0x00;// 上报是否使用代理
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

