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
#include <linux/if_ether.h>


// 自定义常量
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20} EAP_Type;

// 函数声明
int ProcessAuthenticaiton_WiredEthernet(const char *UserName, const char *Password, const char *DeviceName);
static void BuildStartPkt(uint8_t pktbuf[], uint8_t localmac[6]);
static int BuildIdentityPkt(const uint8_t request[],
				   uint8_t response[],
				const char username[]);
static int BuildMD5Pkt(const uint8_t request[],
			      uint8_t response[],
			const char username[],
			const char passwd[]);
static int BuildAvailablePkt(const uint8_t request[],
				   uint8_t response[],
				const char username[]);
static int GetErrorCode(const uint8_t captured[]);
static void DumpFailurePkt(const uint8_t captured[]);
static void GetMacFromDevice(uint8_t mac[6], const char *devicename);
static void FillEAPOL(uint8_t response[]);
static void FillEthHdr(const uint8_t request[], uint8_t response[]);
// From fillmd5.c
extern void FillMD5Area(uint8_t digest[],
	       	uint8_t id, const char passwd[], const uint8_t srcMD5[]);
// From fillbase64.c
extern void FillBase64Area(char area[]);

// 定义DPRINTF宏：输出调试信息
#define DPRINTF(...)	fprintf(stderr, __VA_ARGS__)


// 存储本机网卡物理地址
static uint8_t	MAC[6];

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
	char		FilterStr[100];
	struct bpf_program	fcode;


	/* 打开适配器 */
	const int DefaultTimeOut=60000;//设置接收超时参数，单位ms
	adhandle = pcap_open_live(DeviceName,65536,1,DefaultTimeOut,errbuf);
	if (adhandle==NULL) {
		fprintf(stderr, "%s\n", errbuf); 
		exit(-1);
	}

	/* 查询本机网卡MAC地址 */
	GetMacFromDevice(MAC, DeviceName);

	// 设置过滤器，只捕获发往本机的802.1X认证会话（不接收多播信息）
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
		MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);


	START_AUTHENTICATION:
	{
		int retcode;
		unsigned pktlen;
		struct pcap_pkthdr *header;
		const uint8_t	*captured;
		uint8_t		StartPkt[60]={0};
		uint8_t		NotificationPkt[60];
		uint8_t		IdentityPkt[128]={0};
		uint8_t		AvailablePkt[128]={0};
		uint8_t		MD5Pkt[60]={0};

		/* 主动发起认证会话 */
		BuildStartPkt(StartPkt, MAC);
		pcap_sendpacket(adhandle, StartPkt, sizeof(StartPkt));
		DPRINTF("[ ] Client: Start.\n");

		/* 接收来自认证服务器的数据并应答 */

		// 接收第一个Request包
		retcode = pcap_next_ex(adhandle, &header, &captured);
		assert(retcode==1||retcode==0);
		if (retcode==0)
		{
			fprintf(stderr, "服务器无响应或响应超时\n");
			// Note: 也有可能是网线没插好
			fprintf(stderr, "按回车键重试，按Ctrl-C退出\n");
			while (getchar() != '\n')
				;
			goto START_AUTHENTICATION;
		}

		assert((EAP_Code)captured[18] == REQUEST);
		// 若收到的第一个Request包是Notification，直接回答一个空的Notification包
		if ((EAP_Type)captured[22] == NOTIFICATION)
		{
			DPRINTF("[%d] Server: Request Notification!\n", captured[19]);
			// 应答Notification
			FillEthHdr(captured, NotificationPkt);
			memcpy(NotificationPkt+14, captured+14, 60-14);
			NotificationPkt[18] = RESPONSE;
			pcap_sendpacket(adhandle, NotificationPkt, 60);
			DPRINTF("[%d] Client: Response Notification.\n", NotificationPkt[19]);

			// 继续接收下一个Request包
			retcode = pcap_next_ex(adhandle, &header, &captured);
			assert(retcode==1);
			assert((EAP_Code)captured[18] == REQUEST);
		}

		// 分两种情况处理：
		// Request Identity	(南京工程学院目前使用的格式)
		// Request AVAILABLE	(中南财经政法大学目前使用的格式)
		if ((EAP_Type)captured[22] == IDENTITY)
		{
			DPRINTF("[%d] Server: Request Identity!\n", captured[19]);
		}
		else if ((EAP_Type)captured[22] == AVAILABLE)
		{
			DPRINTF("[%d] Server: Request AVAILABLE!\n", captured[19]);
		}
		else
		{
			DPRINTF("[%d] Server: Request (type:%d)!\n", captured[19], (EAP_Type)captured[22]);
			DPRINTF("Error! Unexpected request type\n");
			exit(-1);
		}
		// 发送Response Identity
		pktlen = BuildIdentityPkt(captured, IdentityPkt, UserName);
		assert(pktlen <= sizeof(IdentityPkt));
		pcap_sendpacket(adhandle, IdentityPkt, pktlen);
		DPRINTF("[%d] Client: Response Identity.\n", IdentityPkt[19]);

		// 接收并应答“MD5-Challenge”
		retcode = pcap_next_ex(adhandle, &header, &captured);
		assert(retcode==1);
		assert(   (EAP_Code)captured[18] == REQUEST
			&&(EAP_Type)captured[22] == MD5);
		DPRINTF("[%d] Server: Request MD5-Challenge!\n", captured[19]);

		pktlen = BuildMD5Pkt(captured, MD5Pkt, UserName, Password);
		assert(pktlen <= sizeof(MD5Pkt));
		pcap_sendpacket(adhandle, MD5Pkt, pktlen);
		DPRINTF("[%d] Client: Response MD5-Challenge.\n", MD5Pkt[19]);
			//注：H3C发送的MD5包长固定为60字节，其中最后20字节为
			//    用户名区域。此处pktlen可以小于等于60。

		// 重设过滤器，捕获华为802.1X认证设备发来的包（包括多播Request Identity）
		sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			captured[6],captured[7],captured[8],captured[9],captured[10],captured[11]);
		pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
		pcap_setfilter(adhandle, &fcode);

		// 循环应答保持在线，另外处理认证失败信息和其他数据
		for (;;)
		{
			retcode = pcap_next_ex(adhandle, &header, &captured);
			assert(retcode==1||retcode==0);
			if (retcode==0)
			{
				fprintf(stderr, "服务器无响应或响应超时\n");
				// Note: 也有可能是网线没插好
				fprintf(stderr, "按回车键重试，按Ctrl-C退出\n");
				while (getchar() != '\n')
					;
				goto START_AUTHENTICATION;
			}

			if ((EAP_Code)captured[18] == REQUEST)
			{
				EAP_Type  type = captured[22];
				// 分两种情况：Identity或AVAILABLE
				if (type == IDENTITY)
				{
					DPRINTF("[%d] Server: Request Identity!\n", captured[19]);
					pktlen = BuildIdentityPkt(captured, IdentityPkt, UserName);
					assert(pktlen <= sizeof(IdentityPkt));
					pcap_sendpacket(adhandle, IdentityPkt, pktlen);
					DPRINTF("[%d] Client: Response Identity.\n", IdentityPkt[19]);
				}
				else if (type == AVAILABLE)
				{
					DPRINTF("[%d] Server: Request AVAILABLE!\n", captured[19]);
					pktlen = BuildAvailablePkt(captured, AvailablePkt, UserName);
					assert(pktlen <= sizeof(AvailablePkt));
					pcap_sendpacket(adhandle, AvailablePkt, pktlen);
					DPRINTF("[%d] Client: Response AVAILABLE.\n", AvailablePkt[19]);
				}
				else
				{
					DPRINTF("[%d] Server: Request (type:%d)!\n", captured[19], type);
					DPRINTF("Error! Unexpected request type\n");
					exit(-1);
				}
			}
			else if ((EAP_Code)captured[18] == FAILURE)
			{
				int errcode = GetErrorCode(captured);
				switch (errcode)
				{
				 case -1: // 被服务器踢下线后自动重连
					goto START_AUTHENTICATION;
					break;
				 case -2:
					DumpFailurePkt(captured);
					exit(-1);
					break;
				 case 2553: // 密码错误
				 case 2531: // 用户名不存在
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
int BuildMD5Pkt(const uint8_t request[],
		       uint8_t response[],
		    const char username[],
		    const char passwd[])
{
	uint16_t eaplen;
	size_t   usernamelen;

	assert(  (EAP_Code)request[18] == REQUEST
	       &&(EAP_Type)request[22] == MD5);

	usernamelen = strlen(username);
	eaplen = htons(22+usernamelen);

	response[18] = (EAP_Code) RESPONSE;	// Code
	response[19] = request[19];		// ID
	memcpy(response+20, &eaplen, sizeof(eaplen));	// Length
	response[22] = (EAP_Type) MD5;		// Type
	response[23] = 16;	// Value-Size: 16 Bytes
	FillMD5Area(response+24, request[19], passwd, request+24);
	memcpy(response+40, username, usernamelen);// without '\0'

	FillEAPOL(response);
	FillEthHdr(request, response);

	return (14+4+22+usernamelen);
	// etherHdr+EAPOL+EAP+usernamelen
}

static
int BuildIdentityPkt(const uint8_t request[],
		            uint8_t response[],
			 const char username[])
{
	uint16_t eaplen;
	size_t   usernamelen;

	assert(  (EAP_Code)request[18] == REQUEST
	       &&(EAP_Type)request[22] == IDENTITY);

	usernamelen = strlen(username);
	eaplen = htons((1+1+2+1)+(2+28+2+usernamelen));

	// EAP
	response[18] = (EAP_Code) RESPONSE;	// Code
	response[19] = request[19];		// ID
	memcpy(response+20, &eaplen, sizeof(eaplen));// Length
	response[22] = (EAP_Type) IDENTITY;	// Type

	// H3C未公开的部分
	response[23] = 0x06;	// 验证H3C客户端版本号
	response[24] = 0x07;	//
	FillBase64Area((char*)response+25);//Base64区域，共28字节 [25<=index<=52]
	response[53] = ' ';	// 两个空格符
	response[54] = ' ';	//
	memcpy(response+55, username, strlen(username));//without '\0'

	// 添加报头
	FillEAPOL(response);
	FillEthHdr(request, response);

	return (14+4+(1+1+2+1)+(2+28+2)+usernamelen);
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
void FillEAPOL(uint8_t response[])
{
	response[14] = 0x1;	    // 802.1X Version 1
	response[15] = 0x0;	    // Type=0 (EAP Packet)
	response[16] = response[20];// Length (Copied from EAP)
	response[17] = response[21];
}

static
void FillEthHdr(const uint8_t request[], uint8_t response[])
{
	const struct ethhdr	*requHdr = (struct ethhdr *) request;
	struct ethhdr		*respHdr = (struct ethhdr *) response;

	memcpy(respHdr->h_dest,    requHdr->h_source,  ETH_ALEN);
	memcpy(respHdr->h_source,  MAC,                ETH_ALEN);
	       respHdr->h_proto =  requHdr->h_proto;
}

static
void BuildStartPkt(uint8_t pktbuf[], uint8_t localmac[6])
{
	const uint8_t MultcastAddr[6] = {
		0x01,0x80,0xc2,0x00,0x00,0x03
	};

	// 以太报头
	memcpy(pktbuf, MultcastAddr, 6);
	memcpy(pktbuf+6, localmac,   6);
	pktbuf[12] = 0x88;
	pktbuf[13] = 0x8e;

	// EAPOL头
	pktbuf[14] = 0x01;	//
	pktbuf[15] = 0x01;	// Type=1
	pktbuf[16] = pktbuf[17] =0x00;// Length=0x0000
}

static
int BuildAvailablePkt(const uint8_t request[], uint8_t response[], const char username[])
{
	int i;
	uint16_t eaplen;
	const size_t   usernamelen = strlen(username);

	// Ethernet Header (14 Bytes)
	FillEthHdr(request, response);

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
			response[22] = (EAP_Type) request[22];	// Type
			// Type-Data
			// {
				i = 23;
				response[i++] = 0x00; // 是否使用代理
				response[i++] = 0x06;		  // 携带版本号
				response[i++] = 0x07;		  //
				FillBase64Area((char*)response+i);//
				i += 28;			  //
				response[i++] = ' '; // 两个空格符
				response[i++] = ' '; //
				memcpy(response+i, username, usernamelen);//
				i += usernamelen;			  //
			// }
		// }
	// }
	
	// 补填前面留空的两处Length
	eaplen = htons(i-18);
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));

	// Return the length of the response packet.
	return (i);
}
