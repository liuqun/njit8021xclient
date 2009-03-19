#include <stdint.h>
#include <stdio.h>	// sprintf()
#include <string.h>	// mem*()
#include <time.h>	// time()

#include <arpa/inet.h>	// htol()

void FillBase64Area(char area[])
{
	const char	szVersion[]="EN V2.40-0335";// 华为客户端版本号
	uint8_t		version[16+4];	// 存放20字节加密的H3C版本号信息
	uint32_t	key1;		// key1为任意32位整数
	char		szkey1[8+1];	// key1的字符串形式
	const char	szkey2[]="HuaWei3COM1X";
	int	i,j;

	memset(version, 0x00, sizeof(version));
	memcpy(version, szVersion, strlen(szVersion));

	// 第一轮，以key1为密钥加密16字节version
	key1 = (uint32_t) time(NULL);	// 注：只要两次认证会话不重复使用同一个key1值即可
					//     此处同一认证会话中每个应答包都使用不同的key1
	sprintf(szkey1, "%08x", key1);
	for (i=0; i<16; i++)
		version[i] ^= szkey1[i%8];
	for (i=0,j=16-1; i<16; i++,j--)
		version[j] ^= szkey1[i%8];

	// 第二轮，以szkey2为密钥加密20字节(16字节version + 4字节key1)
	key1 = htonl(key1);
	memcpy(version+16, &key1, sizeof(key1));
	for (i=0; i<20; i++)
		version[i] ^= szkey2[i%12];
	for (i=0,j=20-1; i<20; i++,j--)
		version[j] ^= szkey2[i%12];


	// 第三轮，将前面生成的20字节转换为28字节Base64密文
	const char Tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			   "abcdefghijklmnopqrstuvwxyz"
			   "0123456789+/";
	uint8_t c1,c2,c3;
	i = 0;
	j = 0;
	while (j < 24)
	{
		c1 = version[i++];
		c2 = version[i++];
		c3 = version[i++];
		area[j++] = Tbl[ (c1&0xfc)>>2                               ];
		area[j++] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)               ];
		area[j++] = Tbl[               ((c2&0x0f)<<2)|((c3&0xc0)>>6)];
		area[j++] = Tbl[                                c3&0x3f     ];
	}
	c1 = version[i++];
	c2 = version[i++];
	area[24] = Tbl[ (c1&0xfc)>>2 ];
	area[25] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)];
	area[26] = Tbl[               ((c2&0x0f)<<2)];
	area[27] = '=';
}
