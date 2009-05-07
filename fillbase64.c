#include <stdint.h>
#include <string.h>	// mem*()

#include <arpa/inet.h>	// htol()

void FillClientVersionArea(uint8_t area[20]);

void FillBase64Area(char area[])
{
	uint8_t version[20]; // 存放20字节加密的H3C版本号信息

	FillClientVersionArea(version);

	// 第三轮，将前面生成的20字节转换为28字节Base64密文
	const char Tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			   "abcdefghijklmnopqrstuvwxyz"
			   "0123456789+/";
	uint8_t c1,c2,c3;
	int i, j;
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
