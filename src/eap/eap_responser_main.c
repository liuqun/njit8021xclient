
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "njit8021xclient.h"
int check(const uint8_t data[], int len);
int main()
{
	const int BLOCK_SIZE=1024;
	const int N_BLOCKS=64;
	uint8_t bData[N_BLOCKS][BLOCK_SIZE];
	int nBytes;
	int nTotalBytes;
	int i;

	FILE *pInput=stdin;
	clearerr(pInput);
	for (i=0,nTotalBytes=0;  i<N_BLOCKS && !ferror(pInput) && !feof(pInput);  i++)
	{
		nBytes = fread(&(bData[i][0]), 1, BLOCK_SIZE, pInput);
		assert(nBytes <= BLOCK_SIZE);
		nTotalBytes += nBytes;
		if (nBytes < BLOCK_SIZE) // NOTE: The last block of data is not full
		{
			break;
		}
	}
	assert(nTotalBytes <= BLOCK_SIZE*N_BLOCKS);

	check(&(bData[0][0]), nTotalBytes);
	return (0);
}

int check(const uint8_t data[], int datalen)
{
	EAP_Code code=0;
	EAP_ID id=0;
	uint16_t eaplen=0;
	EAP_Type eaptype=0;
	if (datalen < 5)
	{
		fprintf(stderr, "[Warning: 报文长度不正常datalen=%d]\n", datalen);
		return (0);
	}
	code = data[0];
	id   = data[1];
	if (code != REQUEST)
	{
		fprintf(stderr, "[Warning: 这不是请求桢]\n");
		return (0);
	}
	memcpy(&eaplen, data+2, sizeof(uint16_t));
	eaplen = ntohs(eaplen);
	if (eaplen < 5)
	{
		fprintf(stderr, "[Warning: 报文内容异常eaplen=%d]\n", eaplen);
		return (0);
	}
	if (eaplen > datalen)
	{
		fprintf(stderr, "[Warning: 报文内容异常eaplen=%d大于datalen,datalen=%d]\n", eaplen, datalen);
		return (0);
	}
	eaptype = data[4];
	switch (eaptype)
	{
		case IDENTITY:
			fprintf(stderr, "[%d] Server: Request Identity!\n", id);
			break;
		case NOTIFICATION:
			break;
		case MD5:
			break;
		case H3C_HEARTBEAT:
			break;
	}
	return(eaplen);
}
