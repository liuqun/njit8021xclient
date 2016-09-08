/*
 * iNode 3.60 E6208 PATCH NCEPU
 * Designed by vrqq.
 * vrqq3118@163.com
 */
#include <stdio.h>
#include <string.h>
#include "SParray.h"
#include "desKey.h"

typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned long u_long;

u_int ror(u_int data,u_int clen)
{
	data = (data>>clen) + (data<<(32-clen));
	return data;
}
u_int rol(u_int data,u_int clen)
{
	return (data<<clen)+(data>>(32-clen));
}
u_int ebp[70]; //stack;
u_int* ebpPoint[70];//stack;
void saveEBP(u_int pos,u_int key)
{
	ebp[pos/4]=key;
}
void saveEBPpoint(u_int pos,u_int* key)
{
	ebpPoint[pos/4]=key;
}
u_int getEBP(u_int pos)
{
	return ebp[pos/4];
}
u_int* getEBPpoint(u_int pos)
{
	return ebpPoint[pos/4];
}
void desfunc(u_int *data,u_int *key)
{
    u_int eax=0,ecx=0,edx=0,esi=0,edi=0,tmp;
    u_int desCount=7;
//0x30ABA begin.
	saveEBPpoint(0x18,data); //addr
	saveEBPpoint(0x1C,key); //addr
	edx=data[0];
	saveEBPpoint(0x14,&data[1]); //addr
	esi=data[1];
	eax=edx; // 0x30ACE
	//dispvar("0x30ACE");
	eax>>=4;
	eax^=esi;
	eax&=0x0F0F0F0F;
	esi^=eax;
	eax<<=4;
	eax^=edx;
        //edx=eax;
        //edx>>=0x10;
        //edx^=esi;
        //edx&=0x0FFFF;
    edx= ((eax>>0x10)^esi)&0x0FFFF;
	esi^=edx;
	edx<<=0x10;
	edx^=eax;
        //ecx=esi;
        //ecx>>=2;
        //ecx^=edx;
        //ecx&=0x33333333;
    ecx=((esi>>2)^edx)&0x33333333;
	edx^=ecx;
	ecx<<=2;
	ecx^=esi;
	eax=ecx;
	eax>>=8;
	eax^=edx;
	eax&=0x0FF00FF;
	edx^=eax;
	eax<<=8;
	eax^=ecx;
	eax=ror(eax,0x1F);
	ecx=edx^eax;
        //ecx^=eax;
	ecx&=0x0AAAAAAAA;
	edi=edx^ecx;
        //edi^=ecx;
	eax^=ecx;
	//dispvar(); getchar();
	//pause;
	saveEBP(0x44,eax);
	edi=ror(edi,0x1F);
    //saveEBP(0x10,8);
	edx=0x51f60; saveEBP(0x38,0x51f60);
	ecx=0x51e60; saveEBP(0x30,0x51e60);
	esi=0x15d60; saveEBP(0x28,0x51d60);
	eax=0x51c60; saveEBP(0x20,0x51c60);
	edx=0x51b60; saveEBP(0x3C,0x51b60);
	ecx=0x51a60; saveEBP(0x34,0x51a60);
	esi=0x51960; saveEBP(0x2C,0x51960);
	eax=0x51860; saveEBP(0x24,0x51860);
	//dispvar();
	//dispEBP();
	//loc_30B84:
do{
	eax=getEBP(0x44);
	eax=ror(eax,4);
	eax^=getEBPpoint(0x1C)[0];//Warning>> 0x1C=key*;
	edx= (eax&0x3F);
	ecx=( (eax>>0x8)&0x3F );
//		dispvar("0x30b9c"); getchar();//DEBUG>>
	saveEBP(0x40,ecx); //0x30b9c
	edx=getSP(getEBP(0x38)+edx*4);
	edx^=getSP(getEBP(0x30)+ecx*4);
	eax>>=0x10;
	ecx=eax&0x3F;
//		dispvar("0x30bb3"); getchar();//DEBUG>>
	saveEBP(0x40,ecx); //0x30BB3
	edx^=getSP(getEBP(0x28)+ecx*4);
	eax=(eax>>8)&0x3F;
	edx^=getSP(getEBP(0x20)+eax*4);
	edi^=edx;
	eax=getEBP(0x44);
	eax^=getEBPpoint(0x1C)[1];
	edx=eax&0x3F;
	ecx=(eax>>8)&0x3F;
//		dispvar("0x30be0"); getchar();//DEBUG>>
	saveEBP(0x40,ecx); //0x30BE0
	edx=getSP(getEBP(0x3C)+edx*4);
	edx^=getSP(getEBP(0x34)+ecx*4);
	eax>>=0x10;
	ecx=eax&0x3F;
//		dispvar("0x30bf7"); getchar();//DEBUG>>
	saveEBP(0x40,ecx); //0x30BF7;
	edx^=getSP(getEBP(0x2C)+ecx*4);
	eax>>=8;
	eax&=0x3F;
	edx^=getSP(getEBP(0x24)+eax*4);
	edi^=edx;
	//eax=edi;
	eax=ror(edi,4); //0x30C10;
	eax^=getEBPpoint(0x1C)[2];
	edx=eax&0x3F;
	ecx=(eax>>8)&0x3F;
//		dispvar("0x30c26"); getchar();//DEBUG>>
	saveEBP(0x40,ecx); //0x30C26
	edx=getSP(getEBP(0x38)+edx*4);
	edx^=getSP(getEBP(0x30)+ecx*4);
	eax>>=0x10;
	ecx=eax&0x3F;
//		dispvar("0x30c3d"); getchar();//DEBUG>>
	saveEBP(0x40,ecx); //0x30C3D
	edx^=getSP(getEBP(0x28)+ecx*4);
	eax>>=8;
	eax&=0x3F;
	edx^=getSP(getEBP(0x20)+eax*4);
	tmp=getEBP(0x44); saveEBP(0x44,tmp^edx);
	edx=edi;
	//esi=getEBP(0x1C);
	edx^=getEBPpoint(0x1C)[3];
	//esi+=0x10;
	saveEBPpoint(0x1C,&(getEBPpoint(0x1C)[4])); //0x30C60
	eax=edx&0x3F;
	ecx=(edx>>8)&0x3F;
//		dispvar("0x30c70"); getchar();//DEBUG>>
	saveEBP(0x40,ecx); //0x30C70
	eax=getSP(getEBP(0x3C)+eax*4);
	eax^=getSP(getEBP(0x34)+ecx*4);
	edx>>=0x10;
	ecx=edx&0x3F;
	saveEBP(0x40,ecx); //0x30C87
	eax^=getSP(getEBP(0x2C)+ecx*4);
	edx>>=8;
	edx&=0x3F;
	eax^=getSP(getEBP(0x24)+edx*4);
//		dispvar("0x30c9C"); getchar();//DEBUG>>
	tmp=getEBP(0x44); saveEBP(0x44,tmp^eax);
        //tmp=getEBP(0x10); saveEBP(0x10,tmp-1); //0x30C9F
	//printf ("<%d>\n",tmp);
}while(desCount--); //tmp=1 ==> tmp-1=0; ==>zf=1;
	ecx=getEBP(0x44);
	ecx=ror(ecx,1);
	eax=ecx^edi;
	eax&=0x0AAAAAAAA;
	edx=eax^edi;
	ecx^=eax;
	edx=ror(edx,1);
	eax=edx;
	eax>>=8;
	eax^=ecx;
	eax&=0x0FF00FF; // 0x30CC6;
	ecx^=eax;
	eax<<=8;
	eax^=edx;
	edx=eax>>2;
	edx^=ecx;
	edx&=0x33333333;
	ecx^=edx;
	edx<<=2;
	edx^=eax;
	eax=ecx;
	eax>>=0x10;
	eax^=edx;
	eax&=0x0FFFF;
	edx^=eax;
	eax<<=0x10;
	eax^=ecx;
	ecx= ((eax>>4)^edx)&0x0F0F0F0F;
	esi=ecx;
	esi<<=4;
	eax^=esi;// result1 =>data[0]
	edx^=ecx;// result2 =>data[1]
	data[0]=eax; data[1]=edx;
	//dispvar("Final");
}
void des_init()
{
    memset(ebpPoint,0,sizeof(ebpPoint));
    
}
void des3_ecb_decrypt (u_int *data)
{
    int i;
	for (i=0;i<4;i++)
	{
		desfunc(data+i*2,keyDES1);
		desfunc(data+i*2,keyDES2);
		desfunc(data+i*2,keyDES3);
	}
}
/*
int main ()
{
	//init();
	memset(ebpPoint,0,sizeof(ebpPoint));
	u_int data[2]={0xe07470b1,0x86542828};
	u_int d2[2]  ={0x74177b93,0xd14c26bc};
	//printf ("<%x %x>\n",*data,(unsigned long)data);
	//printf ("<%lu %lu>\n",sizeof(unsigned int),sizeof(unsigned long));
	//u_int *p=key;
	//printf ("<%x %x>\n",key,*key);
	desfunc(data,keyDES1);
	desfunc(data,keyDES2);
	desfunc(data,keyDES3);
	printf ("------Result------\n");
	printf ("%08x %08x\n",data[0],data[1]);
	return 0;
}
*/