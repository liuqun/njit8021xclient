/*
 * iNode 3.60 E6208 PATCH NCEPU
 * Designed by vrqq.
 * vrqq3118@163.com
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/md5.h>

typedef unsigned int u_int;
typedef unsigned char u_char;
void des3_ecb_decrypt (u_int *data);

u_int  Ddata_i[8];
u_char Ddata_c[32];

u_char result[32];
void data_invert ()
{
    int i,j,tbegin;
    for (i=0;i<8;i++)
    {
        tbegin=i*4;
        Ddata_i[i]=Ddata_c[tbegin];
        for (j=1;j<4;j++)
        {
            Ddata_i[i]<<=8;
            Ddata_i[i]+=Ddata_c[tbegin+j];
        }
            //printf ("i=%d ,After:%x\n",i,Ddata_i[i]);
    }
}
void data_invert2 ()
{
    int i,j,tbegin,tmp;
    for (i=0;i<8;i++)
    {
            //printf ("i=%d >> Before:%x\n",i,Ddata_i[i]);
        tmp=0xFF000000;
        tbegin=i*4;
        for (j=0;j<4;j++)
        {
            Ddata_c[tbegin+j] = (tmp&Ddata_i[i])>>8*(3-j);
            tmp>>=8;
        }
    }
}
void md5Transform ()
{
    u_char result1[16];
    (void) MD5(Ddata_c,sizeof(Ddata_c),result1);
    (void) MD5(result1,sizeof(result1),result+16);
    memcpy(result,result1,sizeof(result1));
}
u_char* HandleKeepOnline(const uint8_t request[])
{
    int i=0;
    memcpy (Ddata_c,request+27,sizeof(Ddata_c));
     data_invert();//u_char to u_int,eg: 0xE0 74 70 B1 ==> 0xE07470B1
    des3_ecb_decrypt(Ddata_i);
    data_invert2();//u_int to u_char,eg:0x39 34 65 66 ==> 0x39346566
    md5Transform();
     return result;
}

// * Only for debug "patch" folder
/*
u_char OroData[80];
u_char *ans;
int main ()
{
    freopen ("data.in","r",stdin);
    for (int i=0;i<67;i++)
        scanf ("%x",&OroData[i]);
    ans=HandleKeepOnline(OroData);
    for (int i=0;i<32;i++)
    {
        printf ("%02x ",ans[i]);
        if ((i+1)%8==0) printf("\n");
    }
    return 0;
}
*/