typedef unsigned int u_int;
u_int SP[]={
0x80108020, 0x80008000, 0x00008000, 0x00108020,  //0x51860;
0x00100000, 0x00000020, 0x80100020, 0x80008020,  //0x51870;
0x80000020, 0x80108020, 0x80108000, 0x80000000,  //0x51880;
0x80008000, 0x00100000, 0x00000020, 0x80100020,  //0x51890;
0x00108000, 0x00100020, 0x80008020, 0x00000000,  //0x518a0;
0x80000000, 0x00008000, 0x00108020, 0x80100000,  //0x518b0;
0x00100020, 0x80000020, 0x00000000, 0x00108000,  //0x518c0;
0x00008020, 0x80108000, 0x80100000, 0x00008020,  //0x518d0;
0x00000000, 0x00108020, 0x80100020, 0x00100000,  //0x518e0;
0x80008020, 0x80100000, 0x80108000, 0x00008000,  //0x518f0;
0x80100000, 0x80008000, 0x00000020, 0x80108020,  //0x51900;
0x00108020, 0x00000020, 0x00008000, 0x80000000,  //0x51910;
0x00008020, 0x80108000, 0x00100000, 0x80000020,  //0x51920;
0x00100020, 0x80008020, 0x80000020, 0x00100020,  //0x51930;
0x00108000, 0x00000000, 0x80008000, 0x00008020,  //0x51940;
0x80000000, 0x80100020, 0x80108020, 0x00108000,  //0x51950;
0x00802001, 0x00002081, 0x00002081, 0x00000080,  //0x51960;
0x00802080, 0x00800081, 0x00800001, 0x00002001,  //0x51970;
0x00000000, 0x00802000, 0x00802000, 0x00802081,  //0x51980;
0x00000081, 0x00000000, 0x00800080, 0x00800001,  //0x51990;
0x00000001, 0x00002000, 0x00800000, 0x00802001,  //0x519a0;
0x00000080, 0x00800000, 0x00002001, 0x00002080,  //0x519b0;
0x00800081, 0x00000001, 0x00002080, 0x00800080,  //0x519c0;
0x00002000, 0x00802080, 0x00802081, 0x00000081,  //0x519d0;
0x00800080, 0x00800001, 0x00802000, 0x00802081,  //0x519e0;
0x00000081, 0x00000000, 0x00000000, 0x00802000,  //0x519f0;
0x00002080, 0x00800080, 0x00800081, 0x00000001,  //0x51a00;
0x00802001, 0x00002081, 0x00002081, 0x00000080,  //0x51a10;
0x00802081, 0x00000081, 0x00000001, 0x00002000,  //0x51a20;
0x00800001, 0x00002001, 0x00802080, 0x00800081,  //0x51a30;
0x00002001, 0x00002080, 0x00800000, 0x00802001,  //0x51a40;
0x00000080, 0x00800000, 0x00002000, 0x00802080,  //0x51a50;
0x20000010, 0x20400000, 0x00004000, 0x20404010,  //0x51a60;
0x20400000, 0x00000010, 0x20404010, 0x00400000,  //0x51a70;
0x20004000, 0x00404010, 0x00400000, 0x20000010,  //0x51a80;
0x00400010, 0x20004000, 0x20000000, 0x00004010,  //0x51a90;
0x00000000, 0x00400010, 0x20004010, 0x00004000,  //0x51aa0;
0x00404000, 0x20004010, 0x00000010, 0x20400010,  //0x51ab0;
0x20400010, 0x00000000, 0x00404010, 0x20404000,  //0x51ac0;
0x00004010, 0x00404000, 0x20404000, 0x20000000,  //0x51ad0;
0x20004000, 0x00000010, 0x20400010, 0x00404000,  //0x51ae0;
0x20404010, 0x00400000, 0x00004010, 0x20000010,  //0x51af0;
0x00400000, 0x20004000, 0x20000000, 0x00004010,  //0x51b00;
0x20000010, 0x20404010, 0x00404000, 0x20400000,  //0x51b10;
0x00404010, 0x20404000, 0x00000000, 0x20400010,  //0x51b20;
0x00000010, 0x00004000, 0x20400000, 0x00404010,  //0x51b30;
0x00004000, 0x00400010, 0x20004010, 0x00000000,  //0x51b40;
0x20404000, 0x20000000, 0x00400010, 0x20004010,  //0x51b50;
0x10001040, 0x00001000, 0x00040000, 0x10041040,  //0x51b60;
0x10000000, 0x10001040, 0x00000040, 0x10000000,  //0x51b70;
0x00040040, 0x10040000, 0x10041040, 0x00041000,  //0x51b80;
0x10041000, 0x00041040, 0x00001000, 0x00000040,  //0x51b90;
0x10040000, 0x10000040, 0x10001000, 0x00001040,  //0x51ba0;
0x00041000, 0x00040040, 0x10040040, 0x10041000,  //0x51bb0;
0x00001040, 0x00000000, 0x00000000, 0x10040040,  //0x51bc0;
0x10000040, 0x10001000, 0x00041040, 0x00040000,  //0x51bd0;
0x00041040, 0x00040000, 0x10041000, 0x00001000,  //0x51be0;
0x00000040, 0x10040040, 0x00001000, 0x00041040,  //0x51bf0;
0x10001000, 0x00000040, 0x10000040, 0x10040000,  //0x51c00;
0x10040040, 0x10000000, 0x00040000, 0x10001040,  //0x51c10;
0x00000000, 0x10041040, 0x00040040, 0x10000040,  //0x51c20;
0x10040000, 0x10001000, 0x10001040, 0x00000000,  //0x51c30;
0x10041040, 0x00041000, 0x00041000, 0x00001040,  //0x51c40;
0x00001040, 0x00040040, 0x10000000, 0x10041000,  //0x51c50;
0x01010400, 0x00000000, 0x00010000, 0x01010404,  //0x51c60;
0x01010004, 0x00010404, 0x00000004, 0x00010000,  //0x51c70;
0x00000400, 0x01010400, 0x01010404, 0x00000400,  //0x51c80;
0x01000404, 0x01010004, 0x01000000, 0x00000004,  //0x51c90;
0x00000404, 0x01000400, 0x01000400, 0x00010400,  //0x51ca0;
0x00010400, 0x01010000, 0x01010000, 0x01000404,  //0x51cb0;
0x00010004, 0x01000004, 0x01000004, 0x00010004,  //0x51cc0;
0x00000000, 0x00000404, 0x00010404, 0x01000000,  //0x51cd0;
0x00010000, 0x01010404, 0x00000004, 0x01010000,  //0x51ce0;
0x01010400, 0x01000000, 0x01000000, 0x00000400,  //0x51cf0;
0x01010004, 0x00010000, 0x00010400, 0x01000004,  //0x51d00;
0x00000400, 0x00000004, 0x01000404, 0x00010404,  //0x51d10;
0x01010404, 0x00010004, 0x01010000, 0x01000404,  //0x51d20;
0x01000004, 0x00000404, 0x00010404, 0x01010400,  //0x51d30;
0x00000404, 0x01000400, 0x01000400, 0x00000000,  //0x51d40;
0x00010004, 0x00010400, 0x00000000, 0x01010004,  //0x51d50;
0x00000208, 0x08020200, 0x00000000, 0x08020008,  //0x51d60;
0x08000200, 0x00000000, 0x00020208, 0x08000200,  //0x51d70;
0x00020008, 0x08000008, 0x08000008, 0x00020000,  //0x51d80;
0x08020208, 0x00020008, 0x08020000, 0x00000208,  //0x51d90;
0x08000000, 0x00000008, 0x08020200, 0x00000200,  //0x51da0;
0x00020200, 0x08020000, 0x08020008, 0x00020208,  //0x51db0;
0x08000208, 0x00020200, 0x00020000, 0x08000208,  //0x51dc0;
0x00000008, 0x08020208, 0x00000200, 0x08000000,  //0x51dd0;
0x08020200, 0x08000000, 0x00020008, 0x00000208,  //0x51de0;
0x00020000, 0x08020200, 0x08000200, 0x00000000,  //0x51df0;
0x00000200, 0x00020008, 0x08020208, 0x08000200,  //0x51e00;
0x08000008, 0x00000200, 0x00000000, 0x08020008,  //0x51e10;
0x08000208, 0x00020000, 0x08000000, 0x08020208,  //0x51e20;
0x00000008, 0x00020208, 0x00020200, 0x08000008,  //0x51e30;
0x08020000, 0x08000208, 0x00000208, 0x08020000,  //0x51e40;
0x00020208, 0x00000008, 0x08020008, 0x00020200,  //0x51e50;
0x00000100, 0x02080100, 0x02080000, 0x42000100,  //0x51e60;
0x00080000, 0x00000100, 0x40000000, 0x02080000,  //0x51e70;
0x40080100, 0x00080000, 0x02000100, 0x40080100,  //0x51e80;
0x42000100, 0x42080000, 0x00080100, 0x40000000,  //0x51e90;
0x02000000, 0x40080000, 0x40080000, 0x00000000,  //0x51ea0;
0x40000100, 0x42080100, 0x42080100, 0x02000100,  //0x51eb0;
0x42080000, 0x40000100, 0x00000000, 0x42000000,  //0x51ec0;
0x02080100, 0x02000000, 0x42000000, 0x00080100,  //0x51ed0;
0x00080000, 0x42000100, 0x00000100, 0x02000000,  //0x51ee0;
0x40000000, 0x02080000, 0x42000100, 0x40080100,  //0x51ef0;
0x02000100, 0x40000000, 0x42080000, 0x02080100,  //0x51f00;
0x40080100, 0x00000100, 0x02000000, 0x42080000,  //0x51f10;
0x42080100, 0x00080100, 0x42000000, 0x42080100,  //0x51f20;
0x02080000, 0x00000000, 0x40080000, 0x42000000,  //0x51f30;
0x00080100, 0x02000100, 0x40000100, 0x00080000,  //0x51f40;
0x00000000, 0x40080000, 0x02080100, 0x40000100,  //0x51f50;
0x00200000, 0x04200002, 0x04000802, 0x00000000,  //0x51f60;
0x00000800, 0x04000802, 0x00200802, 0x04200800,  //0x51f70;
0x04200802, 0x00200000, 0x00000000, 0x04000002,  //0x51f80;
0x00000002, 0x04000000, 0x04200002, 0x00000802,  //0x51f90;
0x04000800, 0x00200802, 0x00200002, 0x04000800,  //0x51fa0;
0x04000002, 0x04200000, 0x04200800, 0x00200002,  //0x51fb0;
0x04200000, 0x00000800, 0x00000802, 0x04200802,  //0x51fc0;
0x00200800, 0x00000002, 0x04000000, 0x00200800,  //0x51fd0;
0x04000000, 0x00200800, 0x00200000, 0x04000802,  //0x51fe0;
0x04000802, 0x04200002, 0x04200002, 0x00000002,  //0x51ff0;
0x00200002, 0x04000000, 0x04000800, 0x00200000,  //0x52000;
0x04200800, 0x00000802, 0x00200802, 0x04200800,  //0x52010;
0x00000802, 0x04000002, 0x04200802, 0x04200000,  //0x52020;
0x00200800, 0x00000000, 0x00000002, 0x04200802,  //0x52030;
0x00000000, 0x00200802, 0x04200000, 0x00000800,  //0x52040;
0x04000002, 0x04000800, 0x00000800, 0x00200002,  //0x52050;
};
u_int getSP (u_int address)
{
    if (address<0x51860 || address>= 0x52060)
    {
        printf ("**Error: SP Array is overflow.\n");
        return 0xffffffff;
    }
    return SP[(address-0x51860)/4];
}
void setSP (u_int address,u_int value)
{
    if (address<0x51860 || address>= 0x52060)
    {
        printf ("**Error: SP Array is overflow.\n");
        return ;
    }
    SP[(address-0x51860)/4]=value;
}
