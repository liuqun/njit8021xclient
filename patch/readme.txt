## readme
NCEPU 3.60 E6208 Patch
For NCEPU Only
Nov7,2012 Packed by vrqq.

****** Only for test ******
改动：
在 auth.c 中修改如下内容

*** 1 ***
在文件头部 添加
	// From handleDES.c
	uint8_t* HandleKeepOnline(const uint8_t data[]);

*** 2 ***
	“// TODO: 这里没有处理华为自定义数据包”
这个位置 修改至如下内容：
	DPRINTF("[%d] Server: %2x %2x %2x %2x %2x(H3C data)\n", captured[19],captured[22],captured[23],captured[24],captured[25],captured[26]);
	if ((uint8_t)captured[22]==0x19 && (uint8_t)captured[23]==0x2b && (uint8_t)captured[24]==0x44 && (uint8_t)captured[25]==0x2b && (uint8_t)captured[26]==0x32)
	{
	    response1620=HandleKeepOnline(captured);
	    have1620CODE=1;
	    DPRINTF("[0x32] Client: ProcessEapHW  --> hb-pro is set.\n");
	}

****** 关于patch文件夹 ******
可以用如下命令打包：
$(CC) -c des.c handleDES.c
ar rcs libPatch.a des.o handleDES.o
