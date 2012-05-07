#ifndef NJIT8021XCLIENT_H
#define NJIT8021XCLIENT_H

// 自定义常量
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3C_DATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, H3C_HEARTBEAT=20} EAP_Type;
typedef uint8_t EAP_ID;
const uint8_t BroadcastAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址
const char H3C_VERSION[16]="EN V2.40-0335"; // 华为客户端版本号
const char H3C_KEY[]      ="HuaWei3COM1X";  // H3C的固定密钥

#endif//NJIT8021XCLIENT_H
