#ifndef ICMP_H
#define ICMP_H

#include "net.h"
#include <sys/time.h> // for gettimeofday
#include <unistd.h>   // for getpid()

#pragma pack(1)
typedef struct icmp_hdr {
  uint8_t type;        // 类型
  uint8_t code;        // 代码
  uint16_t checksum16; // ICMP报文的校验和
  uint16_t id16;       // 标识符
  uint16_t seq16;      // 序号
} icmp_hdr_t;

#pragma pack()
typedef enum icmp_type {
  ICMP_TYPE_ECHO_REQUEST = 8, // 回显请求
  ICMP_TYPE_ECHO_REPLY = 0,   // 回显响应
  ICMP_TYPE_UNREACH = 3,      // 目的不可达
} icmp_type_t;

typedef enum icmp_code {
  ICMP_CODE_PROTOCOL_UNREACH = 2, // 协议不可达
  ICMP_CODE_PORT_UNREACH = 3      // 端口不可达
} icmp_code_t;

#define ICMP_TIMEOUT_TIME 5 // ICMP 请求超时时间， 5 seconds

int icmp_wait_echo_reply(int target_seq);
int icmp_send_echo_request(uint8_t *data, uint16_t len, uint8_t *dst_ip);
void icmp_in(buf_t *buf, uint8_t *src_ip);
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code);
void icmp_init();
#endif
