#ifndef TCP_H
#define TCP_H

#include "net.h"

// TCPHeader
// ~~~
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |          Source Port          |       Destination Port        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                        Sequence Number                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Acknowledgment Number                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Data |           |U|A|P|R|S|F|                               |
//  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//  |       |           |G|K|H|T|N|N|                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Checksum            |         Urgent Pointer        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Options                    |    Padding    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             data                              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// ~~~
#pragma pack(1)
typedef struct tcp_hdr {
  uint16_t src_port16; // 源端口
  uint16_t dst_port16; // 目标端口
  uint32_t seqno;      // sequence number
  uint32_t ackno;      // ack number
  uint8_t doff;        // data offset, 4 bits + 4 reserve
                // 指向TCP报文数据起始位，默认值： (TCP_HEADER_LEN / 4) << 4
  uint8_t flags;
  uint16_t win;        // window size
  uint16_t checksum16; // 校验和
  uint16_t uptr;       // urgent pointer
} tcp_hdr_t;

typedef struct tcp_peso_hdr {
  uint8_t src_ip[4];    // 源IP地址
  uint8_t dst_ip[4];    // 目的IP地址
  uint8_t placeholder;  // 必须置0,用于填充对齐
  uint8_t protocol;     // 协议号
  uint16_t total_len16; // 整个数据包的长度
} tcp_peso_hdr_t;
#pragma pack()

#define TCP_HEADER_LEN 20
#define FLAG_ACK (0x10) /* 0b0001'0000 */
#define FLAG_SYN (0x02) /* 0b0000'0010 */
#define FLAG_FIN (0x01) /* 0b0000'0001 */

typedef void (*tcp_handler_t)(uint8_t *data, size_t len, uint8_t *src_ip,
                              uint16_t src_port);

void tcp_init();
void tcp_in(buf_t *buf, uint8_t *src_ip);
void tcp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip,
              uint16_t dst_port);
int tcp_open(uint16_t port, tcp_handler_t handler);
void tcp_close(uint16_t port);
#endif