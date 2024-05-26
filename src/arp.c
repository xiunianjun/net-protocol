#include "arp.h"
#include "ethernet.h"
#include "net.h"
#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
// xn: 很有意思的设计，简化了很多操作
static const arp_pkt_t arp_init_pkt = {.hw_type16 = swap16(ARP_HW_ETHER),
                                       .pro_type16 = swap16(NET_PROTOCOL_IP),
                                       .hw_len = NET_MAC_LEN,
                                       .pro_len = NET_IP_LEN,
                                       .sender_ip = NET_IF_IP,
                                       .sender_mac = NET_IF_MAC,
                                       .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip, mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip, buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
  printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
  printf("===ARP TABLE BEGIN===\n");
  map_foreach(&arp_table, arp_entry_print);
  printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
  buf_t arp_buf;
  buf_init(&arp_buf, sizeof(arp_pkt_t));

  arp_pkt_t *arp = (arp_pkt_t *)arp_buf.data;
  memcpy(arp, &arp_init_pkt, sizeof(arp_pkt_t));
  uint16_t opcode = ARP_REQUEST;
  opcode = swap16(opcode);
  memcpy(&(arp->opcode16), &opcode, sizeof(uint16_t));
  memcpy(arp->target_ip, target_ip, arp_init_pkt.pro_len * sizeof(uint8_t));

  // 广播地址发送 ARP 请求
  ethernet_out(&arp_buf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
  buf_t arp_buf;
  buf_init(&arp_buf, sizeof(arp_pkt_t));

  arp_pkt_t *arp = (arp_pkt_t *)arp_buf.data;
  memcpy(arp, &arp_init_pkt, sizeof(arp_pkt_t));
  uint16_t opcode = ARP_REPLY;
  opcode = swap16(opcode);
  memcpy(&(arp->opcode16), &opcode, sizeof(uint16_t));
  memcpy(arp->target_ip, target_ip, arp_init_pkt.pro_len * sizeof(uint8_t));
  memcpy(arp->target_mac, target_mac, arp_init_pkt.hw_len * sizeof(uint8_t));

  ethernet_out(&arp_buf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
  if (buf->len < sizeof(arp_pkt_t)) {
    return;
  }

  arp_pkt_t p;
  memcpy(&p, buf->data, sizeof(arp_pkt_t));

  // 报头检查
  if (p.hw_type16 != arp_init_pkt.hw_type16 ||
      p.pro_type16 != arp_init_pkt.pro_type16 ||
      p.hw_len != arp_init_pkt.hw_len || p.pro_len != arp_init_pkt.pro_len ||
      (p.opcode16 != swap16(ARP_REQUEST) && p.opcode16 != swap16(ARP_REPLY))) {
    return;
  }

  map_set(&arp_table, p.sender_ip, p.sender_mac); // 记录下发送方对应的映射

  /*
    xn: 我这里没有完全按照指导书中的逻辑：
    如果该接收报文的IP地址没有对应的arp_buf缓存，才需要判断接收到的报文是否为ARP_REQUEST请求报文。
    因为我本来觉得有可能出现一种情况，即己方有数据要传输的同时，对方主机发来的又是arp
    request。 不过似乎这种情况不会发生，毕竟如果对方发来arp
    request说明对方需要发数据给自己。 ① 自己为client端
    server不会主动建立连接，所以这时候肯定是server要对自己发过的数据进行回复，那么
    既然自己都发过了，就不可能会还有驻留数据。。。
    ② 自己为server端 差不多同理①，server不会主动传输数据，所以对方肯定已经发过了
    故而有驻留数据的情况和需要response的情况不可能同时发生。
  */
  if (p.opcode16 == swap16(ARP_REQUEST)) { // 如果是 ARP Request
    if (0 == memcmp(p.target_ip, arp_init_pkt.sender_ip,
                    NET_IP_LEN * sizeof(uint8_t))) {
      arp_resp(p.sender_ip, p.sender_mac);
    }
  }

  // 查询该新 ip 地址是否有驻留缓存
  buf_t *sendBuf = map_get(&arp_buf, p.sender_ip);
  if (sendBuf) { // 发送驻留帧
    ethernet_out(sendBuf, p.sender_mac, NET_PROTOCOL_IP);
    map_delete(&arp_buf, p.sender_ip);
  }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
  uint8_t *mac = map_get(&arp_table, ip);
  if (mac) {
    ethernet_out(buf, mac, NET_PROTOCOL_IP);
    return;
  }

  buf_t *p = map_get(&arp_buf, ip);
  if (p)
    return; // 直接丢弃

  map_set(&arp_buf, ip, buf);
  arp_req(ip);
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
  map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
  map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
  net_add_protocol(NET_PROTOCOL_ARP, arp_in);
  arp_req(net_if_ip);
}