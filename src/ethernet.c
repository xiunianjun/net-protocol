#include "ethernet.h"
#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
  if (buf->len < sizeof(ether_hdr_t)) {
    printf("ethernet_in: The packet is too short. Desert.\n");
    return;
  }

  // 获取buf的以太网帧头部信息
  ether_hdr_t head;
  memcpy(&head, buf->data, sizeof(ether_hdr_t));

  // 去掉以太网帧头部
  if (buf_remove_header(buf, sizeof(ether_hdr_t)) < 0) {
    printf("ethernet_in: Error removing header.\n");
    return;
  }

  // 向上层传递
  net_in(buf, swap16(head.protocol16), head.src);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
  // 当数据包过小时，需要填充 padding
  if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
    buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
  }

  // 把上述修改协议头添加到buf中
  buf_add_header(buf, sizeof(ether_hdr_t));
  ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

  // 填入目的MAC地址
  memcpy(hdr->dst, mac, NET_MAC_LEN * sizeof(uint8_t));
  // 填入源MAC地址
  uint8_t src_mac[] = NET_IF_MAC;
  memcpy(hdr->src, src_mac, sizeof(src_mac));
  // 填入目的协议
  hdr->protocol16 = swap16(protocol);

  driver_send(buf);
  // printf(res < 0 ? "Error sending ethernet packet\n"
  //                             : "Success sending ethernet packet\n");
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
  buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
  if (driver_recv(&rxbuf) > 0)
    ethernet_in(&rxbuf);
}