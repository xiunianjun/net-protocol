#include "ip.h"
#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

#define MFU_SIZE 1500

uint16_t id16 = 0; // xn: 当前ip报文所有分片发出去了之后，才能增加

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
  if (buf->len < sizeof(ip_hdr_t)) {
    return;
  }

  ip_hdr_t ip_hdr;
  memcpy(&ip_hdr, buf->data, sizeof(ip_hdr_t));

  if (ip_hdr.version != IP_VERSION_4 || swap16(ip_hdr.total_len16) > buf->len) {
    return;
  }

  if (0 != memcmp(ip_hdr.dst_ip, net_if_ip, NET_IP_LEN * sizeof(uint8_t))) {
    return; // 不是本机地址则丢弃不处理
  }

  // 检查校验和是否一致
  uint16_t hdr_checksum16_ori = ip_hdr.hdr_checksum16;
  ip_hdr.hdr_checksum16 = 0;
  uint16_t hdr_checksum16_new =
      swap16(checksum16((uint16_t *)(&ip_hdr), sizeof(ip_hdr_t)));
  if (0 != memcmp(&hdr_checksum16_new, &hdr_checksum16_ori, sizeof(uint16_t))) {
    return;
  }
  ip_hdr.hdr_checksum16 = hdr_checksum16_ori;

  buf_remove_padding(buf, buf->len - swap16(ip_hdr.total_len16));

  net_protocol_t protocol = (net_protocol_t)(ip_hdr.protocol);
  if (protocol != NET_PROTOCOL_ICMP && protocol != NET_PROTOCOL_UDP) {
    icmp_unreachable(buf, ip_hdr.src_ip, ICMP_CODE_PROTOCOL_UNREACH);
  }

  buf_remove_header(buf, sizeof(ip_hdr_t));

  net_in(buf, protocol, ip_hdr.src_ip);
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id,
                     uint16_t offset, int mf) {
  buf_add_header(buf, sizeof(ip_hdr_t));
  ip_hdr_t *hdr = (ip_hdr_t *)buf->data;

  hdr->hdr_len = (sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE);
  hdr->version = IP_VERSION_4;
  hdr->tos = 0;
  hdr->total_len16 = swap16((uint16_t)(buf->len));
  hdr->id16 = swap16((uint16_t)(id16));

  offset /= 8;
  hdr->flags_fragment16 = swap16(mf | offset);
  hdr->ttl = IP_DEFALUT_TTL;
  hdr->protocol = protocol;
  memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN * sizeof(uint8_t));
  memcpy(hdr->dst_ip, ip, NET_IP_LEN * sizeof(uint8_t));

  hdr->hdr_checksum16 = 0;
  hdr->hdr_checksum16 = swap16(checksum16((uint16_t *)hdr, sizeof(ip_hdr_t)));

  arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
  // 分片为 MTU - 头部大小
  int slice = MFU_SIZE - sizeof(ip_hdr_t) / sizeof(uint8_t);

  if (buf->len <= slice) { // 数据包过小，无需分片
    ip_fragment_out(buf, ip, protocol, 0, 0, 0);
    id16++;
    return;
  }

  // 分片处理
  int n = buf->len / slice;
  for (int i = 0; i <= n - 1; i++) {
    buf_t ip_buf;
    buf_init(&ip_buf, slice * sizeof(uint8_t));
    memcpy(ip_buf.data, buf->data + i * slice, slice * sizeof(uint8_t));
    if (__builtin_expect((i == n - 1 && n * slice == buf->len),
                         0)) { // buf->len被slice整除时标记MF
      ip_fragment_out(&ip_buf, ip, protocol, i, i * slice, 0);
      return;
    }
    ip_fragment_out(&ip_buf, ip, protocol, i, i * slice, IP_MORE_FRAGMENT);
  }

  // 处理buf->len不被slice整除时的最后剩的一点尾巴
  buf_t ip_buf;
  buf_init(&ip_buf, (buf->len - n * slice) * sizeof(uint8_t));
  memcpy(ip_buf.data, buf->data + n * slice,
         (buf->len - n * slice) * sizeof(uint8_t));
  ip_fragment_out(&ip_buf, ip, protocol, n, n * slice, 0);

  id16++; // 当前ip报文所有分片发送完毕
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() { net_add_protocol(NET_PROTOCOL_IP, ip_in); }