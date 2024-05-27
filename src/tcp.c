#include "tcp.h"
#include "icmp.h"
#include "ip.h"
#include <assert.h>

map_t tcp_table;

int window_size = 4;   // 发送窗口
int syn_receive = 0;   // 标识是否已经收到 syn 信号
int syn_send = 0;      // 标识是否已经发送 syn 信号
int fin_receive = 0;   // 标识是否已经收到 fin 信号
int fin_send = 0;      // 标识是否已经发送 fin 信号
int should_ack = 0;    // 标记己方是否需要 ack
uint32_t seq = 0;      // 当前序列号
uint32_t ack = 0;      // 当前要发的 ACK
uint32_t peer_seq = 0; // 对方序列号
uint32_t peer_ack = 0; // 对方发来的 ACK


/**
 * @brief 重置 tcp 连接
 */
void tcp_rst() {
  window_size = 4;
  syn_receive = 0;
  syn_send = 0;
  fin_receive = 0;
  fin_send = 0;
  should_ack = false;
}

/**
 * @brief tcp伪校验和计算
 *
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t tcp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip) {
  uint16_t length = buf->len;

  buf_add_header(buf, sizeof(tcp_peso_hdr_t));
  tcp_peso_hdr_t ip_hdr;
  memcpy(&ip_hdr, buf->data, sizeof(tcp_peso_hdr_t));

  tcp_peso_hdr_t *peso_hdr = (tcp_peso_hdr_t *)buf->data;
  memcpy(peso_hdr->src_ip, src_ip, NET_IP_LEN * sizeof(uint8_t));
  memcpy(peso_hdr->dst_ip, dst_ip, NET_IP_LEN * sizeof(uint8_t));
  peso_hdr->placeholder = 0;
  peso_hdr->protocol = NET_PROTOCOL_TCP;
  peso_hdr->total_len16 = swap16(length);

  uint16_t res = checksum16((uint16_t *)(buf->data), buf->len);
  memcpy(buf->data, &ip_hdr, sizeof(tcp_peso_hdr_t));
  buf_remove_header(buf, sizeof(tcp_peso_hdr_t));
  return res;
}

/**
 * @brief 发送 tcp 报文
 *
 * @param data  要发送的数据
 * @param len   数据长度
 * @param src_port 源端口
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口
 */
void tcp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip,
              uint16_t dst_port) {
  if (!should_ack && !len)
    return;
  buf_t buf;
  buf_init(&buf, len);
  memcpy(buf.data, data, len);
  buf_add_header(&buf, sizeof(tcp_hdr_t));
  tcp_hdr_t *hdr = (tcp_hdr_t *)buf.data;
  hdr->flags = 0;
  hdr->doff = ((TCP_HEADER_LEN / 4) << 4);
  hdr->src_port16 = swap16(src_port);
  hdr->dst_port16 = swap16(dst_port);

  // 还没开始链接，发送
  assert(syn_receive);
  if (!syn_send) {
    hdr->flags = (hdr->flags | FLAG_SYN);
    syn_send = true;
  }
  hdr->seqno = swap32(seq);
  seq += len; // TODO

  // 如果要发送 ACK 则发送（顺带 ACK ）
  if (should_ack) {
    hdr->flags = (hdr->flags | FLAG_ACK);
    hdr->ackno = swap32(ack);
    should_ack = false;
  }
  hdr->win = swap16(window_size);

  // 对方链接关闭
  if (fin_receive) {
    hdr->flags = (hdr->flags | FLAG_FIN);
    fin_send = true;
  }

  // 校验和
  hdr->checksum16 = 0;
  hdr->checksum16 = swap16(tcp_checksum(&buf, net_if_ip, dst_ip));

  // 发送数据
  ip_out(&buf, dst_ip, NET_PROTOCOL_TCP);
}

/**
 * @brief 处理一个收到的 tcp 数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void tcp_in(buf_t *buf, uint8_t *src_ip) {
  if (buf->len < sizeof(tcp_hdr_t)) {
    return;
  }

  tcp_hdr_t *hdr = (tcp_hdr_t *)buf->data;
  int head_len = (hdr->doff >> 4) * 4;

  // 还没开始链接，则收到链接报文时做出处理，否则直接返回
  if (!syn_receive && !(hdr->flags & FLAG_SYN))
    return;

  // 校验checksum
  uint16_t checksum16_old = hdr->checksum16;
  hdr->checksum16 = 0;
  uint16_t checksum16_new = swap16(tcp_checksum(buf, src_ip, net_if_ip));
  if (0 != memcmp(&checksum16_old, &checksum16_new, sizeof(uint16_t))) {
    return;
  }
  hdr->checksum16 = checksum16_old;

  // 收到链接报文
  if (hdr->flags & FLAG_SYN) {
    fin_receive = false;
    syn_receive = true;
  }

  // 收到终止报文
  if (hdr->flags & FLAG_FIN) {
    fin_receive = true;
  }

  // 收到终止报文确认 TODO
  if (fin_send && fin_receive && (hdr->flags & FLAG_ACK)) {
    tcp_rst();
    return;
  }

  // 更新 ack TODO
  peer_seq = swap32(hdr->seqno);
  if (hdr->flags & FLAG_ACK) {
    peer_ack = swap32(hdr->ackno);
  }
  if (buf->len > head_len ||
      ((hdr->flags & FLAG_FIN) || (hdr->flags & FLAG_SYN))) {
    ack = swap32(hdr->seqno) + ((hdr->flags & FLAG_FIN) ? 1 : 0) +
          ((hdr->flags & FLAG_SYN) ? 1 : 0) + buf->len - head_len;
    should_ack = true;
  }

  // 更新 window size
  if (swap16(hdr->win) < 4)
    window_size = swap16(hdr->win);
  else
    window_size = 4;

  // 递交数据到上层
  // 由 tcp_send 发送回复 SYN 报文。此处是偷懒 trick ，因为我们知道 handler
  // 会立刻调用 tcp_send ，所以无需进行额外的 ACK
  uint16_t dst_port16 = swap16(hdr->dst_port16);
  uint16_t src_port16 = swap16(hdr->src_port16);

  tcp_handler_t *handler = map_get(&tcp_table, &dst_port16);
  if (handler == NULL) {
    buf_add_header(buf, sizeof(ip_hdr_t));
    icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
  } else {
    buf_remove_header(buf, head_len);
    (*handler)(buf->data, buf->len, src_ip, src_port16);
  }
}

/**
 * @brief 打开一个 tcp 端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int tcp_open(uint16_t port, tcp_handler_t handler) {
  return map_set(&tcp_table, &port, &handler);
}

/**
 * @brief 关闭一个 tcp 端口
 *
 * @param port 端口号
 */
void tcp_close(uint16_t port) { map_delete(&tcp_table, &port); }

/**
 * @brief 初始化 tcp 协议
 *
 */
void tcp_init() {
  map_init(&tcp_table, sizeof(uint16_t), sizeof(tcp_handler_t), 0, 0, NULL);
  net_add_protocol(NET_PROTOCOL_TCP, tcp_in);
  tcp_rst();
}