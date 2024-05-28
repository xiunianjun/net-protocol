#include "tcp.h"
#include "icmp.h"
#include "ip.h"
#include <assert.h>

map_t tcp_table;

queue outstream;

int is_end = 0;        // 当前连接是否结束
int is_server = 0;     // 主机是 server 吗？
int window_size = 4;   // 发送窗口
int syn_receive = 0;   // 标识是否已经收到 syn 信号
int syn_send = 0;      // 标识是否已经发送 syn 信号
int fin_receive = 0;   // 标识是否已经收到 fin 信号
int fin_send = 0;      // 标识是否已经发送 fin 信号
int should_ack = 0;    // 标记己方是否需要 ack
uint32_t seq = 0;      // 当前序列号
uint32_t ackno = 0;    // 当前要发的 ACK
uint32_t peer_seq = 0; // 对方序列号
uint32_t peer_ack = 0; // 对方发来的 ACK
int retrans_time_cnt_on = 0;// 记录是否进行超时统计
time_t start = 0;  // 当前帧发送出去的时间
buf_t restrans_sent_data;

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
void tcp_out(buf_t *buf, int len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port,
             int syn, int fin, int ack) {
  buf_add_header(buf, sizeof(tcp_hdr_t));
  tcp_hdr_t *hdr = (tcp_hdr_t *)buf->data;
  hdr->flags = 0;
  hdr->doff = ((TCP_HEADER_LEN / 4) << 4);
  hdr->src_port16 = swap16(src_port);
  hdr->dst_port16 = swap16(dst_port);
  hdr->seqno = swap32(seq);

  seq += len;

  // 还没开始链接，发送
  if (syn) {
    seq ++;
    hdr->flags = (hdr->flags | FLAG_SYN);
  }

  // 如果要发送 ACK 则发送（顺带 ACK ）
  if (ack) {
    hdr->flags = (hdr->flags | FLAG_ACK);
    hdr->ackno = swap32(ackno);
  }
  hdr->win = swap16(window_size);

  // 对方链接关闭
  if (fin) {
    seq ++;
    hdr->flags = (hdr->flags | FLAG_FIN);
  }


  // 校验和
  hdr->checksum16 = 0;
  hdr->checksum16 = swap16(tcp_checksum(buf, net_if_ip, dst_ip));

  if (!retrans_time_cnt_on && (syn || fin || buf->len - TCP_HEADER_LEN > 0)) {  // 不对 ACK 进行重传
    buf_init(&restrans_sent_data, buf->len);
    memcpy(restrans_sent_data.data, buf->data, buf->len);
    tcp_hdr_t* tmp_hdr = (tcp_hdr_t*)(buf->data);
    retrans_time_cnt_on = 1;
    start = time(NULL);
  }

  // 发送数据
  ip_out(buf, dst_ip, NET_PROTOCOL_TCP);
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
  int syn = 0, fin = 0, ack = 0;
  buf_t buf;
  buf_init(&buf, len);
  if (data)
    memcpy(buf.data, data, len);

  // 还没开始链接，发送
  if (!syn_receive && !syn_send && !is_server && !is_end) {
    syn = 1;
    syn_send = true;
    is_end = false;
  }

  if (!syn_send && syn_receive && is_server) {
    syn = 1;
    syn_send = true;
    is_end = false;
  }

  // 如果要发送 ACK 则发送（顺带 ACK ）
  ack = should_ack;
  should_ack = false;

  // 对方链接关闭
  if (fin_receive && !fin_send) {
    fin = 1;
    fin_send = true;
  }

  if (!fin && !syn && !len && !ack)
    return;
  tcp_out(&buf, len, src_port, dst_ip, dst_port, syn, fin, ack);
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

  peer_seq = swap32(hdr->seqno);
  // if (syn_send && syn_receive && peer_seq != ackno)
  //   return; // 未收到顺序包，丢弃。一个简单的保证接收方可靠传输的 solution

  if (hdr->flags & FLAG_ACK) {
    peer_ack = swap32(hdr->ackno);
    // printf("%d, %d, %d, %d\n", seq, peer_seq, ackno, peer_ack);
    // if (seq != peer_ack - 1)  return; // 简单地保障当前帧先被传出去再发下一个，从而简单地实现超时重传
    should_ack = false;
  }

  retrans_time_cnt_on = 0;

  // 收到链接报文
  if (hdr->flags & FLAG_SYN) {
    fin_receive = false;
    syn_receive = true;
    is_end = false;
    should_ack = true;
  }

  // 收到终止报文
  if (hdr->flags & FLAG_FIN) {
    fin_receive = true;
    should_ack = true;
  }

  // 收到终止报文确认
  if (fin_send && fin_receive && (hdr->flags & FLAG_ACK)) {
    tcp_rst();
    is_end = true;
  }

  // 更新 ack TODO
  if (buf->len > head_len ||
      ((hdr->flags & FLAG_FIN) || (hdr->flags & FLAG_SYN))) {
    ackno = peer_seq + ((hdr->flags & FLAG_FIN) ? 1 : 0) +
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

  if ((fin_receive || fin_send || is_end || (syn_receive && !syn_send) ||
       (!syn_receive && !syn_send))) {
    // send syn/fin/empty ack, without data
    tcp_send(NULL, 0, dst_port16, src_ip, src_port16);
    return;
  }

  // fill window
  uint8_t new_data[QUEUE_MAX_SIZE];
  int ori_size = (outstream.size > window_size ? window_size : outstream.size);
  for (int i = 0; i < ori_size; ++i) {
    new_data[i] = queue_front(&outstream);
    queue_pop(&outstream);
  }
  if (ori_size > 0) should_ack = true;
  tcp_send(new_data, ori_size, dst_port16, src_ip, src_port16);
}

void tcp_tick() {  // 由 net class 周期性调用
  if (!retrans_time_cnt_on) return;
  time_t cur_time = time(NULL);
  if (cur_time - start >= RETRANSMISSON_TIMEOUT) {
    uint8_t dst_ip[NET_IP_LEN] = {10, 250, 196, 1};
    tcp_hdr_t* tmp_hdr = (tcp_hdr_t*)(restrans_sent_data.data);
    buf_t retrans_tmp_buf;
    buf_init(&retrans_tmp_buf, restrans_sent_data.len);
    memcpy(retrans_tmp_buf.data, restrans_sent_data.data, restrans_sent_data.len);
    ip_out(&retrans_tmp_buf, dst_ip, NET_PROTOCOL_TCP);
    start = cur_time;
  }
}

/**
 * @brief tcp client 发送连接请求
 *
 * @param port 目标端口号
 * @param dst_ip 目标ip地址
 */
void tcp_connect(uint16_t port, uint8_t *dst_ip) {
  printf("connect!\n");
  tcp_send(NULL, 0, 60000, dst_ip, port);
}

/**
 * @brief 打开一个 tcp 端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @param server 当前主机是服务器吗？
 * @return int 成功为0，失败为-1
 */
int tcp_open(uint16_t port, tcp_handler_t handler, int server) {
  is_server = server;
  return map_set(&tcp_table, &port, &handler);
}

/**
 * @brief 查询 tcp 连接是否已经关闭
 *
 * @return 1表示已经关闭，0表示没有关闭
 */
int tcp_is_closed() { return is_end; }

/**
 * @brief 关闭一个 tcp 端口
 *
 * @param port 目标端口号
 * @param dst_ip 目标 ip 地址
 */
void tcp_close(uint16_t port, uint8_t *dst_ip) {
  buf_t buf;
  buf_init(&buf, 0);
  tcp_out(&buf, 0, 60000, dst_ip, port, 0, 1, 1);
  fin_send = true;
}

/**
 * @brief 初始化 tcp 协议
 *
 */
void tcp_init() {
  map_init(&tcp_table, sizeof(uint16_t), sizeof(tcp_handler_t), 0, 0, NULL);
  net_add_protocol(NET_PROTOCOL_TCP, tcp_in);
  queue_init(&outstream);
  tcp_rst();
}