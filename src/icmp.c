#include "icmp.h"
#include "ip.h"
#include "net.h"

uint16_t seq_id = 0;

map_t icmp_table; // <seq id, icmp_echo_info>

typedef struct {
  struct timeval start; // ICMP 请求开始时间
  int interval;         // ICMP 请求收到回信之间的时间间隔
} icmp_echo_info;

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
  buf_init(&txbuf, req_buf->len);
  memcpy(txbuf.data, req_buf->data, req_buf->len);

  icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
  hdr->type = ICMP_TYPE_ECHO_REPLY;
  hdr->code = 0;

  hdr->checksum16 = 0;
  // 校验和涵盖整个报文
  uint16_t checksum16_new =
      swap16(checksum16((uint16_t *)(txbuf.data), txbuf.len));
  hdr->checksum16 = checksum16_new;

  ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
  // 不对差错报告报文再发送差错报告报文
  if (buf->len < sizeof(icmp_hdr_t)) {
    return;
  }

  icmp_hdr_t hdr;
  memcpy(&hdr, buf->data, sizeof(icmp_hdr_t));

  // 查看该报文的ICMP类型是否为回显请求（如 ping 应答）
  if (hdr.type == ICMP_TYPE_ECHO_REQUEST && hdr.code == 0) {
    icmp_resp(buf, src_ip);
  }

  // 计算 seq id 对应的 interval
  if (hdr.type == ICMP_TYPE_ECHO_REPLY && hdr.code == 0) {
    icmp_echo_info *res = (icmp_echo_info *)map_get(&icmp_table, &(hdr.seq16));
    struct timeval end;
    gettimeofday(&end, NULL);
    res->interval = ((end.tv_sec - res->start.tv_sec) * 1000 +
                     (end.tv_usec - res->start.tv_usec) / 1000.0) +
                    0.5;
  }

  // xn: 未实现错误处理。我猜如果要处理也是需要注册 handler 之类的结构
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
  buf_init(&txbuf, 0);
  buf_add_header(&txbuf, sizeof(ip_hdr_t) + sizeof(uint8_t) * 8);
  memcpy(txbuf.data, recv_buf->data, sizeof(ip_hdr_t) + sizeof(uint8_t) * 8);

  buf_add_header(&txbuf, sizeof(icmp_hdr_t));
  icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
  hdr->code = code;
  hdr->type = ICMP_TYPE_UNREACH;
  hdr->id16 = 0;
  hdr->seq16 = seq_id++;

  hdr->checksum16 = 0;
  uint16_t checksum16_new =
      swap16(checksum16((uint16_t *)(txbuf.data), txbuf.len));
  hdr->checksum16 = checksum16_new;

  ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 发送icmp回显请求
 *
 * @param data  要发送的数据
 * @param len   数据长度
 * @param dst_ip 目的地址
 * @return      该icmp请求编号
 */
int icmp_send_echo_request(uint8_t *data, uint16_t len, uint8_t *dst_ip) {
  buf_init(&txbuf, 0);
  buf_add_header(&txbuf, len);
  memcpy(txbuf.data, data, len);

  buf_add_header(&txbuf, sizeof(icmp_hdr_t));
  icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
  hdr->code = 0;
  hdr->type = ICMP_TYPE_ECHO_REQUEST;
  hdr->id16 = getpid();
  hdr->seq16 = seq_id++;

  hdr->checksum16 = 0;
  uint16_t checksum16_new =
      swap16(checksum16((uint16_t *)(txbuf.data), txbuf.len));
  hdr->checksum16 = checksum16_new;

  // 加入时间戳 map 中
  icmp_echo_info im;
  gettimeofday(&(im.start), NULL);
  im.interval = -1;
  map_set(&icmp_table, &(hdr->seq16), &im);

  ip_out(&txbuf, dst_ip, NET_PROTOCOL_ICMP);
  return seq_id - 1;
}

/**
 * @brief 等待icmp回显响应
 *
 * @param target_seq 要等待的icmp请求编号
 * @return 请求来回的时间间隔
 */
// xn: 其实这里将int封装为一个类似 icmp_msg
// 这样的消息结构会更加优雅，不过为了方便起见就这样吧
int icmp_wait_echo_reply(int target_seq) {
  icmp_echo_info *res = (icmp_echo_info *)map_get(&icmp_table, &(target_seq));
  return res->interval;
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
  map_init(&icmp_table, sizeof(uint16_t), sizeof(icmp_echo_info), 0,
           ICMP_TIMEOUT_TIME * 2, NULL);
  net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}