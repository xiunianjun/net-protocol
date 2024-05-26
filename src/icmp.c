#include "icmp.h"
#include "ip.h"
#include "net.h"

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
  hdr->seq16 = 0;

  hdr->checksum16 = 0;
  uint16_t checksum16_new =
      swap16(checksum16((uint16_t *)(txbuf.data), txbuf.len));
  hdr->checksum16 = checksum16_new;

  ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() { net_add_protocol(NET_PROTOCOL_ICMP, icmp_in); }