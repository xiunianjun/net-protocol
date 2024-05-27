#include "ip.h"
#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

#define MFU_SIZE 1500

uint16_t id16 = 0; // xn: 当前ip报文所有分片发出去了之后，才能增加

typedef struct {
  uint16_t offset; // 该分片的 offset
  uint8_t *data;   // 该分片的 data
  uint16_t len;    // 该分片数据部分的长度
} do_pair;

typedef struct {
  do_pair bufs[IP_MAX_FRAGMENT]; // 对应 IP 报文的所有分片 buf
  int cnt;                       // 该 IP 报文当前已接收的分片总数
  int tot_size;                  // 该 IP 报文当前已接收的总大小
  int is_over; // 是否已经接收到该 IP 报文的 MF == 0  的分片
} fragment_value;

// for qsort
int compare_do_pair(const void *a, const void *b) {
  const do_pair *pair_a = (const do_pair *)a;
  const do_pair *pair_b = (const do_pair *)b;

  if (pair_a->offset < pair_b->offset)
    return -1;
  if (pair_a->offset > pair_b->offset)
    return 1;
  return 0;
}

map_t fragment_table; // <ip id, fragment_value> ，同一 ip 报文的分片 id 相同

// foreach handler
void fragtable_entry_free(void *key, void *value, time_t *timestamp) {
  if (*timestamp + fragment_table.timeout < time(NULL)) {
    // 超时，释放内存
    fragment_value *fv = (fragment_value *)value;
    for (int i = 0; i < fv->cnt; i++) {
      free(fv->bufs[i].data);
    }
  }
}

void ip_fragment_in(uint8_t *data, uint16_t len, uint16_t flags_fragment16,
                    uint16_t id, uint16_t protocol, uint8_t *src_ip) {
  // 获取 mf 和 offset
  int mf = ((flags_fragment16 & IP_MORE_FRAGMENT) != 0);
  uint16_t offset = flags_fragment16;
  if (mf)
    offset -= IP_MORE_FRAGMENT;
  offset *= 8;

  // 首先删除整个 fragment table 超时的表项，防止内存泄漏
  map_foreach(&fragment_table, fragtable_entry_free);

  // 查找驻留帧
  fragment_value *fv = map_get(&fragment_table, &id);
  if (!fv) { // 第一次收到该 id
    fragment_value new_fv;
    new_fv.is_over = false;
    new_fv.cnt = 0;
    new_fv.tot_size = 0;
    map_set(&fragment_table, &id, &new_fv);
    fv = map_get(&fragment_table, &id);
  }

  if (!mf) {
    fv->is_over = true; // 表明已经收到了结束帧。注意此处不能直接整理然后 net_in
                        // ，因为可能结束帧乱序到达
  }

  // 记录相关信息
  fv->bufs[fv->cnt].data = (uint8_t *)malloc(sizeof(uint8_t) * len);
  memcpy(fv->bufs[fv->cnt].data, data, len);
  fv->bufs[fv->cnt].offset = offset;
  fv->bufs[fv->cnt].len = len;
  fv->tot_size += len;
  fv->cnt += 1;

  if (fv->is_over) {
    // 这里简单粗暴直接排序了，感觉 IP 不用像 TCP 那么复杂需要考虑区间重合
    qsort(fv->bufs, fv->cnt, sizeof(do_pair), compare_do_pair);
    // 排序中 offset 最大的帧的右边界与累积接收到数据大小相等，并且已经收到 mf
    // 帧，说明接收完毕
    if (fv->bufs[fv->cnt - 1].offset + fv->bufs[fv->cnt - 1].len ==
        fv->tot_size) {
      // 全部接收完毕，传递给上层 UDP
      buf_t new_buf;
      buf_init(&new_buf, fv->tot_size);
      uint8_t *p = new_buf.data;
      for (int i = 0; i < fv->cnt; i++) {
        memcpy(p, fv->bufs[i].data, fv->bufs[i].len);
        p += fv->bufs[i].len;
        free(fv->bufs[i].data);
      }
      map_delete(&fragment_table, &id);
      net_in(&new_buf, protocol, src_ip);
    }
  }
}

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

  /* 一系列检查 */
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
  if (0 != memcmp(&hdr_checksum16_new, &hdr_checksum16_ori, sizeof(uint16_t)))
    return;
  ip_hdr.hdr_checksum16 = hdr_checksum16_ori;

  // 掐头去尾
  buf_remove_padding(buf, buf->len - swap16(ip_hdr.total_len16));
  net_protocol_t protocol = (net_protocol_t)(ip_hdr.protocol);
  if (protocol != NET_PROTOCOL_ICMP && protocol != NET_PROTOCOL_UDP &&
      protocol != NET_PROTOCOL_TCP) {
    icmp_unreachable(buf, ip_hdr.src_ip, ICMP_CODE_PROTOCOL_UNREACH);
  }
  buf_remove_header(buf, sizeof(ip_hdr_t));

  // 传入
  ip_fragment_in(buf->data, buf->len, swap16(ip_hdr.flags_fragment16),
                 swap16(ip_hdr.id16), protocol, ip_hdr.src_ip);
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
void ip_init() {
  map_init(&fragment_table, sizeof(uint16_t), sizeof(fragment_value), 0,
           IP_FRAGMENT_TIMEOUT_SEC, NULL);
  net_add_protocol(NET_PROTOCOL_IP, ip_in);
}