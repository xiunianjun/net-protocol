#include "tcp.h"

map_t tcp_table;

void tcp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip,
              uint16_t dst_port) {}

void tcp_in(buf_t *buf, uint8_t *src_ip) {}

void tcp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip,
             uint16_t dst_port) {}

int tcp_open(uint16_t port, tcp_handler_t handler) {
  return map_set(&tcp_table, &port, &handler);
}

void tcp_close(uint16_t port) { map_delete(&tcp_table, &port); }

void tcp_init() {
  map_init(&tcp_table, sizeof(uint16_t), sizeof(tcp_handler_t), 0, 0, NULL);
  net_add_protocol(NET_PROTOCOL_UDP, tcp_in);
}