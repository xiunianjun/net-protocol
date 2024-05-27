#include "driver.h"
#include "icmp.h"
#include "net.h"
#include "tcp.h"
#include "udp.h"
#include <stdlib.h>

#ifdef UDP
void handler(uint8_t *data, size_t len, uint8_t *src_ip, uint16_t src_port) {
  printf("recv udp packet from %s:%u len=%zu\n", iptos(src_ip), src_port, len);
  for (int i = 0; i < len; i++)
    putchar(data[i]);
  putchar('\n');
  printf("there is %ld as\n", len);
  udp_send(data, len, 60000, src_ip, 60000); //发送udp包
  // uint8_t new_data[1600];
  // memcpy(new_data, data, sizeof(uint8_t) * len);
  // for (size_t i = len; i < sizeof(new_data); ++i) {
  //   new_data[i] = 'a'; // 'a' 的 ASCII 码是 97
  // }
  // // uint8_t sender_ip[NET_IP_LEN] = NET_IF_IP;
  // udp_send(new_data, 1600, 60000, src_ip, 60000); //发送udp包
}

void udp_listen() {
  udp_open(60000, handler); // 注册端口的udp监听回调
  while (1) {
    net_poll(); // 一次主循环
  }
}
#endif

#ifdef TCP
int handle_times = 0;
void tcp_handler(uint8_t *data, size_t len, uint8_t *src_ip,
                 uint16_t src_port) {
  handle_times++;
  for (int i = 0; i < len; i++)
    putchar(data[i]);
  if (len)
    putchar('\n');
  fflush(stdout);
  char *str = "hi";
  str[0] += handle_times;
  for (int i = 0; i < strlen(str); i++) {
    queue_push(&outstream, (uint8_t)(str[i]));
  }
}

void tcp_server() {
  printf("tcp server!\n");
  tcp_open(60000, tcp_handler, 1);
  while (1) {
    net_poll(); // 一次主循环
  }
  uint8_t dst_ip[NET_IP_LEN] = {10, 250, 196, 1};
  tcp_close(60000, dst_ip);
}

void tcp_client_handler(uint8_t *data, size_t len, uint8_t *src_ip,
                        uint16_t src_port) {
  handle_times++;
  for (int i = 0; i < len; i++)
    putchar(data[i]);
  if (len)
    putchar('\n');
  fflush(stdout);
  char *str = "hi";
  str[0] += handle_times;
  for (int i = 0; i < strlen(str); i ++) {
    queue_push(&outstream, (uint8_t)(str[i]));
  }
}

void tcp_client() {
  printf("tcp client!\n");
  uint8_t dst_ip[NET_IP_LEN] = {10, 250, 196, 1};
  tcp_open(60000, tcp_client_handler, 0);
  tcp_connect(60000, dst_ip);
  while (handle_times < 5) {
    net_poll();
  }
  printf("close connection.\n");
  tcp_close(60000, dst_ip);
  while (!(tcp_is_closed())) {
    net_poll();
  }
  printf("client exit.\n");
}
#endif

void ping() {
  uint8_t data[32] = {0};
  uint8_t dst_ip[4] = {10, 250, 196, 1};
  printf("Pinging baidu.com [%s] with 32 bytes of data:\n", iptos(dst_ip));

  /* for statistics */
  int recv_num = 0;
  int min_time = ICMP_TIMEOUT_TIME * 1000;
  int max_time = 0;
  double sum_time = 0;

  int ping_times = 0;
  int waiting_req_seq = -1;
  time_t last_request_time = time(NULL);

  while (ping_times < 4) {
    if (ping_times == 0 || time(NULL) - last_request_time >= 1) {
      waiting_req_seq = icmp_send_echo_request(data, 32, dst_ip);
      last_request_time = time(NULL);
      ++ping_times;
    }

    if (waiting_req_seq == -1)
      continue;

    int interval = 0;
    while (time(NULL) < last_request_time + ICMP_TIMEOUT_TIME) {
      net_poll(); // 一次主循环
      interval = icmp_wait_echo_reply(waiting_req_seq);
      if (interval != -1)
        break;
    }

    waiting_req_seq = -1;

    if (interval == -1) {
      printf("Request timed out.\n");
      continue;
    }

    printf("Reply from %s: bytes=32 time=%dms\n", iptos(dst_ip), interval);
    ++recv_num;
    if (min_time > interval)
      min_time = interval;
    if (max_time < interval)
      max_time = interval;
    sum_time += interval;
  }

  printf("Ping statistics for %s:\n", iptos(dst_ip));
  printf("\tPackets: Sent = 4, Received = %d, Lost = %d (%lf%% loss),\n",
         recv_num, 4 - recv_num, (double)(4 - recv_num) / 4);
  printf("Approximate round trip times in milli-seconds:\n");
  printf("\tMinimum = %dms, Maximum = %dms, Average = %fms\n", min_time,
         max_time, sum_time / recv_num);
}

int main(int argc, char const *argv[]) {

  if (net_init() == -1) //初始化协议栈
  {
    printf("net init failed.");
    return -1;
  }

  int op_code = 0;
  if (argc >= 2)
    op_code = atoi(argv[1]);

  switch (op_code) {
  case 0:
#ifdef UDP
    udp_listen();
    break;
#else
    printf("not define UDP!\n");
    return -1;
#endif
  case 1:
    ping();
    break;
  case 2:
    tcp_server();
    break;
  case 3:
    tcp_client();
    break;
  default:
    break;
  }

  return 0;
}
