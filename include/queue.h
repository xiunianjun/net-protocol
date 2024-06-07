#ifndef QUEUE_H
#define QUEUE_H

#include "net.h"

#define QUEUE_MAX_SIZE 1024

typedef struct queue {
  int size;
  int front; // 队列首
  int rear;  // 队列末
  uint8_t queue[QUEUE_MAX_SIZE];
} queue;

void queue_push(queue *que, uint8_t c);
void print(queue *que);
uint8_t queue_front(queue *que);
void queue_pop(queue *que);
void queue_init(queue *que);
#endif