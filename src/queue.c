#include "queue.h"

void queue_push(queue *que, uint8_t c) {
  if (((que->rear + 1) % QUEUE_MAX_SIZE == que->front) ||
      (que->rear == QUEUE_MAX_SIZE - 2 && que->front == -1)) {
    printf("The queue is full!\n");
    return;
  }
  que->size++;
  que->rear = (que->rear + 1) % QUEUE_MAX_SIZE;
  que->queue[que->rear] = c;
}

void print(queue *que) {
  if (que->front < que->rear) {
    for (int i = que->front + 1; i <= que->rear; i++) {
      printf("%d ", que->queue[i]);
    }
  } else if (que->front >= que->rear) {
    for (int i = que->front + 1; i < QUEUE_MAX_SIZE; i++) {
      printf("%d ", que->queue[i]);
    }
    for (int i = 0; i <= que->rear; i++) {
      printf("%d ", que->queue[i]);
    }
  }
}

uint8_t queue_front(queue *que) { return que->queue[que->front]; }

void queue_pop(queue *que) {
  if (que->rear == que->front) {
    printf("The queue is empty!\n");
    return;
  }
  que->size--;
  que->front = (que->front + 1) % QUEUE_MAX_SIZE;
}

void queue_init(queue *que) {
  que->front = 0;
  que->rear = 0;
  que->size = 0;
}