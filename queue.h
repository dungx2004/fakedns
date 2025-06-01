#ifndef QUEUE_H
#define QUEUE_H

#include "query.h"
#include <pthread.h>

typedef struct Node {
	struct dns_query *query;
	struct Node *next;
} node_t;

typedef struct Queue {
	node_t *head;
	node_t *tail;
	int size;
	pthread_mutex_t mutex;
} queue_t;

queue_t *queue_init();
int queue_push(queue_t *q, struct dns_query *query);
struct dns_query *queue_pop(queue_t *q);
void queue_free(queue_t *q);

#endif
