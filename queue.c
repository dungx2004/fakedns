#include <stdlib.h>
#include "queue.h"
#include "query.h"


queue_t *queue_init() {
	queue_t *q = (queue_t *)malloc(sizeof(queue_t));
	if (!q) {
		return NULL;
	}
	q->head = NULL;
	q->tail = NULL;
	q->size = 0;
	if (pthread_mutex_init(&(q->mutex), NULL) != 0) {
		free(q);
		return NULL;
	}
	return q;
}

int queue_push(queue_t *q, struct dns_query *query) {
	pthread_mutex_lock(&(q->mutex));
	node_t *new = (node_t *)malloc(sizeof(node_t));
	if (!new) {
		pthread_mutex_unlock(&(q->mutex));
		return -1;
	}
	new->query = query;
	new->next = NULL;

	if (q->size == 0) {
		q->head = new;
		q->tail = new;
	} else {
		q->tail->next = new;
		q->tail = new;
	}
	q->size++;
	pthread_mutex_unlock(&(q->mutex));
	return 0;
}

struct dns_query *queue_pop(queue_t *q) {
	pthread_mutex_lock(&(q->mutex));
	if (q->head == NULL) {
		pthread_mutex_unlock(&(q->mutex));
		return NULL;
	}
	node_t *temp = q->head;
	q->head = q->head->next;

	if (q->head == NULL) {
		q->tail = NULL;
	}

	struct dns_query *query = temp->query;
	free(temp);
	q->size--;
	pthread_mutex_unlock(&(q->mutex));
	return query;
}

void queue_free(queue_t *q) {
	while (q->size > 0) {
		free(q->head->query);
		queue_pop(q);
	}
	free(q);
}
