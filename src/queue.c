#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "queue.h"
#include "fakedns.h"


queue_t *queue_init() {
	queue_t *q = (queue_t *)malloc(sizeof(queue_t));
	if (!q) {
		return NULL;
	}
	q->head = NULL;
	q->tail = NULL;
	if (pthread_mutex_init(&(q->mutex), NULL) != 0) {
		free(q);
		return NULL;
	}
	return q;
}

void queue_push(queue_t *q, struct dns_query *query) {
	pthread_mutex_lock(&(q->mutex));
	node_t *new = (node_t *)malloc(sizeof(node_t));
	if (!new) {
		free(new);
		pthread_mutex_unlock(&(q->mutex));
		return;
	}
	new->query = *query;
	new->next = NULL;

	if (!q->head) {
		q->head = new;
		q->tail = new;
	} else {
		q->tail->next = new;
		q->tail = new;
	}

	pthread_mutex_unlock(&(q->mutex));
}

int queue_pop(queue_t *q, struct dns_query *query) {
	pthread_mutex_lock(&(q->mutex));
	if (!q->head) {
		pthread_mutex_unlock(&(q->mutex));
		return -1;
	}
	node_t *temp = q->head;
	q->head = q->head->next;

	if (!q->head) {
		q->tail = NULL;
	}

	if (query) {
		*query = temp->query;
	}

	free(temp);
	pthread_mutex_unlock(&(q->mutex));
	return 0;
}

void queue_free(queue_t *q) {
	while (q->head) {
		queue_pop(q, NULL);
	}
	pthread_mutex_destroy(&(q->mutex));
	free(q);
}
