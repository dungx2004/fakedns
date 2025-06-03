#ifndef CAPTURE_H
#define CAPTURE_H

#include <libnet.h>
#include "queue.h"
#include "config.h"

struct capture_response_args {
	struct config *conf;
	queue_t *queue;
};

struct packet_handler_args {
	struct config_qname *blacklist;
	queue_t *queue;
	libnet_t *libnet;
	unsigned char *answer_rr;
	struct dns_query *query;
};

int capture_response(struct capture_response_args *args);

#endif
