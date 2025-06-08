#ifndef CAPTURE_H
#define CAPTURE_H

#include <libnet.h>
#include "queue.h"
#include "config.h"

struct capture_response_args {
	struct config *conf;
	queue_t *queue;
};

int capture_response(struct capture_response_args *args);

#endif
