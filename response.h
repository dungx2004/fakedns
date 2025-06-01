#ifndef RESPONSE_H
#define RESPONSE_H

#include "fakedns.h"
#include "queue.h"

struct response_args {
	char *interface;
	queue_t *capture_response;
	queue_t *response_writelog;
	struct config_qname *blacklist;
};

int response(struct response_args *arg);

#endif
