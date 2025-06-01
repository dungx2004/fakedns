#ifndef RESPONSE_H
#define RESPONSE_H

#include "query.h"
#include "queue.h"

struct response_args {
	queue_t *capture_response;
	queue_t *response_writelog;
	struct domain_name *blacklist;
};

int response(struct response_args *arg);

#endif