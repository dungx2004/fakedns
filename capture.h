#ifndef CAPTURE_H
#define CAPTURE_H

#include "queue.h"

struct capture_args {
	char *interface;
	queue_t *capture_response;
};

int capture(struct capture_args *args);

#endif
