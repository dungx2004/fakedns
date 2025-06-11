#ifndef WRITELOG_H
#define WRITELOG_H

#include "queue.h"

struct writelog_args {
	queue_t *queue;
	char *path_to_log_file;
};

int write_log(struct writelog_args *arg);
void qname_to_dname(unsigned char *qname, char *dname);
#endif
