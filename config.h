#ifndef CONFIG_H
#define CONFIG_H

#include "query.h"
#define FAKE_IP "42.112.27.54"

struct domain_name {
	unsigned char qname[MAX_NAME_LEN];
	struct domain_name *next;
};

struct config {
	char interface_name[MAX_NAME_LEN];
	struct domain_name *domain_list;
};

int read_config(char *path_to_config_file, struct config *conf);
void free_conf(struct config *conf);
#endif
