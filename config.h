#ifndef CONFIG_H
#define CONFIG_H

#include "fakedns.h"

struct config_qname {
	unsigned char qname[MAX_DNS_QNAME_LEN];
	struct config_qname *next;
};

struct config {
	char interface[MAX_IFNAME_LEN];
	struct config_qname *blacklist;
};

int read_config(char *path_to_config_file, struct config *conf);
void free_conf(struct config *conf);
#endif
