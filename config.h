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

struct config *config_read(char *path_to_config_file);
void config_free(struct config *conf);
#endif
