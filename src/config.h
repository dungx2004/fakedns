#ifndef CONFIG_H
#define CONFIG_H

#include "fakedns.h"

#define MAX_IFNAME_LEN 32
#define MAX_IPS 128
#define MAX_DOMAINS 128

struct qname_list {
	unsigned char *qnames[MAX_DOMAINS];
	int qname_count;
};

struct config {
	char *interface;
	char *fake_ipv4;
	char *fake_ipv6;
	char *logfile;
	char *ips[MAX_IPS];
	struct qname_list lists[MAX_IPS];
	int ip_count;
	struct qname_list default_list;
};

int config_read(struct config *conf);
void config_free(struct config *conf);
size_t dname_to_qname(char *dname, unsigned char *qname);
#endif
