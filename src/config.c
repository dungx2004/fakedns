#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

// Convert domain name dạng người đọc sang dạng QNAME
size_t dname_to_qname(char *dname, unsigned char *qname) {
	memset(qname, 0, MAX_DNS_QNAME_LEN);
	char label_len[2] = {'\0', '\0'};
	size_t qname_len = 0;

	char *label = strtok(dname, ".");
	while (label != NULL) {
		label_len[0] = strlen(label);
		strcat((char *)qname, label_len);
		strcat((char *)qname, label);
		label = strtok(NULL, ".");
		qname_len += 1 + label_len[0];
	}
	qname_len++;
	return qname_len;
}

struct config *config_read(char *path_to_config_file) {
	struct config *conf = (struct config *)malloc(sizeof(struct config));
	if (!conf) {
		printf("Read config: Failed to init config struct\n");
		return NULL;
	}

	FILE *file = fopen(path_to_config_file, "r");
	if (!file) {
		printf("Read config: Failed to open config file\n");
		free(conf);
		return NULL;
	}

	// Đọc tên interface
	char buffer[MAX_DNS_QNAME_LEN]; // vì MAX_DNS_QNAME_LEN > MAX_IFNAME_LEN
	rewind(file);
	if (fgets(buffer, MAX_IFNAME_LEN, file) != NULL) {
		buffer[strcspn(buffer, "\n")] = '\0';
		strncpy(conf->interface, buffer, MAX_IFNAME_LEN);
	} else {
		free(conf);
		fclose(file);
		printf("Read config: Failed to read interface name\n");
	}

	// Đọc các domain name
	while (fgets(buffer, MAX_DNS_QNAME_LEN, file) != NULL) {
		buffer[strcspn(buffer, "\n")] = '\0';
		struct config_qname *qname_in_blacklist = (struct config_qname *)malloc(sizeof(struct config_qname));
		
		qname_in_blacklist->qname_len = dname_to_qname(buffer, qname_in_blacklist->qname);
		qname_in_blacklist->next = conf->blacklist;
		conf->blacklist = qname_in_blacklist;
	}

	return conf;
}

// Xoá cấu trúc config
void config_free(struct config *conf) {
	struct config_qname *temp;
	while (conf->blacklist != NULL) {
		temp = conf->blacklist;
		conf->blacklist = conf->blacklist->next;
		free(temp);
	}
	free(conf);
}
