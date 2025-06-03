#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

// Convert domain name dạng người đọc sang dạng QNAME
void dname_to_qname(char *dname, unsigned char *qname) {
	memset(qname, 0, MAX_DNS_QNAME_LEN);
	char label_len[2] = {'\0', '\0'};

	char *label = strtok(dname, ".");
	while (label != NULL) {
		label_len[0] = strlen(label);
		strcat((char *)qname, label_len);
		strcat((char *)qname, label);
		label = strtok(NULL, ".");
	}
}

// Đọc file config
// Trả về -1 nếu gặp lỗi, 0 nếu đọc thành công
int read_config(char *path_to_config_file, struct config *conf) {
	char buffer[MAX_DNS_QNAME_LEN];
	int buf_len;

	FILE *file = fopen(path_to_config_file, "r");
	if (!file) {
		printf("Read config: Failed to open config file\n");
		return -1;
	}

	// Đọc tên interface
	rewind(file);
	if (fgets(buffer, MAX_IFNAME_LEN, file) != NULL) {
		buffer[strcspn(buffer, "\n")] = '\0';
		strncpy(conf->interface, buffer, MAX_IFNAME_LEN);
	} else {
		printf("Read config: Failed to read interface name\n");
	}
	printf("%s\n", conf->interface);
	// Đọc domain name
	while (fgets(buffer, MAX_DNS_QNAME_LEN, file) != NULL) {
		buffer[strcspn(buffer, "\n")] = '\0';
		struct config_qname *qname_in_blacklist = (struct config_qname *)malloc(sizeof(struct config_qname));
		
		dname_to_qname(buffer, qname_in_blacklist->qname);
		qname_in_blacklist->next = conf->blacklist;
		conf->blacklist = qname_in_blacklist;
	}

	return 0;
}

// Xoá cấu trúc config
void free_conf(struct config *conf) {
	struct config_qname *temp;
	while (conf->blacklist != NULL) {
		temp = conf->blacklist;
		conf->blacklist = conf->blacklist->next;
		free(temp);
	}
	free(conf);
}
