#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

// Convert domain name dạng người đọc sang dạng QNAME
void dname_to_qname(char *dname, unsigned char *qname) {
	memset(qname, 0, MAX_NAME_LEN);
	char label_len[2] = {'\0', '\0'};

	char *label = strtok(dname, ".");
	while (label != NULL) {
		label_len[0] = strlen(label);
		strcat(qname, label_len);
		strcat(qname, label);
		label = strtok(NULL, ".");
	}
}

// Đọc file config
// Trả về -1 nếu gặp lỗi, 0 nếu đọc thành công
int read_config(char *path_to_config_file, struct config *conf) {
	char buffer[MAX_NAME_LEN];
	int buf_len;

	FILE *file = fopen(path_to_config_file, "r");
	if (!file) {
		printf("Read config: Failed to open config file\n");
		return -1;
	}

	// Đọc tên interface
	rewind(file);
	if (fgets(buffer, MAX_NAME_LEN, file) != NULL) {
		buffer[strcspn(buffer, "\n")] = '\0';
		strncpy(conf->interface_name, buffer, MAX_NAME_LEN);
	} else {
		printf("Read config: Failed to read interface name\n");
	}
	printf("%s\n", conf->interface_name);
	// Đọc domain name
	while (fgets(buffer, MAX_NAME_LEN, file) != NULL) {
		buffer[strcspn(buffer, "\n")] = '\0';
		struct domain_name *dname = (struct domain_name *)malloc(sizeof(struct domain_name));
		
		dname_to_qname(buffer, dname->qname);
		dname->next = conf->domain_list;
		conf->domain_list = dname;
	}

	return 0;
}

// Xoá cấu trúc config
void free_conf(struct config *conf) {
	struct domain_name *temp;
	while (conf->domain_list != NULL) {
		temp = conf->domain_list;
		conf->domain_list = conf->domain_list->next;
		free(temp);
	}
	free(conf);
}
