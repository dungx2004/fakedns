#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "query.h"
#include "queue.h"
#include "writelog.h"


void qname_to_dname(unsigned char *qname, char *dname) {
	memset(dname, 0, MAX_NAME_LEN);
	int label_len = 0, i = 0;
	while (qname[i] != 0 && i < MAX_NAME_LEN) {
		label_len = qname[i];
		i++;
		strncat(dname, &(qname[i]), label_len);
		strcat(dname, ".");
		i += label_len;
	}
	dname[strlen(dname)-1] = '\0';
}

int write_log(struct writelog_args *args) {
	queue_t *q = args->q;
	//char *path_to_log_file = args->path_to_log_file;
	char path_to_log_file[] = "fakedns.log";

	struct dns_query query;
	memset(&query, 0, sizeof(struct dns_query));

	char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
	int src_port, dest_port;
	char domain_name[MAX_NAME_LEN];

	time_t current_time;
	struct tm *local_time;
	char time_str[20];

	FILE *logfile = fopen(path_to_log_file, "a");
	if (!logfile) {
		printf("Write log: Failed to open log file %s\n", path_to_log_file);
		return -1;
	}

	printf("Start write log\n");
	while (1) {
		struct dns_query *query = queue_pop(q);
		if (!query) {
			continue;
		}

		// Địa chỉ IP
		inet_ntop(AF_INET, &(query->ip_header.saddr), src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(query->ip_header.daddr), dest_ip, INET_ADDRSTRLEN);

		// Số hiệu cổng
		src_port = ntohs(query->udp_header.source);
		dest_port = ntohs(query->udp_header.dest);

		// Tên miền
		qname_to_dname(query->dns_question.qname, domain_name);

		// Thời điểm ghi log
		current_time = time(NULL);
		local_time = localtime(&current_time);
		strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S %Z", local_time);

		// Ghi ra log
		fprintf(logfile, "[%s] Query %s from %s port %d to %s port %d\n",
			time_str, domain_name, src_ip, src_port, dest_ip, dest_port);

		free(query);
	}

	return 0;
}
