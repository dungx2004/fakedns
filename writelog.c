#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "fakedns.h"
#include "queue.h"
#include "writelog.h"


void qname_to_dname(unsigned char *qname, char *dname) {
	memset(dname, 0, MAX_DNS_QNAME_LEN);
	int label_len = 0, i = 0;
	while (qname[i] != 0 && i < MAX_DNS_QNAME_LEN) {
		label_len = qname[i];
		i++;
		strncat(dname, (char *)(&(qname[i])), label_len);
		strcat(dname, ".");
		i += label_len;
	}
	dname[strlen(dname)-1] = '\0';
}

int write_log(struct writelog_args *args) {
	queue_t *response_writelog = args->queue;

	struct dns_query query;

	char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
	int src_port, dest_port;
	char domain_name[MAX_DNS_QNAME_LEN];

	time_t current_time;
	struct tm *local_time;
	char time_str[20];

	FILE *logfile = fopen(args->path_to_log_file, "a");
	if (!logfile) {
		printf("Write log: Failed to open log file\n");
		return -1;
	}

	printf("Start write log\n");
	while (1) {
		if (queue_pop(response_writelog, &query)) {
			continue;
		}

		// Địa chỉ IP
		inet_ntop(AF_INET, &(query.ip_src), src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(query.ip_dest), dest_ip, INET_ADDRSTRLEN);

		// Số hiệu cổng
		src_port = ntohs(query.port_src);
		dest_port = 53;

		// Tên miền
		qname_to_dname(query.qname, domain_name);

		// Thời điểm ghi log
		current_time = time(NULL);
		local_time = localtime(&current_time);
		strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", local_time);

		long offset = local_time->tm_gmtoff;
		int offset_hours = offset/3600;
		int offset_minutes = (offset % 3600) / 60;
		char offset_sign = (offset >= 0) ? '+' : '-';

		fprintf(logfile, "[%s %c%02d:%02d] Query %s from %s:%d to %s:%d\n",
			time_str, offset_sign, offset_hours, offset_minutes,
			domain_name, src_ip, src_port, dest_ip, dest_port);
		fflush(logfile);
	}

	return 0;
}
