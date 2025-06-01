#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "query.h"
#include "queue.h"
#include "capture.h"
#include "config.h"
#include "response.h"
#include "writelog.h"


int main(int argc, char *argv[]) {
	// Đọc file config
	struct config *conf = (struct config *)malloc(sizeof(struct config));
	if (!conf) {
		return -1;
	}
	if (read_config("fakedns.conf", conf) == -1) {
		printf("Failed to read config\n");
		return -1;
	}

	// Bắt đầu 2 queue: capture() -> response() và response() -> writelog()
	queue_t *capture_response = queue_init();
	if (!capture_response) {
		printf("Failed to init queue capture_response\n");
		return -1;
	}

	queue_t *response_writelog = queue_init();
	if (!response_writelog) {
		printf("Failed to init queue response_writelog\n");
		return -1;
	}

	// Bắt đầu 3 thread: capture(), response() và writelog()
	pthread_t thread_capture, thread_response, thread_writelog;
	// capture
	struct capture_args *capture_arg = (struct capture_args *)malloc(sizeof(struct capture_args));
	if (!capture_arg) {
		printf("Failed to write capture_arg\n");
		return -1;
	}
	capture_arg->interface = conf->interface_name;
	capture_arg->queue = capture_response;

	if (pthread_create(&thread_capture, NULL, (void *)capture, capture_arg) != 0) {
		printf("Failed to start capture\n");
		return -1;
	}

	// response
	struct response_args *response_arg = (struct response_args *)malloc(sizeof(struct response_args));
	if (!response_arg) {
		printf("Failed to write response_arg\n");
		return -1;
	}
	response_arg->capture_response = capture_response;
	response_arg->response_writelog = response_writelog;
	response_arg->blacklist = conf->domain_list;

	if (pthread_create(&thread_response, NULL, (void *)response, response_arg) != 0) {
		printf("Failed to start response\n");
		return -1;
	}

	// writelog
	struct writelog_args *writelog_arg = (struct writelog_args *)malloc(sizeof(struct writelog_args));
	if (!writelog_arg) {
		printf("Failed to write writelog_arg\n");
		return -1;
	}
	writelog_arg->q = response_writelog;
	writelog_arg->path_to_log_file = "fakedns.log";
	if (pthread_create(&thread_writelog, NULL, (void *)write_log, writelog_arg) != 0) {
		printf("Failed to start write log\n");
		return -1;
	}
	// TODO: Reload config khi được gọi
	// Đóng các luồng
	pthread_join(thread_capture, NULL);
 	pthread_join(thread_response, NULL);
 	pthread_join(thread_writelog, NULL);
	// Đóng các queue
	queue_free(capture_response);
	queue_free(response_writelog);

	// Đóng file config
	free_conf(conf);
}
