#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "fakedns.h"
#include "config.h"
#include "queue.h"
#include "capture_response.h"
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

	// Bắt đầu hàng đợi
	queue_t *queue = queue_init();
	if (!queue) {
		printf("Failed to init queue capture_response\n");
		return -1;
	}

	// Bắt đầu 2 thread: capture_response() và writelog()
	pthread_t thread_capture_response, thread_writelog;
	// capture and response
	struct capture_response_args *capture_response_arg = (struct capture_response_args *)malloc(sizeof(struct capture_response_args));
	if (!capture_response_arg) {
		printf("Failed to write capture_response_arg\n");
		return -1;
	}
	capture_response_arg->conf = conf;
	capture_response_arg->queue = queue;

	if (pthread_create(&thread_capture_response, NULL, (void *)capture_response, capture_response_arg) != 0) {
		printf("Failed to start capture and response\n");
		return -1;
	}

	// writelog
	struct writelog_args *writelog_arg = (struct writelog_args *)malloc(sizeof(struct writelog_args));
	if (!writelog_arg) {
		printf("Failed to write writelog_arg\n");
		return -1;
	}
	writelog_arg->queue = queue;
	writelog_arg->path_to_log_file = PATH_TO_LOG;
	
	if (pthread_create(&thread_writelog, NULL, (void *)write_log, writelog_arg) != 0) {
		printf("Failed to start write log\n");
		return -1;
	}
	// TODO: Reload config khi được gọi
	// Đóng các luồng
	pthread_join(thread_capture_response, NULL);
 	pthread_join(thread_writelog, NULL);
	// Đóng các queue
	queue_free(queue);

	// Xoá struct config
	free_conf(conf);
}
