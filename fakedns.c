#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

#include "fakedns.h"
#include "config.h"
#include "queue.h"
#include "capture_response.h"
#include "writelog.h"

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_flag; // flag = 0 là dừng, flag = 1 là chạy, flag = 2 là tải lại config

struct fakedns_args {
	struct config *conf;
	queue_t *queue;
	pthread_t thread_capture_response;
	pthread_t thread_writelog;
};


int start_fakedns(char *path_to_conf, char *path_to_log, struct fakedns_args *fakedns) {
	// Đọc file config
	fakedns->conf = config_read(path_to_conf);
	if (!(fakedns->conf)) {
		printf("Failed to read config\n");
		return -1;
	}

	// Khởi tạo hàng đợi
	fakedns->queue = queue_init();
	if (!(fakedns->queue)) {
		printf("Failed to init queue capture_response\n");
		return -1;
	}

	// Bắt đầu chương trình
	g_flag = 1;
	// capture_response()
	struct capture_response_args *capture_response_arg = (struct capture_response_args *)malloc(sizeof(struct capture_response_args));
	if (!capture_response_arg) {
		printf("Failed to write capture_response_arg\n");
		return -1;
	}
	capture_response_arg->conf = fakedns->conf;
	capture_response_arg->queue = fakedns->queue;

	if (pthread_create(&(fakedns->thread_capture_response), NULL, (void *)capture_response, capture_response_arg)) {
		printf("Failed to start capture and response\n");
		return -1;
	}

	// writelog()
	struct writelog_args *writelog_arg = (struct writelog_args *)malloc(sizeof(struct writelog_args));
	if (!writelog_arg) {
		printf("Failed to write writelog_arg\n");
		return -1;
	}
	writelog_arg->queue = fakedns->queue;
	writelog_arg->path_to_log_file = path_to_log;
	
	if (pthread_create(&(fakedns->thread_writelog), NULL, (void *)write_log, writelog_arg)) {
		printf("Failed to start write log\n");
		free(writelog_arg);
		return -1;
	}
	return 0;
}

void stop_fakedns(struct fakedns_args *fakedns) {
	pthread_mutex_lock(&g_mutex);
	g_flag = 0;
	pthread_mutex_unlock(&g_mutex);

	pthread_join(fakedns->thread_capture_response, NULL);
	pthread_join(fakedns->thread_writelog, NULL);

	queue_free(fakedns->queue);
	config_free(fakedns->conf);
}

int reload_config_fakedns(char *path_to_conf, struct fakedns_args *fakedns) {
	struct config *new_config = config_read(path_to_conf);
	if (!new_config) {
		printf("Failed to read new config\n");
		return 1;
	}

	pthread_mutex_lock(&g_mutex);
	g_flag = 2;
	pthread_mutex_unlock(&g_mutex);

	pthread_join(fakedns->thread_capture_response, NULL);

	config_free(fakedns->conf);
	fakedns->conf = new_config;

	struct capture_response_args *capture_response_arg = (struct capture_response_args *)malloc(sizeof(struct capture_response_args));
	if (!capture_response_arg) {
		printf("Failed to write capture_response_arg\n");
		return -1;
	}
	capture_response_arg->conf = fakedns->conf;
	capture_response_arg->queue = fakedns->queue;

	pthread_mutex_lock(&g_mutex);
	g_flag = 1;
	pthread_mutex_unlock(&g_mutex);

	if (pthread_create(&(fakedns->thread_capture_response), NULL, (void *)capture_response, capture_response_arg)) {
		printf("Failed to start capture and response\n");
		free(capture_response_arg);
		return -1;
	}
	return 0;
}

int fakedns_daemon() {
	if (mkfifo(FIFO_PATH, 0666) == -1) {
		return -1;
	}

	int fd = open(FIFO_PATH, O_RDONLY | O_NONBLOCK);
	if (fd == -1) {
		return -1;
	}

	struct fakedns_args fakedns;
	if (start_fakedns(DEFAULT_PATH_TO_CONF, DEFAULT_PATH_TO_LOG, &fakedns) == -1) {
		return -1;
	}

	char buffer[128];
	while (1) {
		ssize_t n = read(fd, buffer, sizeof(buffer)-1);
		if (n > 0) {
			buffer[n] = '\0';
		}

		if (!strcmp(buffer, "reload")) {
			reload_config_fakedns(DEFAULT_PATH_TO_CONF, &fakedns);
		}
		if (!strcmp(buffer, "stop")) {
			stop_fakedns(&fakedns);
			break;
		}
	}

	close(fd);
	unlink(FIFO_PATH);
	return 0;
}

int main(int argc, char *argv[]) {
	if (geteuid() != 0) {
		printf("Sudo, please!\n");
		return -1;
	}

	if (argc != 2) {
		goto end;
	}

	if (!strcmp(argv[1], "start")) {
		if (!access(FIFO_PATH, F_OK)) {
			printf("Daemon already running\n");
			printf("Try stop then restart\n");
			return -1;
		}
		pid_t pid = fork();
		if (pid < 0) {
			printf("Failed to start daemon\n");
			return -1;
		}
		if (pid > 0) return 0;
		return fakedns_daemon();
	}

	if (!strcmp(argv[1], "reload")) {
		if (access(FIFO_PATH, F_OK)) {
			printf("No daemon running\n");
			return -1;
		}

		int fd = open(FIFO_PATH, O_WRONLY);
		if (fd == -1) {
			printf("Failed to connect to the running daemon\n");
			return -1;
		}
		const char *msg = "reload";
		write(fd, msg, strlen(msg));
		close(fd);
		return 0;
	}

	if (!strcmp(argv[1], "stop")) {
		if (access(FIFO_PATH, F_OK)) {
			printf("No daemon running\n");
			return -1;
		}
		int fd = open(FIFO_PATH, O_WRONLY | O_NONBLOCK);
		if (fd == -1) {
			printf("Failed to connect to the running daemon\n");
			return -1;
		}
		const char *msg = "stop";
		write(fd, msg, strlen(msg));
		close(fd);
	}

end:
	printf("Wrong usage!\n");
	printf("Usage: sudo fakedns <command>\n");
	printf("Commands: start, stop, reload\n");
	return 0;
}
