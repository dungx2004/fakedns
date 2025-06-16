#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <pcap.h>

#include "fakedns.h"
#include "config.h"
#include "queue.h"
#include "capture_response.h"
#include "writelog.h"

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_flag; // flag = 0 là dừng, flag = 1 là chạy

struct fakedns_args {
	struct config conf;
	queue_t *queue;
	pthread_t thread_capture_response;
	pthread_t thread_writelog;
	pcap_t *handle;
};


int start_fakedns(struct fakedns_args *fakedns) {
	// Đọc file config
	if (config_read(&(fakedns->conf))) {
		printf("Failed to read config\n");
		return -1;
	}

	// Khởi tạo hàng đợi
	fakedns->queue = queue_init();
	if (!(fakedns->queue)) {
		printf("Failed to init queue capture_response\n");
		return -1;
	}

	fakedns->handle = pcap_create(fakedns->conf.interface, NULL);
	if (!(fakedns->handle)) {
		printf("Failed to open pcap\n");
		return -1;
	}

	g_flag = 1;
	// Bắt đầu capture_response()
	struct capture_response_args *capture_response_arg = (struct capture_response_args *)malloc(sizeof(struct capture_response_args));
	if (!capture_response_arg) {
		printf("Failed to write capture_response_arg\n");
		return -1;
	}
	capture_response_arg->conf = &fakedns->conf;
	capture_response_arg->queue = fakedns->queue;
	capture_response_arg->handle = fakedns->handle;

	if (pthread_create(&(fakedns->thread_capture_response), NULL, (void *)capture_response, capture_response_arg)) {
		printf("Failed to start capture and response\n");
		return -1;
	}

	// Bắt đầu writelog()
	struct writelog_args *writelog_arg = (struct writelog_args *)malloc(sizeof(struct writelog_args));
	if (!writelog_arg) {
		printf("Failed to write writelog_arg\n");
		return -1;
	}
	writelog_arg->queue = fakedns->queue;
	writelog_arg->path_to_log_file = fakedns->conf.logfile;
	
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

	pcap_breakloop(fakedns->handle);
	pthread_join(fakedns->thread_capture_response, NULL);
	pthread_join(fakedns->thread_writelog, NULL);

	queue_free(fakedns->queue);
	config_free(&fakedns->conf);
}

int reload_config_fakedns(struct fakedns_args *fakedns) {
	struct config new_config;
	if (config_read(&new_config)) {
		return -1;
	}

	stop_fakedns(fakedns);
	fakedns->conf = new_config;

	return start_fakedns(fakedns);
}

void fakedns_daemon_sock() {
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		return;
	}

	struct sockaddr_un daemon_sock;
	memset(&daemon_sock, 0, sizeof(daemon_sock));
	daemon_sock.sun_family = AF_UNIX;
	strncpy(daemon_sock.sun_path, SOCKET_PATH, sizeof(daemon_sock.sun_path));

	if (bind(sockfd, (struct sockaddr *)(&daemon_sock), sizeof(daemon_sock)) == -1) {
		goto end;
	}

	if (listen(sockfd, 5)) {
		goto end;
	}

	struct fakedns_args fakedns;
	if (start_fakedns(&fakedns)) {
		goto end;
	}
	

	while (1) {
		struct sockaddr_un client_sock;
		socklen_t client_socklen = sizeof(struct sockaddr_storage);
		char buffer[128];
		int client_fd = accept(sockfd, (struct sockaddr *)&client_sock, &client_socklen);
		if (client_fd == -1) {
			continue;
		}

		int msg_len = recv(client_fd, buffer, 128, 0);
		buffer[msg_len] = '\0';

		if (!strcmp(buffer, "reload")) {
			reload_config_fakedns(&fakedns);
		}

		if (!strcmp(buffer, "stop")) {
			stop_fakedns(&fakedns);
			close(client_fd);
			break;
		}
		close(client_fd);
	}
end:
	unlink(SOCKET_PATH);
	close(sockfd);
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
		if (!access(SOCKET_PATH, F_OK)) {
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
		fakedns_daemon_sock();
	}

	if (!strcmp(argv[1], "reload") || !strcmp(argv[1], "stop")) {
		if (access(SOCKET_PATH, F_OK)) {
			printf("No daemon running\n");
			return -1;
		}
		
		int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sockfd == -1) {
			printf("Failed to create client socket\n");
			return -1;
		}

		struct sockaddr_un daemon_sock;
		memset(&daemon_sock, 0, sizeof(daemon_sock));
		daemon_sock.sun_family = AF_UNIX;
		strncpy(daemon_sock.sun_path, SOCKET_PATH, sizeof(daemon_sock.sun_path) - 1);

		if (connect(sockfd, (struct sockaddr *)(&daemon_sock), sizeof(daemon_sock)) == -1) {
			close(sockfd);
			if (!strcmp(argv[1], "stop")) {
				unlink(SOCKET_PATH);
			}
			return -1;
		}

		if (send(sockfd, argv[1], strlen(argv[1]), 0) == -1) {
			printf("Failed to write to socket\n");
		}
		close(sockfd);
		
		return 0;
	}

end:
	printf("Wrong usage!\n");
	printf("Usage: sudo fakedns <command>\n");
	printf("Commands: start, stop, reload\n");
	return 0;
}
