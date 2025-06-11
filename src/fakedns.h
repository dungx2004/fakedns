#ifndef FAKEDNS_H
#define FAKEDNS_H

#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

#define SOCKET_PATH "/tmp/fakedns.sock"
#define CONFIG_FILE "/etc/fakedns/config.yaml"

#define FAKE_IP4 "127.0.0.1"
#define IP4_LEN 4
#define ANSRR_IP4_LEN 16

#define FAKE_IP6 "::1"
#define IP6_LEN 16
#define ANSRR_IP6_LEN 28

#define MAX_PACKET_LEN 4096

#define ETH_HEADER_LEN 14
#define MAX_IP_HEADER_LEN 60
#define UDP_HEADER_LEN 8
#define DNS_HEADER_LEN 12

#define MAX_DNS_PAYLOAD_LEN 4002 // = max packet len - các header len
#define MAX_DNS_QNAME_LEN 3970 // = max payload len - 4 byte qtypeqclass - max(28, 16) byte answer rr


struct dns_query {
	uint8_t mac_src[6];
	uint8_t mac_dest[6];
	int is_ip6;
	uint32_t ip_src;
	uint32_t ip_dest;
	struct in6_addr ip6_src;
	struct in6_addr ip6_dest;
	uint16_t port_src;
	uint16_t dns_id;
	unsigned char qname[MAX_DNS_QNAME_LEN];
	size_t qname_len;
	uint32_t qtype_qclass;
};

extern pthread_mutex_t g_mutex;
extern int g_flag;
#endif
