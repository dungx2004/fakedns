#ifndef FAKEDNS_H
#define FAKEDNS_H

#include <stdlib.h>
#include <stdint.h>

#define MAX_IFNAME_LEN 32
#define FAKE_IP "42.112.27.54"
#define PATH_TO_LOG "fakedns.log"

#define MAX_QNAME_LEN 128
#define MAX_PACKET_LEN 1024 // 1kib
#define ETH_HEADER_LEN 14
#define UDP_HEADER_LEN 8
#define DNS_HEADER_LEN 12

struct dns_query {
	uint32_t ip_src;
	uint32_t ip_dest;
	uint16_t port_src;
	uint16_t dns_id;
	unsigned char qname[MAX_QNAME_LEN];
	size_t qname_len;
	uint16_t qtype;
	uint16_t qclass;
};
#endif
