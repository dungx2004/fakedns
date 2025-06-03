#ifndef FAKEDNS_H
#define FAKEDNS_H

#include <stdlib.h>
#include <stdint.h>

#define MAX_IFNAME_LEN 32
#define FAKE_IP "42.112.27.54"
#define PATH_TO_LOG "fakedns.log"

#define ETH_HEADER_LEN 14
#define MAX_IP_HEADER_LEN 60
#define UDP_HEADER_LEN 8
#define DNS_HEADER_LEN 12

#define MAX_DNS_PAYLOAD_LEN 1024
#define MAX_DNS_QNAME_LEN 128

#define MAX_PACKET_LEN 1118 // = max payload len + các header len

struct dns_query {
	uint32_t ip_src;
	uint32_t ip_dest;
	uint16_t port_src;
	uint16_t dns_id;
	unsigned char qname[MAX_DNS_QNAME_LEN];
	size_t qname_len;
	uint32_t qtype_qclass;
};
#endif
