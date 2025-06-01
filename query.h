#ifndef QUERY_H
#define QUERY_H

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define MAX_NAME_LEN 128

struct dnshdr {
	unsigned short id;
	unsigned short flags;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
};

struct dns_question {
	unsigned char qname[MAX_NAME_LEN];
	int qname_len;
	unsigned short qtype;
	unsigned short qclass;
};

struct dns_query {
	struct ethhdr eth_header;
	struct iphdr ip_header;
	struct udphdr udp_header;
	struct dnshdr dns_header;
	struct dns_question dns_question;
};
#endif
