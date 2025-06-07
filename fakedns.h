#ifndef FAKEDNS_H
#define FAKEDNS_H

#include <stdlib.h>
#include <stdint.h>

#define MAX_IFNAME_LEN 32
#define PATH_TO_LOG "fakedns.log"

#define FAKE_IP4 "127.0.0.1"
#define IP4_LEN 4
#define ANSRR_IP4_LEN 16

#define FAKE_IP6 "::1"
#define IP6_LEN 16
#define ANSRR_IP6_LEN 28

#define MAX_PACKET_LEN 512

#define ETH_HEADER_LEN 14
#define MAX_IP_HEADER_LEN 60
#define UDP_HEADER_LEN 8
#define DNS_HEADER_LEN 12

#define MAX_DNS_PAYLOAD_LEN 418 // = max packet len - các header len
#define MAX_DNS_QNAME_LEN 384 // 386 = max payload len - 4 byte qtypeqclass - max(28, 16) byte answer rr
			      // lấy 384 = 128 * 3


struct dns_query {
	uint8_t mac_src[6];
	uint8_t mac_dest[6];
	uint32_t ip_src;
	uint32_t ip_dest;
	uint16_t port_src;
	uint16_t dns_id;
	unsigned char qname[MAX_DNS_QNAME_LEN];
	size_t qname_len;
	uint32_t qtype_qclass;
};
#endif
