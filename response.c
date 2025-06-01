#include <libnet.h>
#include <libnet/libnet-functions.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-structures.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "query.h"
#include "queue.h"
#include "config.h"
#include "response.h"

#define MAX_PAYLOAD_LEN 65536

int is_invalid_query(const struct dns_query *query, struct domain_name *blacklist) {
	struct domain_name *temp = blacklist;
	while (temp != NULL) {
		if (!memcmp(query->dns_question.qname, temp->qname, MAX_NAME_LEN)) {
			return 1;
		}
		temp = temp->next;
	}
	return 0;
}

int create_payload(const struct dns_query *query, unsigned char dns_payload[MAX_PAYLOAD_LEN]) {
	int payload_idx = 0;
	// QNAME
	if ((payload_idx + query->dns_question.qname_len) > MAX_PAYLOAD_LEN) {
		printf("Create payload: QNAME overflow\n");
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), query->dns_question.qname,
			query->dns_question.qname_len);
	payload_idx += query->dns_question.qname_len;

	// QTYPE: A
	int qtype = htons(0x0001);
	if ((payload_idx + 2) > MAX_PAYLOAD_LEN) {
		printf("Create payload: QTYPE overflow\n");
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), &(qtype), 2);
	payload_idx += 2;

	// QCLASS: IN
	int qclass = htons(0x0001);
	if ((payload_idx + 2) > MAX_PAYLOAD_LEN) {
		printf("Create payload: QCLASS overflow\n");
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), &(qclass), 2);
	payload_idx += 2;

	// DNS answer RR
	// pointer to QNAME
	int p_qname = htons(0xc00c);
	if (payload_idx + 2 > MAX_PAYLOAD_LEN) {
		printf("Create payload: Answer RR, qname pointer overflow\n");
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), &p_qname, 2);
	payload_idx += 2;

	// RR TYPE: A
	int ans_type = htons(0x0001);
	if (payload_idx + 2 > MAX_PAYLOAD_LEN) {
		printf("Create payload: Answer RR, type overflow\n");
		return -1;
	}
	memcpy(&dns_payload[payload_idx], &ans_type, 2);
	payload_idx += 2;

	// RR CLASS: IN
	int ans_class = htons(0x0001);
	if (payload_idx + 2 > MAX_PAYLOAD_LEN) {
		printf("Create payload: Answer RR, CLASS overflow\n");
		return -1;
	}
	memcpy(&dns_payload[payload_idx], &ans_class, 2);
	payload_idx += 2;

	// RDATA length
	uint16_t ans_data_len = htons(4);
	if (payload_idx + sizeof(ans_data_len) > MAX_PAYLOAD_LEN) {
		printf("Create payload: Answer RR, RDATA length overflow\n");
		return -1;
	}
	memcpy(&dns_payload[payload_idx], &ans_data_len, sizeof(ans_data_len));
	payload_idx += sizeof(ans_data_len);

	// RDATA
	uint32_t ans_ip;
	inet_pton(AF_INET, FAKE_IP, &ans_ip);
	if (payload_idx + ntohs(ans_data_len) > MAX_PAYLOAD_LEN) {
		printf("Create payload: Answer RR, RDATA overflow\n");
		return -1;
	}
	memcpy(&dns_payload[payload_idx], &ans_ip, ans_data_len);
	payload_idx += ntohs(ans_data_len);
	
	return payload_idx;
}

void inject_response(const struct dns_query *query) {
	// Khởi tạo libnet context
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *libnet = libnet_init(LIBNET_RAW4, "virbr1", errbuf);
	if (!libnet) {
		printf("Response: Failed to init libnet: %s\n", errbuf);
		return;
	}

	// DNS payload
	unsigned char dns_payload[MAX_PAYLOAD_LEN];
	int payload_len = create_payload(query, dns_payload);
	if (payload_len == -1) {
		printf("Inject response: Failed to create DNS payload\n");
		return;
	}
	// DNS message
	libnet_ptag_t dns_tag = libnet_build_dnsv4(LIBNET_DNS_H, query->dns_header.id,
			0x8180, 1, 1, 0, 0, dns_payload, payload_len, libnet, 0);
	if (dns_tag == -1) {
		printf("Inject response: Failed to build DNS header: %s\n",
				libnet_geterror(libnet));
		return;
	}

	// UDP header
	libnet_ptag_t udp_tag = libnet_build_udp(53, ntohs(query->udp_header.source),
			LIBNET_UDP_H + LIBNET_DNS_H + payload_len,
			0, NULL, 0, libnet, 0);
	if (udp_tag == -1) {
		printf("Inject response: Failed to build UDP header\n");
		return;
	}
	
	// IP header
	libnet_ptag_t ip_tag = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + payload_len,
			0, libnet_get_prand(LIBNET_PR8), 0, 64, IPPROTO_UDP, 0,
			query->ip_header.daddr, query->ip_header.saddr,
			NULL, 0, libnet, 0
			);
	if (ip_tag == -1) {
		printf("Inject response: Failed to build IP header\n");
		return;
	}

	int packet_len = libnet_write(libnet);
	if (packet_len == -1) {
		printf("Inject response: Failed to write libnet\n");
		return;
	}
	printf("Inject successfull\n");
	libnet_destroy(libnet);
}

int response(struct response_args *args) {
	queue_t *capture_response = args->capture_response;
	queue_t *response_writelog = args->response_writelog;
	struct domain_name *blacklist = args->blacklist;

	printf("Start response\n");
	while (1) {
		struct dns_query *query = queue_pop(capture_response);
		if (!query) {
			continue;
		}

		if (is_invalid_query(query, blacklist)) {
			inject_response(query);
		}

		queue_push(response_writelog, query);
	}
}
