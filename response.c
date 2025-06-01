#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "fakedns.h"
#include "queue.h"
#include "response.h"

#define MAX_PAYLOAD_LEN 1024

int is_invalid_query(const struct dns_query *query, struct config_qname *blacklist) {
	struct config_qname *temp = blacklist;
	while (temp != NULL) {
		if (!memcmp(query->qname, temp->qname, MAX_QNAME_LEN)) {
			return 1;
		}
		temp = temp->next;
	}
	return 0;
}

void create_answer_rr(unsigned char *answer_rr) {
	int idx = 0;
	// pointer to QNAME
	uint16_t p_qname = htons(0xc00c);
	memcpy(&(answer_rr[idx]), &p_qname, 2);
	idx += 2;

	// RR TYPE: A
	uint16_t ans_type = htons(0x0001);
	memcpy(&answer_rr[idx], &ans_type, 2);
	idx += 2;

	// RR CLASS: IN
	uint16_t ans_class = htons(0x0001);
	memcpy(&answer_rr[idx], &ans_class, 2);
	idx += 2;

	// RR TTL: 3600s
	uint32_t ttl = htonl(3600);
	memcpy(&answer_rr[idx], &ttl, 4);
	idx += 4;

	// RDATA length
	uint16_t ans_data_len = htons(4);
	memcpy(&answer_rr[idx], &ans_data_len, 2);
	idx += 2;

	// RDATA
	uint32_t ans_ip;
	inet_pton(AF_INET, FAKE_IP, &ans_ip);
	memcpy(&answer_rr[idx], &ans_ip, 4);
}

int create_payload(const struct dns_query *query, unsigned char *dns_payload, unsigned char *answer_rr) {
	int payload_idx = 0;

	// QNAME
	if ((payload_idx + query->qname_len) > MAX_PAYLOAD_LEN) {
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), query->qname, query->qname_len);
	payload_idx += query->qname_len;

	// QTYPE: A
	uint16_t qtype = query->qtype;
	if ((payload_idx + 2) > MAX_PAYLOAD_LEN) {
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), &(qtype), 2);
	payload_idx += 2;

	// QCLASS: IN
	uint16_t qclass = query->qclass;
	if ((payload_idx + 2) > MAX_PAYLOAD_LEN) {
		printf("Create payload: QCLASS overflow\n");
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), &(qclass), 2);
	payload_idx += 2;

	// DNS answer RR
	memcpy(&(dns_payload[payload_idx]), answer_rr, 16);
	payload_idx += 16;
	return payload_idx;
}

void inject_response(libnet_t *libnet, const struct dns_query *query, unsigned char *fake_answer_rr) {
	// DNS payload
	unsigned char dns_payload[MAX_PAYLOAD_LEN];
	int payload_len = create_payload(query, dns_payload, fake_answer_rr);
	if (payload_len == -1) {
		printf("Inject response: Failed to create DNS payload\n");
		return;
	}
	// DNS message
	libnet_ptag_t dns_tag = libnet_build_dnsv4(LIBNET_DNS_H, htons(query->dns_id),
			0x8180, 1, 1, 0, 0, dns_payload, payload_len, libnet, 0);
	if (dns_tag == -1) {
		printf("Inject response: Failed to build DNS header: %s\n",
				libnet_geterror(libnet));
		return;
	}

	// UDP header
	libnet_ptag_t udp_tag = libnet_build_udp(53, ntohs(query->port_src),
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
			query->ip_dest, query->ip_src,
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
	libnet_clear_packet(libnet);
}

int response(struct response_args *args) {
	queue_t *capture_response = args->capture_response;
	queue_t *response_writelog = args->response_writelog;
	struct config_qname *blacklist = args->blacklist;

	// Khởi tạo libnet context
	libnet_t *libnet = libnet_init(LIBNET_RAW4, "virbr0", NULL);
	if (!libnet) {
		printf("Response: Failed to init libnet\n", NULL);
		return -1;
	}

	unsigned char answer_rr[16];
	create_answer_rr(answer_rr);
	struct dns_query query;

	printf("Start response\n");
	while (1) {
		if (queue_pop(capture_response, &query)) {
			continue;
		}

		if (is_invalid_query(&query, blacklist)) {
			inject_response(libnet, &query, answer_rr);
		}

		queue_push(response_writelog, &query);
	}

	libnet_destroy(libnet);
	return 0;
}
