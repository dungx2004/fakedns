#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <pcap.h>
#include <libnet.h>
#include "config.h"
#include "fakedns.h"
#include "queue.h"
#include "capture_response.h"

int is_invalid_query(const struct dns_query *query, struct config_qname *blacklist) {
	struct config_qname *temp = blacklist;
	while (temp != NULL) {
		if (!strncmp((char *)query->qname, (char *)temp->qname, MAX_DNS_QNAME_LEN)) {
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
	if (query->qname_len > MAX_DNS_PAYLOAD_LEN) {
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), query->qname, query->qname_len);
	payload_idx += query->qname_len;

	// QTYPE: A
	uint32_t qtype_qclass = query->qtype_qclass;
	if (payload_idx + 4 > MAX_DNS_PAYLOAD_LEN) {
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), &(qtype_qclass), 4);
	payload_idx += 4;

	// DNS answer RR
	memcpy(&(dns_payload[payload_idx]), answer_rr, 16);
	payload_idx += 16;
	return payload_idx;
}

void inject_response(libnet_t *libnet, const struct dns_query *query, unsigned char *fake_answer_rr) {
	// DNS payload
	unsigned char dns_payload[MAX_DNS_PAYLOAD_LEN];
	int payload_len = create_payload(query, dns_payload, fake_answer_rr);
	if (payload_len == -1) {
		printf("Inject response: Failed to create DNS payload\n");
		return;
	}
	// DNS message
	libnet_ptag_t dns_tag = libnet_build_dnsv4(LIBNET_DNS_H, htons(query->dns_id),
			0x8180, 1, 1, 0, 0, dns_payload, payload_len, libnet, 0);
	if (dns_tag == -1) {
		printf("Inject response: Failed to build DNS header\n");
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
			NULL, 0, libnet, 0);
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

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr,
			const unsigned char *packet) {
	struct dns_query *query = ((struct packet_handler_args *)user_data)->query;
	
	const unsigned char *temp = packet;
	const unsigned char *packet_limit = packet + pkthdr->caplen;

	// IP header
	temp = packet + ETH_HEADER_LEN;
	struct iphdr *ip_header = (struct iphdr *)temp;
	size_t ip_header_len = ip_header->ihl * 4;
	if (temp + ip_header_len > packet_limit) {
		return;
	}
	if (ip_header->protocol != IPPROTO_UDP) {
		return;
	}
	query->ip_src = ip_header->saddr;
	query->ip_dest = ip_header->daddr;

	// UDP header
	temp += ip_header_len;
	if (temp + UDP_HEADER_LEN > packet_limit) {
		return;
	}
	struct udphdr *udp_header = (struct udphdr *)temp;
	if (ntohs(udp_header->dest) != 53) {
		return;
	}
	query->port_src = udp_header->source;

	// DNS header
	temp += UDP_HEADER_LEN;
	if (temp + DNS_HEADER_LEN > packet_limit) {
		return;
	}
	if (ntohs(*((uint16_t *)(temp + 2))) & 0x8000) { // 0x8000 = 1000 0000 0000 0000 nhị phân
		return;
	}
	query->dns_id = *((uint16_t *)temp);

	// DNS qname
	temp += DNS_HEADER_LEN;
	size_t qname_len = 0;
	while (temp[qname_len] != '\0' && qname_len < MAX_DNS_QNAME_LEN) {
		qname_len++;
	}
	qname_len++;
	memcpy(query->qname, temp, qname_len);
	query->qname[qname_len] = '\0';
	query->qname_len = qname_len;

	// DNS qtype and qclass
	temp += qname_len;
	memcpy(&(query->qtype_qclass), temp, 4);

	// Fake response if necessary
	if (is_invalid_query(query, ((struct packet_handler_args *)user_data)->blacklist)) {
		inject_response(((struct packet_handler_args *)user_data)->libnet,
				query,
				((struct packet_handler_args *)user_data)->answer_rr);
	}

	// Push vào queue
	queue_push(((struct packet_handler_args *)user_data)->queue, query);
	printf("Capture successfully %s\n", query->qname);
}

int capture_response(struct capture_response_args *args) {
	char *interface = args->conf->interface;

	pcap_t *handle;
	struct bpf_program fp;
	char filter[] = "ip";
	bpf_u_int32 ip;
	bpf_u_int32 mask;

	// Xác định IP gắn với interface và mặt nạ mạng
	if (pcap_lookupnet(interface, &ip, &mask, NULL) == -1) {
		printf("Capture: Failed to lookup IP and subnet mask\n");
		return -1;
	}

	// Chuẩn bị live capture
	handle = pcap_open_live(interface, MAX_PACKET_LEN, 1, 1000, NULL);
	if (!handle) {
		printf("Capture: Failed to open interface for live capture\n");
		return -1;
	}

	// Kiểm tra có phải Ethernet interface không
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("Capture: Not an Ethernet interface\n");
		pcap_close(handle);
		return -1;
	}

	// Lọc các gói không dùng IP
	if (pcap_compile(handle, &fp, filter, 0, mask) == -1) {
		printf("Capture: Failed to compile filter expression \n");
		pcap_close(handle);
		return -1;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("Capture: Failed to apply filter\n");
		pcap_close(handle);
		return -1;
	}

	// Khởi tạo libnet
	libnet_t *libnet = libnet_init(LIBNET_RAW4, interface, NULL);
	if (!libnet) {
		printf("Capture_response: Failed to init libnet\n", NULL);
		return -1;
	}

	// Capture and response
	unsigned char answer_rr[16];
	create_answer_rr(answer_rr);
	struct dns_query query;

	struct packet_handler_args packet_handler_arg = {
		.blacklist = args->conf->blacklist,
		.queue = args->queue,
		.libnet = libnet,
		.answer_rr = answer_rr,
		.query = &query
	};

	printf("Start capture and response\n");
	pcap_loop(handle, -1, packet_handler, (unsigned char *)(&packet_handler_arg));

	// Dọn dẹp
	pcap_freecode(&fp);
	pcap_close(handle);
	libnet_destroy(libnet);

	return 0;
}
