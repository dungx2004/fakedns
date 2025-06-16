#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <pcap.h>
#include <libnet.h>
#include "config.h"
#include "fakedns.h"
#include "queue.h"
#include "capture_response.h"
#include "writelog.h"

struct packet_handler_args {
	struct config *conf;
	queue_t *queue;
	libnet_t *libnet;
	unsigned char *answer_rr;
	struct dns_query *query;
	pcap_t *handle;
};

int is_invalid_query(const struct dns_query *query, struct config *conf) {
	struct qname_list *list = NULL;
	char ipbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &query->ip_src, ipbuf, sizeof(ipbuf));

	for (int i = 0; i < conf->ip_count; i++) {
		if (strcmp(conf->ips[i], ipbuf) == 0) {
			list = &conf->lists[i];
			break;
		}
	}
	if (!list) {
		list = &conf->default_list;
	}

	char query_dname[MAX_DNS_QNAME_LEN];
	qname_to_dname((unsigned char *)query->qname, query_dname);
	size_t query_dname_len = strlen(query_dname);

	for (int i = 0; i < list->qname_count; i++) {
		char blacklist_dname[MAX_DNS_QNAME_LEN];
		qname_to_dname(list->qnames[i], blacklist_dname);
		size_t blacklist_dname_len = strlen(blacklist_dname);

		if (query_dname_len >= blacklist_dname_len) {
			if (strcmp(query_dname + query_dname_len - blacklist_dname_len, blacklist_dname) == 0) {
				if (query_dname_len == blacklist_dname_len || query_dname[query_dname_len - blacklist_dname_len - 1] == '.') {
					return 1;
				}
			}
		}
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

	// RR TTL: 10s
	uint32_t ttl = htonl(10);
	memcpy(&answer_rr[idx], &ttl, 4);
	idx += 4;

	// RDATA length
	uint16_t ans_data_len = htons(IP4_LEN);
	memcpy(&answer_rr[idx], &ans_data_len, 2);
	idx += 2;

	// RDATA
	uint32_t ans_ip;
	inet_pton(AF_INET, FAKE_IP4, &ans_ip);
	memcpy(&answer_rr[idx], &ans_ip, IP4_LEN);
}

int create_payload(const struct dns_query *query, unsigned char *dns_payload, unsigned char *answer_rr) {
	int payload_idx = 0;

	// Chép lại QNAME, QTYPE và QCLASS
	if (query->qname_len > MAX_DNS_PAYLOAD_LEN) {
		return -1;
	}
	memcpy(&(dns_payload[payload_idx]), query->qname, query->qname_len);
	payload_idx += query->qname_len;

	uint32_t qtype_qclass = query->qtype_qclass;
	memcpy(&(dns_payload[payload_idx]), &(qtype_qclass), 4);
	payload_idx += 4;

	// Gắn DNS answer RR
	memcpy(&(dns_payload[payload_idx]), answer_rr, ANSRR_IP4_LEN);
	payload_idx += ANSRR_IP4_LEN;
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

	libnet_clear_packet(libnet);
	// DNS header
	libnet_build_dnsv4(LIBNET_DNS_H, htons(query->dns_id),
			0x8180, 1, 1, 0, 0, dns_payload, payload_len, libnet, 0);

	// UDP header
	libnet_build_udp(53, ntohs(query->port_src),
			LIBNET_UDP_H + LIBNET_DNS_H + payload_len,
			0, NULL, 0, libnet, 0);
	
	// IP và ethernet header
	if (query->is_ip6 == 1) {
		struct libnet_in6_addr libnet_ip6_src, libnet_ip6_dest;
		memcpy(&libnet_ip6_src, &(query->ip6_src), sizeof(struct libnet_in6_addr));
		memcpy(&libnet_ip6_dest, &(query->ip6_dest), sizeof(struct libnet_in6_addr));

		libnet_build_ipv6(0, 0, LIBNET_UDP_H + LIBNET_DNS_H + payload_len,
				IPPROTO_UDP, 64, libnet_ip6_dest, libnet_ip6_src, NULL, 0, libnet, 0);

		libnet_build_ethernet(query->mac_src, query->mac_dest, ETHERTYPE_IPV6, NULL, 0, libnet, 0);
	} else {
		libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + payload_len,
				0, libnet_get_prand(LIBNET_PR8), 0, 64, IPPROTO_UDP, 0,
				query->ip_dest, query->ip_src, NULL, 0, libnet, 0);

		libnet_build_ethernet(query->mac_src, query->mac_dest, ETHERTYPE_IP, NULL, 0, libnet, 0);
	}
	libnet_write(libnet);
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr,
			const unsigned char *packet) {
	struct packet_handler_args *args = (struct packet_handler_args *)user_data;
	struct dns_query *query = args->query;
	
	const unsigned char *temp = packet;

	// Ethernet header
	struct ethhdr *eth_header = (struct ethhdr *)temp;
	memcpy(query->mac_src, eth_header->h_source, 6);
	memcpy(query->mac_dest, eth_header->h_dest, 6);
	if (ntohs(eth_header->h_proto) == ETH_P_IPV6) {
		query->is_ip6 = 1;
	} else query->is_ip6 = 0;

	// IP header
	temp = packet + ETH_HEADER_LEN;
	if (query->is_ip6 == 1) {
		struct ip6_hdr *ip_header = (struct ip6_hdr *)temp;
		query->ip6_src = ip_header->ip6_src;
		query->ip6_dest = ip_header->ip6_dst;
		temp += sizeof(struct ip6_hdr);
	} else {
		struct iphdr *ip_header = (struct iphdr *)temp;
		query->ip_src = ip_header->saddr;
		query->ip_dest = ip_header->daddr;
		temp += ip_header->ihl * 4;
	}

	// UDP header
	struct udphdr *udp_header = (struct udphdr *)temp;
	query->port_src = udp_header->source;

	// DNS header
	temp += UDP_HEADER_LEN;
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
	if (is_invalid_query(query, args->conf)) {
		inject_response(args->libnet, query, args->answer_rr);
	}

	// Push vào queue
	queue_push(args->queue, query);
}

int capture_response(struct capture_response_args *args) {
	char *interface = args->conf->interface;

	bpf_u_int32 ip;
	bpf_u_int32 mask;

	// Xác định IP gắn với interface và mặt nạ mạng
	if (pcap_lookupnet(interface, &ip, &mask, NULL) == -1) {
		free(args);
		return 1;
	}

	// Chuẩn bị live capture
	pcap_t *handle = args->handle;
	pcap_set_immediate_mode(handle, 1);
	pcap_set_snaplen(handle, MAX_PACKET_LEN);
	pcap_set_promisc(handle, 1);
	if (pcap_activate(handle) != 0) {
		printf("Capture: Failed to activate pcap handle\n");
		pcap_close(handle);
		free(args);
		return 1;
	}

	// Kiểm tra có phải Ethernet interface không
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("Capture: Not an Ethernet interface\n");
		pcap_close(handle);
		free(args);
		return 1;
	}

	// Lọc các gói không dùng IP
	struct bpf_program fp;
	char filter[] = "udp dst port 53 and udp[10] & 0x80 == 0";

	if (pcap_compile(handle, &fp, filter, 0, mask) == -1) {
		printf("Capture: Failed to compile filter expression \n");
		pcap_close(handle);
		free(args);
		return 1;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("Capture: Failed to apply filter\n");
		pcap_close(handle);
		free(args);
		return 1;
	}

	// Khởi tạo libnet
	libnet_t *libnet = libnet_init(LIBNET_LINK, interface, NULL);
	if (!libnet) {
		free(args);
		return 1;
	}

	// Capture and response
	unsigned char answer_rr[16];
	create_answer_rr(answer_rr);
	struct dns_query query;

	struct packet_handler_args packet_handler_arg = {
		.conf = args->conf,
		.queue = args->queue,
		.libnet = libnet,
		.answer_rr = answer_rr,
		.query = &query,
		.handle = handle
	};

	pcap_loop(handle, -1, packet_handler, (unsigned char *)(&packet_handler_arg));
	
	// Dọn dẹp
	pcap_freecode(&fp);
	pcap_close(handle);
	libnet_destroy(libnet);
	free(args);

	return 0;
}
