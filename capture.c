#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include "query.h"
#include "queue.h"
#include "capture.h"

#define PACKET_LEN 65536 // 64kib

// TODO: Kiểm tra sau mỗi lần temp += có đọc quá packet không
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr,
			const unsigned char *packet) {
	const unsigned char *temp = packet;
	size_t header_len = 0;
	int packet_len = pkthdr->caplen;
	struct dns_query *query = (struct dns_query *)malloc(sizeof(struct dns_query));
	memset(query, 0, sizeof(struct dns_query));

	// Ethernet header
	struct ethhdr *eth_header = (struct ethhdr *)temp;
	if (ntohs(eth_header->h_proto) != ETH_P_IP) {
		printf("Packet handler: Not an IPv4 packet\n");
		return;
	}

	memcpy(&(query->eth_header), eth_header, ETH_HLEN);

	// IP header
	temp += ETH_HLEN;
	struct iphdr *ip_header = (struct iphdr *)temp;
	if ((temp + header_len) > (packet + packet_len)) {
		printf("Packet handler: IP header truncated or too short\n");
		free(query);
		return;
	}
	if (ip_header->protocol != IPPROTO_UDP) {
		// printf("Packet handler: Not an UDP packet\n");
		free(query);
		return;
	}
	header_len = ip_header->ihl * 4;
	// Chỉ lấy 20 byte đầu, không quan tâm đến IP option
	memcpy(&(query->ip_header), ip_header, sizeof(struct iphdr));

	// UDP header
	temp += header_len;
	struct udphdr *udp_header = (struct udphdr *)temp;
	if (ntohs(udp_header->dest) != 53) {
		// printf("Packet handler: Not a DNS query\n");
		return;
	}
	header_len = sizeof(struct udphdr);
	memcpy(&(query->udp_header), udp_header, header_len);

	// DNS header
	temp += header_len;
	struct dnshdr *dns_header = (struct dnshdr *)temp;
	if (ntohs(dns_header->flags) & 0x8000) { // 0x8000 = 1000 0000 0000 0000 nhị phân
		printf("Packet handler: Not a DNS query\n");
		return;
	}
	header_len = sizeof(struct dnshdr);
	memcpy(&(query->dns_header), dns_header, header_len);

	// DNS qname
	temp += header_len;
	// TODO: Thay đổi cách đọc qname để đáp ứng các compressed query
	int qname_len = 0;
	while (temp[qname_len] != '\0' && qname_len < MAX_NAME_LEN) {
		qname_len++;
	}
	qname_len++;
	query->dns_question.qname_len = qname_len;
	memcpy(query->dns_question.qname, temp, qname_len);

	// DNS qtype
	temp += qname_len;
	memcpy(&(query->dns_question.qtype), temp, 2);
	memcpy(&(query->dns_question.qclass), temp + 2, 2);


	// Push vào queue
	queue_push((queue_t *)user_data, query);
}

int capture(struct capture_args *args) {
	char *interface = args->interface;
	queue_t *queue = args->queue;

	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter[] = "ip";
	bpf_u_int32 ip;
	bpf_u_int32 mask;

	// Chuẩn bị live capture
	handle = pcap_open_live(interface, PACKET_LEN, 1, 1000, error_buffer);
	if (!handle) {
		printf("Capture: Failed to open interface %s for live capture: %s\n",
				interface, error_buffer);
		return -1;
	}

	if (pcap_lookupnet(interface, &ip, &mask, error_buffer) == -1) {
		printf("Capture: Failed to lookup interface %s\n", interface);
		return -1;
	}

	// Kiểm tra có phải Ethernet interface không
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("Capture: %s is not an Ethernet interface\n", interface);
		pcap_close(handle);
		return -1;
	}

	// Lọc các gói không dùng IP
	if (pcap_compile(handle, &fp, filter, 0, mask) == -1) {
		printf("Capture: Failed to compile filter expression %s: %s\n",
				filter, pcap_geterr(handle));
		pcap_close(handle);
		return -1;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("Capture: Failed to apply filter %s: %s\n", filter, pcap_geterr(handle));
		pcap_close(handle);
		return -1;
	}

	// Bắt đầu capture
	printf("Start capture\n");
	pcap_loop(handle, -1, packet_handler, (unsigned char *)queue);

	// Dọn dẹp
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("Capture stopped\n");
	return 0;
}
