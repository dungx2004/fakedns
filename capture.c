#include <stdlib.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <pcap.h>
#include "fakedns.h"
#include "queue.h"
#include "capture.h"
#include "response.h"

// TODO: Kiểm tra sau mỗi lần temp += có đọc quá packet không
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr,
			const unsigned char *packet) {
	const unsigned char *temp = packet;
	const unsigned char *packet_limit = packet + pkthdr->caplen;
	struct dns_query query;
	memset(query.qname, 0, MAX_QNAME_LEN);

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
	query.ip_src = ip_header->saddr;
	query.ip_dest = ip_header->daddr;

	// UDP header
	temp += ip_header_len;
	if (temp + UDP_HEADER_LEN > packet_limit) {
		return;
	}
	struct udphdr *udp_header = (struct udphdr *)temp;
	if (ntohs(udp_header->dest) != 53) {
		return;
	}
	query.port_src = udp_header->source;

	// DNS header
	temp += UDP_HEADER_LEN;
	if (temp + DNS_HEADER_LEN > packet_limit) {
		return;
	}
	if (ntohs(*((uint16_t *)(temp + 2))) & 0x8000) { // 0x8000 = 1000 0000 0000 0000 nhị phân
		return;
	}
	query.dns_id = *((uint16_t *)temp);

	// DNS qname
	temp += DNS_HEADER_LEN;
	size_t qname_len = 0;
	while (temp[qname_len] != '\0' && qname_len < MAX_QNAME_LEN) {
		qname_len++;
	}
	qname_len++;
	memcpy(query.qname, temp, qname_len);
	query.qname_len = qname_len;

	// DNS qtype
	temp += qname_len;
	memcpy(&(query.qtype), temp, 2);
	memcpy(&(query.qclass), temp + 2, 2);

	// Push vào queue
	printf("Capture successfully %s\n", query.qname);
	queue_push((queue_t *)user_data, &query);
}

int capture(struct capture_args *args) {
	char *interface = args->interface;
	queue_t *capture_response = args->capture_response;

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

	// Bắt đầu capture
	printf("Start capture\n");
	pcap_loop(handle, -1, packet_handler, (unsigned char *)capture_response);

	// Dọn dẹp
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("Capture stopped\n");
	return 0;
}
