#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	struct iphdr *in_ip_head = packet_to_ip_hdr(in_pkt);

	int packet_len = 0; 
	if (type == ICMP_ECHOREPLY) {
		packet_len = len;
	} 
	else {
		packet_len = ETHER_HDR_SIZE + ICMP_HDR_SIZE + IP_BASE_HDR_SIZE + IP_HDR_SIZE(in_ip_head) + 8;
	}

	char *packet = (char *)malloc(packet_len);

	struct iphdr *out_ip_head = packet_to_ip_hdr(packet);
	struct ether_header *ether_head = (struct ether_header *)packet;
    ether_head->ether_type = htons(ETH_P_IP);

	struct icmphdr * icmp_head = (struct icmphdr *)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(in_ip_head));
	icmp_head->type = type;
	icmp_head->code = code;

	rt_entry_t *entry = longest_prefix_match(ntohl(in_ip_head->saddr));

    ip_init_hdr(out_ip_head, entry->iface->ip, ntohl(in_ip_head->saddr), packet_len - ETHER_HDR_SIZE, IPPROTO_ICMP);

	if (type != ICMP_ECHOREPLY) {
		memset((char*)icmp_head + ICMP_HDR_SIZE - 4, 0, 4);
		memcpy((char*)icmp_head + ICMP_HDR_SIZE, in_ip_head, IP_HDR_SIZE(in_ip_head) + 8);
	} else {
		memcpy((char*)icmp_head + ICMP_HDR_SIZE - 4,
		(char*)in_ip_head + IP_HDR_SIZE(in_ip_head) + 4,
		len - ETHER_HDR_SIZE - IP_HDR_SIZE(in_ip_head) - 4);
	}
	icmp_head->checksum = icmp_checksum(icmp_head, packet_len - ETHER_HDR_SIZE - IP_HDR_SIZE(in_ip_head));
	ip_send_packet(packet, packet_len);
}

