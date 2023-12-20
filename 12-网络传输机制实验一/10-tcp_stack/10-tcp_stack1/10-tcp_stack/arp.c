#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	char * arp_packet = (char *)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));

	struct ether_header * ethhdr = (struct ether_header *)arp_packet;
	struct ether_arp * arp = (struct ether_arp *)(arp_packet + ETHER_HDR_SIZE);

	//以太网帧协议报头
	memcpy(ethhdr->ether_shost,iface->mac,ETH_ALEN);//源mac地址
	memset(ethhdr->ether_dhost,(u8)0xff,ETH_ALEN);//目的mac地址，0xff表示广播地址
	ethhdr-> ether_type = htons(ETH_P_ARP);//网络中的数据包为网络序

	//ARP报文
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = (u8)6;
	arp->arp_pln = (u8)4;
	arp->arp_op =  htons(ARPOP_REQUEST);
	memcpy(arp->arp_sha,iface->mac,ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	memset(arp->arp_tha,0,ETH_ALEN);
	arp->arp_tpa = htonl(dst_ip);
	iface_send_packet(iface,arp_packet,ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	char * arp_packet = (char *)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));

	struct ether_header * ethhdr = (struct ether_header *)arp_packet;
	struct ether_arp * arp = (struct ether_arp *)(arp_packet + ETHER_HDR_SIZE);

	//以太网帧协议报头
	memcpy(ethhdr->ether_shost,iface->mac,ETH_ALEN);//源mac地址
	memcpy(ethhdr->ether_dhost,req_hdr->arp_sha,ETH_ALEN);//目的mac地址，0xff表示广播地址
	ethhdr-> ether_type = htons(ETH_P_ARP);//网络中的数据包为网络序

	//ARP报文
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = (u8)6;
	arp->arp_pln = (u8)4;
	arp->arp_op =  htons(ARPOP_REPLY);
	memcpy(arp->arp_sha,iface->mac,ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	memcpy(arp->arp_tha,req_hdr->arp_sha,ETH_ALEN);
	arp->arp_tpa = req_hdr->arp_spa;
	iface_send_packet(iface,arp_packet,ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp * arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	if (ntohl(arp->arp_tpa) == iface->ip) {
		if (ntohs(arp->arp_op) == ARPOP_REQUEST) {
			arp_send_reply(iface, arp);
		} else if (ntohs(arp->arp_op) == ARPOP_REPLY) {
			arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
		}
	}
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
