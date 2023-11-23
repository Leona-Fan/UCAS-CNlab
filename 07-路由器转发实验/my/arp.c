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
	//fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	char *request_packet = (char *)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	// Ethernet header
	struct ether_header *eth_header = (struct ether_header *)request_packet;
	memcpy(eth_header->ether_shost, iface->mac, ETH_ALEN);
	memset(eth_header->ether_dhost, 0xFF, ETH_ALEN);
	eth_header->ether_type = htons(ETH_P_ARP);

	struct ether_arp *arp = (struct ether_arp *)(request_packet + ETHER_HDR_SIZE);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = 6;
	arp->arp_pln = 4;
	arp->arp_op  = htons(ARPOP_REQUEST);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	memset(arp->arp_tha, 0, ETH_ALEN);
	arp->arp_tpa = htonl(dst_ip);
	iface_send_packet(iface, request_packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	//fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
	char *reply_packet = (char *)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	// Ethernet header
	struct ether_header *eth_header = (struct ether_header *)reply_packet;
	memcpy(eth_header->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	memcpy(eth_header->ether_shost, iface->mac, ETH_ALEN);
	eth_header->ether_type = htons(ETH_P_ARP);
	// ARP packet
	struct ether_arp *eth_arp = (struct ether_arp *)(reply_packet + ETHER_HDR_SIZE);
	eth_arp->arp_hrd = htons(ARPHRD_ETHER);
	eth_arp->arp_pro = htons(ETH_P_IP);
	eth_arp->arp_hln = 6;
	eth_arp->arp_pln = 4;
	eth_arp->arp_op  = htons(ARPOP_REPLY);
	memcpy(eth_arp->arp_sha, iface->mac, ETH_ALEN);
	eth_arp->arp_spa = htonl(iface->ip);
	memcpy(eth_arp->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	eth_arp->arp_tpa = req_hdr->arp_spa;

	iface_send_packet(iface, reply_packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	//fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	struct ether_arp *eth_arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);

	if (ntohl(eth_arp->arp_tpa) == iface->ip) {
		if(ntohs(eth_arp->arp_op) == ARPOP_REPLY){
			arpcache_insert(ntohl(eth_arp -> arp_spa), eth_arp->arp_sha);
		}
		else if(ntohs(eth_arp->arp_op) == ARPOP_REQUEST){
			arp_send_reply(iface, eth_arp);
		}
		else{
			free(packet);
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
