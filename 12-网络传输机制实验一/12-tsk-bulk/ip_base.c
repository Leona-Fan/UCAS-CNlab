#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

// #include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// initialize ip header 
void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto)
{
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(len);
	ip->id = rand();
	ip->frag_off = htons(IP_DF);
	ip->ttl = DEFAULT_TTL;
	ip->protocol = proto;
	ip->saddr = htonl(saddr);
	ip->daddr = htonl(daddr);
	ip->checksum = ip_checksum(ip);
}

// lookup in the routing table, to find the entry with the same and longest prefix.
// the input address is in host byte order
rt_entry_t *longest_prefix_match(u32 dst)
{
	//fprintf(stderr, "TODO: longest prefix match for the packet.\n");
	rt_entry_t *ptr1, *ptr2 = NULL;
	u32 max_mask = 0;
	list_for_each_entry(ptr1, &rtable, list) {
		if ((ptr1->mask & ptr1->dest) == (ptr1->mask & dst)) {
			if (ptr1->mask > max_mask) {
				ptr2 = ptr1;
				max_mask = ptr1->mask;
			}
		}
	}
	return ptr2;
}

// send IP packet
//
// Different from forwarding packet, ip_send_packet sends packet generated by
// router itself. This function is used to send ICMP packets.
void ip_send_packet(char *packet, int len)
{
	//fprintf(stderr, "TODO: send ip packet.\n");
	struct ether_header *eh = (struct ether_header*)packet;
	struct iphdr *ih = packet_to_ip_hdr(packet);
	u32 dst = ntohl(ih->daddr);
	rt_entry_t *rt_entry = longest_prefix_match(ntohl(ih -> daddr));
	if (rt_entry == NULL) {
		free(packet);
		return;
	}
	u32 next_ip;
	if (rt_entry->gw) {
		next_ip = rt_entry->gw;
	} else {
		next_ip = dst;
	}
	iface_send_packet_by_arp(rt_entry->iface, next_ip, packet, len);
}