#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *entry = NULL, *q;
	list_for_each_entry_safe(entry, q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(entry->list));
		free(entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&arpcache.lock);
	for(int i = 0 ;i<MAX_ARP_SIZE; i++){
		if(arpcache.entries[i].ip4 == ip4 && arpcache.entries[i].valid){
			memcpy(mac,arpcache.entries[i].mac,ETH_ALEN);
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	pthread_mutex_lock(&arpcache.lock);
	
	struct arp_req *entry = NULL;
	int find = 0;
	list_for_each_entry(entry,&(arpcache.req_list),list){
		if(entry->ip4 == ip4){
			find = 1;
			break;
		}
	}

	if(find){
		struct cached_pkt * new_packet = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
		new_packet->packet = packet;
		new_packet->len = len;
		list_add_head(&new_packet->list,&entry->cached_packets);
		entry->retries++;
	}
	else{
		struct arp_req * new_req = (struct arp_req *)malloc(sizeof(struct arp_req));
		init_list_head(&new_req->list);
		new_req->iface = (iface_info_t *) safe_malloc(sizeof(iface_info_t));
		memcpy(new_req->iface,iface,sizeof(iface_info_t));
		new_req->ip4 = ip4;
		new_req->retries = 0;
		
		struct cached_pkt * new_packet = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
		new_packet->packet = packet;
		new_packet->len = len;

		init_list_head(&new_req->cached_packets);
		list_add_head(&new_packet->list,&new_req->cached_packets);
		list_add_head(&new_req->list,&arpcache.req_list);

		arp_send_request(iface,ip4);
		new_req->sent = time(NULL);
		new_req->retries++;

	}

	pthread_mutex_unlock(&arpcache.lock);
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&arpcache.lock);
	
	int num;
	for(num = 0; num < MAX_ARP_SIZE; num++){
		if(arpcache.entries[num].valid == 0)
			break;
	}

	int replace_num = num == MAX_ARP_SIZE ? rand()%MAX_ARP_SIZE: num;

	//将新的映射填入缓存表
	arpcache.entries[replace_num].ip4 = ip4;
	memcpy(&arpcache.entries[replace_num].mac,mac,ETH_ALEN);
	arpcache.entries[replace_num].valid = 1;
	arpcache.entries[replace_num].added = time(NULL);

	//释放相应的等待序列
	int find_pending_packets;
	struct arp_req * entry;
	list_for_each_entry(entry,&arpcache.req_list,list){
		if(entry->ip4 == ip4){
			find_pending_packets = 1;
			break;
		}
	}
	
	if(find_pending_packets){
		struct cached_pkt * q,*temp;
		list_for_each_entry_safe(temp,q,&entry->cached_packets,list){
			struct ether_header * pkt_hdr = (struct ether_header *)temp->packet;
			memcpy(pkt_hdr->ether_dhost,mac,ETH_ALEN);
			pthread_mutex_unlock(&arpcache.lock);
			iface_send_packet_by_arp(entry->iface,entry->ip4,temp->packet,temp->len);
			pthread_mutex_lock(&arpcache.lock);
			list_delete_entry(&temp->list);
			free(temp);
		}

		list_delete_entry(&entry->list);
		free(entry);
	}

	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	
	while (1) {
		sleep(1);
		pthread_mutex_lock(&arpcache.lock);
		//对IP-MAC条目表映射的操作
		for(int i = 0; i<MAX_ARP_SIZE;i++){
			if(time(NULL) - arpcache.entries[i].added > 15 && arpcache.entries[i].valid){
				arpcache.entries[i].valid = 0;
			}
		}
		
		struct arp_req * req_entry,*q;
		req_entry = q = NULL;
		list_for_each_entry_safe(req_entry,q,&arpcache.req_list,list){
			//检查等待的数据包，等待时间超过一秒钟则重发
			if(time(NULL) - req_entry->sent > 1 && req_entry->retries < 5){
				arp_send_request(req_entry->iface,req_entry->ip4);
				req_entry->sent = time(NULL);
				req_entry->retries++;
			}
			//如果重发次数超过5次则抛弃这些数据包，发送icmp包不可达
			else if(req_entry->retries >= 5){
				struct cached_pkt * pkt_entry,*q;
				pkt_entry = q = NULL;
				list_for_each_entry_safe(pkt_entry,q,&req_entry->cached_packets,list){
					pthread_mutex_unlock(&arpcache.lock);
					icmp_send_packet(pkt_entry->packet,pkt_entry->len,ICMP_DEST_UNREACH,ICMP_HOST_UNREACH);
					pthread_mutex_lock(&arpcache.lock);
					list_delete_entry(& pkt_entry->list);
					free(pkt_entry->packet);
					free(pkt_entry);
				}
				list_delete_entry(&req_entry->list);
				free(req_entry);
			}
			
		}
		pthread_mutex_unlock(&arpcache.lock);
	}

	return NULL;
}
