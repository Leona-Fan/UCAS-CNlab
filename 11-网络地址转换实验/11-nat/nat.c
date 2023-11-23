#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	//fprintf(stdout, "TODO: determine the direction of this packet.\n");
	struct iphdr *iphdr = packet_to_ip_hdr(packet);
	rt_entry_t *match = longest_prefix_match(ntohl(iphdr->saddr));

	if (match->iface->index == nat.internal_iface->index) {
		return DIR_OUT;
	} else if (match->iface->index == nat.external_iface->index) {
		return DIR_IN;
	}

	return DIR_INVALID;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	//fprintf(stdout, "TODO: do translation for this packet.\n");
	pthread_mutex_lock(&nat.lock);
	struct iphdr *iphdr = packet_to_ip_hdr(packet);
	struct tcphdr *tcphdr = packet_to_tcp_hdr(packet);

	// Get hash addr.
	u32 addr = (dir == DIR_IN)? ntohl(iphdr->saddr) : ntohl(iphdr->daddr);
	u16 port = (dir == DIR_IN)? ntohs(tcphdr->sport) : ntohs(tcphdr->dport);
	rmt_set_t rs;
	rs.ip = addr;
	rs.port = port;
	u8 hash = hash8((char*)&rs, sizeof(rmt_set_t));
	if (dir == DIR_IN) {
		int found = 0;
		struct list_head *head = &(nat.nat_mapping_list[hash]);
		struct nat_mapping *map;
		struct nat_mapping *new_mapping = (struct nat_mapping*)malloc(sizeof(struct nat_mapping));

		list_for_each_entry(map, head, list) {
			if (map->external_ip == ntohl(iphdr->daddr) && map -> external_port == ntohs(tcphdr->dport)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			struct dnat_rule *rule;
			list_for_each_entry(rule, &nat.rules, list) {
				if (nat.assigned_ports[rule->external_port] == 0 && rule->external_ip == ntohl(iphdr->daddr) \
					&& rule->external_port == ntohs(tcphdr->dport)) {
						nat.assigned_ports[rule->external_port] = 1;
						new_mapping->external_ip = rule->external_ip;
						new_mapping->external_port = rule->external_port;
						new_mapping->internal_ip = rule->internal_ip;
						new_mapping->internal_port = rule->internal_port;
						list_add_tail(&(new_mapping->list), head);
						map = new_mapping;
						break;
				}
			}
		}

		tcphdr->dport = htons(map->internal_port);
		iphdr->daddr = htonl(map->internal_ip);

		map->conn.external_seq_end = tcphdr->seq;
		if (tcphdr->flags == TCP_ACK) {
			map->conn.external_ack = tcphdr->ack;
		}
		map->conn.external_fin = (tcphdr->flags == TCP_FIN)? TCP_FIN : 0;
		map->update_time = time(NULL);
	} else if (dir == DIR_OUT) {
		int found = 0;
		struct list_head *head = &(nat.nat_mapping_list[hash]);
		struct nat_mapping *map;
		struct nat_mapping *new_mapping = (struct nat_mapping*)malloc(sizeof(struct nat_mapping));

		list_for_each_entry(map, head, list) {
			if (map->internal_ip == ntohl(iphdr->saddr) && map->internal_port == ntohs(tcphdr->sport)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			int i;
			for (i = NAT_PORT_MIN; i < NAT_PORT_MAX; i++) {
				if (nat.assigned_ports[i] == 0) {
					nat.assigned_ports[i] = 1;
					break;
				}
			}
			
			if (i == NAT_PORT_MAX) {
				perror("No available port!\n");
			}

			new_mapping->external_ip = nat.external_iface->ip;
			new_mapping->external_port = i;
			new_mapping->internal_ip = ntohl(iphdr->saddr);
			new_mapping->internal_port = ntohs(tcphdr->sport);
			
			list_add_tail(&(new_mapping->list), head);
			map = new_mapping;

		}

		iphdr->saddr = htonl(map->external_ip);
		tcphdr->sport = htons(map->external_port);

		map->conn.external_seq_end = tcphdr->seq;
		if (tcphdr->flags == TCP_ACK) {
			map->conn.external_ack = tcphdr->ack;
		}
		map->conn.external_fin = (tcphdr->flags == TCP_FIN)? TCP_FIN : 0;

		map->update_time = time(NULL);
	}
	
	iphdr->checksum = ip_checksum(iphdr);
	tcphdr->checksum = tcp_checksum(iphdr, tcphdr);

	pthread_mutex_unlock(&nat.lock);
	
	ip_send_packet(packet, len);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
    return (conn->internal_fin && conn->external_fin) && \
            (conn->internal_ack >= conn->external_seq_end) && \
            (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while (1) {
		//fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		pthread_mutex_lock(&nat.lock);
		time_t now = time(NULL);
		for (int i = 0; i < HASH_8BITS; i++) {
			struct list_head *head = &(nat.nat_mapping_list[i]);
			if (!list_empty(head)) {
				struct nat_mapping *cur = NULL, *next;
				list_for_each_entry_safe(cur, next, head, list) {
					if (now - cur->update_time > TCP_ESTABLISHED_TIMEOUT || is_flow_finished(&(cur->conn))) {
						nat.assigned_ports[cur->external_port] = 0;
						list_delete_entry(&(cur->list));
						free(cur);
					} 
				}
			}
		}
		pthread_mutex_unlock(&nat.lock);
		sleep(1);
	}

	return NULL;
}

int parse_config(const char *filename)
{
	//fprintf(stdout, "TODO: parse config file, including i-iface, e-iface (and dnat-rules if existing).\n");
    char line[256];
    FILE *fp = fopen(filename, "rb");
    char type[128], name[128], exter[64], inter[64];
    while (!feof(fp) && !ferror(fp)) {
        strcpy(line, "\n");
        fgets(line, sizeof(line), fp);
        if (line[0] == '\n') break;
        sscanf(line, "%s %s", type, name);
        type[14] = '\0';
        if (strcmp(type, "internal-iface") == 0) {
            printf("Internal-iface: %s .\n", name);
            nat.internal_iface = if_name_to_iface(name);
        } 
		else if (strcmp(type, "external-iface") == 0) {
            printf("External-iface: %s .\n", name);
            nat.external_iface = if_name_to_iface(name);
        } 
		else printf("config iface failed : %s .\n", type);
    }
    u32 ip4, ip3, ip2, ip1, ip;
    u16 port;
    while (!feof(fp) && !ferror(fp)) {
        strcpy(line, "\n");
        fgets(line, sizeof(line), fp);
        if (line[0] == '\n') break;
        sscanf(line, "%s %s %s %s", type, exter, name, inter);
        type[10] = '\0';
        if (strcmp(type, "dnat-rules") == 0) {
            printf("[Dnat] Loading rule item : %s to %s.\n", exter, inter);
            struct dnat_rule *rule = (struct dnat_rule*)malloc(sizeof(struct dnat_rule));
            list_add_tail(&rule->list, &nat.rules);

            sscanf(exter, "%[^:]:%hu", name, &port);
            sscanf(name, "%u.%u.%u.%u", &ip4, &ip3, &ip2, &ip1);
            ip = (ip4 << 24) | (ip3 << 16) | (ip2 << 8) | (ip1);
            rule->external_ip = ip;
            rule->external_port = port;
            printf("External ip(u32) : %08x ; port : %hu\n", ip, port);

            sscanf(inter, "%[^:]:%hu", name, &port);
            sscanf(name, "%u.%u.%u.%u", &ip4, &ip3, &ip2, &ip1);
            ip = (ip4 << 24) | (ip3 << 16) | (ip2 << 8) | (ip1);
            rule->internal_ip = ip;
            rule->internal_port = port;
            printf("Internal ip(us3) : %08x ; port : %hu\n", ip, port);
        }
        else printf("config rules failed : %s .\n", type);
    }
    return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	//fprintf(stdout, "TODO: release all resources allocated.\n");
	pthread_mutex_lock(&nat.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		struct nat_mapping *entry, *q;
		list_for_each_entry_safe(entry, q, &nat.nat_mapping_list[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}

	pthread_kill(nat.thread, SIGTERM);
	pthread_mutex_unlock(&nat.lock);
}
