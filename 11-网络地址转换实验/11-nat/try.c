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

void ip_str_to_u32(char *str);

int main(){
    char *str="0.0.0.224";

    u32 ip,ip2;
	ip=ntohl(inet_addr(str));
    
    //ip_str_to_u32(str);
    printf("ip:%u\n",ip);
}

void ip_str_to_u32(char *str) {
	
	int p1, p2, p3, p4;

	char *ptr1 = strchr(str, '.');
	char sp1[5] = {0};
	memcpy(sp1, str, ptr1 - str);
	p1 = atoi(sp1);
	str = ptr1 + 1;

	char *ptr2 = strchr(str, '.');
	char sp2[5] = {0};
	memcpy(sp2, str, ptr2 - str);
	p2 = atoi(sp2);
	str = ptr2 + 1;

	char *ptr3 = strchr(str, '.');
	char sp3[5] = {0};
	memcpy(sp3, str, ptr3 - str);
	p3 = atoi(sp3);
	str = ptr3 + 1;

	char *ptr4 = strchr(str, ':');
	char sp4[5] = {0};
	memcpy(sp4, str, ptr4 - str);
	p4 = atoi(sp4);
	str = ptr4 + 1;

	u32 ip;
	ip = p1 & 0xff;
	ip = (ip << 8) | (p2 & 0xff);
	ip = (ip << 8) | (p3 & 0xff);
	ip = (ip << 8) | (p4 & 0xff);

	printf("ip:%u\n",ip);
}
