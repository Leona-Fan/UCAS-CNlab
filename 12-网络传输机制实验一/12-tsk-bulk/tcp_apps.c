#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>
#define SIZE 10000000
// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	FILE *fp = fopen("server-output.dat", "w+");
	char buf_read[1000];
	int len_read, len_write;
	while(1)
	{
		len_read = tcp_sock_read(csk, buf_read, sizeof(buf_read));
		if(len_read == 0) break;
		else if(len_read > 0) len_write = fwrite(buf_read, sizeof(char), len_read, fp);
		else break;	// if(len_read < 0)
	}
	fclose(fp);

	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	FILE *fp = fopen("client-input.dat", "r");
	char *data = (char *)malloc(SIZE);
	int data_len = 0;
	while((data[data_len++] = fgetc(fp)) != EOF);
	data_len--;
	tcp_sock_write(tsk, data, data_len);
	free(data);
	tcp_sock_close(tsk);

	return NULL;
}
