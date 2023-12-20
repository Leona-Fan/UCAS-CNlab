#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>

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

	
	char rbuf[1001];
	char wbuf[1024];
	int recv_len = 0;
	while(1){
		recv_len = tcp_sock_read(csk,rbuf,1000);
		if(recv_len == 0){
			fprintf(stdout, "tcp read @!\n");
			break;
		}
		else if(recv_len > 0){
			rbuf[recv_len] = '\0';
			fprintf(stdout, "server recv: %d\n",recv_len);
			fprintf(stdout, "server echoes: %s\n",rbuf);
			memcpy(wbuf,rbuf,recv_len);
			tcp_sock_write(csk,wbuf,recv_len);
			fprintf(stdout, "send back!\n");
		}else{
			break;
		}
	}
	
	sleep(5);
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

	char *wbuf = "0123456789abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int wlen = strlen(wbuf);
	char rbuf[1000];
	int recv_len = 0;
	fprintf(stdout, "start send!\n");
	for(int i = 0 ;i<10 ; i++){
		tcp_sock_write(tsk,wbuf+i,wlen-1);
		fprintf(stdout,"client send sep:%d,num:%d!\n",i,wlen);
		recv_len = tcp_sock_read(tsk,rbuf,1000);
		rbuf[recv_len] = '\0';
		fprintf(stdout,"client recv(%d): %s",recv_len,rbuf);
	}
	sleep(1);

	tcp_sock_close(tsk);

	return NULL;
}

