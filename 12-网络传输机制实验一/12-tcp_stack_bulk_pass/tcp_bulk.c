#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>

// tcp server application, listens to port (specified by arg), serves only one
// connection request: receives data from client and writes the data to local file
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	// printf("alloc ok\n");

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	// printf("bind ok\n");

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	// printf("-----check: server have established\n");

	char *ofile_name = "server-output.dat";
	FILE *ofile = fopen(ofile_name, "w+");
	if (!ofile) {
		log(ERROR, "could not open %s to write.", ofile_name);
		exit(-1);
	}

	char buffer[65536];
	int rlen, wlen, total = 0;
	while (1) {
		rlen = tcp_sock_read(csk, buffer, sizeof(buffer)); // read from ring buffer
		if (rlen < 0)
			break;
		// printf("%dB\n", rlen);
		// printf("buffer: %s\n", buffer);
		// now the point is here: whether the buffer is empty or fwrite is wrong?
		wlen = fwrite(buffer, 1, rlen, ofile); // write into the file
		fflush(ofile);  // 刷新文件缓冲区
		// printf("%dB ok\n", wlen);
		// total += wlen;
	}

	// printf("-----check: server have recieved\n");
	// sleep(1);
	fclose(ofile);

	// log(DEBUG, "received %d bytes of data.", total);

	printf("hi\n");

	tcp_sock_close(csk);

	printf("here\n");
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), and sends a file to it
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	printf("-----check: client have established\n");

	char *ifile_name = "client-input.dat";
	FILE *ifile = fopen(ifile_name, "rb");
	if (!ifile) {
		log(ERROR, "could not open file: %s.", ifile_name);
		exit(-1);
	}

	char buffer[65536];
	int ret, len, total = 0;
	int cnt = 0;
	while (1) {
		// cnt ++;
		// printf("%d\n", cnt);
		if ((len = fread(buffer, 1, sizeof(buffer), ifile)) <= 0) // read from file
			break;

		if ((ret = tcp_sock_write(tsk, buffer, len)) < 0) { // write into ring buffer
			// log(ERROR, "could not send all data, total = %d.\n", total);
			break;
		}
		// printf("%dB\n", ret);

		// total += len;
	}
	// printf("cnt: %d\n", cnt);

	printf("-----check: transmited\n");

	// if (ret > 0)
	// 	log(INFO, "all data has been sent to server, total = %d.", total);
	// else
	// 	log(ERROR, "there is something wrong.");

	tcp_sock_close(tsk);

	return NULL;
}
