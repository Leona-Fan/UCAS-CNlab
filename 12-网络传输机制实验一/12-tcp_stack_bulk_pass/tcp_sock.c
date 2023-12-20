#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"


/*

梳理一下这个文件里的函数：
会直接被服务器和客户端调用的函数有：
struct tcp_sock *alloc_tcp_sock()
int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr) // todo
int tcp_sock_listen(struct tcp_sock *tsk, int backlog) // todo
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk) // todo
void tcp_sock_close(struct tcp_sock *tsk) // todo

出入listen table & established table：
int tcp_hash(struct tcp_sock *tsk)
void tcp_unhash(struct tcp_sock *tsk)

出入bind table：
static int tcp_bind_hash(struct tcp_sock *tsk)
void tcp_bind_unhash(struct tcp_sock *tsk)

状态转移：
inline void tcp_set_state(struct tcp_sock *tsk, int state)

初始化三张表和老化线程：
void init_tcp_stack()

给ref_cnt减一：
void free_tcp_sock(struct tcp_sock *tsk) // todo

对于新到达的数据包，查找sock：
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport) // todo
struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport) // todo
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)

设置端口：
static int tcp_port_in_use(u16 sport)
static u16 tcp_get_port()
static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)


这三个函数是tcp_sock_accept需要调用的，判断队满、入队、出队：
inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)

*/

// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table	tcp_sock_table.established_table
#define tcp_listen_sock_table		tcp_sock_table.listen_table
#define tcp_bind_sock_table			tcp_sock_table.bind_table

inline void tcp_set_state(struct tcp_sock *tsk, int state)
{
	log(DEBUG, IP_FMT":%hu switch state, from %s to %s.", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, \
			tcp_state_str[tsk->state], tcp_state_str[state]);
	// printf("why into here?\n");
	tsk->state = state;
}

// init tcp hash table and tcp timer
void init_tcp_stack()
{
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_established_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_listen_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_bind_sock_table[i]);

	pthread_t timer;
	pthread_create(&timer, NULL, tcp_timer_thread, NULL);
}

// allocate tcp sock, and initialize all the variables that can be determined
// now
struct tcp_sock *alloc_tcp_sock()
{
	struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));

	memset(tsk, 0, sizeof(struct tcp_sock));

	// tsk->state = TCP_CLOSED;
	tsk->rcv_wnd = 65535;//TCP_DEFAULT_WINDOW;
	// printf("tsk->rcv_wnd: %d\n", tsk->rcv_wnd);

	init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);

	
	init_list_head(&tsk->retrans_timer.list);
	init_list_head(&tsk->send_buf);
    init_list_head(&tsk->rcv_ofo_buf);
	pthread_mutex_init(&tsk->send_lock, NULL);
    pthread_mutex_init(&tsk->count_lock, NULL);
	tsk->send_buf_count = 0;

	// printf("alloc over 1\n");

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);

	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();

	// printf("alloc over 2\n");


	tcp_set_retrans_timer(tsk);

	// printf("alloc over 3\n");

	return tsk;
}

// release all the resources of tcp sock
//
// To make the stack run safely, each time the tcp sock is refered (e.g. hashed), 
// the ref_cnt is increased by 1. each time free_tcp_sock is called, the ref_cnt
// is decreased by 1, and release the resources practically if ref_cnt is
// decreased to zero.
void free_tcp_sock(struct tcp_sock *tsk) // in
{
	// 给传进来的tsk的ref_cnt减一
	// 如果此时正好减到0了，释放套接字和其指针元素指向的内容
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk -> ref_cnt --;
	if (tsk -> ref_cnt == 0) { // 这里yxy用的是<=，不知道有什么道理 aftermath
		// 这里直接free应该也完全ok，只不过编译的时候会有区别
		free_wait_struct(tsk -> wait_connect);
		free_wait_struct(tsk -> wait_accept);
		free_wait_struct(tsk -> wait_recv);
		free_wait_struct(tsk -> wait_send);
		pthread_mutex_destroy(&tsk -> rcv_buf -> lock);
		free_ring_buffer(tsk -> rcv_buf);
		free(tsk);
	}
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport) // in
{
	// 在establish_table里查找对应四元组的套接字并返回，如果没查到就返回空
	// 遍历established_table，如果查到了就直接返回，如果没查到最后再返回NULL
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	int hashval = tcp_hash_function(saddr, daddr, sport, dport);
	// printf("lookup in established table for hashval %d of %u, %u, %u, %u\n", hashval, saddr, daddr, sport, dport);
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, &tcp_established_sock_table[hashval], hash_list) {
		if (saddr == tsk->sk_sip && daddr == tsk->sk_dip && sport == tsk->sk_sport && dport == tsk->sk_dport) {
			return tsk;
		}
	}
	return NULL;
}

// lookup tcp sock in listen_table with key (sport)
//
// In accordance with BSD socket, saddr is in the argument list, but never used.
struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport) // in
{
	// 在listen_table里查找对应四元组的套接字并返回，如果没查到就返回空
	// 这里之所以只需要源端口，是因为监听中的套接字本来也只有源(ip, port)，然后这个实验里的哈希表要求只用sport
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	int hashval = tcp_hash_function(0, sport, 0, 0);
	// printf("lookup in listen table for hashval %d of sport %u\n", hashval, sport);
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, &tcp_listen_sock_table[hashval], hash_list) {
		if (sport == tsk->sk_sport) {
			return tsk;
		}
	}
	return NULL;
}

// lookup tcp sock in both established_table and listen_table
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)
{
	// 传进来的参数是一个数据包的控制块
	// 先提取四元组
	// 调用tcp_sock_lookup_established查找对应的tsk
	// 如果没查到，调用tcp_sock_lookup_listen查找对应的tsk
	// 返回这个tsk
	u32 saddr = cb->daddr,
		daddr = cb->saddr;
	u16 sport = cb->dport,
		dport = cb->sport;

	struct tcp_sock *tsk = tcp_sock_lookup_established(saddr, daddr, sport, dport);
	if (!tsk) {
		tsk = tcp_sock_lookup_listen(saddr, sport);
	}

	return tsk;
}

// hash tcp sock into bind_table, using sport as the key
static int tcp_bind_hash(struct tcp_sock *tsk)
{
	int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list = &tcp_bind_sock_table[bind_hash_value];
	list_add_head(&tsk->bind_hash_list, list);

	tsk->ref_cnt += 1;

	return 0;
}

// unhash the tcp sock from bind_table
void tcp_bind_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->bind_hash_list)) {
		list_delete_entry(&tsk->bind_hash_list);
		free_tcp_sock(tsk);
	}
}

// lookup bind_table to check whether sport is in use
static int tcp_port_in_use(u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_bind_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, bind_hash_list) {
		if (tsk->sk_sport == sport)
			return 1;
	}

	return 0;
}

// find a free port by looking up bind_table
static u16 tcp_get_port()
{
	for (u16 port = PORT_MIN; port < PORT_MAX; port++) {
		if (!tcp_port_in_use(port))
			return port;
	}

	return 0;
}

// tcp sock tries to use port as its source port
static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)
{
	// 若port已经被占用，返回错误
	// 否则将该port设置为套接字的port
	// 将套接字hash进bind table
	if ((port && tcp_port_in_use(port)) ||
			(!port && !(port = tcp_get_port())))
		return -1;

	tsk->sk_sport = port;

	tcp_bind_hash(tsk);

	return 0;
}

// hash tcp sock into either established_table or listen_table according to its
// TCP_STATE
int tcp_hash(struct tcp_sock *tsk)
{
	struct list_head *list;
	int hash;

	if (tsk->state == TCP_CLOSED)
		return -1;

	if (tsk->state == TCP_LISTEN) {
		hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
		list = &tcp_listen_sock_table[hash];
		// printf("have hashed a listen sk of hashval %d of sport %u\n", hash, tsk->sk_sport);
	}
	else {
		int hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip, \
				tsk->sk_sport, tsk->sk_dport); 
		list = &tcp_established_sock_table[hash];
		// printf("have hashed a sk of hashval %d of %u, %u, %u, %u \n", hash, tsk->sk_sip, tsk->sk_dip, tsk->sk_sport, tsk->sk_dport);

		struct tcp_sock *tmp;
		list_for_each_entry(tmp, list, hash_list) {
			if (tsk->sk_sip == tmp->sk_sip &&
					tsk->sk_dip == tmp->sk_dip &&
					tsk->sk_sport == tmp->sk_sport &&
					tsk->sk_dport == tmp->sk_dport)
				return -1;
		}
	}

	list_add_head(&tsk->hash_list, list);
	tsk->ref_cnt += 1;

	return 0;
}

// unhash tcp sock from established_table or listen_table
void tcp_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->hash_list)) {
		list_delete_entry(&tsk->hash_list);
		free_tcp_sock(tsk);
	}
}

// XXX: skaddr here contains network-order variables
int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	int err = 0;

	// omit the ip address, and only bind the port
	err = tcp_sock_set_sport(tsk, ntohs(skaddr->port));

	return err;
}

// connect to the remote tcp sock specified by skaddr
//
// XXX: skaddr here contains network-order variables
// 1. initialize the four key tuple (sip, sport, dip, dport);
// 2. hash the tcp sock into bind_table;
// 3. send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
//    SYN packet by sleep on wait_connect;
// 4. if the SYN packet of the peer arrives, this function is notified, which
//    means the connection is established.
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	// 初始化四元组
	// 将套接字放进bind_table？？？为什么不是established table是不是写错了 aftermath
	// 发送SYN
	// 转移到SYN_SENT状态，再wait_connect上睡到收到SYN
	// 收到SYN后将状态转移到ESTABLISHED状态
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk -> sk_dip = ntohl(skaddr -> ip); // 这里要把网络字节序转换成本地字节序？？？为什么啊这是本地参数啊
	tsk -> sk_dport = ntohs(skaddr -> port);
	tsk -> sk_sip = ((iface_info_t*)(instance -> iface_list.next)) -> ip;// 等会儿再看
	if (tcp_sock_set_sport(tsk, 0) < 0) {
		printf("No available port!\n");
		return -1;
	}

	tsk -> snd_nxt = tsk -> iss = tcp_new_iss();

	// tcp_hash(tsk); // 这一部分和yxy的顺序不一样 aftermath
	tcp_send_control_packet(tsk, TCP_SYN);
	// printf("ok0\n");
	// fflush(stdout);
	tcp_set_state(tsk, TCP_SYN_SENT);
	tcp_hash(tsk);
	sleep_on(tsk -> wait_connect); //////
	tcp_set_state(tsk, TCP_ESTABLISHED);
	// tcp_hash(tsk);
	// printf("ok1\n");
	// fflush(stdout);
	tcp_send_control_packet(tsk, TCP_ACK);
	// printf("ok2\n");
	// fflush(stdout);



	return 0;
}

// set backlog (the maximum number of pending connection requst), switch the
// TCP_STATE, and hash the tcp sock into listen_table
int tcp_sock_listen(struct tcp_sock *tsk, int backlog)
{
	// 设置backlog？
	// 将状态转移到LISTEN
	// 将tsk添加到listen_table
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk -> backlog = backlog;
	tsk -> state = TCP_LISTEN;
	return tcp_hash(tsk);
}

// check whether the accept queue is full
inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
{
	if (tsk->accept_backlog >= tsk->backlog) {
		log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
		return 1;
	}

	return 0;
}

// push the tcp sock into accept_queue
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_delete_entry(&tsk->list);
	list_add_tail(&tsk->list, &tsk->parent->accept_queue);
	tsk->parent->accept_backlog += 1;
}

// pop the first tcp sock of the accept_queue
inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->accept_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);
	tsk->accept_backlog -= 1;

	return new_tsk;
}

// if accept_queue is not emtpy, pop the first tcp sock and accept it,
// otherwise, sleep on the wait_accept for the incoming connection requests
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk) // 参数是父tsk，返回值是接收的子tsk
{
	// 如果队列非空，弹出一个并接收，否则睡到收到请求建立的数据包
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	// printf("into accept\n");
	while(list_empty(&tsk->accept_queue)){
		sleep_on(tsk -> wait_accept);
	}
	// printf("into accept\n");
	// return tcp_sock_accept_dequeue(tsk);
	struct tcp_sock * pop_stack;
	if ((pop_stack = tcp_sock_accept_dequeue(tsk)) != NULL) {
		pop_stack->state = TCP_ESTABLISHED;
		tcp_hash(pop_stack);
		return pop_stack;
	} else {
		return NULL;
	}
}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
void tcp_sock_close(struct tcp_sock *tsk) // 这个tsk一定是主动建立连接的一方client
{
	// 如果是被动断开连接，可能调用close的时候还没收到FIN，要忙等一下
	// 发送FIN
	// 如果是主动断开连接，从 ESTABLISHED 进入 TCP_FIN_WAIT_1；
	// 如果是被动断开连接，从 CLOSE_WAIT 进入 TCP_LAST_ACK
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	while (tsk -> parent) { // 如果是主动建立连接的一方，要忙等自己的状态变到CLOSE_WAIT
							// 也就是默认主动建立连接的一方只能被动断开连接？？
		 while (tsk -> state != TCP_CLOSE_WAIT); // 不知道为什么yxy这么写 aftermath
	}
	if (tsk -> state == TCP_ESTABLISHED) {
		tcp_set_state(tsk, TCP_FIN_WAIT_1);
		// printf("a?\n");
		tcp_send_control_packet(tsk, TCP_FIN| TCP_ACK); // yxy是先转移状态再发送 aftermath
		// printf("send a FIN\n");
		// if (!tsk->parent) {
		// 	tcp_bind_unhash(tsk);
		// 	printf("here?\n");
		// }
		// tcp_unhash(tsk);

	} else if (tsk -> state == TCP_CLOSE_WAIT) {
		tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
		tcp_set_state(tsk, TCP_LAST_ACK);
	}
}



















void tcp_sndbuf_push(struct tcp_sock *tsk, char *packet, int size) 
{
    char *temp = (char *) malloc(sizeof(char) * size);
    memcpy(temp, packet, sizeof(char) * size);
    struct send_buffer *buf = (struct send_buffer *) malloc(sizeof(struct send_buffer));
    buf->packet = temp;
    buf->len = size;
    buf->seq_end = tsk->snd_nxt;
    buf->times = 1;
    buf->timeout = TCP_RETRANS_INTERVAL_INITIAL;
    pthread_mutex_lock(&tsk->send_lock);
    list_add_tail(&buf->list, &tsk->send_buf);
    pthread_mutex_unlock(&tsk->send_lock);
    pthread_mutex_lock(&tsk->count_lock);
    tsk->send_buf_count++;
    pthread_mutex_unlock(&tsk->count_lock);
}

void tcp_sndbuf_pop(struct tcp_sock *tsk, struct send_buffer *buf) 
{
    pthread_mutex_lock(&tsk->send_lock);
    list_delete_entry(&buf->list);
    free(buf->packet);
    free(buf);
    pthread_mutex_unlock(&tsk->send_lock);
    pthread_mutex_lock(&tsk->count_lock);
    tsk->send_buf_count--;
    pthread_mutex_unlock(&tsk->count_lock);
}