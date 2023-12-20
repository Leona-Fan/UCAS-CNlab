#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}







void write_ofo_buffer(struct tcp_sock *tsk, struct tcp_cb *cb) 
{
    struct ofo_buffer *buf = (struct ofo_buffer*)malloc(sizeof(struct ofo_buffer));
    buf->tsk = tsk;
    buf->seq = cb->seq;
    buf->seq_end = cb->seq_end;
    buf->pl_len = cb->pl_len;
    buf->payload = (char*)malloc(buf->pl_len);
    memcpy(buf->payload, cb->payload, buf->pl_len);
    struct ofo_buffer head_ext;
    head_ext.list = tsk->rcv_ofo_buf;
    int insert = 0;
    struct ofo_buffer *pos, *last = &head_ext;
    list_for_each_entry(pos, &tsk->rcv_ofo_buf, list) 
	{
        if (cb->seq > pos->seq) 
		{
            last = pos;
            continue;
        } 
		else if (cb->seq == pos->seq) return;
        list_insert(&buf->list, &last->list, &pos->list);
        insert = 1;
        break;
    }
    if (!insert) 
		list_add_tail(&buf->list, &tsk->rcv_ofo_buf);
}





// Process the incoming packet according to TCP state machine. 
// void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
// {
// 	// 通过状态机的状态来处理TCP数据包
// 	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
// 		// TODO: implement %s please.\n, __FUNCTION__
// 	if (!tsk) {
// 	    printf("No corresponding tsk record!!!\n");
//         return;
// 	}
//     printf("recieve a packet with seq: %d ack: %d flags: %u\n", cb->seq, cb->ack, cb->flags);

// 	switch (cb->flags) {
//         case TCP_SYN:
//             // printf("recieve a SYN\n");
//             if (tsk->state == TCP_LISTEN) {
//                 fflush(stdout);
//                 struct tcp_sock *csk = alloc_tcp_sock();
//                 list_add_tail(&csk->list, &tsk->listen_queue);
//                 csk->sk_sip = cb->daddr;
//                 csk->sk_dip = cb->saddr;
//                 csk->sk_dport =cb->sport;
//                 csk->sk_sport = cb->dport;
//                 csk->parent = tsk;
//                 csk->iss = tcp_new_iss();
//                 csk->snd_una = tsk->snd_una;
//                 csk->rcv_nxt = tsk->rcv_nxt;
//                 csk->snd_nxt = tsk->iss;
//                 struct sock_addr *skaddr = (struct sock_addr*)malloc(sizeof(struct sock_addr));
//                 skaddr->ip = htonl(cb->daddr);
//                 skaddr->port = htons(cb->dport);
//                 tcp_sock_bind(csk, skaddr);
//                 tcp_set_state(csk, TCP_SYN_RECV);
//                 tcp_hash(csk);
//                 tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
//                 // if (csk)
//                 //     printf("send a SYN | ACK\n");
//             } else printf("Recv SYN but current state is %d", tsk->state);
//             break;
// 	    case (TCP_SYN | TCP_ACK):
//             // printf("recieve a SYN | ACK\n");
// 	        if (tsk->state == TCP_SYN_SENT) {
// 	            wake_up(tsk->wait_connect);
// 	        }
//             break;
//         case TCP_ACK:
//             // printf("recieve a ACK\n");
//             switch (tsk->state) {
//                 case TCP_SYN_RECV:
//                     tcp_sock_accept_enqueue(tsk);
//                     wake_up(tsk->parent->wait_accept);
//                     tcp_set_state(tsk, TCP_ESTABLISHED);
//                     break;
//                 case TCP_ESTABLISHED:
//                     printf("tsk->state: %d\n", tsk->state);
//                     printf("recieve a ACK in ESTABLISHED\n");
//                     wake_up(tsk->wait_send);
//                     break;
//                 case TCP_FIN_WAIT_1:
//                     printf("recieve a ACK in FIN-WAIT-1\n");
//                     tcp_set_state(tsk, TCP_FIN_WAIT_2);
//                     break;
//                 case TCP_LAST_ACK:
//                     tcp_set_state(tsk, TCP_CLOSED);
//                     if (!tsk->parent) tcp_bind_unhash(tsk);
//                     tcp_unhash(tsk);
//                     break;
//                 default: printf("Unset state for ACK %d\n", tsk->state);
//             }
//             break;
//         case (TCP_ACK | TCP_FIN):
//             // printf("recieve a ACK | FIN\n");
//             if (tsk->state == TCP_FIN_WAIT_1) {
//                 tcp_set_state(tsk, TCP_TIME_WAIT);
//                 tcp_send_control_packet(tsk, TCP_ACK);
//                 tcp_set_timewait_timer(tsk);
//             } else printf("Recv ACK | FIN but current state is %d", tsk->state);
//             break;
//         case TCP_FIN:
//             // printf("recieve a FIN\n");
//             switch (tsk->state) {
//                 case TCP_ESTABLISHED:
//                     tcp_set_state(tsk, TCP_LAST_ACK);
//                     printf("tsk->state: %d\n", tsk->state);
//                     tcp_send_control_packet(tsk, TCP_ACK | TCP_FIN);
//                     break;
//                 case TCP_FIN_WAIT_2:
//                     tcp_set_state(tsk, TCP_TIME_WAIT);
//                     tcp_send_control_packet(tsk, TCP_ACK);
//                     tcp_set_timewait_timer(tsk);
//                     break;
//                 default: printf("Unset state for FIN %d\n", tsk->state);
//             }
//             break;
//         case (TCP_PSH | TCP_ACK):
//             // printf("recieve a PSH | ACK\n");
//             if (tsk->state == TCP_ESTABLISHED) {

//                 printf("-----check: get data\n");
                
//                 // pthread_mutex_lock(&tsk -> rcv_buf -> lock);
//                 // write_ring_buffer(tsk -> rcv_buf, cb -> payload, cb -> pl_len);
//                 // pthread_mutex_unlock(&tsk -> rcv_buf -> lock);

//                 // if seq == rcv_nxt, then write into ring buf, add 1 to rec_nxt, 
//                 // check if there is one in ofo buf that seq == rcv_nxt, get it from ofo buf and write into ring buf
//                 // otherwise, put it into ofo buf

//                 pthread_mutex_lock(&tsk->rcv_buf->lock);
//                 while (cb -> pl_len <= 0 || ring_buffer_free(tsk -> rcv_buf) < cb -> pl_len) {
//                     pthread_mutex_unlock(&tsk -> rcv_buf -> lock);
//                     // printf("wait\n");
//                     // sleep_on(tsk -> wait_send); // sleep on send, it will wake up in stack
//                     // printf("size = %d\nring_buffer_free(rbuf) = %d\n", cb -> pl_len, ring_buffer_free(tsk -> rcv_buf));
//                     pthread_mutex_lock(&tsk -> rcv_buf -> lock);
//                 }
//                 printf("here\n");
//                 printf("cb -> seq : %d tsk -> rcv_nxt : %d\n", cb -> seq, tsk -> rcv_nxt);
//                 // my newly add
//                 if (cb -> seq == tsk -> rcv_nxt) {
//                     write_ring_buffer(tsk -> rcv_buf, cb -> payload, cb -> pl_len);
//                     // printf("tsk -> rcv_nxt : %d\n", tsk -> rcv_nxt);
//                     struct ofo_packet *pos = NULL, *q = NULL;
//                     list_for_each_entry_safe(pos, q, &tsk -> rcv_ofo_buf, list) {
//                         printf("hi\n");
//                         if (pos -> cb.seq == tsk -> rcv_nxt) {
//                             write_ring_buffer(tsk -> rcv_buf, cb -> payload, cb -> pl_len); // write into ring buffer
//                             list_delete_entry(&(pos->list)); // delete it
//                             free(pos);
//                         }
//                     }





//                     printf("here?\n");
//                 } else {
//                     struct ofo_packet *new_ofo = (struct ofo_packet*)malloc(sizeof(struct ofo_packet));
//                     new_ofo.packet = packet;
//                     new_ofo.cb = cb;
//                     list_add_tail(&new_ofo -> list ,&tsk -> rcv_ofo_buf);
//                 }
                
//                 pthread_mutex_unlock(&tsk -> rcv_buf -> lock);

//                 if (tsk -> wait_recv -> sleep) {
//                     wake_up(tsk -> wait_recv);
//                 }
//                 tcp_send_control_packet(tsk, TCP_ACK);
//                 if (tsk -> wait_send -> sleep) {
//                     wake_up(tsk -> wait_send);
//                 }
//                 break;

//             } else printf("Recv TCP_PSH | TCP_ACK but current state is %d", tsk->state);
//         default: printf("Unset flag %d\n", cb->flags);
// 	}


//     tsk->snd_una = cb->ack;
// 	tsk->rcv_nxt = cb->seq_end;
//     printf("tsk->snd_una = %d, tsk->rcv_nxt = %d\n", tsk->snd_una, tsk->rcv_nxt);

// }







void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	// printf("state,flags,len:%d,%x,%d\n",tsk->state,cb->flags,cb->pl_len);
    if (cb->flags != (TCP_PSH | TCP_ACK) && (cb->flags != TCP_ACK && cb->pl_len == 0)) 
		tsk->rcv_nxt = cb->seq_end;

    if ((cb->flags) | TCP_ACK) 
	{
        struct send_buffer *entry, *q;
        // printf("here??\n");
        list_for_each_entry_safe(entry, q, &tsk->send_buf, list) 
		{
            if (entry->seq_end > cb->ack) 
				break;
            else 
			{
                tsk->snd_una = entry->seq_end;
                tcp_sndbuf_pop(tsk, entry);
            }
        }
    }

    struct tcp_sock *child_sk = alloc_tcp_sock();
    switch (cb->flags) 
	{
        case TCP_SYN:
            switch (tsk->state) 
			{
                case TCP_LISTEN:
					
                    // struct tcp_sock *child_sk = alloc_tcp_sock();
                    // printf("here?\n");
                    list_add_tail(&child_sk->list, &tsk->listen_queue);
                    child_sk->sk_sip = cb->daddr;
                    child_sk->sk_dip = cb->saddr;
                    child_sk->sk_dport = cb->sport;
                    child_sk->sk_sport = cb->dport;
                    child_sk->parent = tsk;
                    child_sk->iss = tcp_new_iss();
                    child_sk->snd_una = tsk->snd_una;
                    child_sk->rcv_nxt = tsk->rcv_nxt;
                    child_sk->snd_nxt = tsk->iss;

                    tcp_set_state(child_sk, TCP_SYN_RECV);
                    tcp_hash(child_sk);
                    tcp_send_control_packet(child_sk, TCP_SYN | TCP_ACK);
                    break;
                default:
					break;
            }
            break;
        case (TCP_SYN | TCP_ACK):
            if (tsk->state == TCP_SYN_SENT) 
                wake_up(tsk->wait_connect);
            break;
        case TCP_ACK:
            switch (tsk->state) 
			{
                case TCP_SYN_RECV:
                    if (cb->pl_len == 0) {
                        tcp_sock_accept_enqueue(tsk);
                        wake_up(tsk->parent->wait_accept);
                        tcp_set_state(tsk, TCP_ESTABLISHED);
                    } else {
                        tcp_set_state(tsk, TCP_ESTABLISHED);
                    }
                    break;
                case TCP_ESTABLISHED:
                    if (cb->pl_len == 0) {
                        wake_up(tsk->wait_send);
                    } else {
                        // printf("recieve a ACK with seq: %d, ack: %d\n", cb->seq, cb->ack);
                        // if (tsk->state == TCP_SYN_RECV) 
                        //     tcp_set_state(tsk, TCP_ESTABLISHED)
                        // printf("enter: tsk->rcv_nxt = %u\n", tsk->rcv_nxt);
                        u32 seq_end = tsk->rcv_nxt;
                        // printf("ACK    seq_end = %u, cb->seq = %u\n", seq_end, cb->seq);
                        if (seq_end == cb->seq) 
                        {
                            // printf("size: %d\n", cb->pl_len);
                            // printf("ring buffer free: %d\n", ring_buffer_free(cb->payload));
                            write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
                            // printf("write ring buffer out\n");
                            seq_end = cb->seq_end;
                            struct ofo_buffer *entry, *q;
                            list_for_each_entry_safe(entry, q, &tsk->rcv_ofo_buf, list) 
                            {
                                if (seq_end < entry->seq) 
                                    break;
                                else 
                                {
                                    seq_end = entry->seq_end;
                                    write_ring_buffer(entry->tsk->rcv_buf, entry->payload, entry->pl_len);
                                    // printf("write ring buffer in\n");
                                    list_delete_entry(&entry->list);
                                    free(entry->payload);
                                    free(entry);
                                }
                            }
                            tsk->rcv_nxt = seq_end;
                        } 
                        else if (seq_end < cb->seq){
                            write_ofo_buffer(tsk, cb);
                            // printf("put into ofo_buffer\n");
                        }
                        if (tsk->wait_recv->sleep)
                            wake_up(tsk->wait_recv);

                        tcp_send_control_packet(tsk, TCP_ACK);
                        // printf("handle seq %d\n", cb->seq);

                        if (tsk->wait_send->sleep) 
                            wake_up(tsk->wait_send);

                        // printf("leave: tsk->rcv_nxt = %u\n", tsk->rcv_nxt);
                    }
                    break;
                case TCP_FIN_WAIT_1:
                    tcp_set_state(tsk, TCP_FIN_WAIT_2);
                    break;
                case TCP_LAST_ACK:
                    tcp_set_state(tsk, TCP_CLOSED);
                    if (!tsk->parent) 
						tcp_bind_unhash(tsk);
                    tcp_unhash(tsk);
                    break;
                default:
                    break;
            }
            break;
        case (TCP_PSH | TCP_ACK):
            // printf("recieve a PSH | ACK with seq: %d, ack: %d\n", cb->seq, cb->ack);
            if (tsk->state == TCP_SYN_RECV) 
				tcp_set_state(tsk, TCP_ESTABLISHED);
            // printf("enter: tsk->rcv_nxt = %u\n", tsk->rcv_nxt);
            u32 seq_end = tsk->rcv_nxt;
            // printf("PSH | ACK    seq_end = %u, cb->seq = %u\n", seq_end, cb->seq);
            if (seq_end == cb->seq) 
			{
                // printf("size: %d\n", cb->pl_len);
                // printf("ring buffer free: %d\n", ring_buffer_free(cb->payload));
                write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
                seq_end = cb->seq_end;
                struct ofo_buffer *entry, *q;
                list_for_each_entry_safe(entry, q, &tsk->rcv_ofo_buf, list) 
				{
                    if (seq_end < entry->seq) 
						break;
                    else 
					{
                        seq_end = entry->seq_end;
                        write_ring_buffer(entry->tsk->rcv_buf, entry->payload, entry->pl_len);
                        list_delete_entry(&entry->list);
                        free(entry->payload);
                        free(entry);
                    }
                }
                tsk->rcv_nxt = seq_end;
            } 
			else if (seq_end < cb->seq){
                write_ofo_buffer(tsk, cb);
            }
            if (tsk->wait_recv->sleep)
                wake_up(tsk->wait_recv);

            tcp_send_control_packet(tsk, TCP_ACK);

            if (tsk->wait_send->sleep) 
                wake_up(tsk->wait_send);

            // printf("leave: tsk->rcv_nxt = %u\n", tsk->rcv_nxt);

            break;


        case (TCP_FIN | TCP_PSH | TCP_ACK):
            printf("recieve FIN|PSH|ACK\n");
            // printf("recieve a PSH with seq: %d, ack: %d\n", cb->seq, cb->ack);
            if (tsk->state == TCP_SYN_RECV) 
				tcp_set_state(tsk, TCP_ESTABLISHED);
            u32 seq_end_p = tsk->rcv_nxt;
            if (seq_end_p == cb->seq)
			{
                // printf("size: %d\n", cb->pl_len);
                // printf("ring buffer free: %d\n", ring_buffer_free(cb->payload));
                write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
                seq_end_p = cb->seq_end;
                struct ofo_buffer *entry, *q;
                list_for_each_entry_safe(entry, q, &tsk->rcv_ofo_buf, list) 
				{
                    if (seq_end_p < entry->seq) 
						break;
                    else 
					{
                        seq_end_p = entry->seq_end;
                        write_ring_buffer(entry->tsk->rcv_buf, entry->payload, entry->pl_len);
                        list_delete_entry(&entry->list);
                        free(entry->payload);
                        free(entry);
                    }
                }
                tsk->rcv_nxt = seq_end_p;
            } 
			else if (seq_end_p < cb->seq) 
                write_ofo_buffer(tsk, cb);
            if (tsk->wait_recv->sleep)
                wake_up(tsk->wait_recv);
            tcp_send_control_packet(tsk, TCP_ACK);
            if (tsk->wait_send->sleep) 
                wake_up(tsk->wait_send);
            
            tcp_set_state(tsk, TCP_LAST_ACK);
            tcp_send_control_packet(tsk, TCP_ACK | TCP_FIN);
            tcp_set_timewait_timer(tsk);
            break;



        case (TCP_ACK | TCP_FIN):
            switch (tsk->state) 
			{
                case TCP_ESTABLISHED:
                    // printf("revieve a FIN in ESTABLISHED\n");
                    tcp_set_state(tsk, TCP_LAST_ACK);
                    tcp_send_control_packet(tsk, TCP_ACK | TCP_FIN);
                    tcp_set_timewait_timer(tsk);
                    break;
                case TCP_FIN_WAIT_2:
                    tcp_set_state(tsk, TCP_TIME_WAIT);
                    tcp_send_control_packet(tsk, TCP_ACK);
                    // printf("sent ACK when WAIR_2\n");
                    tcp_set_timewait_timer(tsk);
                    break;
                default:
                    break;
            }
            break;
            // if (tsk->state == TCP_FIN_WAIT_2) 
			// {
            //     tcp_set_state(tsk, TCP_TIME_WAIT);
            //     tcp_send_control_packet(tsk, TCP_ACK);
            //     // printf("sent a ACK before TIME_WAIT\n");
            //     tcp_set_timewait_timer(tsk); // put tsk->timewait.list into timer list
            //     // some magic
            //     // sleep(1);
            //     // tsk -> state = TCP_CLOSED;
            // } 
            // break;
        // case TCP_FIN:
        //     switch (tsk->state) 
		// 	{
        //         case TCP_ESTABLISHED:
        //             // printf("revieve a FIN in ESTABLISHED\n");
        //             tcp_set_state(tsk, TCP_LAST_ACK);
        //             tcp_send_control_packet(tsk, TCP_ACK | TCP_FIN);
        //             tcp_set_timewait_timer(tsk);
        //             break;
        //         case TCP_FIN_WAIT_2:
        //             tcp_set_state(tsk, TCP_TIME_WAIT);
        //             tcp_send_control_packet(tsk, TCP_ACK);
        //             // printf("sent ACK when WAIR_2\n");
        //             tcp_set_timewait_timer(tsk);
        //             break;
        //         default:
        //             break;
        //     }
        //     break;
        default:
            break;
    }
}














// 怎么把packet从process传给read啊？
int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len)
{
    // 把从tsk收到的packet的内容写进长度为len的buf

    // while (tsk -> state != TCP_READ);
    // buf = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;

    // rlen = len - ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE // 
    // read_ring_buffer(rbuf, buf, size);
    // ring_buffer_free(rbuf);
    // tcp_set_state(tsk, TCP_ESTABLISHED);
    // return rlen;



    pthread_mutex_lock(&tsk->rcv_buf->lock);
    while (ring_buffer_empty(tsk -> rcv_buf)) { // do not need a new state, we can use ring buffer
        pthread_mutex_unlock(&tsk -> rcv_buf -> lock);
        sleep_on(tsk -> wait_recv); // sleep on recv, it will wake up in stack
        pthread_mutex_lock(&tsk -> rcv_buf -> lock);
    }
    int res = read_ring_buffer(tsk -> rcv_buf, buf, len); // read
    pthread_mutex_unlock(&tsk -> rcv_buf -> lock);
    // printf("res: %d\n", res);
    return res; // return length of buf
}