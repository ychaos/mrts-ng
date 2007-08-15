/*
 * Copyright (C) 2007, Vladimir Lettiev                                 
 * lettiev-vv@komi.tgc-9.ru                                              
 *                                                                       
 * This program is free software; you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation; either version 2 of the License, or     
 * (at your option) any later version.                                   
 *                                                                       
 * This program is distributed in the hope that it will be useful,       
 * but WITHOUT ANY WARRANTY; without even the implied warranty of        
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         
 * GNU General Public License for more details.                          
 *                                                                       
 * You should have received a copy of the GNU General Public License     
 * along with this program; if not, write to the                         
 * Free Software Foundation, Inc.,                                       
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <event.h>
#include <sys/queue.h>

#include "iecsock.h"
#include "iec104.h"

/* #include "iecsock_internal.h" */

#define BACKLOG	10
#define STR_IOA		0

const u_short ASDU_ADDR = 5;

const u_char  SPORADIC  = 3;
const u_char  CLOSE_ACT = 10;
const u_char  ACK_ACT   = 7;

struct iechooks default_hooks;

void iec_send_frame(struct iecsock *s, u_char *buf, size_t *buflen){

	struct iec_buf *b;

	if (! iecsock_can_queue(s))
		return;
	b = calloc(1, sizeof(struct iec_buf) + *buflen);
	if (!b)
		return;
	b->data_len = *buflen;
	memcpy(b->data, buf, *buflen );
	iecsock_prepare_iframe(b);
	TAILQ_INSERT_TAIL(&s->write_q, b, head);
	fprintf(stderr, "packet added to queue\n");
	iecsock_run_write_queue(s);
}

void send_base_request(struct iecsock *s, void *arg)
{
/*	struct timeval tv; */
	u_char *buf;	
	size_t buflen = 0;

	buf = calloc(1,sizeof(struct iec_buf) + 249);
	if (!buf) 
		return;

	iecasdu_create_header(buf, &buflen, C_IC_NA_1, 1, ACTIVATION, ASDU_ADDR);
	iecasdu_create_type_100(buf + buflen, &buflen);
	iec_send_frame(s,buf,&buflen);
	
/*	tv.tv_sec = 0;
	tv.tv_usec = 1000;
	iecsock_user_timer_start(s, &tv); */
}

void disconnect_hook(struct iecsock *s, short reason)
{	
	fprintf(stderr, "%s: what=0x%02x\n", __FUNCTION__, reason);
	return;
}

void data_received_hook(struct iecsock *s, struct iec_buf *b)
{
/*	struct timeval tv; */
	struct iec_object obj[IEC_OBJECT_MAX];
	int ret, n, i;
	u_short caddr;
	u_char cause, test, pn, t, str_ioa;
	str_ioa = 0;

	fprintf(stderr, "%s: data_len=%d Success\n", __FUNCTION__, b->data_len);
		
	/* iecsock_user_timer_start(s, &tv); */
	
	ret = iecasdu_parse(obj, &t, &caddr, &n, &cause, &test, &pn, 
		&str_ioa, b->data, b->data_len);

	fprintf(stderr, "| TYPE: %i: CA=0x%04x NUM=%i CAUSE=%i TEST=%i P/N=%i\n",
		t, caddr, n, cause, test, pn);
	
	if (ret) {
		fprintf(stderr,"proto error: %i!\n",ret);
		return;
	}
	
	switch(t) {
	case C_IC_NA_1: /* 100 */
		fprintf(stderr, "| Value: IDX:%i qoi:0x%02x\n",obj[0].ioa, obj[0].o.type100.qoi);
		break;
	case 36:
		for (i=0;i<n;i++) {
			fprintf(stderr, "| Value: IDX:%i MV:%f, OV:%i\n",
			obj[i].ioa+65536*obj[i].ioa2,obj[i].o.type36.mv, obj[i].o.type36.ov);
		}
		break;
	case 1: 
		for (i=0;i<n;i++) {
			fprintf(stderr, "| Value: IDX:%i SPI:%i, SB:%i\n",
			obj[i].ioa+65536*obj[i].ioa2, obj[i].o.type1.sp, obj[i].o.type1.sb);
		}
		break;
	case 13: 
		for (i=0;i<n;i++) {
			fprintf(stderr, "| Value: IDX:%i MV:%f, OV:%i\n",
			obj[i].ioa+65536*obj[i].ioa2, obj[i].o.type13.mv, obj[i].o.type13.ov); 
		}
		break;
	case 37: 
		for (i=0;i<n;i++) {
			fprintf(stderr, "| Value: IDX:%i, BCR:%i, SEQ:%i\n",
			obj[i].ioa+65536*obj[i].ioa2, obj[i].o.type37.bcr, obj[i].o.type37.sq);
		}
		break;
	default:
		fprintf(stderr, "| !!! Unknown type: %i\n", t);
		break;
	}
	free(b);
}

void activation_hook(struct iecsock *s)
{
	struct timeval tv;
	
	fprintf(stderr, "%s: Sucess 0x%lu\n", __FUNCTION__, (unsigned long) s);
	
	tv.tv_sec  = 1;
	tv.tv_usec = 0;
	
/*	iecsock_user_timer_set(s, timer_send_frame, NULL); */
	send_base_request(s,NULL);
}

void connect_hook(struct iecsock *s)
{	
	struct iecsock_options opt;
	opt.w	= 1;
	opt.k	= 3;
	opt.t0	= 30;
	opt.t1  = 15;
	opt.t2  = 10;
	opt.t3  = 20;
	iecsock_set_options(s,&opt);
	
	fprintf(stderr, "%s: Sucess 0x%lu\n", __FUNCTION__, (unsigned long) s);

}

int main(int argc, char **argv)
{
	struct sockaddr_in addr;
	
	event_init();
	
	default_hooks.disconnect_indication = disconnect_hook;
	default_hooks.connect_indication = connect_hook;
	default_hooks.data_indication = data_received_hook;
	default_hooks.activation_indication = activation_hook;
	
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(IEC_PORT_DEFAULT+3);
	
	if (argc > 1 && inet_pton(AF_INET, argv[1], &addr.sin_addr) > 0)
		iecsock_connect(&addr);
	else
		iecsock_connect(NULL);
	
	event_dispatch();
	
	return EXIT_SUCCESS;
}
