/*
 * Copyright (C) 2005, Grigoriy Sitkarev                                 
 * sitkarev@komitex.ru                                                
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

#define BACKLOG	10
#define COM_ADDRLEN    2
#define IOA_ADDRLEN    3

const u_short ASDU_ADDR = 1;

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

void timer_send_base(struct iecsock *s, void *arg){

	struct timeval tv;
	u_char *buf;	
	size_t buflen = 0;
	
	float datas[] = {52.0, 54.0, 55.0};
	
	buf = calloc(1,sizeof(struct iec_buf) + 249);
	if (!buf) 
		return;
	
	iecasdu_create_header(buf, &buflen, M_ME_TF_1, 3, SPORADIC, ASDU_ADDR);
	iecasdu_create_type_36(buf + buflen, &buflen, 3, datas);
	iec_send_frame(s,buf,&buflen);
	
	free(buf);
	
	tv.tv_sec  = 1;
	tv.tv_usec = 0;
	iecsock_user_timer_start(s, &tv);
	
}

void send_all_database(struct iecsock *s)
{
	u_char *buf;	
	size_t buflen = 0;
	
	float datas[] = {52.0, 54.0, 55.0};
	
	buf = calloc(1,sizeof(struct iec_buf) + 249);
	if (!buf) 
		return;

	iecasdu_create_header(buf, &buflen, C_IC_NA_1, 1, ACK_ACT, ASDU_ADDR);
	iecasdu_create_type_100(buf + buflen, &buflen);
	iec_send_frame(s,buf,&buflen);
	
	buflen = 0;
	iecasdu_create_header(buf, &buflen, M_ME_TF_1, 3, SPORADIC, ASDU_ADDR);
	iecasdu_create_type_36(buf + buflen, &buflen, 3, datas);
	iec_send_frame(s,buf,&buflen);
	
	buflen = 0;
	iecasdu_create_header(buf, &buflen, C_IC_NA_1, 1, CLOSE_ACT, ASDU_ADDR);
	iecasdu_create_type_100(buf + buflen, &buflen);
	iec_send_frame(s,buf,&buflen);
	
	free(buf);
}

void time_sync(struct iecsock *s)
{
	u_char *buf;
	size_t buflen = 0;

	buf = calloc(1,sizeof(struct iec_buf) + 249);
	if (!buf) 
		return;
	
	iecasdu_create_header(buf, &buflen, C_CS_NA_1, 1, ACK_ACT, ASDU_ADDR);
	iecasdu_create_type_103(buf + buflen, &buflen);
	iec_send_frame(s,buf,&buflen);

	free(buf);

}

void send_counters_database(struct iecsock *s)
{
	u_char *buf;
	size_t buflen = 0;

	buf = calloc(1,sizeof(struct iec_buf) + 249);
	if (!buf) 
		return;
	
	iecasdu_create_header(buf, &buflen, C_CI_NA_1, 1, ACK_ACT, ASDU_ADDR);
	iecasdu_create_type_101(buf + buflen, &buflen);
	iec_send_frame(s,buf,&buflen);
	
	buflen = 0;
	iecasdu_create_header(buf, &buflen, C_CI_NA_1, 1, CLOSE_ACT, ASDU_ADDR);
	iecasdu_create_type_101(buf + buflen, &buflen);
	iec_send_frame(s,buf,&buflen);

	free(buf);
	
}

void disconnect_hook(struct iecsock *s, short reason)
{	
	fprintf(stderr, "%s: what=0x%02x\n", __FUNCTION__, reason);
	return;
}

void data_received_hook(struct iecsock *s, struct iec_buf *b)
{
	struct timeval tv;
	struct iec_object obj[IEC_OBJECT_MAX];
	int ret, n, i;
	u_short caddr;
	u_char cause, test, pn, t;
	u_char str_ioa = 0;

	fprintf(stderr, "%s: data_len=%d Success\n", __FUNCTION__, b->data_len);

	/* 
	 * Here we are to start application layer using libiecasdu
	 */
	ret = iecasdu_parse(obj, &t, &caddr, &n, &cause, &test, &pn, 
		&str_ioa, b->data, b->data_len);

	iecsock_user_timer_stop(s);
	tv.tv_sec  = 1;
	tv.tv_usec = 0;
	
	switch(t) {
	case C_IC_NA_1: /* 100 */
		fprintf(stderr, "C_IC_NA_1: CA=0x%04x NUM=%i CAUSE=%i TEST=%i P/N=%i\n",
				caddr, n, cause, test, pn);
		for (i=0;i<n;i++) {
			fprintf(stderr, "Value: IDX:%04i qoi:0x%02x\n",
			obj[i].ioa, obj[i].o.type100.qoi);
		}
		send_all_database(s);
		iecsock_user_timer_start(s, &tv);
		break;
	case C_CI_NA_1: /* 101 */
		fprintf(stderr, "C_CI_NA_1: CA=0x%04x NUM=%i CAUSE=%i TEST=%i P/N=%i\n",
				caddr, n, cause, test, pn);
		send_counters_database(s);
		iecsock_user_timer_start(s, &tv);
		break;
	case C_CS_NA_1: /* 103 */
		fprintf(stderr, "C_CS_NA_1: CA=0x%04x NUM=%i CAUSE=%i TEST=%i P/N=%i\n",
				caddr, n, cause, test, pn);
		time_sync(s);
		break;
	default:
		fprintf(stderr, "unknown type %i\n", t);
		break;
	}
	
	free(b);
}

void activation_hook(struct iecsock *s)
{
	
	fprintf(stderr, "%s: Sucess 0x%lu\n", __FUNCTION__, (unsigned long) s);
	
}

void connect_hook(struct iecsock *s)
{	
	fprintf(stderr, "%s: Sucess 0x%lu\n", __FUNCTION__, (unsigned long) s);
	iecsock_user_timer_set(s, timer_send_base, NULL);
}

int main(int argc, char **argv)
{
	event_init();
	
	default_hooks.disconnect_indication = disconnect_hook;
	default_hooks.connect_indication = connect_hook;
	default_hooks.data_indication = data_received_hook;
	default_hooks.activation_indication = activation_hook;
	
	iecsock_listen(NULL, 10);
	
	event_dispatch();
	
	return EXIT_SUCCESS;
}
