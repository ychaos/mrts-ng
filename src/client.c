/*
 * Copyright (C) 2005, Grigoriy Sitkarev                                 
 * sitkarev@komi.tgk-9.ru                                                
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

#define BACKLOG	10

unsigned char asdu_test[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
};

struct iechooks default_hooks;

void timer_send_frame(struct iecsock *s, void *arg)
{
	struct iec_buf *b;
	struct timeval tv;

	while (iecsock_can_queue(s)) {
		b = calloc(1, sizeof(struct iec_buf) + 70);
		if (!b)
			return;
		b->data_len = 70;
		memcpy(b->data, asdu_test, 70);
		
		iecsock_prepare_iframe(b);
		TAILQ_INSERT_TAIL(&s->write_q, b, head);
		iecsock_run_write_queue(s);
	}
	
	tv.tv_sec = 0;
	tv.tv_usec = 1000;
	iecsock_user_timer_start(s, &tv);
}

void disconnect_hook(struct iecsock *s, short reason)
{	
	fprintf(stderr, "%s: what=0x%02x\n", __FUNCTION__, reason);
	return;
}

void data_received_hook(struct iecsock *s, struct iec_buf *b)
{
	fprintf(stderr, "%s: data_len=%d Success\n", __FUNCTION__, b->data_len);

	/* 
	 * Here we are to start application layer using libiecasdu
	 */
	
	free(b);
}

void activation_hook(struct iecsock *s)
{
	struct timeval tv;
	
	fprintf(stderr, "%s: Sucess 0x%lu\n", __FUNCTION__, (unsigned long) s);
	
	tv.tv_sec  = 1;
	tv.tv_usec = 0;
	
	iecsock_user_timer_set(s, timer_send_frame, NULL);
	iecsock_user_timer_start(s, &tv);
}

void connect_hook(struct iecsock *s)
{	
	fprintf(stderr, "%s: Sucess 0x%lu\n", __FUNCTION__, (unsigned long) s);

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
