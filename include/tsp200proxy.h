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
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <event.h>
#include <sys/queue.h>
#include <time.h>
#include <db.h>
#include <signal.h>

#include "iecsock.h"
#include "iec104.h"

#define	TII	1
#define	TI	2
#define	TS	3

struct slaves_param
{
	char asdu;
	char *ipaddr;
	u_short port;
	struct iecsock *s;
};

struct tii_base
{
	u_short	asdu;
	u_short	ioa;
	u_char	ioa2;
	int32_t	value;
	time_t	tm;
	struct tii_base *next;
};

struct ti_base
{
	u_short asdu;
	u_short ioa;
	u_char ioa2;
	float	value;
	time_t	tm;
	struct ti_base *next;
};

struct ts_base
{
	u_short asdu;
	u_short ioa;
	u_char ioa2;
	u_char	value;
	time_t	tm;
	struct ts_base *next;
};

struct db_key
{
	u_short asdu;
	u_short ioa;
	u_char  ioa2;
	u_char  type;
	time_t	tm;
};

struct db_data
{
	u_short asdu;
	u_short ioa;
	u_char  ioa2;
	u_char  type;
	time_t	tm;
	union
	{
		int32_t tii;
		float   ti;
		u_char  ts;
	};
};

struct masters_db
{
	struct iecsock *s;
	time_t lasttime;
	struct masters_db *next;
};

/* Standard iecsock hooks */

void disconnect_hook(struct iecsock *s, short reason);
void data_received_hook(struct iecsock *s, struct iec_buf *b);
void activation_hook(struct iecsock *s);
void connect_hook(struct iecsock *s);


int iec_send_frame(struct iecsock *s, u_char *buf, size_t buflen);
inline struct iecsock *get_sock_from_asdu(unsigned short caddr);
void send_master_request(unsigned short caddr, unsigned char type);
void print_db(unsigned short caddr);
void conv_ioa(unsigned short *ioa, unsigned char *ioa2, unsigned short ioa_old, unsigned char ioa2_old);
void timer_send_frame(struct iecsock *s, void *arg);
void print_raw_packet(u_char *buf, size_t buflen);
void send_slave_answer(unsigned short caddr, unsigned char type, struct iecsock *s);

#define put_data(struct_type,root,caddr,ioa,ioa2,value,tm)		\
	struct struct_type *dbp_cur;					\
	struct struct_type *dbp_prev;					\
	int exist = 0;							\
	dbp_prev = NULL;						\
	dbp_cur  = *root; 						\
									\
	while (dbp_cur != NULL) {					\
		if (	dbp_cur->asdu == caddr	&&			\
			dbp_cur->ioa  == ioa	&&			\
			dbp_cur->ioa2 == ioa2){				\
			dbp_cur->value = value;				\
			dbp_cur->tm = tm;				\
			exist = 1;					\
			break;						\
		}							\
		dbp_prev = dbp_cur;					\
		dbp_cur  = dbp_cur->next;				\
	}								\
	if (exist)							\
		return;							\
									\
	dbp_cur = calloc(1, sizeof(struct struct_type));		\
	if (!dbp_cur)							\
			return;						\
	dbp_cur->asdu  = caddr;						\
	dbp_cur->ioa   = ioa;						\
	dbp_cur->ioa2  = ioa2;						\
	dbp_cur->value = value;						\
	dbp_cur->tm    = tm;						\
	dbp_cur->next  = NULL;						\
	if (dbp_prev != NULL)						\
		dbp_prev->next = dbp_cur;				\
	if (*root == NULL)						\
		*root = dbp_cur;
	
	
void put_db_data(unsigned short caddr, unsigned short ioa, unsigned char ioa2,
		time_t tm, unsigned char type, void *value);

void put_ts_data(struct ts_base **root, unsigned short caddr, unsigned short ioa,
		unsigned char ioa2, unsigned char value, time_t tm );
void put_ti_data(struct ti_base **root, unsigned short caddr, unsigned short ioa,
		unsigned char ioa2, float value, time_t tm );
void put_tii_data(struct tii_base **root, unsigned short caddr, unsigned short ioa,
		unsigned char ioa2, int32_t value, time_t tm );

/* koef.c */

#define	KFILE	"/home/crux/Devel/mrts/db/koef.csv"
#define LMAX	80	

#define	KOEFI	1
#define KOEFU	2
#define KOEFP	3
#define KOEFF	4 

struct kdb_key
{
	unsigned short asdu;
	unsigned char ioa2;
}__attribute__((__packed__));

struct kdb_data
{
	float koef_u;
	float koef_i;
}__attribute__((__packed__));

int init_koef_db(DB **kdbp);
int show_koef_db(DB *dbp);
float get_koef(DB *dbp, unsigned short caddr, unsigned char ioa2, unsigned char type);
unsigned char get_value_type(unsigned short ioa);
