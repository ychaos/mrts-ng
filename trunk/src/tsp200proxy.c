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

#include "tsp200proxy.h"

#define	DBPATH	"/home/crux/Devel/mrts/db"
#define LOGFILE "/home/crux/Devel/mrts/db/tsp200proxy.log"

struct iechooks default_hooks;

struct slaves_param tsp200[] = {
	{5,"172.29.24.110",2407,NULL},
};
/*
	{3,"172.29.22.174",2407,NULL},
	{5,"172.29.24.110",2407,NULL},
	{7,"172.29.28.17",2407,NULL},
	{9,"172.29.16.39",2407,NULL},
	{0,NULL,0,NULL}
}; */

struct tii_base *tii = NULL;
struct ti_base  *ti  = NULL;
struct ts_base  *ts  = NULL;

struct masters_db *mdbp = NULL;

DB *dbp, *kdbp;
DB_ENV *dbenvp;

static unsigned short asdu_addr;

FILE *logfile;

void term_handler(int i)
{
	if (dbp != NULL)
		dbp->close(dbp, 0); 
	if (dbenvp != NULL)
		dbenvp->close(dbenvp, 0);
	fprintf(logfile,"recieve SIGTERM, exiting\n");
	if (logfile != NULL)
		fclose(logfile);
	exit(EXIT_SUCCESS);
}

int iec_send_frame(struct iecsock *s, u_char *buf, size_t buflen)
{
	struct iec_buf *b;

	if (! iecsock_can_queue(s))
		return 1;
	b = calloc(1, sizeof(struct iec_buf) + buflen);
	if (!b)
		return 2;
	b->data_len = buflen;
	memcpy(b->data, buf, buflen );
	iecsock_prepare_iframe(b);
	TAILQ_INSERT_TAIL(&s->write_q, b, head);
	iecsock_run_write_queue(s);
	return 0;
}

inline struct iecsock *get_sock_from_asdu(unsigned short caddr)
{
	int i;
	struct iecsock *ret = NULL;
	for (i=0; tsp200[i].asdu !=0; i++) {
		if (caddr == tsp200[i].asdu){
			ret = tsp200[i].s;
			break;
		}
	}
	return ret;	
}

void send_master_request(unsigned short caddr, unsigned char type)
{
	u_char *buf;	
	size_t buflen = 0;
	struct iecsock *s;

	s = get_sock_from_asdu(caddr);
	
	buf = calloc(1,sizeof(struct iec_buf) + 249);
	if (!buf) 
		return;

	iecasdu_create_header(buf, &buflen, type, 1, ACTIVATION, caddr);

	if (type == C_IC_NA_1) {
		iecasdu_create_type_100(buf + buflen, &buflen);
	} else if ( type == C_CI_NA_1 ) {
		iecasdu_create_type_101(buf + buflen, &buflen);
	} else if ( type == C_CS_NA_1 ) {
		iecasdu_create_type_103(buf + buflen, &buflen);
	} else {
		free(buf);
		return;
	}

	iec_send_frame(s,buf,buflen);
}

void print_db(unsigned short caddr)
{
	int i;
	struct ts_base *ts_b;
	struct ti_base *ti_b;
	struct tii_base *tii_b;
	ts_b = ts;
	ti_b = ti;
	tii_b = tii;

	fprintf(logfile,"=========== TS base of ASDU No %i ============\n",caddr);
	for (i=0; ts_b!=NULL; i++) {
		if (ts_b->asdu == caddr) {
			fprintf(logfile,"IOA: %x, VALUE: %i, TIME: %s",ts_b->ioa+65536*ts_b->ioa2,ts_b->value,ctime(&(ts_b->tm)));
		}
		ts_b = ts_b->next;
	}
	fprintf(logfile,"=========== TI base of ASDU No %i ============\n",caddr);
	for (i=0; ti_b!=NULL; i++) {
		if (ti_b->asdu == caddr) {
			fprintf(logfile,"IOA: %x, VALUE: %f, TIME: %s",ti_b->ioa+65536*ti_b->ioa2,ti_b->value,ctime(&(ti_b->tm)));
		}
		ti_b = ti_b->next;
	}
	fprintf(logfile,"=========== TII base of ASDU No %i ============\n",caddr);
	for (i=0; tii_b!=NULL; i++) {
		if (tii_b->asdu == caddr) {
			fprintf(logfile,"IOA: %x, VALUE: %i, TIME: %s",tii_b->ioa+65536*tii_b->ioa2,tii_b->value,ctime(&(tii_b->tm)));
		}
		tii_b = tii_b->next;
	}
	fprintf(logfile,"==============================================\n");
}

void conv_ioa(unsigned short *ioa, unsigned char *ioa2, unsigned short ioa_old, unsigned char ioa2_old)
{
	*ioa  = (ioa_old&0xFFF) + ((ioa2_old & 0xF) - 1)*0x10;
	*ioa2 = 0;
}

void timer_send_frame(struct iecsock *s, void *arg)
{
	struct timeval tv;
	unsigned short *caddrp, caddr;
	unsigned char *buf;
	size_t buflen, pnum, len;
	struct iec_type36 tp36;
	unsigned short ioa;
	unsigned char ioa2;
	
	int i;
	
	struct ti_base *tip;
	struct masters_db *mp;

	tip = ti;

	caddrp = (unsigned short *) arg;
	caddr = *caddrp;

	buf = calloc(1,sizeof(struct iec_buf) + IEC104_ASDU_MAX);
	if (!buf) 
		return;
	
/*	iecasdu_create_header(buf, &buflen, C_IC_NA_1, 1, ACTCONFIRM, *caddrp);
	iecasdu_create_type_100(buf + buflen, &buflen);
	iec_send_frame(s,buf,buflen);
	buflen=0; */
	
	for (mp = mdbp; (mp != NULL) && (mp->s->sock != s->sock); mp = mp->next);
	
	if (!mp)
		return;
	
	/* Send all TI database */
	buflen = pnum = len = 0;
		
	for (i=0; tip != NULL; i++){
		if ((tip->asdu == *caddrp) && ( difftime(mp->lasttime,tip->tm) < 2 )){
			if (IEC104_ASDU_MAX - sizeof(struct iec_unit_id) - len > sizeof(struct iec_type36) + 3  ) {
				tp36.mv  = tip->value;
				tp36.ov  = 0;
				tp36.res = 0;
				tp36.bl  = 0;
				tp36.sb  = 0;
				tp36.nt  = 0;
				tp36.iv  = 0;
				time_t_to_cp56time2a(&tp36.time,&(tip->tm));
				conv_ioa(&ioa,&ioa2,tip->ioa,tip->ioa2);	/* Convert IOA */
				memcpy(buf + sizeof(struct iec_unit_id) + len, &ioa, sizeof(u_short));
				memcpy(buf + sizeof(struct iec_unit_id) + len + sizeof(u_short), &ioa2, sizeof(u_char));
				memcpy(buf + sizeof(struct iec_unit_id) + len + sizeof(u_short) + sizeof(u_char), &tp36, sizeof(struct iec_type36));
				len += sizeof(struct iec_type36) + sizeof(unsigned short) + sizeof(unsigned char);
				pnum++;
				/* fprintf(stderr, "IOA: %u, VALUE: %f, time: %s\n", ioa, tip->value, ctime(&tip->tm));*/
			} else {
				iecasdu_create_header(buf, &buflen, M_ME_TF_1, pnum, SPONTANEOUS, caddr);
				/* print_raw_packet(buf,len+buflen); */
        			iec_send_frame(s,buf,len+buflen);
				buflen = len = pnum = 0;
			}
/*		} else if (tip->asdu == *caddrp) {
			fprintf(stderr, "difftime: %.0f\n", difftime(tip->tm,mp->lasttime)); */
		}
		tip = tip->next;
	}
	if (len != 0) {
		iecasdu_create_header(buf, &buflen, M_ME_TF_1, pnum, SPONTANEOUS, caddr);
		/* print_raw_packet(buf,len+buflen); */
        	iec_send_frame(s,buf,len+buflen);
		buflen = len = pnum = 0;
	}
/*
	buflen = 0;	
	iecasdu_create_header(buf, &buflen, C_IC_NA_1, 1, ACTTERM, *caddrp);
	iecasdu_create_type_100(buf + buflen, &buflen);
	iec_send_frame(s,buf,buflen); */
	
	free(buf);
	
	tv.tv_sec  = 0;
	tv.tv_usec = 500000;

	mp->lasttime = time(NULL);
	dbp->sync(dbp,0);
	/* fprintf(stderr, ">>>>>>>>>>>>> %s\n", ctime(&mp->lasttime)); */
	
	iecsock_user_timer_start(s, &tv);
}

void print_raw_packet(u_char *buf, size_t buflen)
{
	int i;
	
	for (i=0; i < buflen; i++){
		fprintf(logfile,"%02x ",*(buf+i));
	}
	fprintf(logfile,"\n");
}


void send_slave_answer(unsigned short caddr, unsigned char type, struct iecsock *s)
{
	int i,pnum;
	unsigned char *buf;
	size_t len, buflen = 0;
	struct iec_type36 tp36;
	unsigned short ioa;
	unsigned char ioa2;
	
	struct timeval tv;
	struct masters_db *mp;
	
/*	struct ts_base *tsp; */
	struct ti_base *tip;
/*	struct tii_base *tiip; */
	
	for (mp = mdbp; (mp != NULL) && (mp->s->sock != s->sock); mp = mp->next);
	if (!mp)
		return;
	
	tip = ti;
	
	buf = calloc(1,sizeof(struct iec_buf) + IEC104_ASDU_MAX);
	if (!buf) 
		return;

	iecasdu_create_header(buf, &buflen, type, 1, ACTCONFIRM, caddr);

	if (type == C_IC_NA_1) {
		print_db(caddr);
		iecasdu_create_type_100(buf + buflen, &buflen);
		iec_send_frame(s,buf,buflen);

		/* Send all TI database */
		buflen = pnum = len = 0;
		
		for (i=0; tip != NULL ; i++){
			if (tip->asdu == caddr) {
				if (IEC104_ASDU_MAX - sizeof(struct iec_unit_id) - len > sizeof(struct iec_type36) + 3  ) {
					tp36.mv  = tip->value;
					tp36.ov  = 0;
					tp36.res = 0;
					tp36.bl  = 0;
					tp36.sb  = 0;
					tp36.nt  = 0;
					tp36.iv  = 0;
					time_t_to_cp56time2a(&tp36.time,&(tip->tm));
					conv_ioa(&ioa,&ioa2,tip->ioa,tip->ioa2);	/* Convert IOA */
					memcpy(buf + sizeof(struct iec_unit_id) + len, &ioa, sizeof(u_short));
					memcpy(buf + sizeof(struct iec_unit_id) + len + sizeof(u_short), &ioa2, sizeof(u_char));
					memcpy(buf + sizeof(struct iec_unit_id) + len + sizeof(u_short) + sizeof(u_char), &tp36, sizeof(struct iec_type36));
					len += sizeof(struct iec_type36) + sizeof(unsigned short) + sizeof(unsigned char);
					pnum++;
				} else {
					iecasdu_create_header(buf, &buflen, M_ME_TF_1, pnum, SPONTANEOUS, caddr);
					/* print_raw_packet(buf,len+buflen); */
        				iec_send_frame(s,buf,len+buflen);
					buflen = len = pnum = 0;
				}
			}
			tip = tip->next;
		}
		if (len != 0) {
			iecasdu_create_header(buf, &buflen, M_ME_TF_1, pnum, SPONTANEOUS, caddr);
			/* print_raw_packet(buf,len+buflen); */
        		iec_send_frame(s,buf,len+buflen);
			buflen = len = pnum = 0;
		}

		/* FIXME: Send all TS database */
		
		buflen = 0;
		iecasdu_create_header(buf, &buflen, C_IC_NA_1, 1, ACTTERM, caddr);
		iecasdu_create_type_100(buf + buflen, &buflen);
		print_raw_packet(buf,buflen);
		for(i=0; i<100; i++){
			if (iec_send_frame(s,buf,buflen) == 0){
				break;
			}
			usleep(1000);
		}

	} else if ( type == C_CI_NA_1 ) {
		
		iecasdu_create_type_101(buf + buflen, &buflen);

		/* FIXME: Send all TII database */

		buflen = 0;
		iecasdu_create_header(buf, &buflen, C_CI_NA_1, 1, ACTTERM, caddr);
		iecasdu_create_type_101(buf + buflen, &buflen);
		iec_send_frame(s,buf,buflen);
		
	} else if ( type == C_CS_NA_1 ) {
		
		iecasdu_create_type_103(buf + buflen, &buflen);
		iec_send_frame(s,buf,buflen);
		
	}
	
	/* CICLICLY SEND DATA */
	tv.tv_sec  = 1;
	tv.tv_usec = 0;

	mp->lasttime = time(NULL);
	iecsock_user_timer_start(s, &tv);
	
	free(buf);
}

void put_db_data(unsigned short caddr, unsigned short ioa, unsigned char ioa2,
		time_t tm, unsigned char type, void *value)
{
	DBT key, data;
	struct db_key	dbkey;
	struct db_data	dbdata;
	int ret;
	
/*	int32_t tii;
	float	ti;
	u_char	ts;*/

	/* Zero out the DBTs before using them. */
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	dbkey.asdu = caddr;
	dbkey.ioa  = ioa;
	dbkey.ioa2 = ioa2;
	dbkey.type = type;
	dbkey.tm   = tm;

	dbdata.asdu = caddr;
	dbdata.ioa  = ioa;
	dbdata.ioa2 = ioa2;
	dbdata.type = type;
	dbdata.tm   = tm;
	switch (type) {
	case TII:	dbdata.tii = *((int32_t *) value);
			/* fprintf(stderr,"INT: %i ",dbdata.tii); */
		break;
	case TI:	dbdata.ti  = *((float *)   value);
		break;
	case TS:	dbdata.ts  = *((u_char *)  value);
		break;
	}

	key.data = &dbkey;
	key.size = sizeof(struct db_key);

	data.data = &dbdata;
	data.size = sizeof(struct db_data);
	
	ret = dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
	if (ret != 0) {
		dbp->err(dbp, ret, "Put failed: ");
	}
}

void put_ts_data(struct ts_base **root, unsigned short caddr, unsigned short ioa,
		unsigned char ioa2, unsigned char value, time_t tm )
{

	if (dbp != NULL)
		put_db_data(caddr,ioa,ioa2,tm,TS,&value);
	put_data(ts_base,root,caddr,ioa,ioa2,value,tm);

}

void put_ti_data(struct ti_base **root, unsigned short caddr, unsigned short ioa,
		unsigned char ioa2, float value, time_t tm )
{

	if (dbp != NULL)
		put_db_data(caddr,ioa,ioa2,tm,TI,&value);
	put_data(ti_base,root,caddr,ioa,ioa2,value,tm);

}

void put_tii_data(struct tii_base **root, unsigned short caddr, unsigned short ioa,
		unsigned char ioa2, int32_t value, time_t tm )
{
	
	if (dbp != NULL)
		put_db_data(caddr,ioa,ioa2,tm,TII,&value);
	put_data(tii_base,root,caddr,ioa,ioa2,value,tm);

}

void disconnect_hook(struct iecsock *s, short reason)
{
	struct masters_db *mp, *mpold;
	fprintf(logfile, "%s: what=0x%02x\n", __FUNCTION__, reason);
	
	if (s->type == IEC_SLAVE) {
		mp = mpold = mdbp;		
		if (mdbp != NULL && mdbp->next == NULL) {
			mdbp = NULL;
		}
		while (mp != NULL){
			if (mp->s->sock == s->sock) {
				mpold->next = mp->next;
				free(mp);
				break;
			}
			mpold = mp;
			mp = mp->next;
		}
	}
}

void data_received_hook(struct iecsock *s, struct iec_buf *b)
{
/*	struct timeval tv; */
	struct iec_object obj[IEC_OBJECT_MAX];
	int ret, n, i;
	u_short caddr;
	u_char cause, test, pn, t, str_ioa,vtype;
	time_t timet;
	str_ioa = 1;

/*	fprintf(stderr, "%s: data_len=%d Success\n", __FUNCTION__, b->data_len);*/

	ret = iecasdu_parse(obj, &t, &caddr, &n, &cause, &test, &pn, 
		&str_ioa, b->data, b->data_len);

	/* if (s->type == IEC_SLAVE) {
		fprintf(stderr,"MASTER: ");
		fprintf(stderr, "TYPE: %03i: CA=0x%04x NUM=%i CAUSE=%i TEST=%i P/N=%i\n", 
			t, caddr, n, cause, test, pn);
		
	} else {
		fprintf(stderr,"SLAVE: ");
	}*/

	if (ret) {
		fprintf(logfile,"proto error: %i!\n",ret);
		for (i=0; i < b->data_len; i++){
			fprintf(logfile,"%02x ",*(b->data+i));
		}
		fprintf(logfile,"\n---------------\n");
		return;
	}

	if (get_sock_from_asdu(caddr) == NULL)
		return;
	
	if (s->type == IEC_SLAVE) {	/* Request from master */
		if (s->usercb != NULL) {
			iecsock_user_timer_stop(s);
		} else {
			asdu_addr = caddr;
			iecsock_user_timer_set(s, timer_send_frame, &asdu_addr);
		}
		if (cause == ACTIVATION) {
			send_slave_answer(caddr,t,s);
		}
	} else {
		switch(t) {
		/* answers on master initiation */
		case 100:
		case 101:
		case 103:
			break;
		case 1: 
			for (i=0;i<n;i++) {
				/* fprintf(stderr, "| Value: IDX:%i SPI:%i, SB:%i\n",
				obj[i].ioa+65536*obj[i].ioa2, obj[i].o.type1.sp, obj[i].o.type1.sb); */
				put_ts_data(&ts, caddr, obj[i].ioa,obj[i].ioa2, obj[i].o.type1.sp, time(NULL));
			}
			break;
		case 13: 
			for (i=0;i<n;i++) {
				/* fprintf(stderr, "| Value: IDX:%i MV:%f, OV:%i\n",
				obj[i].ioa+65536*obj[i].ioa2, obj[i].o.type13.mv, obj[i].o.type13.ov); */
				vtype = get_value_type(obj[i].ioa);
				if (vtype != KOEFF) {
					obj[i].o.type13.mv *= get_koef(kdbp,caddr,obj[i].ioa2,vtype);
				} else if (obj[i].o.type13.mv !=0 ) {
					obj[i].o.type13.mv = 2457600/obj[i].o.type13.mv;
				}
				put_ti_data(&ti, caddr, obj[i].ioa,obj[i].ioa2, obj[i].o.type13.mv, time(NULL));
			}
			break;
		case 30: 
			for (i=0;i<n;i++) {
				/* fprintf(stderr, "| Value: IDX:%i SP:%i\n",
				obj[i].ioa+65536*obj[i].ioa2, obj[i].o.type30.sp); */
				timet = cp56time2a_to_tm(&obj[i].o.type30.time);
				put_ts_data(&ts, caddr, obj[i].ioa, obj[i].ioa2, obj[i].o.type30.sp, time(&timet));
			}
			break;
		case 36:
			for (i=0;i<n;i++) {
				timet = cp56time2a_to_tm(&obj[i].o.type36.time);
				vtype = get_value_type(obj[i].ioa);
				if (vtype != KOEFF) {
					obj[i].o.type36.mv *= get_koef(kdbp,caddr,obj[i].ioa2,vtype);
				} else if (obj[i].o.type36.mv != 0){
					obj[i].o.type36.mv = 2457600/obj[i].o.type36.mv;
				}

				/* fprintf(stderr, "| Value: IDX:%i MV:%f, OV:%i, VTYPE:%i\n",
				obj[i].ioa+65536*obj[i].ioa2,obj[i].o.type36.mv, obj[i].o.type36.ov,vtype); */
				put_ti_data(&ti, caddr, obj[i].ioa, obj[i].ioa2, obj[i].o.type36.mv, time(&timet));
			}
			break;
		case 37: 
			for (i=0;i<n;i++) {
				/*fprintf(stderr, "| Value: IDX:%i, BCR:%i, SEQ:%i\n",
				obj[i].ioa+65536*obj[i].ioa2, obj[i].o.type37.bcr, obj[i].o.type37.sq);*/
				timet = cp56time2a_to_tm(&obj[i].o.type37.time);
				put_tii_data(&tii, caddr, obj[i].ioa, obj[i].ioa2, obj[i].o.type37.bcr, time(&timet));
			}
			break;
		default:
			fprintf(logfile, "| !!! Unknown type: %i\n", t);
			break;
		}
	}
	
	free(b);
}

void activation_hook(struct iecsock *s)
{
	char *str;
	int i;
	struct timeval tv;
	struct masters_db *mp, *mpold;
	tv.tv_sec  = 0;
	tv.tv_usec = 1000;
	
	if (s->type == IEC_SLAVE) {
		fprintf(logfile, "Success start of slave.\n");
		mp = mpold = mdbp;
		while (mp != NULL){
			mpold = mp;
			mp = mp->next;
		}
		mp = calloc(1, sizeof(struct masters_db));
		if (!mp)
			return;
		if (mpold != NULL)
			mpold->next = mp;
		mp->s = s;
		mp->lasttime = time(NULL);
		mp->next = NULL;
		if (mdbp == NULL)
			mdbp = mp;
	} else {
		str = inet_ntoa(s->addr.sin_addr); 
		fprintf(logfile, "Success activate connection to slave: Sock = %i, Addr: %s\n",s->sock,str);
		for (i=0; tsp200[i].asdu != 0; i++){
			if (strcmp(tsp200[i].ipaddr,str)  == 0) {
				tsp200[i].s = s;
				send_master_request(tsp200[i].asdu,C_IC_NA_1);
				break;
			}
		}
	}
}

void connect_hook(struct iecsock *s)
{	
	fprintf(logfile, "%s: Sucess 0x%lu\n", __FUNCTION__, (unsigned long) s);
	
	if (s->type == IEC_MASTER) {
		struct iecsock_options opt;
		opt.w	= 1;
		opt.k	= 3;
		opt.t0	= 30;
		opt.t1  = 15;
		opt.t2  = 10;
		opt.t3  = 20;
		iecsock_set_options(s,&opt);
	}
}

int main(int argc, char **argv)
{
	pid_t pid, sid;
	u_int32_t flags;   /* database open flags */
	u_int32_t env_flags;
	int ret;           /* function return value */

	struct sockaddr_in addr;
	int i;
	struct sigaction sa;
	sigset_t newset;

	/* become daemon */
	pid = fork();
	if (pid < 0 )
		exit(EXIT_FAILURE);
	if (pid > 0)
		exit(EXIT_SUCCESS);
	umask(0);

	logfile = fopen(LOGFILE,"a+");
	if (logfile == NULL)
		exit(EXIT_FAILURE);

	sid = setsid();
	if (sid < 0)
		exit(EXIT_FAILURE);
	if ((chdir("/")) < 0)
		exit(EXIT_FAILURE);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/* now we are daemon */
	
	/* set signal handler */
	sigemptyset(&newset);
	sigaddset(&newset, SIGHUP);
	sigprocmask(SIG_BLOCK, &newset, 0);
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, 0);

	/* begin */
	event_init();
	
	default_hooks.disconnect_indication = disconnect_hook;
	default_hooks.connect_indication = connect_hook;
	default_hooks.data_indication = data_received_hook;
	default_hooks.activation_indication = activation_hook;

	/* database stuff */
	ret = db_env_create(&dbenvp, 0);
	if (ret != 0) {
		fprintf(logfile, "Error creating env handle: %s\n", db_strerror(ret));
		goto is_error;
	}
	env_flags = DB_CREATE | DB_INIT_LOCK | DB_INIT_MPOOL;
	ret = dbenvp->open(dbenvp,	/* DB_ENV ptr */
		DBPATH,		/* env home directory */
		env_flags,	/* Open flags */
		0		/* File mode (default) */
	);
	if (ret != 0) {
		fprintf(logfile, "Environment open failed: %s", db_strerror(ret));
		goto is_error;
	} 
	ret = db_create(&dbp, dbenvp, 0);

	if (ret != 0){
		fprintf(logfile, "bu\n");
		goto is_error;		
	}
	flags = DB_CREATE;
	ret = dbp->open(
		dbp,		/* DB structure pointer */
		NULL,		/* Transaction pointer */
		"tsp200.db",		/* On-disk file that holds the database. */
		NULL,		/* Optional logical database name */
		DB_BTREE,	/* Database access method */
		flags,		/* Open flags */
		0		/* File mode (using defaults) */
	);
	if (ret != 0){
		fprintf(logfile, "buu: %s\n", db_strerror(ret));
		goto is_error;
	}
	
	ret = init_koef_db(&kdbp);
	if (ret != 0) {
		fprintf(logfile,"can not init koef db\n");
		goto is_error;
	}
	
	/* connect to slaves */ 
	for (i=0; tsp200[i].ipaddr != NULL; i++) {
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(tsp200[i].port);
		if (inet_pton(AF_INET, tsp200[i].ipaddr, &addr.sin_addr) > 0)
			iecsock_connect(&addr);
		else
			iecsock_connect(NULL);
	}
	
	iecsock_listen(NULL,10);
	
	fprintf(logfile,"i'm daemonized and begin to work\n");
	
	event_dispatch();

	if (dbp != NULL)
		dbp->close(dbp, 0); 
	if (dbenvp != NULL) {
		dbenvp->close(dbenvp, 0);
	} 
	return EXIT_SUCCESS;

is_error:
	fclose(logfile);
	exit(EXIT_FAILURE);
}
