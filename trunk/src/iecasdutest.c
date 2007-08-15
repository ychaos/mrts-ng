/*
 * Copyright (C) 2005 by Grigoriy A. Sitkarev                            
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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <event.h>

#include "iecsock.h"
#include "iec104.h"

struct iec_unit_id	unit;
struct iec_type33	type;

#define COM_ADDRLEN	2
#define IOA_ADDRLEN	2

#define ASDU_ADDR(asdu_addr, ioa_len, addrv)				\
	asdu_addr = (ioa_len == 2 ? addrv : addrv & 0xFF);	

int main(int argc, char **argv)
{
	int ret, i;
	int n, len;
	u_short ioa, caddr;
	u_char cause, test, pn, *cp, t, str_ioa=0;
	struct iec_buf *b;
	struct iec_object obj[IEC_OBJECT_MAX];
	
	memset(&obj, 0, sizeof(obj));
	b = calloc(1, sizeof(struct iec_buf) + 249);
	if (!b)
		return (1);
	
	unit.type = 33;
	unit.num = 10;
	unit.sq = 0;
	unit.cause = 12;
	unit.ca = 0x5677;
	*type.stcd.st = 0xffff;
	*type.stcd.cd = 0xa3df;
	/* type.mv = 33.55677; */
	ioa = 0x1133;
	
	/*
	len = IEC_TYPEID_LEN + COM_ADDRLEN + (sizeof(struct iec_type13) * unit.num) + IOA_ADDRLEN;
	if (len > IEC104_ASDU_MAX)
		return (1);
		
	b->data_len = len;
	cp = b->data;
	ASDU_ADDR(caddr, COM_ADDRLEN, unit.ca);
	memcpy(cp, &unit, IEC_TYPEID_LEN);
	cp += IEC_TYPEID_LEN;
	memcpy(cp, &caddr, COM_ADDRLEN);
	cp += COM_ADDRLEN;
	
	memcpy(cp, &ioa, IOA_ADDRLEN);
	cp += IOA_ADDRLEN;
	memcpy(cp, &type, sizeof(type));
	cp += sizeof(type);
	
	for (i=0; i < unit.num - 1; i++) {
		memcpy(cp, &type, sizeof(type));
		cp += sizeof(type);
	}
	*/
	
	len = IEC_TYPEID_LEN + COM_ADDRLEN + ((sizeof(struct iec_type33) + IOA_ADDRLEN) * unit.num);
	if (len > IEC104_ASDU_MAX)
		return (1);
	b->data_len = len;
	cp = b->data;
	memcpy(cp, &unit, IEC_TYPEID_LEN + COM_ADDRLEN);
	cp += IEC_TYPEID_LEN + COM_ADDRLEN;
	
	for (i=0; i < unit.num; i++) {
		memcpy(cp, &ioa, IOA_ADDRLEN);
		cp += IOA_ADDRLEN;
		ioa += 2;
		memcpy(cp, &type, sizeof(type));
		cp += sizeof(type);
	}
	
	
	ret = iecasdu_parse(obj, &t, &caddr, &n, &cause, &test, &pn, 
		&str_ioa, b->data, b->data_len);
	
	/*
	ret = iecasdu_parse_type7(obj, &caddr, &n, &cause, &test, 
			&pn, IOA_ADDRLEN, COM_ADDRLEN, b->data, b->data_len);
	*/
	
	fprintf(stderr, "CA=0x%04x NUM=%i CAUSE=%i TEST=%i P/N=%i\n", caddr, n, cause, test, pn);
	for (i=0;i<n;i++) {
		fprintf(stderr, "Value: IDX:%04i st:0x%04x cd:0x%04x ov:%i bl:%i sb:%i nt:%i iv:%i\n",
		obj[i].ioa,
		*(obj[i].o.type33.stcd.st), *(obj[i].o.type33.stcd.cd),
		obj[i].o.type33.ov, obj[i].o.type33.bl, 
		obj[i].o.type33.sb, obj[i].o.type33.nt, obj[i].o.type33.iv);
	}

	/*
	fprintf(stderr, "CA=0x%04x NUM=%i CAUSE=%i TEST=%i P/N=%i\n", caddr, n, cause, test, pn);
	for (i=0;i<n;i++) {
		fprintf(stderr, "Value: IDX:%i mv:%f ov:%i bl:%i sb:%i nt:%i iv:%i\n",
		obj[i].ioa,
		obj[i].o.type13.mv, obj[i].o.type13.ov, obj[i].o.type13.bl, 
		obj[i].o.type13.sb, obj[i].o.type13.nt, obj[i].o.type13.iv);
	} */
	return 0;
}
