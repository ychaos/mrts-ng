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
#ifndef __IEC104_H
#define __IEC104_H

#ifndef __IEC104_TYPES_H
#include "iec104_types.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define IEC_OBJECT_MAX	127
#define IEC_TYPEID_LEN	3

/* Information object */
struct iec_object {
	u_short		ioa;	/* information object address */
	u_char		ioa2;	/* information object address */
	union {
		struct iec_type1	type1;
		struct iec_type7	type7;
		struct iec_type9	type9;
		struct iec_type11	type11;
		struct iec_type13	type13;
		struct iec_type30	type30;
		struct iec_type33	type33;
		struct iec_type34	type34;
		struct iec_type35	type35;
		struct iec_type36	type36;
		struct iec_type37	type37;
		struct iec_type100	type100;
		struct iec_type101	type101;
		struct iec_type103	type103;
	} o;	
}__attribute__((__packed__));


int iecasdu_parse(struct iec_object *obj, u_char *type, u_short *com_addr, 
	int *cnt, u_char *cause, u_char *test, u_char *pn, u_char *str_ioa,
	u_char *buf, size_t buflen);

/*
 * New functions
 */
void time_t_to_cp56time2a (cp56time2a *tm, time_t *timet);
void current_cp56time2a (cp56time2a *tm);
time_t cp56time2a_to_tm (cp56time2a *tm);

void iecasdu_create_header_all (u_char *buf, size_t *buflen, u_char type, u_char num,
	u_char sq, u_char cause, u_char t, u_char pn, u_char ma, u_short ca );

#define iecasdu_create_header(buf, buflen, type, num, cause, ca) \
	iecasdu_create_header_all(buf, buflen, type, num, 0, cause, 0, 0, 0, ca);

void iecasdu_create_type_36 (u_char *buf, size_t *buflen, int num, float *mv);
void iecasdu_create_type_100 (u_char *buf, size_t *buflen);
void iecasdu_create_type_101 (u_char *buf, size_t *buflen);
void iecasdu_create_type_103 (u_char *buf, size_t *buflen);

/* end of New functions */

#ifdef __cplusplus
}
#endif

#endif	/* __IEC104_H */
