#include "tsp200proxy.h"

/*#include <db.h>
#include <string.h>
#include <stdio.h>

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
*/

int init_koef_db(DB **kdbp)
{
	FILE *fp;
	DB *dbp;
	DBT key, data;
	struct kdb_key	kdbkey;
	struct kdb_data	kdbdata;

	unsigned int asdu;
	unsigned int ioaf;
	float koefu, koefi;
	int ret;
	char line[LMAX];

	if ( (fp = fopen(KFILE,"r")) == NULL)
		return -1;

	if ( db_create(&dbp, NULL, 0) != 0)
		return -2;

	if ( dbp->open(dbp,NULL,NULL,NULL,DB_BTREE,DB_CREATE,0) != 0 )
		return -3;

	/* Zero out the DBTs before using them. */
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	
	while(fgets(line, LMAX, fp)!=NULL){
		if (sscanf(line,"%u;%x;%f;%f\n",&asdu,&ioaf,&koefu,&koefi) < 1)
			continue;
		kdbkey.asdu = (unsigned short) asdu;
		kdbkey.ioa2 = (unsigned char)  ioaf;
		kdbdata.koef_u = koefu;
		kdbdata.koef_i = koefi;

		key.data = &kdbkey;
		key.size = sizeof(struct kdb_key);

		data.data = &kdbdata;
		data.size = sizeof(struct kdb_data);

		ret = dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
		if (ret != 0) {
			dbp->err(dbp, ret, "Put failed: ");
		}

	}

	fclose(fp);
	*kdbp = dbp;
	return 0;
}

int show_koef_db(DB *dbp)
{
	DBT key, data;
	DBC *cursorp;
	struct kdb_key	*kdbkeyp;
	struct kdb_data	*kdbdatap;
	int ret;

	dbp->cursor(dbp, NULL, &cursorp, 0); 
	/* Initialize our DBTs. */
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	while ((ret = cursorp->c_get(cursorp, &key, &data, DB_NEXT)) == 0) {
		kdbkeyp  = (struct kdb_key *)  key.data;
		kdbdatap = (struct kdb_data *) data.data;
		fprintf(stdout,"%i : %x : %f\t%f\n",
			kdbkeyp->asdu,
			kdbkeyp->ioa2,
			kdbdatap->koef_u,
			kdbdatap->koef_i
		);
	}
	return 0;
}

float get_koef(DB *dbp, unsigned short caddr, unsigned char ioa2, unsigned char type)
{
	DBT key, data;
	struct kdb_key	kdbkey;
	struct kdb_data	kdbdata;
	float ret;

	/* Initialize our DBTs. */
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	
	kdbkey.asdu = caddr;
	kdbkey.ioa2 = ioa2;

	key.data = &kdbkey;
	key.size = sizeof(struct kdb_key);
	key.flags = DB_DBT_USERMEM;

	memset(&kdbdata, 0, sizeof(struct kdb_data));
	data.data = &kdbdata;
	data.ulen = sizeof(struct kdb_data);
	data.flags = DB_DBT_USERMEM;

	ret = dbp->get(dbp,NULL,&key,&data,0);
	if (ret != 0) {
		dbp->err(dbp, ret, "get failed: ");
		return 0;
	}
	
	switch(type){
	case KOEFU:
		ret = kdbdata.koef_u;
		break;
	case KOEFI:
		ret = kdbdata.koef_i;
		break;
	case KOEFP:
		ret = kdbdata.koef_i * kdbdata.koef_u;
		break;
	default:
		ret = 1;
	}

	return ret;
}

unsigned char get_value_type(unsigned short ioa) {
	unsigned char ret = 0;

	if (ioa < 1000 && ioa > 2000)
		return 0;

	switch (ioa & 0xF) {
		case  1: ret = KOEFI; break;
		case  2: ret = KOEFU; break;
		case  3: ret = KOEFP; break;
		case  4: ret = KOEFP; break;
		case  5: ret = KOEFI; break;
		case  6: ret = KOEFU; break;
		case  7: ret = KOEFP; break;
		case  8: ret = KOEFP; break;
		case  9: ret = KOEFI; break;
		case 10: ret = KOEFU; break;
		case 11: ret = KOEFP; break;
		case 12: ret = KOEFP; break;
		case 13: ret = KOEFF; break;
		default: ret = 0;
	}

	return ret;
}
/*

int main(int argc, char **argv)
{
	int ret;
	DB *db_p;

	ret = init_koef_db(&db_p);
	if (ret) fprintf(stderr,"error occured\n");

	fprintf(stdout,"%f\t",get_koef(db_p,5,0x46,KOEFU));
	fprintf(stdout,"%f\n",get_koef(db_p,5,0x47,KOEFI));

	ret = show_koef_db(db_p);

	if (db_p != NULL)
		db_p->close(db_p, 0);
	return 0;
}

*/
