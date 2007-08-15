#include <db.h>
#include <string.h>
#include <time.h>
/*
#define	DBPATH	"/home/crux/db"
#define	DBNAME	"/home/crux/db/tsp200.db"
*/
#define	TII	1
#define	TI	2
#define	TS	3

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

int main(int argc, char **argv)
{
	DB *dbp;           /* DB structure handle */
	DB_ENV *dbenvp;
	DBC *cursorp;
	DBT key, data;
	struct db_key dbkey;
	struct db_data dbdata, *dbdatap;
	
	int ret;           /* function return value */

	ret = db_env_create(&dbenvp, 0);
	if (ret != 0) {
		fprintf(stderr, "Error creating env handle: %s\n", db_strerror(ret));
		return -1;
	}

/*	if ((ret = dbenvp->set_cachesize(dbenvp, 0, 5 * 1024 * 1024, 0)) != 0) {
		dbenvp->err(dbenvp, ret, "set_cachesize");
		return -1;
	}
	if ((ret = dbenvp->set_data_dir(dbenvp, "/home/crux/db")) != 0) {
		dbenvp->err(dbenvp, ret, "set_data_dir: /home/crux/db");
		return -1;
	} */

	ret = dbenvp->open(dbenvp,	/* DB_ENV ptr */
		"/home/crux/Devel/mrts/db",		/* env home directory */
		DB_CREATE  |
		DB_INIT_LOCK |
		DB_INIT_MPOOL
		,/* Open flags */
		0		/* File mode (default) */
	);
	if (ret != 0) {
		fprintf(stderr, "Environment open failed: %s\n", db_strerror(ret));
		return -1;
	} 

	/* Initialize the structure. This
	 * database is not opened in an environment, 
	 * so the environment pointer is NULL. */
	ret = db_create(&dbp, dbenvp, 0); 
	/* ret = db_create(&dbp, NULL, 0); */
	if (ret != 0) {
	  /* Error handling goes here */
		fprintf(stderr,"bu!\n");
		return 1;
	}

	/* open the database */
	ret = dbp->open(dbp,        /* DB structure pointer */
	                NULL,       /* Transaction pointer */
	                "tsp200.db", /* On-disk file that holds the database. */
	                NULL,       /* Optional logical database name */
	                DB_BTREE,   /* Database access method */
	                DB_CREATE,      /* Open flags */
	                0);         /* File mode (using defaults) */
	if (ret != 0) {
	  /* Error handling goes here */
		dbp->err(dbp, ret,
	      "Database open failed: %i %s", __LINE__ , "test.db");
		return ret;
	}

	dbkey.asdu = 5;
	dbkey.ioa  = 1;
	dbkey.ioa2 = 0;
	dbkey.type = TS;
	dbkey.tm   = time(NULL);

	dbdata.asdu = 5;
	dbdata.ioa  = 1;
	dbdata.ioa2 = 0;
	dbdata.type = TS;
	dbdata.tm   = time(NULL);
	switch (dbdata.type) {
	case TII:	dbdata.tii = 222;
		break;
	case TI:	dbdata.ti  = 5.1;
		break;
	case TS:	dbdata.ts  = 1;
		break;
	}
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	key.data = &dbkey;
	key.size = sizeof(struct db_key);

	data.data = &dbdata;
	data.size = sizeof(struct db_data);
	
/*	ret = dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
	if (ret != 0) {
		dbp->err(dbp, ret, "Put failed");
	} */

	dbp->cursor(dbp, NULL, &cursorp, 0); 
	/* Initialize our DBTs. */
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	fprintf(stdout,"ASDU;ADDR;ADDRHEX;VALUE;TIME\n");
	/* Iterate over the database, retrieving each record in turn. */
	while ((ret = cursorp->c_get(cursorp, &key, &data, DB_NEXT)) == 0) {
        	/* Do interesting things with the DBTs here. */
		dbdatap = (struct db_data *) data.data;
		switch(dbdatap->type){
		case TII:
			fprintf(
				stdout,"%i;%i;%x;%i;%s",
				dbdatap->asdu,
				dbdatap->ioa + dbdatap->ioa2*65536,
				dbdatap->ioa + dbdatap->ioa2*65536,
				dbdatap->tii, ctime(&(dbdatap->tm)));
			break;
		case TI:
			fprintf(stdout,"%i;%i;%x;%f;%s",
				dbdatap->asdu,
				dbdatap->ioa + dbdatap->ioa2*65536,
				dbdatap->ioa + dbdatap->ioa2*65536,
				dbdatap->ti, ctime(&(dbdatap->tm)));
			break;
		case TS:
			fprintf(stdout,"%i;%i;%x;%i;%s",
				dbdatap->asdu,
				dbdatap->ioa + dbdatap->ioa2*65536,
				dbdatap->ioa + dbdatap->ioa2*65536,
				dbdatap->ts, ctime(&(dbdatap->tm)));
			break;
		default: 
			fprintf(stderr,"VALUE IS: %i\n",dbdatap->type);
		}
			
	}
	if (ret != DB_NOTFOUND) {
	        /* Error handling goes here */
		fprintf(stderr,"buuu!\n");
		return 3;
	}

	/* Cursors must be closed */
	if (cursorp != NULL) 
	    cursorp->c_close(cursorp); 

	if (dbp != NULL) 
	    dbp->close(dbp, 0);	

	if (dbenvp != NULL) {
		dbenvp->close(dbenvp, 0);
	} 
	
	return 0;
}
