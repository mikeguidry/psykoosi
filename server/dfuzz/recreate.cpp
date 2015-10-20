#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <mysql.h>
#include <sys/stat.h>
#include <sys/types.h>


char g_db[1024];




// Operations are each of the different fuzz tasks.. such as a specific version of Adobe
// using a specific Sample strand, or sample generation function/python script
// Also whether we have to inject a DLL to control something in the application (maybe blocking networking),
// or which IPC file for nanomsg controls this task....
typedef struct _operations {
    struct _operations *next;
    int id;
    char application[25];
    char version[25];
    int thinapp;
    char sample[25];
    int max_clients;
    int queue_timeout;
    int enabled;
    int created_ts;
    int memory_only;
    int trace_mode;
    int operating_system;
    int inject_dll;
    char dll[25];
    char ipc_file[25];
    char installer_url[1024];
    char installer_command_line[1024];
    char application_path[1024];
    char application_path64[1024];
    int max_bytes_per_worker;
} Operations;



// Samples contains the sample information.. the generator used.. application and version the samples are for
// the initial file for the generator, and the data returned by the generator if this sample has already been created for distribution
// exhausted means the entire sample has already been distributed
typedef struct _samples {
    struct _samples *next;
    int id;
    char application[25];
    char version[25];
    char generator[25];
    int ts;
    int bytes;
    unsigned char *data;
    int exhausted;
    unsigned char *initial_file;
    int operation_id;
    int mode;
    int parent_id;
    int initial_file_size;
    struct _samples *generated;
    int cur_generation;
    int max_generation;
    int cur_distribution_byte;
} Samples;


// Exceptions structure... this is mainly how the data should come from the webserver.... in the form of a nanomsg... extra_size determines size of extra
typedef struct _exceptions {
    struct _exceptions *next;
    int id;
    int operation_id;
    char application[25];
    char version[25];
    char exception_address[25];
    char exception_code[25];
    int sample_id;
    int byte;
    char newbyte[25];
    int  ts;
    int mode;
    char hash[64];
    char ip[16];
    int checked;
    int extra_size;
    unsigned char *extra;
    int queue_id;
} Exceptions;



Operations *operations = NULL;
Exceptions *exceptions = NULL;
Samples *samples = NULL;
MYSQL *mysql = NULL;



Samples *sample_by_id(int id, int parent) {
    Samples *sptr;
    Samples *gptr;
    for (sptr = samples; sptr != NULL; sptr = sptr->next) {
        if (parent && sptr->id == id) return sptr;
        if (!parent) {
            for (gptr = samples->generated; gptr != NULL; gptr = gptr->next) {
                if (gptr->id == id) return gptr;
            }
        }
    }
    return NULL;
}



// this is used to initialize mysql.. but can also be called later to reconnect if we get any server has gone away messages from idles, etc
// we just exit if error since we'll just loop this application
void mysql_reopen(void) {
    MYSQL *sql = NULL;
    
    if (mysql != NULL) mysql_close(mysql);

    if ((sql = mysql_init(NULL)) == NULL) {
        printf("Fatal sql error\n");
        exit(-1);
    }
    if (!(mysql_real_connect(sql,"localhost","root","",0,0,NULL,0))) {
        printf("Error connecting to SQL\n");
        exit(-1);
    }
    
    if (mysql_select_db(sql,g_db)) {
        printf("Error selecting database\n");
        exit(-1);
    }
    
    mysql = sql;
}



MYSQL_RES *my_sql_query(MYSQL *sql, char *query, int query_len, int no_result, int use_result) {
	MYSQL_RES *res = NULL;
    int ret;
    
    // maybe some error.. but shouldnt happen
	if (query == NULL || !query_len) return NULL;

    if ((ret = mysql_real_query(sql, query, query_len))) {
        mysql_reopen();
        ret = mysql_real_query(sql, query, query_len);

        if (no_result)
            return res;
        
        if (ret) {
            printf("mysql [%p] error querying: %s [%s]\n", sql, query, mysql_error(sql));
            exit(-1);
        }
    }
    
    // query was okay.. lets return results
    if (!ret) {
        res = use_result ? mysql_use_result(sql) : mysql_store_result(sql);
        return res;
    }
    
    return NULL;
}



void Operations_Load() {
    Operations *optr = NULL;
    char query[1024];
    int querylen;
    MYSQL_RES			*res = NULL;
    MYSQL_ROW			row;

    printf("Operations_Load();\n");
    querylen = snprintf(query, sizeof(query) - 1, "SELECT *,unix_timestamp(created) from operations where enabled = 1;");
    res = my_sql_query(mysql, query, querylen, 0, 0);

    if (operations != NULL) {
      printf("Purposely (lazily) leaking the operations... so we can start on a new list...\n");
      operations = NULL;
    }



    while ((row = mysql_fetch_row(res)) != NULL) {
        if ((optr = (Operations *)malloc(sizeof(Operations) + 1)) == NULL) goto end;
        memset(optr, 0, sizeof(Operations));
    
        optr->id = atoi(row[0]);
    
        strncpy(optr->application, row[1], 24);
        strncpy(optr->version, row[2], 24);
        strncpy(optr->sample, row[3], 24);
        optr->thinapp = atoi(row[4]);
        optr->max_clients = atoi(row[5]);
        optr->queue_timeout = atoi(row[6]);
        optr->memory_only = atoi(row[7]);
        optr->trace_mode = atoi(row[8]);

        optr->enabled = atoi(row[10]);
        optr->operating_system = atoi(row[11]);
        strncpy(optr->ipc_file, row[12], 24);
        optr->inject_dll = atoi(row[13]);
        if (row[14] != NULL)
            strncpy(optr->dll, row[14], 24);

	
	if (row[15] != NULL)
	    strncpy(optr->installer_url, row[15], 1023);
	    
	if (row[16] != NULL)
	    strncpy(optr->installer_command_line, row[16], 1023);
        
        
    if (row[17] != NULL)
        strncpy(optr->application_path, row[17], 1023);
        
    if (row[18] != NULL)
        strncpy(optr->application_path64, row[18], 1023);
        
        
        optr->max_bytes_per_worker = atoi(row[19]);
        
        optr->created_ts = atoi(row[20]); // should be row 9 but its the extra unix_timestamp parameter.. so 15
	    
        printf("App: %s Ver: %s Sample: %s Thinapp: %d Clients %d Timeout %d Memory %d Trace %d Created %d Enabled %d OS %d\n",
               optr->application, optr->version, optr->sample, optr->thinapp, optr->max_clients, optr->queue_timeout, optr->memory_only,
               optr->trace_mode, optr->created_ts, optr->enabled, optr->operating_system);
        printf("Install URL: %s Install CMD Line: \"%s\" App Path: %s App Path2: %s\n", optr->installer_url, optr->installer_command_line,
               optr->application_path, optr->application_path64);
        
        // push it to the beginning of linked list..
        optr->next = operations;
        operations = optr;
    }

end:;

    if (res != NULL) mysql_free_result(res);
}




void Samples_Load() {
    Samples *optr = NULL;
    Samples *parent = NULL;
    char query[1024];
    int querylen;
    MYSQL_RES			*res = NULL;
    MYSQL_ROW			row;
    unsigned long *lengths;
    
    printf("Samples_Load();\n");
    querylen = snprintf(query, sizeof(query) - 1, "SELECT *,unix_timestamp(ts) from samples order by id asc;");
    res = my_sql_query(mysql, query, querylen, 0, 1);

    samples = NULL;
    
    
    while ((row = mysql_fetch_row(res)) != NULL) {
	
        lengths = mysql_fetch_lengths(res);
        if ((optr = (Samples *)malloc(sizeof(Samples) + 1)) == NULL) goto end;
        memset(optr, 0, sizeof(Samples));
printf("Loading sample %d\n", atoi(row[0]));
        
        optr->id = atoi(row[0]);
        strncpy(optr->application, row[1], 24);
        strncpy(optr->version, row[2], 24);
        strncpy(optr->generator, row[3], 24);
        optr->ts = atoi(row[4]); // should be 4 but using unix_timestamp(ts)
        optr->bytes = atoi(row[5]);
	if (optr->bytes != lengths[6]) printf("error with sample size? %d %d\n", optr->bytes, lengths[6]);
	
	// copy blob data of data variable from sql table
	if (lengths[6]) {
	    optr->data = (unsigned char *)malloc(lengths[6] + 1);
	    memcpy(optr->data, row[6], lengths[6]);
	}
	
	optr->exhausted = atoi(row[7]);
	
	// copy blob data of initial file
	if (lengths[8]) {
	    optr->initial_file = (unsigned char *)malloc(lengths[8] + 1);
	    memcpy(optr->initial_file, row[8], lengths[8]);
        optr->initial_file_size = lengths[8];
	}
        
        optr->operation_id = atoi(row[9]);
        optr->parent_id = atoi(row[10]);
        
        // push it to the beginning of linked list.. unless it has a parent_id...
        if (!optr->parent_id) {
            optr->next = samples;
            samples = optr;
        } else {
            parent = sample_by_id(optr->parent_id, 1);
            if (parent == NULL) {
                printf("error finding parent? some database fuck up!\n");
                exit(-1);
            }
            // put inside of the initial sample structure
            optr->next = parent->generated;
            parent->generated = optr;
        }
        
        optr->initial_file_size = atoi(row[11]);
        optr->cur_generation = atoi(row[12]);
        optr->max_generation = atoi(row[13]);
        optr->cur_distribution_byte = atoi(row[14]);
    }
    
end:;
    
    if (res != NULL) mysql_free_result(res);
}





void Exceptions_Load(int id) {
    Exceptions *optr = NULL;
    Exceptions *parent = NULL;
    char query[1024];
    int querylen;
    MYSQL_RES			*res = NULL;
    MYSQL_ROW			row;
    unsigned long *lengths;
    
memset(query,0,1024);
    printf("Exceptions_Load();\n");
    querylen = snprintf(query, sizeof(query) - 1, "SELECT *,unix_timestamp(ts) from exceptions ");
if (id)
sprintf(query+querylen, " where id=%d", id);
strcat(query, ";");
    res = my_sql_query(mysql, query, strlen(query), 0, 1);
    
    exceptions = NULL;
    
    
    while ((row = mysql_fetch_row(res)) != NULL) {
	
        lengths = mysql_fetch_lengths(res);
        if ((optr = (Exceptions *)malloc(sizeof(Exceptions) + 1)) == NULL) goto end;
        memset(optr, 0, sizeof(Exceptions));
        
        optr->id = atoi(row[0]);
	optr->operation_id = atoi(row[1]);
        strncpy(optr->application, row[2], 24);
        strncpy(optr->version, row[3], 24);
        memcpy(optr->exception_address, row[4], 24);
	memcpy(optr->exception_code, row[5], 24);
	optr->sample_id = atoi(row[6]);
	optr->byte = atoi(row[7]);
	memcpy(optr->newbyte, row[8], 24);
	optr->ts = atoi(row[17]); // should be 9 but 17 due to UNIX_TIMESTAMP
	optr->mode = atoi(row[10]);
	strncpy(optr->hash, row[11], 63);
	strncpy(optr->ip, row[12], 15);
	optr->checked = atoi(row[14]);
	optr->queue_id = atoi(row[15]);
	optr->extra_size = atoi(row[16]);
	// extra should be row[15]
	
	
	// copy blob data of data variable from sql table
	if (lengths[13]) {
	    optr->extra = (unsigned char *)malloc(lengths[13] + 1);
	    memcpy(optr->extra, row[13], lengths[13]);
	    optr->extra_size = lengths[13];
	}
    
	optr->next = exceptions;
	exceptions = optr;
	
    }
    
end:;
    
    if (res != NULL) mysql_free_result(res);
}

int recreate_sample(Exceptions *eptr, char *output_dir, char *suffix) {
    Samples *sptr;
    FILE *fd;
    char *tmpfile = tempnam(output_dir, "exception");
    char _tmpfile[1024];
    char *ptr;
    int _newbyte;
    unsigned char newbyte;
    char *data = NULL;
    int n;
    
    sprintf(_tmpfile, "%s%d.%s", output_dir, eptr->id, suffix);
    
    sptr = sample_by_id(eptr->sample_id, 0);
    if (sptr == NULL) {
	printf("Exception #%d - cannot find sample id %d\n", eptr->id, eptr->sample_id);
	return -1;
    }
 
    // due to bug with the way sql stors newbyte..there may be 0x00 infront..
    for (ptr = (char *)&eptr->newbyte[0], n = 0; n < 22; n++)
	if (*ptr != 0) break; else ptr++;

    sscanf(ptr, "%02x", &_newbyte);
    newbyte = (unsigned char)_newbyte;
    
    data = (char *)malloc(sptr->bytes+ 1);
    memcpy(data, sptr->data, sptr->bytes);
    
    // recreate the sample that caused the exception by changing to the correct byte
    data[eptr->byte] = newbyte;

    if ((fd = fopen(_tmpfile, "wb")) == NULL) {
	printf("Exception #%d - error opening output file %s\n", eptr->id, _tmpfile);
	return -1;
    }
    
    if (fwrite(data, 1, sptr->bytes, fd) != sptr->bytes) {
	printf("Exception #%d - error writing output file\n", eptr->id);
	fclose(fd);
	unlink(_tmpfile);
	return -1;
    }
    
    fclose(fd);
    
    
    
    printf("Exception #%d - Wrote output file %s [%d bytes] Changed byte %d [%02X -> %02X]\n", eptr->id,
		_tmpfile, sptr->bytes, eptr->byte, (unsigned char)sptr->data[eptr->byte], (unsigned char)data[eptr->byte]);
	
    free(data);	
    
    return 1;
}

int main(int argc, char *argv[]) {
int id=0;
if (argc < 2) {
printf("%s <db> <exception id>\n", argv[0]);
exit(0);
} else {
strcpy(g_db, argv[1]);
}
if (argc == 3) id=atoi(argv[2]);
    mysql_reopen();
    Operations_Load();
    Samples_Load();
    Exceptions_Load(id);


mkdir("original", 0777);
mkdir("exceptions", 0777);
   printf("Recreating exception sample files\n");
    for (Exceptions *eptr = exceptions; eptr != NULL; eptr = eptr->next) {
        recreate_sample(eptr, "exceptions/", "pdf");
    }

    printf("Recreating original sample files before exceptions:\n");
	for (Samples *sptr = samples->generated; sptr != NULL; sptr = sptr->next) {
	if (sptr->parent_id == 0) continue;
	char filename[1024];
	sprintf(filename, "original/sample_%d.pdf", sptr->id);
	FILE *fd = fopen(filename, "wb");
	if (fd) {
		fwrite(sptr->data, 1, sptr->bytes, fd);
		fclose(fd);
	} else printf(" cannot open file %s\n", filename);
	}


}
