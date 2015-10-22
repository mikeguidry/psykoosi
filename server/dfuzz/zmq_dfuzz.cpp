#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <zmq.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <mysql.h>
#include <Python.h>
#include <sys/param.h>
#include <netdb.h>




// appends a single byte into a stream and increments the pointer
int putbyte(char **dst, unsigned char value) {
	**dst = value;
	(*dst)++;
	
	return sizeof(char);
}

// appends an integer into a stream and increments the pointer
int putint(char **dst, int n) {
	unsigned char *p;
	unsigned char *int_raw = (unsigned char *)&n;
	p = (unsigned char *)*dst;
	
	memcpy(p, int_raw, sizeof(int));
	(*dst) += sizeof(int);
	
	return sizeof(int);
}

// appends a specific amount of data into a stream and then increments the pointer
int putdata(char **dst, char *data, size_t len) {
	if ((len <= 0) || (dst == NULL) || (data == NULL))
		return 0;
	
	memcpy(*dst, data, len);
	
	(*dst) += len;
	return len;
}

typedef struct _id_search {
    struct _id_search *next;
    int id;
} ID_Search;




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

// Complete is a structure of tasks that have been completed by a specific worker/client..
// it contains the usual information to relate it back to its initial operation profile
// and amount of time for completion...
// This can be used later for statistics and figuring out how to increase overall speed rather
// than something necessary for continuous operation...maybe even if we test a specific injection
// DLL which could help increase overall fuzzing speed if we choose to use that method for success/fail
// rather than a timeout.. saving 5-10 seconds per fuzz can increase overall operational performance
// substantially
typedef struct _complete {
    struct _complete *next;
    int id;
    char application[25];
    char version[25];
    int ts;
    int sample_id;
    int byte;
    int mode;
    int count;
    char hash[64];
    int exceptions;
    int time;
    int operation_id;
} Complete;

// Queue are active tasks that were distributed and being executed now.. it contains the time it was distributed
// this can be used to determine if it should be redistributed to another client due to assuming failure since we
// never know when a client may go offline.. very important to consistenly check this,
typedef struct _queue {
    struct _queue *next;
    int id;
    char application[25];
    char version[25];
    int ts;
    char ip[16];
    char hash[64];
    int sample_id;
    int byte;
    int mode;
    int count;
    int complete;
    int operation_id;
    int timeout;
} Queue;


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

typedef struct _emu_snapshot {
    struct _emu_snapshot *next;
    int id;
    char application[25];
    char version[25];
    int ts;
    int bytes;
    unsigned char *data;
    int operation_id;
    int parent_id;
} Snapshot;

typedef struct _protocol_exchange {
    struct _protocol_exchange *next;
    int id;
    int side;
    int count;
    char application[25];
    char version[25];
    int exec_id;
    int ts;
    int bytes;
    unsigned char *data;
    int data_size;
    int operation_id;
    int parent_id;
} ProtocolExchange;

typedef struct _protocol_sample {
    struct _protocol_sample *next;
    int id;
    char application[25];
    char version[25];
    int ts;
    int snapshot_id;
    int operation_id;
    int parent_id;
} ProtocolSample;



Operations *operations = NULL;
Complete *complete = NULL;
Queue *queue = NULL;
Queue *requeue = NULL;
Exceptions *exceptions = NULL;
Samples *samples = NULL;
Snapshot *snapshots = NULL;
ProtocolExchange *exchanges = NULL;
ProtocolSample *protocol_samples = NULL;

MYSQL *mysql = NULL;

Queue *GetQueue(Operations *optr);



enum {
    CONTACT,
    COMPLETE,
    EXCEPTION,
    CONTACT_RESP,
    COMPLETE_RESP,
    EXCEPTION_RESP,
    SNAPSHOT,
    SNAPSHOT_RESP,
    PROTOCOL_EXCHANGE,
    PROTOCOL_EXCHANGE_RESP,
    PROTOCOL_SAMPLE,
    PROTOCOL_SAMPLE_RESP,
    NONE
};





Operations *operation_by_id(int id) {
    for (Operations *optr = operations; optr != NULL; optr = optr->next) {
        if (optr->id == id) return optr;
    }
    return NULL;
}


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

// since all IDs are the 2nd place in the structure.. lets use a generic structure...
// just cast it..
ID_Search *Element_by_ID(ID_Search *list, int id) {
    ID_Search *sptr = list;
    
    for (; sptr != NULL; sptr = sptr->next) {
        if (sptr->id == id) return sptr;
    }
    
    return NULL;
}



// this is used to initialize mysql.. but can also be called later to reconnect if we get any server has gone away messages from idles, etc
// we just exit if error since we'll just loop this application
void mysql_reopen(void) {
    char name[MAXHOSTNAMELEN];
    size_t namelen = MAXHOSTNAMELEN;
    MYSQL *sql = NULL;
    char *sock=NULL;
    
    if ((gethostname(name, namelen) != -1) && (strcmp(name, "RC665")==0))
        sock = "/var/run/mysqld/mysqld.sock";
    
    if (mysql != NULL) mysql_close(mysql);

    if ((sql = mysql_init(NULL)) == NULL) {
        printf("Fatal sql error\n");
        exit(-1);
    }
    if (!(mysql_real_connect(sql,"localhost","root","",0,0,sock,0))) {
        printf("Error connecting to SQL\n");
        exit(-1);
    }
    
    if (mysql_select_db(sql,"dfuzz")) {
        printf("Error selecting database\n");
        exit(-1);
    }
    
    mysql = sql;
}



MYSQL_RES *my_sql_query(MYSQL *sql, char *query, int query_len, int no_result) {
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
        res = mysql_store_result(sql);
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
    res = my_sql_query(mysql, query, querylen, 0);

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


void Complete_Load() {
    Complete *optr = NULL;
    char query[1024];
    int querylen;
    MYSQL_RES			*res = NULL;
    MYSQL_ROW			row;
    
    printf("Complete_Load();\n");
    querylen = snprintf(query, sizeof(query) - 1, "SELECT *,unix_timestamp(ts) from complete;");
    res = my_sql_query(mysql, query, querylen, 0);
    
    complete = NULL;
    
    
    while ((row = mysql_fetch_row(res)) != NULL) {
        if ((optr = (Complete *)malloc(sizeof(Complete) + 1)) == NULL) goto end;
        memset(optr, 0, sizeof(Complete));
        
        optr->id = atoi(row[0]);
        strncpy(optr->application, row[1], 24);
        strncpy(optr->version, row[2], 24);

        optr->sample_id = atoi(row[4]);
        optr->byte = atoi(row[5]);
        optr->mode = atoi(row[6]);
        optr->count = atoi(row[7]);
        
        strncpy(optr->hash, row[8], 24);
        optr->exceptions = atoi(row[9]);
        optr->time = atoi(row[10]);

        optr->operation_id = atoi(row[11]);
        
        optr->ts = atoi(row[12]); // should be 3 but using unix_timestamp to get integer
        // put first in list..
        optr->next = complete;
        complete = optr;
        
    }
    
end:;
    
    if (res != NULL) mysql_free_result(res);
}

void Queue_Load() {
    Queue *optr = NULL;
    char query[1024];
    int querylen;
    MYSQL_RES			*res = NULL;
    MYSQL_ROW			row;
    
    printf("Queue_Load();\n");
    querylen = snprintf(query, sizeof(query) - 1, "SELECT *,unix_timestamp(ts) from queue where complete = 0;");
    res = my_sql_query(mysql, query, querylen, 0);
    
    queue = NULL;
    
    
    while ((row = mysql_fetch_row(res)) != NULL) {
        if ((optr = (Queue *)malloc(sizeof(Queue) + 1)) == NULL) goto end;
        memset(optr, 0, sizeof(Queue));
        
        optr->id = atoi(row[0]);
        strncpy(optr->application, row[1], 24);
        strncpy(optr->version, row[2], 24);

        strncpy(optr->ip, row[4], 16);
        strncpy(optr->hash, row[5], 24);
        optr->sample_id = atoi(row[6]);
        optr->byte = atoi(row[7]);
        optr->mode = atoi(row[8]);
        optr->count = atoi(row[9]);
        optr->complete = atoi(row[10]);

        optr->operation_id = atoi(row[11]);
        
        optr->timeout = atoi(row[12]);
        
        optr->ts = atoi(row[13]); // should be 3 but using unix_timestamp(ts)
        
        // push it to the beginning of linked list..
        optr->next = queue;
        queue = optr;
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
    querylen = snprintf(query, sizeof(query) - 1, "SELECT *,unix_timestamp(ts) from samples;");
    res = my_sql_query(mysql, query, querylen, 0);
    
    samples = NULL;
    
    
    while ((row = mysql_fetch_row(res)) != NULL) {
	
        lengths = mysql_fetch_lengths(res);
        if ((optr = (Samples *)malloc(sizeof(Samples) + 1)) == NULL) goto end;
        memset(optr, 0, sizeof(Samples));
        
        optr->id = atoi(row[0]);
        strncpy(optr->application, row[1], 24);
        strncpy(optr->version, row[2], 24);
        strncpy(optr->generator, row[3], 24);
        optr->ts = atoi(row[4]); // should be 4 but using unix_timestamp(ts)
        optr->bytes = atoi(row[5]);
	
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


void ProtocolSample_Load() {
    ProtocolSample *optr = NULL;
    ProtocolSample *parent = NULL;
    char query[1024];
    int querylen;
    MYSQL_RES			*res = NULL;
    MYSQL_ROW			row;
    unsigned long *lengths;
    
    printf("ProtocolSample_Load();\n");
    querylen = snprintf(query, sizeof(query) - 1, "SELECT *,unix_timestamp(ts) from protocol_samples;");
    res = my_sql_query(mysql, query, querylen, 0);
    
    samples = NULL;
    
    
    while ((row = mysql_fetch_row(res)) != NULL) {
	
        //lengths = mysql_fetch_lengths(res);
        if ((optr = (ProtocolSample *)malloc(sizeof(ProtocolSample) + 1)) == NULL) goto end;
        memset(optr, 0, sizeof(ProtocolSample));
        
        optr->id = atoi(row[0]);
        strncpy(optr->application, row[1], 24);
        strncpy(optr->version, row[2], 24);
        optr->ts = atoi(row[3]); // should be 4 but using unix_timestamp(ts)
        optr->snapshot_id = atoi(row[4]);
        optr->operation_id = atoi(row[5]);
        optr->parent_id = atoi(row[6]);
        
        optr->next = protocol_samples;
        protocol_samples = optr;
    }
    
end:;
    
    if (res != NULL) mysql_free_result(res);
}



void ProtocolExchanges_Load() {
    ProtocolExchanges *optr = NULL;
    ProtocolExchanges *parent = NULL;
    char query[1024];
    int querylen;
    MYSQL_RES			*res = NULL;
    MYSQL_ROW			row;
    unsigned long *lengths;
    
    printf("ProtocolExchange_Load();\n");
    querylen = snprintf(query, sizeof(query) - 1, "SELECT *,unix_timestamp(ts) from protocol_exchanges;");
    res = my_sql_query(mysql, query, querylen, 0);
    
    samples = NULL;
    
    
    while ((row = mysql_fetch_row(res)) != NULL) {
	
        lengths = mysql_fetch_lengths(res);
        if ((optr = (ProtocolExchange *)malloc(sizeof(ProtocolExchange) + 1)) == NULL) goto end;
        memset(optr, 0, sizeof(ProtocolExchange));
        
        optr->id = atoi(row[0]);
        optr->side = atoi(row[1]);
        optr->count = atoi(row[2]);
        strncpy(optr->application, row[3], 24);
        strncpy(optr->version, row[4], 24);
        optr->exec_id = atoi(row[5]);
        optr->ts = atoi(row[6]); // should be 4 but using unix_timestamp(ts)
        optr->bytes = atoi(row[7]);
        
        if (lengths[8]) {
            optr->data = (unsigned char *)malloc(lengths[8] + 1);
            if (optr->data) {
                memcpy(optr->data, row[8], lengths[8]);
                optr->data_size = lengths[8];
            }
        }
        
        optr->operation_id = atoi(row[9]);
        optr->parent_id = atoi(row[10]);
        
        optr->next = exchanges;
        exchanges = optr;
    }
    
end:;
    
    if (res != NULL) mysql_free_result(res);
}



void Snapshot_Load() {
    Snapshot *optr = NULL;
    Snapshot *parent = NULL;
    char query[1024];
    int querylen;
    MYSQL_RES			*res = NULL;
    MYSQL_ROW			row;
    unsigned long *lengths;
    
    printf("Snapshot_Load();\n");
    querylen = snprintf(query, sizeof(query) - 1, "SELECT *,unix_timestamp(ts) from snapshot;");
    res = my_sql_query(mysql, query, querylen, 0);
    
    samples = NULL;
    
    while ((row = mysql_fetch_row(res)) != NULL) {
	
        lengths = mysql_fetch_lengths(res);
        if ((optr = (Snapshot *)malloc(sizeof(Snapshot) + 1)) == NULL) goto end;
        memset(optr, 0, sizeof(Snapshot));
        
        optr->id = atoi(row[0]);
        strncpy(optr->application, row[1], 24);
        strncpy(optr->version, row[2], 24);
        optr->ts = atoi(row[3]); // should be 4 but using unix_timestamp(ts)
        optr->bytes = atoi(row[4]);
        
        // copy blob data of data variable from sql table
        if (lengths[5]) {
            optr->data = (unsigned char *)malloc(lengths[5] + 1);
            memcpy(optr->data, row[5], lengths[5]);
        }

        optr->operation_id = atoi(row[6]);
        optr->parent_id = atoi(row[7]);
        

        optr->next = snapshots;
        snapshots = optr;
    }
    
end:;
    
    if (res != NULL) mysql_free_result(res);
}




int LogException(Exceptions *eptr) {
    Operations *optr;

    char *query = NULL;
    int query_len= 0;
    my_ulonglong id=0;
    char application[sizeof(eptr->application) * 2 + 1];
    char version[sizeof(eptr->version) * 2 + 1];
    char exception_address[sizeof(eptr->exception_address) * 2 + 1];
    char exception_code[sizeof(eptr->exception_code) * 2 + 1];
    char newbyte[sizeof(eptr->newbyte) * 2 + 1];
    char hash[sizeof(eptr->hash) * 2 + 1];
    char ip[sizeof(eptr->ip) * 2 + 1];
    char *extra = NULL;
    int encoded_extra_size = 0;

    
    if ((query = (char *)malloc(sizeof(Exceptions) + 1024)) == NULL) {
        // crash fail miserably...
        return -1;
    }
    memset(query, 0, sizeof(Exceptions) + 1024);
    
    if ((optr = operation_by_id(eptr->operation_id)) != NULL) {
        strncpy(eptr->application, optr->application, 24);
        strncpy(eptr->version, optr->version, 24);
    }
    mysql_real_escape_string(mysql, application, eptr->application, sizeof(eptr->application));
    mysql_real_escape_string(mysql, version, eptr->version, sizeof(eptr->version));
    mysql_real_escape_string(mysql, exception_address, eptr->exception_address, sizeof(eptr->exception_address));
    mysql_real_escape_string(mysql, exception_code, eptr->exception_code, sizeof(eptr->exception_code));
    mysql_real_escape_string(mysql, newbyte, eptr->newbyte, sizeof(eptr->newbyte));
    mysql_real_escape_string(mysql, hash, eptr->hash, sizeof(eptr->hash));
    mysql_real_escape_string(mysql, ip, eptr->ip, sizeof(eptr->ip));
    
    query_len = sprintf(query, "INSERT into exceptions set operation_id=%d,sample_id=%d,byte=%d,mode=%d,application='%s',version='%s',exception_address='%s',exception_code='%s',newbyte='%s',hash='%s',ip='%s',extra_size=%d,queue_id=%d;", eptr->operation_id,
            eptr->sample_id, eptr->byte, eptr->mode, application, version, exception_address, exception_code, newbyte, hash, ip, eptr->extra_size, eptr->queue_id);
    
    if (my_sql_query(mysql, query, query_len, 0)==NULL) {
        // failed to insert row?.. crash and/or save another way
    }
    
    free(query);
    
    if (eptr->extra_size && eptr->extra) {

        id = mysql_insert_id(mysql);
        
        if ((extra = (char *)malloc(eptr->extra_size * 2 + 1)) == NULL) {
            // fail miserably again.. work this out later
            printf("fail\n");
            return -1;
        }
    
        encoded_extra_size = mysql_real_escape_string(mysql, (char *)extra, (char *)eptr->extra, eptr->extra_size);
        
        query = (char *)malloc(1024 + encoded_extra_size + 1);
        query_len = sprintf(query, "UPDATE exceptions set extra='%s' where id = %llu;", extra, id);
        
        my_sql_query(mysql, query, query_len, 0);
        
        free(extra);
        free(query);
        
        
    }

    return 1;
    
}




// logs a queue we distributed to a client.. in case we have to redistribute later...
int AddQueue(Queue *eptr, int update) {
    char *query = NULL;
    int query_len= 0;
        my_ulonglong id=0;
    char application[sizeof(eptr->application) * 2 + 1];
    char version[sizeof(eptr->version) * 2 + 1];
    char hash[sizeof(eptr->hash) * 2 + 1];
    char ip[sizeof(eptr->ip) * 2 + 1];
        char update_str[1024];

    
    if ((query = (char *)malloc(sizeof(Queue) + 1024)) == NULL) {
        // crash fail miserably...
        return -1;
    }
    memset(query, 0, sizeof(Queue) + 1024);
    
    mysql_real_escape_string(mysql, application, eptr->application, sizeof(eptr->application));
    mysql_real_escape_string(mysql, version, eptr->version, sizeof(eptr->version));
    mysql_real_escape_string(mysql, hash, eptr->hash, sizeof(eptr->hash));
    mysql_real_escape_string(mysql, ip, eptr->ip, sizeof(eptr->ip));
    
   sprintf(update_str, "WHERE id = %d", eptr->id);
    query_len = sprintf(query, "%s queue set application='%s',version='%s',ip='%s',hash='%s',sample_id=%d,byte=%d,mode=%d,count=%d,operation_id=%d,complete=%d,timeout=%d%s %s;",
                        update ? "UPDATE" : "INSERT into",
                        application, version, ip, hash, eptr->sample_id, eptr->byte, eptr->mode, eptr->count, eptr->operation_id, eptr->complete,eptr->timeout,
                        update ? ",ts=now() " : "",
                        update ? update_str : "");
    
    
    if (my_sql_query(mysql, query, query_len, 0)==NULL) {
        // failed to insert row?.. crash and/or save another way
    }

    if (!update) {
        id = mysql_insert_id(mysql);
    
        eptr->id = id;
    }
    
    free(query);
    
    if (!update) {
        eptr->next = queue;
        queue = eptr;
    }
    
    return id;
}





// logs a queue we distributed to a client.. in case we have to redistribute later...
int AddSample(Samples *eptr, int update) {
    char *query = NULL;
    int query_len= 0;
    my_ulonglong id=0;
    char application[sizeof(eptr->application) * 2 + 1];
    char version[sizeof(eptr->version) * 2 + 1];
    char generator[sizeof(eptr->generator) * 2 + 1];
    char update_str[1024];
    
    if ((query = (char *)malloc(sizeof(Queue) + 1024)) == NULL) {
        // crash fail miserably...
        return -1;
    }
    memset(query, 0, sizeof(Queue) + 1024);
    
    mysql_real_escape_string(mysql, application, eptr->application, sizeof(eptr->application));
    mysql_real_escape_string(mysql, version, eptr->version, sizeof(eptr->version));
    mysql_real_escape_string(mysql, generator, eptr->generator, sizeof(eptr->generator));
    
    sprintf(update_str, "WHERE id = %d", eptr->id);
    query_len = sprintf(query, "%s samples set application='%s',version='%s',generator='%s',operation_id=%d,parent_id=%d,initial_file_size=%d,cur_generation=%d,max_generation=%d,bytes=%d,exhausted=%d,current_distribution_byte=%d %s;", update ? "UPDATE" : "INSERT INTO",
                        application, version, eptr->generator, eptr->operation_id, eptr->parent_id, eptr->initial_file_size, eptr->cur_generation, eptr->max_generation, eptr->bytes, eptr->exhausted, eptr->cur_distribution_byte,
                        update ? update_str : "");
    
    if (my_sql_query(mysql, query, query_len, 0)==NULL) {
        // failed to insert row?.. crash and/or save another way
    }
    
    free(query);
    
    id = mysql_insert_id(mysql);
    
    
    if (eptr->initial_file) {
        char *extra;
        int encoded_extra_size;
        
        if ((extra = (char *)malloc(eptr->initial_file_size * 2 + 1)) == NULL) {
            // fail miserably again.. work this out later
            printf("fail\n");
            return -1;
        }
        
        encoded_extra_size = mysql_real_escape_string(mysql, (char *)extra, (char *)eptr->initial_file, eptr->initial_file_size);
        
        query = (char *)malloc(1024 + encoded_extra_size + 1);
        query_len = sprintf(query, "UPDATE samples set initial_file='%s' where id = %llu;", extra, id);
        
        my_sql_query(mysql, query, query_len, 0);
        
        free(extra);
        free(query);
        
        
    }

    
    if (eptr->data) {
        char *extra;
        int encoded_extra_size;
        
        if ((extra = (char *)malloc(eptr->bytes * 2 + 1)) == NULL) {
            // fail miserably again.. work this out later
            printf("fail\n");
            return -1;
        }
        
        encoded_extra_size = mysql_real_escape_string(mysql, (char *)extra, (char *)eptr->data, eptr->bytes);
        
        query = (char *)malloc(1024 + encoded_extra_size + 1);
        query_len = sprintf(query, "UPDATE samples set data='%s' where id = %llu;", extra, id);
        
        my_sql_query(mysql, query, query_len, 0);
        
        free(extra);
        free(query);
        
        
    }

    
    return id;
}







// Periodically check queues for timeouts which need to be redistributed to another worker
void CheckQueue() {
    Queue *qptr, *qptr2;
    Operations *optr;
    int changed=0;
    
    
    do {
        changed=0;
    for (qptr = queue; qptr != NULL; qptr = qptr->next) {
        if (qptr->complete || qptr->timeout) continue;
        optr = operation_by_id(qptr->operation_id);
        if (optr == NULL) continue; // fix this later.. should never happen though unless DB issues
        if (optr && ((time(0) - qptr->ts) > optr->queue_timeout)) {
            
            qptr->timeout=1;
            AddQueue(qptr, 1);
            // remove from queue list
            if (queue == qptr) {
                queue = qptr->next;
            } else {
                for (qptr2 = queue; qptr2; qptr2 = qptr2->next) {
                    if (qptr2->next == qptr) {
                        qptr2->next = qptr->next;
                    }
                }
            }
            
            // insert into requeue list to get redistributed
            qptr->next = requeue;
            requeue = qptr;
            changed=1;
            break;
        }
        
    }
    } while (changed);
    
}



typedef struct _nano_pkt {
    int type;
    int len;
} NanoPkt;

typedef struct _client_op {
    int operation_id;
    char application[25];
    char version[25];
    char installer_url[1024];
    char installer_command_line[1024];
    char application_path[1024];
    char application_path64[1024];
    int byte;
    int count;
    int mode;
    int queue_id;
    int sample_id;
    int sample_size;
} ClientOp;


int CountQueueOperation(Operations *optr) {
    Queue *qptr;
    int count = 0;
    
    if (optr == NULL) return 0;
    
    for (qptr = queue; qptr != NULL; qptr = qptr->next)
        if (!qptr->timeout && !qptr->complete && qptr->id == optr->id) count++;
    
    return count;
}


void nginx_contact(unsigned char *pkt, unsigned char **ret, int *ret_len) {
    NanoPkt *pkthdr = NULL;
    Operations *optr = NULL;
    Queue *qptr = NULL;
    Samples *sptr;
    void *_ret = NULL;
    for (optr = operations; optr != NULL; optr = optr->next) {
        if (!optr->enabled) continue;
        if ((qptr = GetQueue(optr)) != NULL)
            break;
    }
    
    if (optr == NULL || qptr == NULL) return;
    
    if ((sptr = sample_by_id(qptr->sample_id, 0)) == NULL) return;
    
    if (qptr == NULL || optr == NULL) return;
    
    // yay we have an operation.. lets get the data to the client
    
    _ret = (void *)malloc(sizeof(NanoPkt) + sizeof(ClientOp) + sptr->bytes + 1);
    
    pkthdr = (NanoPkt *)_ret;
    pkthdr->type = CONTACT_RESP;
    pkthdr->len = sizeof(NanoPkt) + sizeof(ClientOp) + sptr->bytes;
    
    ClientOp *clientop = (ClientOp *)(_ret + sizeof(NanoPkt));
    strncpy(clientop->application, optr->application, 24);
    strncpy(clientop->installer_url, optr->installer_url, 1023);
    strncpy(clientop->installer_command_line, optr->installer_command_line, 1023);
    strncpy(clientop->application_path, optr->application_path, 1023);
    strncpy(clientop->application_path64, optr->application_path64, 1023);
    clientop->operation_id = optr->id;
    clientop->byte = qptr->byte;
    clientop->count = qptr->count;
    clientop->mode = qptr->mode;
    clientop->queue_id = qptr->id;
    clientop->sample_id = qptr->sample_id;
    clientop->sample_size = sptr->bytes;
    
    memcpy(_ret + sizeof(NanoPkt) + sizeof(ClientOp), sptr->data, sptr->bytes);


    *ret = (unsigned char *)_ret;
    *ret_len = pkthdr->len;
    
    return;
}



typedef struct _complete_op {
    int operation_id;
    int queue_id;
    int sample_id;
    int mode;
    int byte;
    int count;
} CompleteOp;




void nginx_complete(unsigned char *pkt, unsigned char **ret, int *ret_len) {
     NanoPkt *pkthdr;
    CompleteOp *cptr;
    Operations *optr;
    Samples *sptr;
    Queue *qptr;
    
    pkthdr = (NanoPkt *)pkt;
    
    if (pkthdr->len != (sizeof(NanoPkt) + sizeof(CompleteOp))) return;
    
    cptr = (CompleteOp *)(pkt + sizeof(NanoPkt));
    
    
    for (qptr = queue; qptr != NULL; qptr = qptr->next) {
        if (qptr->id == cptr->queue_id) break;
    }
    
    sptr = sample_by_id(cptr->sample_id, 0);
    
    optr = operation_by_id(cptr->operation_id);
    
    if ((sptr == NULL) || (optr == NULL) || (qptr == NULL)) return;
    
    // mark queue as complete....
    qptr->complete = 1;
    
    AddQueue(qptr, 1);
}


typedef struct _exception_op {
    int operation_id;
    int queue_id;
    int sample_id;
    int mode;
    int byte;
    char exception_address[23];
    char exception_code[23];
    char newbyte[23];
} ExceptionOp;

void nginx_exception(unsigned char *pkt, unsigned char **ret, int *ret_len) {
     NanoPkt *pkthdr;
     ExceptionOp *eptr;
    Operations *optr;
    Samples *sptr;
    Queue *qptr;
    Exceptions *xptr;
    
     pkthdr = (NanoPkt *)pkt;
    
    if (pkthdr->len != (sizeof(NanoPkt) + sizeof(ExceptionOp))) return;
    
    eptr = (ExceptionOp *)(pkt + sizeof(NanoPkt));
    
    //if (pkthdr->len != (sizeof(NanoPkt) + sizeof(ExceptionOp))) return;
    
    for (qptr = queue; qptr != NULL; qptr = qptr->next) {
        if (qptr->id == eptr->queue_id) break;
    }
    
    sptr = sample_by_id(eptr->sample_id, 0);
    
    optr = operation_by_id(eptr->operation_id);
    
    if ((sptr == NULL) || (optr == NULL) || (qptr == NULL)) return;
    
    /// all good log exception
    
    xptr = (Exceptions *)malloc(sizeof(Exceptions) + 1);
    memset(xptr, 0, sizeof(Exceptions));
    
    xptr->operation_id = eptr->operation_id;
    xptr->sample_id = eptr->sample_id;
    xptr->byte = eptr->byte;
    xptr->queue_id = eptr->queue_id;
    memcpy(xptr->exception_address, eptr->exception_address, 23);
    memcpy(xptr->exception_code, eptr->exception_code, 23);
    memcpy(xptr->newbyte, eptr->newbyte, 23);
    
    LogException(xptr);
    
    free(xptr);
    
}



struct _packet_types {
    int type;
    void (*func)(unsigned char *, unsigned char **, int *);
} Commands[] = {
    { CONTACT, &nginx_contact },
    { COMPLETE, &nginx_complete },
    { EXCEPTION, &nginx_exception },
    { 0, NULL }
};


unsigned char *Python_SampleGenerate(char *python_file, char *python_function, int iteration, int *_len, unsigned char *initial,
int i_len) {
    PyObject *pName=NULL, *pModule=NULL, *pFunc=NULL;
    PyObject *pArgs=NULL, *pFilename = NULL, *pValue=NULL;
    PyObject *pArray=NULL;
    int size = 0;
    char *data = NULL;
    FILE *fd;
    char *tmpfile;
    char _tmpfile[1024] = "null";

    printf("Python_GenerateSample - Python File: %s Function: %s iteration: %d Return Len: %p Initial %p Initial size %d\n", 
    python_file, python_function, iteration, _len, initial, i_len);
    Py_Initialize();
    
    if (initial && i_len) {
	tmpfile = tempnam("/tmp", "initial");
	sprintf(_tmpfile, "%s.pdf", tmpfile);
    
	if ((fd = fopen(_tmpfile, "wb")) == NULL) {
	    return NULL;
	} else {
	    size = fwrite(initial, 1, i_len, fd);
	    if (size != i_len) {
		return NULL;
	    }
	    fclose(fd);
	}
    }

    
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.append(\"/home/mike/PyPDF2\")");
    //PyRun_SimpleString("sys.path.append(\".\")");
    
    pName = PyString_FromString(python_file);
    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    
    if (pModule != NULL) {
	pFunc = PyObject_GetAttrString(pModule, python_function);
	
	if ((pFunc && PyCallable_Check(pFunc))) {
    
	    // setup and convert arguments for python script
	    pArgs = PyTuple_New(2);
	
	    pFilename = PyString_FromString(_tmpfile);
	    if (!pFilename) {
		Py_DECREF(pArgs);
		Py_DECREF(pModule);
		return NULL;
	    }
	    PyTuple_SetItem(pArgs, 0, pFilename);

	    pValue = PyInt_FromLong(iteration);
	    if (!pValue) {
		Py_DECREF(pArgs);
		Py_DECREF(pModule);
		return NULL;
	    }
	    PyTuple_SetItem(pArgs, 1, pValue);
    
	    // call python function
	    pValue = PyObject_CallObject(pFunc, pArgs);
	    Py_DECREF(pArgs);
    
	    // if return value.. then we wanna convert and print
    	    if (pValue != NULL && !PyErr_Occurred()) {
		if ((pArray = PyByteArray_FromObject(pValue)) != NULL) {
		    size = PyByteArray_Size(pArray);
		    if ((data = (char *)malloc(size+1)) != NULL) {
			memcpy(data, PyByteArray_AsString(pArray), size);
			*_len = size;
		    }
		    
		    Py_DECREF(pArray);
		} else {
		    PyErr_Print();
		    
		    Py_DECREF(pValue);
		    Py_DECREF(pFunc);
		    Py_DECREF(pModule);
		    PyErr_Print();
		    return NULL;
		}
		
		Py_DECREF(pValue);
	    }
		
		
	    Py_XDECREF(pFunc);
	}
	
	Py_DECREF(pModule);
    }

    Py_Finalize();
    
    return (unsigned char *)data;
}


// generates a sample for an operation if there arent any that exist already which are not exhausted....
Queue *GetQueue(Operations *optr) {
    Samples *sptr = NULL, *gptr = NULL;
    Queue *qptr = NULL;
    int bytes = 0;
    
    
    if ((qptr = requeue) != NULL) {
        // readd to queue list...should change ip hash etc here..
        requeue = qptr->next;
        qptr->timeout=0;
        qptr->ts=time(0);
        AddQueue(qptr,1);
        qptr->next = queue;
        queue = qptr;
        return qptr;
    }
    
    
    for (sptr = samples; sptr != NULL; sptr = sptr->next) {
        if (sptr->parent_id != 0) continue;
        if ((sptr->operation_id == optr->id)) {
            for (gptr = sptr->generated; gptr != NULL; gptr = gptr->next) {
                if (gptr->exhausted) continue;
                if (gptr->cur_distribution_byte > gptr->bytes) {
                    gptr->exhausted = 1;
                    continue;
                }
                
                bytes = gptr->bytes - gptr->cur_distribution_byte;
                // we have x bytes more to distribute to exhaust this sample file
                if (bytes > optr->max_bytes_per_worker) {
                    bytes = optr->max_bytes_per_worker;
                } else {
                    // this will be last distribution for this sample.. lets exhaust it
                    gptr->exhausted = 1;
                }
                

                
                // create queue ... add to database and distribute to client
                qptr = (Queue *)malloc(sizeof(Queue) + 1);
                memset(qptr, 0, sizeof(Queue));
                
                qptr->operation_id = optr->id;
                qptr->ts=time(0);
                qptr->sample_id=gptr->id;
                qptr->byte = gptr->cur_distribution_byte;
                qptr->count = bytes;
                qptr->mode = gptr->mode;
                strcpy(qptr->application, gptr->application);
                strcpy(qptr->version, gptr->version);

                gptr->cur_distribution_byte += bytes;
                
                
                AddSample(gptr, 1);
                
                AddQueue(qptr,0);
                
                return qptr;
            } // done looking for already generated which isnt exhausted.. now to see if we can generate more

            if (sptr->max_generation && sptr->cur_generation > sptr->max_generation) {
                sptr->exhausted = 1;
                AddSample(sptr, 1);
                
            }
            

            int sample_len = 0;
            unsigned char *sample_data = Python_SampleGenerate((char *)"generate", (char *)"generate", sptr->cur_generation++, &sample_len, sptr->initial_file, sptr->initial_file_size);

            if (sample_data == NULL || !sample_len) return NULL;
            
            gptr = (Samples *)malloc(sizeof(Samples) + 1);
            // copy parent over child...
            memcpy(gptr, sptr, sizeof(Samples));
            
            gptr->cur_distribution_byte = 0;
            gptr->ts=0;
            gptr->exhausted=0;
            gptr->cur_generation = 0;
            gptr->max_generation = 0;
            gptr->parent_id = sptr->id;
            gptr->next = NULL;
            gptr->initial_file = NULL;
            gptr->initial_file_size = 0;
            
            // new sample information goes here...
            gptr->data = sample_data;
            gptr->bytes = sample_len;
            gptr->generated = NULL;
            
            
            

            
            bytes = gptr->bytes - gptr->cur_distribution_byte;
            // we have x bytes more to distribute to exhaust this sample file
            if (bytes > optr->max_bytes_per_worker) {
                bytes = optr->max_bytes_per_worker;
            } else {
                // this will be last distribution for this sample.. lets exhaust it
                gptr->exhausted = 1;
            }
         

            gptr->cur_distribution_byte += bytes;
            
            // insert sample into database
            gptr->id = AddSample(gptr,0);
            
            gptr->next = sptr->generated;
            sptr->generated = gptr;
            
            // update original sample context...
            AddSample(sptr, 1);
            
            
            
   
            // create queue ... add to database and distribute to client
            qptr = (Queue *)malloc(sizeof(Queue) + 1);
            memset(qptr, 0, sizeof(Queue));
            
            qptr->operation_id = optr->id;
            qptr->ts=time(0);
            qptr->sample_id=gptr->id;
            qptr->byte= gptr->cur_distribution_byte - bytes;
            qptr->count = bytes;
            qptr->mode = gptr->mode;
            strcpy(qptr->application, gptr->application);
            strcpy(qptr->version, gptr->version);
            
            
            
            
            AddQueue(qptr,0);
            
            return qptr;
     
        
            
            
        }
    }
    
    if (sptr != NULL) {
        
    }

    
    return NULL;
    
}


int main(int argc, char *argv[]) {
    void *data = NULL;
    int r_len = 0;
    int timeout = 1000;
    unsigned char *s_data = NULL;
    int s_len = 0;
    int s;
    int a;
    int len;
    int _time=time(0);
    char file[1024];
    char ipc[1024];
    int ipc_num = 0;
    void *context = NULL;
    void *responder = NULL;
    zmq_msg_t omsg, imsg;
    

    if (argc > 1) {
        ipc_num = atoi(argv[1]) + 1;
    } else ipc_num = 1;
    
    sprintf(file, "/tmp/zdfuzz%d.ipc", ipc_num);
    sprintf(ipc, "ipc:///tmp/zdfuzz%d.ipc", ipc_num);

    if ((context =  zmq_ctx_new()) == NULL) {
        printf("cannot create zmq context\n");
        exit(-1);
    }
    
    if ((responder = zmq_socket(context, ZMQ_REP)) == NULL) {
        printf("cannot open zmq socket\n");
        exit(-1);
    }
    
    if (zmq_bind(responder, ipc) != 0) {
        printf("zmq cannot bind to IPC\n");
        exit(-1);
    }

 

    // initialize mysql
    mysql_reopen();
    Operations_Load();
    Complete_Load();
    Queue_Load();
    Samples_Load();
    
    
    chmod(file, 0777);
    
    
    
    printf("Bound to IPC: %s\n", ipc);
    
    
    _time = time(0);
    while (1) {
        s_len = 0;
        s_data = NULL;
        
        if (zmq_msg_init (&imsg) != 0) break;
        if (zmq_recvmsg(responder, &imsg, 0) == -1) break;
            
        len = zmq_msg_size(&imsg);
        data = zmq_msg_data(&imsg);
        if (data && ((unsigned)len >= (unsigned)sizeof(NanoPkt))) {
            // do whatever with data here... always be sure to set s_data, and s_len
            NanoPkt *pkthdr = (NanoPkt *)data;
            
            for (int i = 0; Commands[i].func != NULL; i++) {
                if (pkthdr->type == Commands[i].type) {
                    (*Commands[i].func)((unsigned char *)data, &s_data, &s_len);
                }
            }
            
            
            // just in case something went wrong.. we have to return something or we will force a stall
            if (zmq_msg_init_size(&omsg, (s_len ? s_len : 4) + 1) == -1) break;
            data = zmq_msg_data(&omsg);

            if (s_data == NULL || !s_len) {
                memcpy(data, "null", 4);
                if (zmq_sendmsg(responder, &omsg, 0) == -1) break;
            } else {
                zmq_msg_init_size(&omsg, s_len + 1);
                data = zmq_msg_data(&omsg);
                if (zmq_sendmsg(responder, &omsg, 0) == -1) break;
                free(s_data);
            }
            zmq_msg_close(&omsg);
            data = NULL;
        }
        
        zmq_msg_close(&imsg);
        
        if ((time(0) - _time) > 10) {
            _time = time(0);
            CheckQueue();
        }
    }

    if (responder != NULL) zmq_close(responder);
    if (context != NULL) zmq_ctx_destroy(context);

    
}







