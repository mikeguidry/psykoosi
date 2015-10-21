

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread.h>
#include <ngx_event.h>
#include <GeoIP.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
//#include <libmemcached/memcached.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <string.h>
#include <nanomsg/nn.h>
#include <nanomsg/ipc.h>
#include <nanomsg/pair.h>
#include <nanomsg/reqrep.h>
#include <stdarg.h>
#include "utils.h"


typedef struct _nano_pkt {
    int type;
    int len;
} NanoPkt;

enum {
    CONTACT,
    COMPLETE,
    EXCEPTION,
    CONTACT_RESP,
    COMPLETE_RESP,
    EXCEPTION_RESP,
    NONE
};


char *dfuzzpkt(int type, int *_len, void *extra, int extra_size) {
    NanoPkt *pkthdr;
    char *ret = NULL;
    int msg_sock = 0;
    int len = 0;
    void *data = NULL;
    void *out_data = NULL;
    int out_size = 0;
    char *ptr;
    int value=1000;
    int prio=1;
    char ipc[1024];
    
    out_data = (void *)malloc(sizeof(NanoPkt) + extra_size + 1);
    if (out_data == NULL) return NULL;
    ptr = (char *)out_data;
    pkthdr = (NanoPkt *)ptr;
    ptr += sizeof(NanoPkt);
    
    pkthdr->type = type;
    pkthdr->len = sizeof(NanoPkt) + extra_size;
    
    if (extra_size) {
        memcpy(ptr, extra, extra_size);
        ptr += extra_size;
    }
    
    out_size = ptr - (char *)out_data;
    
    if ((msg_sock = nn_socket(AF_SP, NN_REQ)) < 0) goto end;
    nn_setsockopt(msg_sock, NN_SOL_SOCKET, NN_SNDTIMEO, &value, sizeof(value));
    value *= 2;
    nn_setsockopt(msg_sock, NN_SOL_SOCKET, NN_RCVTIMEO, &value, sizeof(value));
    for (prio = 1; prio < 10; prio++) {
        sprintf(ipc, "ipc:///tmp/dfuzz%d.ipc", prio);
        nn_setsockopt (msg_sock, NN_SOL_SOCKET, NN_SNDPRIO, &prio, sizeof (int));
        nn_connect(msg_sock, ipc);
    }

    //if (nn_connect(msg_sock, "ipc:///tmp/dfuzz.ipc") < 0) goto end;
    
    if (nn_send(msg_sock, out_data, out_size, 0) < 0) goto end;
    
    len = nn_recv(msg_sock, &data, NN_MSG, 0);
    

    
    if (len > 0) {
        ret = malloc(len + 1);
        if (ret == NULL) return NULL; // fatal should exit...
        memcpy(ret, data, len);
        *_len = len;
        nn_freemsg(data);
    }
end:;
    if (msg_sock) nn_close(msg_sock);
    return ret;
}



// nginx function declaration for each URL contact point
static char *ngx_http_contact(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_report(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_exception(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_contact_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_report_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_exception_handler(ngx_http_request_t *r);


// These are the command names for use in nginx.conf for each contact point for the module
static ngx_command_t ngx_http_dfuzz_commands[] = {
    { ngx_string("dfuzz_contact"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, ngx_http_contact, 0, 0, NULL },
    { ngx_string("dfuzz_report"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, ngx_http_report, 0, 0, NULL },
    { ngx_string("dfuzz_exception"), NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, ngx_http_exception, 0, 0, NULL },
    ngx_null_command
};


// initialize any variables to be used during the entire module process
static ngx_int_t init_variables(ngx_conf_t *cf) {
    return NGX_OK;
}



// very minimal and generic nginx module context information
static ngx_http_module_t ngx_http_dfuzz_module_ctx = {
    init_variables,                /* preconfiguration */
    NULL,                          /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
    NULL, NULL
};



// more generic nginx module stuff... 
ngx_module_t ngx_http_dfuzz_module = {
    NGX_MODULE_V1,
    &ngx_http_dfuzz_module_ctx,    /* module context */
    ngx_http_dfuzz_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};



static char *ngx_http_contact(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_contact_handler;
    
    return NGX_CONF_OK;
}

static char *ngx_http_report(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_report_handler;
    
    return NGX_CONF_OK;
}


static char *ngx_http_exception(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_exception_handler;
    
    return NGX_CONF_OK;
}






// This is the main C&C handler for our fuzz workers....
static ngx_int_t ngx_http_contact_handler(ngx_http_request_t *r) {

    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;

    // buf and buf_len control the output the client will get
    char *buf = NULL;
    int buf_len = 0;

    //content type
    char ctype[1024] = "application/octet-stream";
    unsigned int ip;
    struct sockaddr_in  *sin;
    char *dfuzz_pkt = NULL;
    
    sin = (struct sockaddr_in *) r->connection->sockaddr;
    ip = ntohl(sin->sin_addr.s_addr);

    dfuzz_pkt = (char *)dfuzzpkt(CONTACT, &buf_len, NULL, 0);
    
    if (dfuzz_pkt != NULL) {
        if ((buf = (char *)ngx_pcalloc(r->pool, buf_len + 1)) == NULL)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        
        memcpy(buf, dfuzz_pkt, buf_len);
        
        free(dfuzz_pkt);
    }
    
    // Anything below this is just general NGINX bullshit to get the data pushed to the client
    // we response to 'GET' and 'HEAD' requests only  |NGX_HTTP_HEAD
    if (!(r->method & (NGX_HTTP_GET))) {
        //timemagic(&earlier, "first 1");
        return NGX_HTTP_NOT_ALLOWED;
    }
 
    // discard request body, since we don't need it here
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
 
    // set the 'Content-type' header
    r->headers_out.content_type_len = strlen(ctype);
    r->headers_out.content_type.len = strlen(ctype);
    r->headers_out.content_type.data = (u_char *) ctype;
 
    // allocate a buffer for your response body
    if ((b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
 
    // attach this buffer to the buffer chain
    out.buf = b;
    out.next = NULL;
 
    // adjust the pointers of the buffer
    b->pos = (unsigned char *)buf;
    b->last = (unsigned char *)(buf + buf_len);
    b->memory = 1;
    b->last_buf = 1;
 
    // set the status line
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = buf_len;
 
    // send the headers of your response
    rc = ngx_http_send_header(r);
 
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
 
    // send the buffer chain of your response
    return ngx_http_output_filter(r, &out);
}




typedef struct _complete_op {
    int operation_id;
    int queue_id;
    int sample_id;
    int mode;
    int byte;
    int count;
} CompleteOp;




// This is the main C&C handler for our fuzz workers....
static ngx_int_t ngx_http_report_handler(ngx_http_request_t *r) {
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;
    
    char *uri=NULL;
    char *args = NULL;
    
    // buf and buf_len control the output the client will get
    char *buf = NULL;
    int buf_len = 0;
    char *dfuzz_pkt = NULL;
    
    
    //content type
    char ctype[1024] = "text/html";
    unsigned int ip;
    struct sockaddr_in  *sin;
    CompleteOp *cptr;
    
    sin = (struct sockaddr_in *) r->connection->sockaddr;
    ip = ntohl(sin->sin_addr.s_addr);
    

    if (!r->args.len) return NGX_HTTP_INTERNAL_SERVER_ERROR;

  if ((cptr = (CompleteOp *)malloc(sizeof(CompleteOp) + 1)) == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    sscanf(r->args.data, "op=%d&queue=%d&sample=%d&mode=%d&byte=%d&count=%d", &cptr->operation_id, &cptr->queue_id, &cptr->sample_id, &cptr->mode, &cptr->byte, &cptr->count);
    
    if (!cptr->operation_id || !cptr->queue_id || !cptr->sample_id)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;	
    
    
    dfuzz_pkt = (char *)dfuzzpkt(COMPLETE, &buf_len, cptr, sizeof(CompleteOp));
    
    free(cptr);
    
    if (dfuzz_pkt != NULL) {
        if ((buf = (char *)ngx_pcalloc(r->pool, buf_len + 1)) == NULL)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        
        memcpy(buf, dfuzz_pkt, buf_len);
        
        free(dfuzz_pkt);
    }
    
    
    // Anything below this is just general NGINX bullshit to get the data pushed to the client
    // we response to 'GET' and 'HEAD' requests only  |NGX_HTTP_HEAD
    if (!(r->method & (NGX_HTTP_GET))) {
        //timemagic(&earlier, "first 1");
        return NGX_HTTP_NOT_ALLOWED;
    }
    
    // discard request body, since we don't need it here
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    
    // set the 'Content-type' header
    r->headers_out.content_type_len = strlen(ctype);
    r->headers_out.content_type.len = strlen(ctype);
    r->headers_out.content_type.data = (u_char *) ctype;
         
    // allocate a buffer for your response body
    if ((b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    // attach this buffer to the buffer chain
    out.buf = b;
    out.next = NULL;
    
    // adjust the pointers of the buffer
    b->pos = (unsigned char *)buf;
    b->last = (unsigned char *)(buf + buf_len);
    b->memory = 1;
    b->last_buf = 1;
    
    // set the status line
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = buf_len;
    
    // send the headers of your response
    rc = ngx_http_send_header(r);
    
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    if (uri != NULL) free(uri);
    
    // send the buffer chain of your response
    return ngx_http_output_filter(r, &out);
}



typedef struct _exception_op {
    int operation_id;
    int queue_id;
    int sample_id;
    int mode;
    int byte;
    char exception_address[24];
    char exception_code[24];
    char newbyte[24];
} ExceptionOp;


// This is the main C&C handler for our fuzz workers....
static ngx_int_t ngx_http_exception_handler(ngx_http_request_t *r) {
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;
    
    // buf and buf_len control the output the client will get
    char *buf = NULL;
    int buf_len = 0;
    
    //content type
    char ctype[1024] = "text/html";
    unsigned int ip;
    struct sockaddr_in  *sin;
    ExceptionOp *cptr = NULL;
    char *ptr;
    char *dfuzz_pkt;
    
    ngx_str_t exception_address;
    ngx_str_t exception_code;
    ngx_str_t newbyte;
    
    sin = (struct sockaddr_in *) r->connection->sockaddr;
    ip = ntohl(sin->sin_addr.s_addr);
    
    if (!r->args.len) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  //  if ((ptr = strchr(r->args.data, ' ')) != NULL) *ptr = 0;
    
    if (ngx_http_arg(r, (u_char *) "eaddress", 8, &exception_address) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_http_arg(r, (u_char *) "ecode", 5, &exception_code) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_http_arg(r, (u_char *) "newbyte", 7, &newbyte) != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    if ((cptr = (ExceptionOp *)malloc(sizeof(ExceptionOp) + 1)) == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    memset(cptr, 0, sizeof(ExceptionOp));

    
    sscanf(r->args.data, "op=%d&queue=%d&sample=%d&mode=%d&byte=%d&eaddress=", &cptr->operation_id,
           &cptr->queue_id, &cptr->sample_id, &cptr->mode, &cptr->byte);
    

    if ((ptr = strchr(exception_address.data, '&')) != NULL) *ptr = 0;
    if ((ptr = strchr(exception_code.data, '&')) != NULL) *ptr = 0;
    if ((ptr = strchr(newbyte.data, ' ')) != NULL) *ptr = 0;
    
    strncpy(cptr->exception_address, exception_address.data, 24);
    strncpy(cptr->exception_code, exception_code.data, 24);
    strncpy(cptr->newbyte, newbyte.data, 24);
    
    
    if (!cptr->operation_id || !cptr->queue_id || !cptr->sample_id)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    
    dfuzz_pkt = (char *)dfuzzpkt(EXCEPTION, &buf_len, cptr, sizeof(ExceptionOp));
    
    free(cptr);
    
    if (dfuzz_pkt != NULL) {
        if ((buf = (char *)ngx_pcalloc(r->pool, buf_len + 1)) == NULL)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        
        memcpy(buf, dfuzz_pkt, buf_len);
        
        free(dfuzz_pkt);
    }
    
    
    
    // Anything below this is just general NGINX bullshit to get the data pushed to the client
    // we response to 'GET' and 'HEAD' requests only  |NGX_HTTP_HEAD
    if (!(r->method & (NGX_HTTP_GET))) {
        //timemagic(&earlier, "first 1");
        return NGX_HTTP_NOT_ALLOWED;
    }
    
    // discard request body, since we don't need it here
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    
    // set the 'Content-type' header
    r->headers_out.content_type_len = strlen(ctype);
    r->headers_out.content_type.len = strlen(ctype);
    r->headers_out.content_type.data = (u_char *) ctype;
    
    // allocate a buffer for your response body
    if ((b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    // attach this buffer to the buffer chain
    out.buf = b;
    out.next = NULL;
    
    // adjust the pointers of the buffer
    b->pos = (unsigned char *)buf;
    b->last = (unsigned char *)(buf + buf_len);
    b->memory = 1;
    b->last_buf = 1;
    
    // set the status line
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = buf_len;
    
    // send the headers of your response
    rc = ngx_http_send_header(r);
    
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    // send the buffer chain of your response
    return ngx_http_output_filter(r, &out);
}



