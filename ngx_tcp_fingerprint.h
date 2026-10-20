/*
 * Copyright (C) 2026, Vitalyn
 */


#ifndef _NGX_TCP_FINGERPRINT_H_INCLUDED_
#define _NGX_TCP_FINGERPRINT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_str_t   signature;
    ngx_str_t   ttl;
    ngx_str_t   ittl;
    ngx_str_t   hops;
    ngx_str_t   win;
    ngx_str_t   mss;
    ngx_str_t   wscale;
    ngx_str_t   options;
    ngx_str_t   quirks;
    ngx_str_t   tls_rtt;
    ngx_str_t   tcp_rtt;
    uint64_t    finished;           /* server Finished sent, microseconds */
    unsigned    syn_read:1;
} ngx_tcp_fingerprint_ctx_t;


ngx_tcp_fingerprint_ctx_t *ngx_tcp_fingerprint_get_ctx(ngx_connection_t *c);
ngx_int_t ngx_tcp_fingerprint_init_listening(ngx_cycle_t *cycle,
    ngx_connection_handler_pt handler);

#if (NGX_HTTP_SSL || NGX_STREAM_SSL)
void ngx_tcp_fingerprint_ssl_init(ngx_ssl_t *ssl);
#endif


#endif /* _NGX_TCP_FINGERPRINT_H_INCLUDED_ */
