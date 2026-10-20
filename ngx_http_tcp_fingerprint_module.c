/*
 * Copyright (C) 2026, Vitalyn
 *
 * ngx_http_tcp_fingerprint_module: passive fingerprint of the client's TCP/IP
 * stack, read from the SYN that opened the connection, the way p0f does it.
 *
 * Linux only. "tcp_fingerprint on;" sets TCP_SAVE_SYN on the HTTP listening
 * sockets (in the master process, at each configuration load). The kernel
 * then keeps the IP and TCP headers of each accepted connection's SYN, and
 * TCP_SAVED_SYN hands them over once. The first request that reads one of the
 * variables on a connection fetches them; the result stays in the connection
 * pool for the following requests (keepalive, HTTP/2 streams). HTTP/3 has no
 * TCP SYN.
 *
 * TLS 1.3 also gives one round trip to time: the server waits for the
 * client's Finished right after sending its own. That round trip ends at the
 * holder of the TLS keys, the kernel's TCP RTT at whoever acknowledges the
 * segments: the same machine for a direct client, but the exit node of a
 * tunnel (CONNECT or SOCKS proxy) for a proxied one. A message callback on
 * the server's SSL contexts timestamps both Finished and reads TCP_INFO when
 * the client's arrives, then removes itself from the connection.
 *
 * Variables:
 *   $tcpfp_signature  ver:ttl+hops:olen:mss:wsize,scale:options:quirks:pclass,
 *                     the layout of p0f v3 raw signatures, e.g.
 *                     4:57+7:0:1460:mss*44,7:mss,sok,ts,nop,ws:df:0
 *   $tcpfp_ttl        TTL (IPv4) or hop limit (IPv6) the SYN arrived with
 *   $tcpfp_ittl       initial TTL guessed from it: 32, 64, 128 or 255
 *   $tcpfp_hops       $tcpfp_ittl - $tcpfp_ttl
 *   $tcpfp_win        TCP window
 *   $tcpfp_mss        MSS option
 *   $tcpfp_wscale     window scale option
 *   $tcpfp_options    option layout: mss, ws, sok, sack, ts, nop, eol+N
 *                     (N padding bytes after it), ?K (unknown kind K)
 *   $tcpfp_quirks     oddities of the headers, in this order: df, id+, id-,
 *                     ecn, 0+, flow, seq-, ack+, ack-, uptr+, urgf+, pushf+,
 *                     ts1-, ts2+, opt+, exws, bad
 *   $tcpfp_tls_rtt    TLS 1.3 handshake round trip, server Finished sent to
 *                     client Finished read, in microseconds
 *   $tcpfp_tcp_rtt    kernel smoothed TCP RTT at that moment, in microseconds
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_tcp_fingerprint.h"


typedef struct {
    ngx_flag_t  enable;
} ngx_http_tcp_fingerprint_main_conf_t;


static ngx_int_t ngx_http_tcp_fingerprint_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_tcp_fingerprint_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_tcp_fingerprint_init(ngx_conf_t *cf);
static void *ngx_http_tcp_fingerprint_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_tcp_fingerprint_init_main_conf(ngx_conf_t *cf,
    void *conf);
static ngx_int_t ngx_http_tcp_fingerprint_init_module(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_tcp_fingerprint_commands[] = {

    { ngx_string("tcp_fingerprint"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_tcp_fingerprint_main_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_tcp_fingerprint_module_ctx = {
    ngx_http_tcp_fingerprint_add_variables,    /* preconfiguration */
    ngx_http_tcp_fingerprint_init,             /* postconfiguration */

    ngx_http_tcp_fingerprint_create_main_conf, /* create main configuration */
    ngx_http_tcp_fingerprint_init_main_conf,   /* init main configuration */

    NULL,                                      /* create server configuration */
    NULL,                                      /* merge server configuration */

    NULL,                                      /* create location configuration */
    NULL                                       /* merge location configuration */
};


ngx_module_t  ngx_http_tcp_fingerprint_module = {
    NGX_MODULE_V1,
    &ngx_http_tcp_fingerprint_module_ctx,  /* module context */
    ngx_http_tcp_fingerprint_commands,     /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_tcp_fingerprint_init_module,  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_tcp_fingerprint_vars[] = {

    { ngx_string("tcpfp_signature"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, signature), 0, 0 },

    { ngx_string("tcpfp_ttl"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, ttl), 0, 0 },

    { ngx_string("tcpfp_ittl"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, ittl), 0, 0 },

    { ngx_string("tcpfp_hops"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, hops), 0, 0 },

    { ngx_string("tcpfp_win"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, win), 0, 0 },

    { ngx_string("tcpfp_mss"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, mss), 0, 0 },

    { ngx_string("tcpfp_wscale"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, wscale), 0, 0 },

    { ngx_string("tcpfp_options"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, options), 0, 0 },

    { ngx_string("tcpfp_quirks"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, quirks), 0, 0 },

    { ngx_string("tcpfp_tls_rtt"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, tls_rtt), 0, 0 },

    { ngx_string("tcpfp_tcp_rtt"), NULL, ngx_http_tcp_fingerprint_variable,
      offsetof(ngx_tcp_fingerprint_ctx_t, tcp_rtt), 0, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_tcp_fingerprint_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                             *s;
    ngx_tcp_fingerprint_ctx_t             *ctx;
    ngx_http_tcp_fingerprint_main_conf_t  *tmcf;

    tmcf = ngx_http_get_module_main_conf(r, ngx_http_tcp_fingerprint_module);

    if (!tmcf->enable) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_tcp_fingerprint_get_ctx(r->main->connection);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    s = (ngx_str_t *) ((char *) ctx + data);

    if (s->len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = s->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcp_fingerprint_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_tcp_fingerprint_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


/*
 * Sets the message callback on the SSL context of every server: SSL objects
 * copy it at creation, and keep it when SNI switches them to another
 * server's context.
 */

static ngx_int_t
ngx_http_tcp_fingerprint_init(ngx_conf_t *cf)
{
#if (NGX_HTTP_SSL)
    ngx_uint_t                             s;
    ngx_http_ssl_srv_conf_t               *sscf;
    ngx_http_core_srv_conf_t             **cscfp;
    ngx_http_core_main_conf_t             *cmcf;
    ngx_http_tcp_fingerprint_main_conf_t  *tmcf;

    tmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_tcp_fingerprint_module);

    if (!tmcf->enable) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        ngx_tcp_fingerprint_ssl_init(&sscf->ssl);
    }
#endif

    return NGX_OK;
}


static void *
ngx_http_tcp_fingerprint_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_tcp_fingerprint_main_conf_t  *tmcf;

    tmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcp_fingerprint_main_conf_t));
    if (tmcf == NULL) {
        return NULL;
    }

    tmcf->enable = NGX_CONF_UNSET;

    return tmcf;
}


static char *
ngx_http_tcp_fingerprint_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_tcp_fingerprint_main_conf_t  *tmcf = conf;

    ngx_conf_init_value(tmcf->enable, 0);

    return NGX_CONF_OK;
}


/*
 * Runs in the master process once the listening sockets are open, at start
 * and at each reload: turns TCP_SAVE_SYN on every TCP socket that serves
 * HTTP. Accepted connections inherit the option. "off" leaves the sockets
 * alone, so that another module reading the SYN keeps it: a socket kept
 * across a reload from "on" goes on saving SYNs (about 100 bytes per
 * connection, freed at close) until nginx restarts.
 */

static ngx_int_t
ngx_http_tcp_fingerprint_init_module(ngx_cycle_t *cycle)
{
    ngx_http_tcp_fingerprint_main_conf_t  *tmcf;

    tmcf = ngx_http_cycle_get_module_main_conf(cycle,
                                               ngx_http_tcp_fingerprint_module);
    if (tmcf == NULL || !tmcf->enable) {
        return NGX_OK;
    }

    return ngx_tcp_fingerprint_init_listening(cycle, ngx_http_init_connection);
}
