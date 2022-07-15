// SPDX-FileCopyrightText: 2019, Giovanni Dante Grazioli <gda@nbs-system.com>
// SPDX-FileCopyrightText: 2016-2019, Thibault 'bui' Koechlin <tko@nbs-system.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <naxsi.h>

void
ngx_http_naxsi_rawbody_parse(ngx_http_request_ctx_t* ctx,
                             ngx_http_request_t*     r,
                             u_char*                 src,
                             u_int                   len)
{
  ngx_http_naxsi_loc_conf_t*  cf;
  ngx_str_t                   body;
  ngx_http_naxsi_main_conf_t* main_cf;
  ngx_str_t                   empty = ngx_string("");

  NX_DEBUG(
    _debug_rawbody, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-RAWBODY CALLED len:%d", len);
  if (len <= 0 || !src)
    return;
  cf      = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
  main_cf = ngx_http_get_module_main_conf(r, ngx_http_naxsi_module);

  body.data = src;
  body.len  = len;

  naxsi_unescape(&body);

  /* here we got val name + val content !*/
  if (cf->raw_body_rules) {
    NX_DEBUG(
      _debug_rawbody, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-(local) RAW BODY RULES");
    ngx_http_basestr_ruleset_n(r->pool, &empty, &body, cf->raw_body_rules, r, ctx, BODY);
  }

  if (main_cf->raw_body_rules) {
    NX_DEBUG(
      _debug_rawbody, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-(global) RAW BODY RULES");
    ngx_http_basestr_ruleset_n(r->pool, &empty, &body, main_cf->raw_body_rules, r, ctx, BODY);
  }
}
