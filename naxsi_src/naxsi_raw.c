/*
 * NAXSI, a web application firewall for NGINX
 * Copyright (C) 2016, Thibault 'bui' Koechlin
 *  
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "naxsi.h"


void
ngx_http_dummy_rawbody_parse(ngx_http_request_ctx_t *ctx, 
			       ngx_http_request_t	 *r,
			       u_char			*src,
			       u_int			 len)
{
  ngx_http_dummy_loc_conf_t		*cf;
  ngx_str_t				body;
  ngx_http_dummy_main_conf_t		*main_cf;
  ngx_str_t				empty = ngx_string("");
  
  NX_DEBUG(_debug_rawbody, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-RAWBODY CALLED len:%d",len);
  if (len <= 0 || !src)
    return;
  cf = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
  main_cf = ngx_http_get_module_main_conf(r, ngx_http_naxsi_module);


  body.data = src;
  body.len = len;
  
  naxsi_unescape(&body);
  
  /* here we got val name + val content !*/	      
  if (cf->raw_body_rules) {
    NX_DEBUG(_debug_rawbody, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-(local) RAW BODY RULES");
    ngx_http_basestr_ruleset_n(r->pool, &empty, &body,
			       cf->raw_body_rules, r, ctx, BODY);
  }

  if (main_cf->raw_body_rules) {
    NX_DEBUG(_debug_rawbody, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-(global) RAW BODY RULES");
    ngx_http_basestr_ruleset_n(r->pool, &empty, &body,
			       main_cf->raw_body_rules, r, ctx, BODY);
  }
}
