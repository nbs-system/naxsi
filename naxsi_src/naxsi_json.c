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

//#define _debug_json 1

ngx_http_rule_t nx_int__invalid_json = {/*type*/ 0, /*whitelist flag*/ 0, 
					/*wl_id ptr*/ NULL, /*rule_id*/ 15,
					/*log_msg*/ NULL, /*score*/ 0, 
					/*sscores*/ NULL,
					/*sc_block*/ 1,  /*sc_allow*/ 0, 
					/*block*/ 1,  /*allow*/ 0, /*drop*/ 0, /*log*/ 0,
					/*br ptrs*/ NULL};


ngx_int_t
ngx_http_nx_json_forward(ngx_json_t *js) 
{
  while ((*(js->src+js->off) == ' '  ||
	  *(js->src+js->off) == '\t' ||
	  *(js->src+js->off) == '\n' ||
	  *(js->src+js->off) == '\r') && js->off < js->len) {
    js->off++;
  }
  js->c = *(js->src + js->off);
  return (NGX_OK);
}

/*
** used to fast forward in json POSTS,
** we skip whitespaces/tab/CR/LF
*/
ngx_int_t
ngx_http_nx_json_seek(ngx_json_t *js, unsigned char seek) 
{
  
  ngx_http_nx_json_forward(js);
  if (js->c != seek)
    return (NGX_ERROR);
  return (NGX_OK);
}

/*
** extract a quoted strings,
** JSON spec only supports double-quoted strings,
** so do we.
*/
ngx_int_t
ngx_http_nx_json_quoted(ngx_json_t *js, ngx_str_t *ve)
{
  u_char *vn_start, *vn_end;
  
  vn_start = vn_end = NULL;
  
  if (*(js->src+js->off) != '"')
    return (NGX_ERROR);
  js->off++;
  vn_start = js->src+js->off;
  /* extract varname inbetween "..."*/
  while (js->off < js->len) {
    /* skip next character if backslashed */
    if (*(js->src+js->off) == '\\') {
      js->off += 2;
      if (js->off >= js->len) break;
    }
    if (*(js->src+js->off) == '"') {
      vn_end = js->src+js->off;
      js->off++;
      break;
    }
    js->off++;
  }
  if (!vn_start || !vn_end)
    return (NGX_ERROR);
  if (!*vn_start || !*vn_end)
    return (NGX_ERROR);
  ve->data = vn_start;
  ve->len = vn_end - vn_start;
  return (NGX_OK);
}

/*
** an array is values separated by ','
*/
ngx_int_t
ngx_http_nx_json_array(ngx_json_t *js) {
  ngx_int_t	rc;
  
  js->c = *(js->src + js->off);
  if (js->c != '[' || js->depth > JSON_MAX_DEPTH)
    return (NGX_ERROR);
  js->off++;
  do {
    rc = ngx_http_nx_json_val(js);
    /* if we cannot extract the value, 
       we may have reached array end. */
    if (rc != NGX_OK)
      break;
    ngx_http_nx_json_forward(js);
    if (js->c == ',') {
      js->off++;
      ngx_http_nx_json_forward(js);
    } else break;
  } while (rc == NGX_OK);
  if (js->c != ']')
    return (NGX_ERROR);
  return (NGX_OK);
}



ngx_int_t
ngx_http_nx_json_val(ngx_json_t *js) {
  ngx_str_t	val;
  ngx_int_t	ret;
  ngx_str_t	empty = ngx_string("");
  
  val.data = NULL;
  val.len = 0;
  
  ngx_http_nx_json_forward(js);
  if (js->c == '"') {
    ret = ngx_http_nx_json_quoted(js, &val);
    if (ret == NGX_OK)
      {
	/* parse extracted values. */
	if (js->loc_cf->body_rules)
	  ngx_http_basestr_ruleset_n(js->r->pool, &js->ckey, &val,
				     js->loc_cf->body_rules, js->r, js->ctx, 
				     BODY);
	if (js->main_cf->body_rules)
	  ngx_http_basestr_ruleset_n(js->r->pool, &js->ckey, &val,
				     js->main_cf->body_rules, js->r, js->ctx, 
				     BODY);
	NX_DEBUG(_debug_json, NGX_LOG_DEBUG_HTTP, js->r->connection->log, 0, "JSON '%V' : '%V'",
		 &(js->ckey), &(val));
      }
    return (ret);
  }
  if ((js->c >= '0' && js->c <= '9') || js->c == '-') {
    val.data = js->src+js->off;
    while ( ((*(js->src+js->off) >= '0' && *(js->src+js->off) <= '9') ||
	     *(js->src+js->off) == '.' || *(js->src+js->off) == '-') && js->off < js->len) {
      val.len++;
      js->off++;
    }
    /* parse extracted values. */
    if (js->loc_cf->body_rules)
      ngx_http_basestr_ruleset_n(js->r->pool, &js->ckey, &val,
				 js->loc_cf->body_rules, js->r, js->ctx, 
				 BODY);
    if (js->main_cf->body_rules)
      ngx_http_basestr_ruleset_n(js->r->pool, &js->ckey, &val,
				 js->main_cf->body_rules, js->r, js->ctx, 
				 BODY);
    NX_DEBUG(_debug_json, NGX_LOG_DEBUG_HTTP, js->r->connection->log, 0, "JSON '%V' : '%V'",
	     &(js->ckey), &(val));
    return (NGX_OK);
  }
  if (!strncasecmp((const char *) (js->src + js->off), (const char *) "true", 4) ||
      !strncasecmp((const char *) (js->src + js->off), (const char *) "false", 5) ||
      !strncasecmp((const char *) (js->src + js->off), (const char *) "null", 4)) {
    js->c = *(js->src + js->off);
    /* we don't check static values, do we ?! */
    val.data = js->src+js->off;
    if (js->c == 'F' || js->c == 'f') {
      js->off += 5;
      val.len = 5;
    }
    else {
      js->off += 4;
      val.len = 4;
    }
    /* parse extracted values. */
    if (js->loc_cf->body_rules)
      ngx_http_basestr_ruleset_n(js->r->pool, &js->ckey, &val,
				 js->loc_cf->body_rules, js->r, js->ctx, 
				 BODY);
    if (js->main_cf->body_rules)
      ngx_http_basestr_ruleset_n(js->r->pool, &js->ckey, &val,
				 js->main_cf->body_rules, js->r, js->ctx, 
				 BODY);
    NX_DEBUG(_debug_json, NGX_LOG_DEBUG_HTTP, js->r->connection->log, 0, "JSON '%V' : '%V'",
	     &(js->ckey), &(val));
    return (NGX_OK);
  }
  
  if (js->c == '[') {
    ret = ngx_http_nx_json_array(js);
    if (js->c != ']')
      return (NGX_ERROR);
    js->off++;
    return (ret);
  }
  if (js->c == '{') {
    /*
    ** if sub-struct, parse key without value :
    ** "foobar" : { "bar" : [1,2,3]} => "foobar" parsed alone.
    ** this is to avoid "foobar" left unparsed, as we won't have
    ** key/value here with "foobar" as a key.
    */
    if (js->loc_cf->body_rules)
      ngx_http_basestr_ruleset_n(js->r->pool, &js->ckey, &empty,
    				 js->loc_cf->body_rules, js->r, js->ctx,
    				 BODY);
    if (js->main_cf->body_rules)
      ngx_http_basestr_ruleset_n(js->r->pool, &js->ckey, &empty,
    				 js->main_cf->body_rules, js->r, js->ctx,
    				 BODY);
    ret = ngx_http_nx_json_obj(js);
    ngx_http_nx_json_forward(js);
    if (js->c != '}')
      return (NGX_ERROR);
    js->off++;
    return (ret);
  }
  return (NGX_ERROR);
}


ngx_int_t
ngx_http_nx_json_obj(ngx_json_t *js)
{
  js->c = *(js->src + js->off);
  
  if (js->c != '{' || js->depth > JSON_MAX_DEPTH)
    return (NGX_ERROR);
  js->off++;
  
  do {
    ngx_http_nx_json_forward(js);
    /* check subs (arrays, objects) */
    switch (js->c) {
    case '[': /* array */
      js->depth++;
      ngx_http_nx_json_array(js);
      if (ngx_http_nx_json_seek(js, ']'))
	return (NGX_ERROR);
      js->off++;
      js->depth--;
      break;
    case '{': /* sub-object */
      js->depth++;
      ngx_http_nx_json_obj(js);
      if (js->c != '}')
	return (NGX_ERROR);
      js->off++;
      js->depth--;
      break;
    case '"': /* key : value, extract and parse. */
      if (ngx_http_nx_json_quoted(js, &(js->ckey)) != NGX_OK)
	return (NGX_ERROR);
      if (ngx_http_nx_json_seek(js, ':'))
	return (NGX_ERROR);
      js->off++;
      ngx_http_nx_json_forward(js);
      if (ngx_http_nx_json_val(js) != NGX_OK)
	return (NGX_ERROR);
    }
    ngx_http_nx_json_forward(js);
    /* another element ? */
    if (js->c == ',') {
      js->off++;
      ngx_http_nx_json_forward(js);
      continue;
      
    } else if (js->c == '}') {
      js->depth--;
      /* or maybe we just finished parsing this object */
      return (NGX_OK);
    } else {
      /* nothing we expected, die. */
      return (NGX_ERROR);
    }
  } while (js->off < js->len);
  
  return (NGX_ERROR);
  
}

/*
** Parse a JSON request
*/
void
ngx_http_dummy_json_parse(ngx_http_request_ctx_t *ctx, 
			  ngx_http_request_t	 *r,
			  u_char		 *src,
			  u_int			 len)
{
  ngx_json_t				*js;
  
  
  js = ngx_pcalloc(r->pool, sizeof(ngx_json_t));
  if (!js) return ;
  js->json.data = js->src = src;
  js->json.len = js->len = len;
  js->r = r;
  js->ctx = ctx;
  js->loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
  js->main_cf = ngx_http_get_module_main_conf(r, ngx_http_naxsi_module);
  
  if (ngx_http_nx_json_seek(js, '{')) {
    ngx_http_apply_rulematch_v_n(&nx_int__invalid_json, ctx, r, NULL, NULL, BODY, 1, 0);
    return ;
  }
  if (ngx_http_nx_json_obj(js) != NGX_OK) {
    ngx_http_apply_rulematch_v_n(&nx_int__invalid_json, ctx, r, NULL, NULL, BODY, 1, 0);
    NX_DEBUG(_debug_json, NGX_LOG_DEBUG_HTTP, js->r->connection->log, 0, "nx_json_obj returned error, apply invalid_json.");
    
  }
  /* we are now on closing bracket, check for garbage. */
  js->off++;
  ngx_http_nx_json_forward(js);
  if (js->off != js->len)
    ngx_http_apply_rulematch_v_n(&nx_int__invalid_json, ctx, r, NULL, NULL, BODY, 1, 0);
  return ;
}

