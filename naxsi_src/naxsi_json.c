/*
 * NAXSI, a web application firewall for NGINX
 * Copyright (C) NBS System – All Rights Reserved
 * Licensed under GNU GPL v3.0 – See the LICENSE notice for details
 */

#include "naxsi.h"
#include "naxsi_macros.h"

#define json_char(x) ((x)->src + (x)->off)

//#define _debug_json 1

ngx_http_rule_t nx_int__invalid_json = {
  0,    /* type */
  0,    /* whitelist flag */
  NULL, /* wl_id ptr */
  15,   /* rule_id */
  NULL, /* log_msg */
  0,    /* score */
  NULL, /* sscores */
  1,    /* sc_block */
  0,    /* sc_allow */
  1,    /* block */
  0,    /* allow */
  0,    /* drop */
  0,    /* log */
  NULL  /* br ptrs */
};

ngx_int_t
ngx_http_nx_json_forward(ngx_json_t* js)
{
  while (js->off < js->len && is_whitespace(*json_char(js))) {
    js->off++;
  }
  js->c = *json_char(js);
  return (NGX_OK);
}

/*
** used to fast forward in json POSTS,
** we skip whitespaces/tab/CR/LF
*/
ngx_int_t
ngx_http_nx_json_seek(ngx_json_t* js, unsigned char seek)
{
  ngx_http_nx_json_forward(js);
  if (js->c != seek) {
    return (NGX_ERROR);
  }
  return (NGX_OK);
}

/*
** extract a quoted strings,
** JSON spec only supports double-quoted strings,
** so do we.
*/
ngx_int_t
ngx_http_nx_json_quoted(ngx_json_t* js, ngx_str_t* ve)
{
  u_char *vn_start, *vn_end;

  vn_start = vn_end = NULL;

  return_value_if(*json_char(js) != '"', NGX_ERROR);
  js->off++;
  vn_start = json_char(js);
  /* extract varname inbetween "..."*/
  while (js->off < js->len) {
    /* skip next character if backslashed */
    if (*json_char(js) == '\\') {
      js->off += 2;
      if (js->off >= js->len)
        break;
      continue;
    }
    if (*json_char(js) == '"') {
      vn_end = js->src + js->off;
      js->off++;
      break;
    }
    js->off++;
  }
  if (!vn_start || !vn_end) {
    return (NGX_ERROR);
  }
  if (!*vn_start || !*vn_end) {
    return (NGX_ERROR);
  }
  ve->data = vn_start;
  ve->len  = vn_end - vn_start;
  return (NGX_OK);
}

/*
** an array is values separated by ','
*/
ngx_int_t
ngx_http_nx_json_array(ngx_json_t* js)
{
  ngx_int_t rc;

  js->c = *(js->src + js->off);
  if (js->c != '[' || js->depth > JSON_MAX_DEPTH)
    return (NGX_ERROR);
  js->off++;
  do {
    rc = ngx_http_nx_json_val(js);
    /* if we cannot extract the value,
       we may have reached array end. */
    if (rc != NGX_OK) {
      break;
    }
    ngx_http_nx_json_forward(js);
    if (js->c == ',') {
      js->off++;
      ngx_http_nx_json_forward(js);
    } else
      break;
  } while (rc == NGX_OK);
  if (js->c != ']') {
    return (NGX_ERROR);
  }
  return (NGX_OK);
}

ngx_int_t
ngx_http_nx_json_val(ngx_json_t* js)
{
  ngx_str_t val;
  ngx_int_t ret;
  ngx_str_t empty = ngx_string("");

  val.data = NULL;
  val.len  = 0;

  ngx_http_nx_json_forward(js);
  if (js->c == '"') {
    ret = ngx_http_nx_json_quoted(js, &val);
    if (ret == NGX_OK) {
      /* parse extracted values. */
      if (js->loc_cf->body_rules) {
        ngx_http_basestr_ruleset_n(
          js->r->pool, &js->ckey, &val, js->loc_cf->body_rules, js->r, js->ctx, BODY);
      }
      if (js->main_cf->body_rules) {
        ngx_http_basestr_ruleset_n(
          js->r->pool, &js->ckey, &val, js->main_cf->body_rules, js->r, js->ctx, BODY);
      }
      NX_DEBUG(_debug_json,
               NGX_LOG_DEBUG_HTTP,
               js->r->connection->log,
               0,
               "quoted-JSON '%V' : '%V'",
               &(js->ckey),
               &(val));
    }
    return (ret);
  }
  if ((js->c >= '0' && js->c <= '9') || js->c == '-') {
    val.data = js->src + js->off;
    while (((*(js->src + js->off) >= '0' && *(js->src + js->off) <= '9') ||
            *(js->src + js->off) == '.' || *(js->src + js->off) == '-' ||
            *(js->src + js->off) == 'e') &&
           js->off < js->len) {
      val.len++;
      js->off++;
    }
    /* parse extracted values. */
    if (js->loc_cf->body_rules) {
      ngx_http_basestr_ruleset_n(
        js->r->pool, &js->ckey, &val, js->loc_cf->body_rules, js->r, js->ctx, BODY);
    }
    if (js->main_cf->body_rules) {
      ngx_http_basestr_ruleset_n(
        js->r->pool, &js->ckey, &val, js->main_cf->body_rules, js->r, js->ctx, BODY);
    }
    NX_DEBUG(_debug_json,
             NGX_LOG_DEBUG_HTTP,
             js->r->connection->log,
             0,
             "JSON '%V' : '%V'",
             &(js->ckey),
             &(val));
    return (NGX_OK);
  }
  if (!strncasecmp((const char*)(js->src + js->off), (const char*)"true", 4) ||
      !strncasecmp((const char*)(js->src + js->off), (const char*)"false", 5) ||
      !strncasecmp((const char*)(js->src + js->off), (const char*)"null", 4)) {
    js->c = *(js->src + js->off);
    /* we don't check static values, do we ?! */
    val.data = js->src + js->off;
    if (js->c == 'F' || js->c == 'f') {
      js->off += 5;
      val.len = 5;
    } else {
      js->off += 4;
      val.len = 4;
    }
    /* parse extracted values. */
    if (js->loc_cf->body_rules) {
      ngx_http_basestr_ruleset_n(
        js->r->pool, &js->ckey, &val, js->loc_cf->body_rules, js->r, js->ctx, BODY);
    }
    if (js->main_cf->body_rules) {
      ngx_http_basestr_ruleset_n(
        js->r->pool, &js->ckey, &val, js->main_cf->body_rules, js->r, js->ctx, BODY);
    }
    NX_DEBUG(_debug_json,
             NGX_LOG_DEBUG_HTTP,
             js->r->connection->log,
             0,
             "JSON '%V' : '%V'",
             &(js->ckey),
             &(val));
    return (NGX_OK);
  }

  if (js->c == '[') {
    ret = ngx_http_nx_json_array(js);
    if (js->c != ']') {
      return (NGX_ERROR);
    }
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
    if (js->loc_cf->body_rules) {
      ngx_http_basestr_ruleset_n(
        js->r->pool, &js->ckey, &empty, js->loc_cf->body_rules, js->r, js->ctx, BODY);
    }
    if (js->main_cf->body_rules) {
      ngx_http_basestr_ruleset_n(
        js->r->pool, &js->ckey, &empty, js->main_cf->body_rules, js->r, js->ctx, BODY);
    }
    ret = ngx_http_nx_json_obj(js);
    ngx_http_nx_json_forward(js);
    if (js->c != '}') {
      return (NGX_ERROR);
    }
    js->off++;
    return (ret);
  }
  return (NGX_ERROR);
}

ngx_int_t
ngx_http_nx_json_obj(ngx_json_t* js)
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
        if (js->c != '}') {
          return (NGX_ERROR);
        }
        js->off++;
        js->depth--;
        break;
      case '"': /* key : value, extract and parse. */
        if (ngx_http_nx_json_quoted(js, &(js->ckey)) != NGX_OK) {
          return (NGX_ERROR);
        }
        if (ngx_http_nx_json_seek(js, ':')) {
          return (NGX_ERROR);
        }
        js->off++;
        ngx_http_nx_json_forward(js);
        if (ngx_http_nx_json_val(js) != NGX_OK) {
          return (NGX_ERROR);
        }
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
ngx_http_naxsi_json_parse(ngx_http_request_ctx_t* ctx,
                          ngx_http_request_t*     r,
                          u_char*                 src,
                          u_int                   len)
{
  ngx_json_t* js;

  js = ngx_pcalloc(r->pool, sizeof(ngx_json_t));
  if (!js)
    return;
  js->json.data = js->src = src;
  js->json.len = js->len = len;
  js->r                  = r;
  js->ctx                = ctx;
  js->loc_cf             = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
  js->main_cf            = ngx_http_get_module_main_conf(r, ngx_http_naxsi_module);

  if (ngx_http_nx_json_val(js) != NGX_OK) {
    ngx_http_apply_rulematch_v_n(&nx_int__invalid_json, ctx, r, NULL, NULL, BODY, 1, 0);
    NX_DEBUG(_debug_json,
             NGX_LOG_DEBUG_HTTP,
             js->r->connection->log,
             0,
             "nx_json_val returned error, apply invalid_json.");
  }
  ngx_http_nx_json_forward(js);
  if (js->off != js->len) {
    ngx_http_apply_rulematch_v_n(&nx_int__invalid_json, ctx, r, NULL, NULL, BODY, 1, 0);
  }
  return;
}
