/*
 * NAXSI, a web application firewall for NGINX
 * Copyright (C) NBS System – All Rights Reserved
 * Licensed under GNU GPL v3.0 – See the LICENSE notice for details
 */

#include "assert.h"
#include "naxsi.h"
#include "naxsi_macros.h"
#include "naxsi_net.h"

/* used to store locations during the configuration time.
   then, accessed by the hashtable building feature during "init" time. */

/*
** Static defined rules struct for internal rules.
** We use those to be able to call is_rule_whitelisted_n() on those
** rules at any time ;)
*/

ngx_http_rule_t nx_int__weird_request = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 1,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 0,     /*sc_allow*/ 0,
  /*block*/ 1,        /*allow*/ 0,          /*drop*/ 0, /*log*/ 0,
  /*br ptrs*/ NULL
};

ngx_http_rule_t nx_int__big_request = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 2,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 0,     /*sc_allow*/ 0,
  /*block*/ 1,        /*allow*/ 0,          /*drop*/ 0, /*log*/ 0,
  /*br ptrs*/ NULL
};

ngx_http_rule_t nx_int__uncommon_hex_encoding = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 10,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 1,     /*sc_allow*/ 0,
  /*block*/ 1,        /*allow*/ 0,          /*drop*/ 0, /*log*/ 0,
  /*br ptrs*/ NULL
};

ngx_http_rule_t nx_int__uncommon_content_type = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 11,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 1,     /*sc_allow*/ 0,
  /*block*/ 1,        /*allow*/ 0,          /*drop*/ 0, /*log*/ 0,
  /*br ptrs*/ NULL
};

ngx_http_rule_t nx_int__uncommon_url = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 12,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 1,     /*sc_allow*/ 0,
  /*block*/ 1,        /*allow*/ 0,          /*drop*/ 0, /*log*/ 0,
  /*br ptrs*/ NULL
};

ngx_http_rule_t nx_int__uncommon_post_format = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 13,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 1,     /*sc_allow*/ 0,
  /*block*/ 1,        /*allow*/ 0,          /*drop*/ 0, /*log*/ 0,
  /*br ptrs*/ NULL
};

ngx_http_rule_t nx_int__uncommon_post_boundary = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 14,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 1,     /*sc_allow*/ 0,
  /*block*/ 1,        /*allow*/ 0,          /*drop*/ 0, /*log*/ 0,
  /*br ptrs*/ NULL
};

ngx_http_rule_t nx_int__empty_post_body = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 16,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 1,     /*sc_allow*/ 0,
  /*block*/ 1,        /*allow*/ 0,          /*drop*/ 0, /*log*/ 0,
  /*br ptrs*/ NULL
};

ngx_http_rule_t* nx_int__libinject_sql; /*ID:17*/
ngx_http_rule_t* nx_int__libinject_xss; /*ID:18*/

ngx_http_rule_t nx_int__no_rules = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 19,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 0,     /*sc_allow*/ 0,
  /*block*/ 0,        /*allow*/ 0,          /*drop*/ 1, /*log*/ 0,
  /*br ptrs*/ NULL
};

ngx_http_rule_t nx_int__bad_utf8 = {
  /*type*/ 0,         /*whitelist flag*/ 0,
  /*wl_id ptr*/ NULL, /*rule_id*/ 20,
  /*log_msg*/ NULL,   /*score*/ 0,
  /*sscores*/ NULL,
  /*sc_block*/ 0,     /*sc_allow*/ 0,
  /*block*/ 0,        /*allow*/ 0,          /*drop*/ 1, /*log*/ 0,
  /*br ptrs*/ NULL
};

#define naxsi_error_fatal(ctx, r, ...)                                                             \
  do {                                                                                             \
    if (ctx)                                                                                       \
      ctx->block = 1;                                                                              \
    if (ctx)                                                                                       \
      ctx->drop = 1;                                                                               \
    ngx_log_debug(NGX_LOG_DEBUG_HTTP,                                                              \
                  r->connection->log,                                                              \
                  0,                                                                               \
                  "XX-******** NGINX NAXSI INTERNAL ERROR ********");                              \
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, __VA_ARGS__);                         \
    ngx_log_debug(NGX_LOG_DEBUG_HTTP,                                                              \
                  r->connection->log,                                                              \
                  0,                                                                               \
                  "XX-func:%s file:%s line:%d",                                                    \
                  __func__,                                                                        \
                  __FILE__,                                                                        \
                  __LINE__);                                                                       \
    if (r && r->uri.data)                                                                          \
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-uri:%s", r->uri.data);          \
  } while (0)

void
ngx_http_naxsi_update_current_ctx_status(ngx_http_request_ctx_t*    ctx,
                                         ngx_http_naxsi_loc_conf_t* cf,
                                         ngx_http_request_t*        r,
                                         ngx_str_t*                 name,
                                         ngx_str_t*                 value);
int
ngx_http_process_basic_rule_buffer(ngx_str_t* str, ngx_http_rule_t* rl, ngx_int_t* match);
void
ngx_http_naxsi_payload_handler(ngx_http_request_t* r);
int
ngx_http_basestr_ruleset_n(ngx_pool_t*             pool,
                           ngx_str_t*              name,
                           ngx_str_t*              value,
                           ngx_array_t*            rules,
                           ngx_http_request_t*     req,
                           ngx_http_request_ctx_t* ctx,
                           naxsi_match_zone_t      zone);
void
ngx_http_naxsi_body_parse(ngx_http_request_ctx_t*     ctx,
                          ngx_http_request_t*         r,
                          ngx_http_naxsi_loc_conf_t*  cf,
                          ngx_http_naxsi_main_conf_t* main_cf);
void
naxsi_log_offending(ngx_str_t*          name,
                    ngx_str_t*          val,
                    ngx_http_request_t* req,
                    ngx_http_rule_t*    rule,
                    naxsi_match_zone_t  zone,
                    ngx_int_t           target_name);
void
ngx_http_naxsi_rawbody_parse(ngx_http_request_ctx_t* ctx,
                             ngx_http_request_t*     r,
                             u_char*                 src,
                             u_int                   len);
unsigned char*
ngx_utf8_check(ngx_str_t* str);

/*
** in : string to inspect, associated rule
** does : apply the rule on the string, return 1 if matched,
**    0 else and -1 on error
*/
int
ngx_http_process_basic_rule_buffer(ngx_str_t* str, ngx_http_rule_t* rl, ngx_int_t* nb_match)

{
  ngx_int_t      match, tmp_idx, len;
  unsigned char* ret;
  int            captures[30];
  if (!rl->br || !nb_match)
    return (-1);

  *nb_match = 0;
  if (rl->br->match_type == RX && rl->br->rx) {
    tmp_idx = 0;
    len     = str->len;
    while
#if defined   nginx_version && (nginx_version >= 1002002 && nginx_version != 1003000)
      (tmp_idx < len && (match = pcre_exec(rl->br->rx->regex->code,
                                           0,
                                           (const char*)str->data,
                                           str->len,
                                           tmp_idx,
                                           0,
                                           captures,
                                           30)) >= 0)
#elif defined nginx_version && (nginx_version > 1001011)
      (tmp_idx < len && (match = pcre_exec(rl->br->rx->regex->pcre,
                                           0,
                                           (const char*)str->data,
                                           str->len,
                                           tmp_idx,
                                           0,
                                           captures,
                                           30)) >= 0)
#elif defined nginx_version && (nginx_version <= 1001011)
      (tmp_idx < len &&
       (match = pcre_exec(
          rl->br->rx->regex, 0, (const char*)str->data, str->len, tmp_idx, 0, captures, 30)) >= 0)
#elif defined nginx_version
#error "Inconsistent nginx version."
      (0)
#else
#error "nginx_version not defined."
      (0)
#endif
    {
      *nb_match += match;
      tmp_idx = captures[1];
    }
    if (*nb_match > 0) {
      if (rl->br->negative)
        return (0);
      else
        return (1);
    } else if (*nb_match == 0) {
      if (rl->br->negative)
        return (1);
      else
        return (0);
    }
    return (-1);
  } else if (rl->br->match_type == STR && rl->br->str) {
    match   = 0;
    tmp_idx = 0;
    while (1) {
      ret = (unsigned char*)strfaststr((unsigned char*)str->data + tmp_idx,
                                       (unsigned int)str->len - tmp_idx,
                                       (unsigned char*)rl->br->str->data,
                                       (unsigned int)rl->br->str->len);
      if (ret) {
        match     = 1;
        *nb_match = *nb_match + 1;
      } else
        break;
      if (nb_match && ret < (str->data + str->len)) {
        tmp_idx = (ret - str->data) + 1;
        if (tmp_idx > (int)(str->len - 1))
          break;
      } else
        break;
    }
    if (match) {
      if (rl->br->negative)
        return (0);
      else
        return (1);
    } else {
      if (rl->br->negative)
        return (1);
      else
        return (0);
    }
  } else if (rl->br->match_type == LIBINJ_XSS) {
    if (libinjection_xss((const char*)str->data, str->len) == 1)
      return (1);
  } else if (rl->br->match_type == LIBINJ_SQL) {
    sfilter state;

    libinjection_sqli_init(&state, (const char*)str->data, str->len, FLAG_NONE);
    if (libinjection_is_sqli(&state) == 1)
      return (1);
  }

  return (0);
}

/*
** Check if a (matched) rule is whitelisted.
** This func will look for the current URI in the wlr_url_hash [hashtable]
** It will also look for varname in the wlr_body|args|headers_hash [hashtable]
** and It will also look for disabled rules.
** 1 - If the rule is disabled, it's whitelisted
** 2 - If a matching URL is found, check if the further information confirms
*that the rule should be whitelisted
** ($URL:/bar|$ARGS_VAR:foo : it's not because URL matches that we should
*whitelist rule)
** 3 - If a matching varname is found, check zone and rules IDs.
** [TODO] : Add mz matches with style BODY|HEADERS|...
** returns (1) if rule is whitelisted, else (0)
*/

int
ngx_http_naxsi_is_whitelist_adapted(ngx_http_whitelist_rule_t* b,
                                    ngx_str_t*                 name,
                                    naxsi_match_zone_t         zone,
                                    ngx_http_rule_t*           r,
                                    ngx_http_request_t*        req,
                                    naxsi_match_type_t         type,
                                    ngx_int_t                  target_name)
{
  /* if something was found, check the rule ID */
  if (!b)
    return (0);
  /* FILE_EXT zone is just a hack, as it indeed targets BODY */
  if (zone == FILE_EXT)
    zone = BODY;
  NX_DEBUG(_debug_whitelist_compat,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "Possible whitelist ... check...");

  /* if whitelist targets arg name, but the rules hit content*/
  if (b->target_name && !target_name) {
    NX_DEBUG(_debug_whitelist_compat,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "whitelist targets name, but rule matched content.");
    return (0);
  }
  /* if if the whitelist target contents, but the rule hit arg name*/
  if (!b->target_name && target_name) {
    NX_DEBUG(_debug_whitelist_compat,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "whitelist targets content, but rule matched name.");
    return (0);
  }

  if (type == NAME_ONLY) {
    NX_DEBUG(_debug_whitelist_compat,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "Name match in zone %s",
             zone == ARGS ? "ARGS"
                          : zone == BODY ? "BODY" : zone == HEADERS ? "HEADERS" : "UNKNOWN!!!!!");
    // False Positive, there was a whitelist that matches the argument name,
    // But is was actually matching an existing URI name.
    if (zone != b->zone || b->uri_only) {
      NX_DEBUG(_debug_whitelist_compat,
               NGX_LOG_DEBUG_HTTP,
               req->connection->log,
               0,
               "bad whitelist, name match, but WL was only on URL.");
      return (0);
    }
    return (nx_check_ids(r->rule_id, b->ids));
  }
  if (type == URI_ONLY || type == MIXED) {
    /* zone must match */
    if (b->uri_only && type != URI_ONLY) {
      NX_DEBUG(_debug_whitelist_compat,
               NGX_LOG_DEBUG_HTTP,
               req->connection->log,
               0,
               "bad whitelist, type is URI_ONLY, but not whitelist");
      return (0);
    }

    if (zone != b->zone) {
      NX_DEBUG(_debug_whitelist_compat,
               NGX_LOG_DEBUG_HTTP,
               req->connection->log,
               0,
               "bad whitelist, URL match, but not zone");
      return (0);
    }

    return (nx_check_ids(r->rule_id, b->ids));
  }
  NX_DEBUG(_debug_whitelist_compat,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "finished wl check, failed.");

  return (0);
}

ngx_http_whitelist_rule_t*
nx_find_wl_in_hash(ngx_http_request_t*        req,
                   ngx_str_t*                 mstr,
                   ngx_http_naxsi_loc_conf_t* cf,
                   naxsi_match_zone_t         zone)
{
  ngx_int_t                  k;
  ngx_http_whitelist_rule_t* b = NULL;
  size_t                     i;
  ngx_str_t                  scratch = { .data = mstr->data, .len = mstr->len };

  if (zone == HEADERS) {
    scratch.data = ngx_pcalloc(req->pool, scratch.len + 1);
    memcpy(scratch.data, mstr->data, scratch.len);
  }

  for (i = 0; i < scratch.len; i++)
    scratch.data[i] = tolower(scratch.data[i]);

  k = ngx_hash_key_lc(scratch.data, scratch.len);

  if ((zone == BODY || zone == FILE_EXT) && cf->wlr_body_hash && cf->wlr_body_hash->size > 0)
    b = (ngx_http_whitelist_rule_t*)ngx_hash_find(
      cf->wlr_body_hash, k, (u_char*)scratch.data, scratch.len);
  else if (zone == HEADERS && cf->wlr_headers_hash && cf->wlr_headers_hash->size > 0)
    b = (ngx_http_whitelist_rule_t*)ngx_hash_find(
      cf->wlr_headers_hash, k, (u_char*)scratch.data, scratch.len);
  else if (zone == URL && cf->wlr_url_hash && cf->wlr_url_hash->size > 0)
    b = (ngx_http_whitelist_rule_t*)ngx_hash_find(
      cf->wlr_url_hash, k, (u_char*)scratch.data, scratch.len);
  else if (zone == ARGS && cf->wlr_args_hash && cf->wlr_args_hash->size > 0)
    b = (ngx_http_whitelist_rule_t*)ngx_hash_find(
      cf->wlr_args_hash, k, (u_char*)scratch.data, scratch.len);
  return (b);
}

int
nx_can_ignore_ip(const ngx_str_t* mstr, ngx_http_naxsi_loc_conf_t* cf)
{
  if (!cf->ignore_ips || cf->ignore_ips_ha.keys.nelts < 1) {
    return 0;
  }
  char ip_str[INET6_ADDRSTRLEN] = { 0 };
  if (strchr((const char*)mstr->data, ':') != NULL) {
    if (!parse_ipv6((const char*)mstr->data, NULL, ip_str)) {
      return 0;
    }
  } else {
    if (!parse_ipv4((const char*)mstr->data, NULL, ip_str)) {
      return 0;
    }
  }

  ngx_str_t  scratch = { .data = (unsigned char*)ip_str, .len = strlen(ip_str) };
  ngx_uint_t k       = ngx_hash_key(scratch.data, scratch.len);
  return ngx_hash_find(cf->ignore_ips, k, (u_char*)scratch.data, scratch.len) != NULL ? 1 : 0;
}

int
nx_can_ignore_cidr(const ngx_str_t* mstr, ngx_http_naxsi_loc_conf_t* cf)
{
  if (!cf->ignore_cidrs) {
    return 0;
  }
  uint        i;
  ip_t        ip;
  const char* ipstr   = (const char*)mstr->data;
  int         is_ipv6 = strchr(ipstr, ':') != NULL;
  if (is_ipv6) {
    if (!parse_ipv6(ipstr, &ip, NULL)) {
      return 0;
    }
  } else {
    if (!parse_ipv4(ipstr, &ip, NULL)) {
      return 0;
    }
  }
  for (i = 0; i < cf->ignore_cidrs->nelts; i++) {
    cidr_t* cidr = &((cidr_t*)cf->ignore_cidrs->elts)[i];
    if (is_in_subnet(cidr, &ip, is_ipv6)) {
      return 1;
    }
  }

  return 0;
}

#define custloc_array(x) ((ngx_http_custom_rule_location_t*)x)

/*
** wrapper used for regex matchzones. Should be used by classic basestr* as
*well.
*/
int
ngx_http_naxsi_pcre_wrapper(ngx_regex_compile_t* rx, unsigned char* str, unsigned int len)
{
  int match;
  int captures[30];

#if defined   nginx_version && (nginx_version >= 1002002 && nginx_version != 1003000)
  match = pcre_exec(rx->regex->code, 0, (const char*)str, len, 0, 0, captures, 1);
#elif defined nginx_version && (nginx_version > 1001011)
  match = pcre_exec(rx->regex->pcre, 0, (const char*)str, len, 0, 0, captures, 1);
#elif defined nginx_version && (nginx_version <= 1001011)
  match = pcre_exec(rx->regex, 0, (const char*)str, len, 0, 0, captures, 1);
#elif defined nginx_version
#error "Inconsistent nginx version."
  return (0);
#else
#error "nginx_version not defined."
  return (0);
#endif
  if (match > 0)
    return (1);
  return (match);
}

int
ngx_http_naxsi_is_rule_whitelisted_rx(ngx_http_request_t*        req,
                                      ngx_http_naxsi_loc_conf_t* cf,
                                      ngx_http_rule_t*           r,
                                      ngx_str_t*                 name,
                                      naxsi_match_zone_t         zone,
                                      ngx_int_t                  target_name)
{
  ngx_http_rule_t* p;
  uint             i, x;
  int              rx_match, violation;

  /* Look it up in regexed whitelists for matchzones */
  if (!cf->rxmz_wlr || cf->rxmz_wlr->nelts < 1)
    return (0);
  NX_DEBUG(wl_debug_rx,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "RXX - Trying to find rx for %v",
           name);

  for (i = 0; i < cf->rxmz_wlr->nelts; i++) {

    p = (((ngx_http_rule_t**)(cf->rxmz_wlr->elts))[i]);

    if (!p->br || !p->br->custom_locations || p->br->custom_locations->nelts < 1) {
      NX_DEBUG(wl_debug_rx,
               NGX_LOG_DEBUG_HTTP,
               req->connection->log,
               0,
               "Rule pushed to RXMZ, but has no custom_location.");

      continue;
    }

    /*
    ** once we have pointer to the rule :
    ** - go through each custom location (ie. ARGS_VAR_X:foobar*)
    ** - verify that regular expressions match. If not, it means whitelist does
    *not apply.
    */

    NX_DEBUG(wl_debug_rx,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "%d/%d RXMZ rule has %d custom locations",
             i,
             cf->rxmz_wlr->nelts,
             p->br->custom_locations->nelts);

    if (p->br->zone != (ngx_int_t)zone) {
      NX_DEBUG(
        wl_debug_rx, NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "%d/%d Not targeting same zone.");

      continue;
    }

    if (target_name != p->br->target_name) {
      NX_DEBUG(wl_debug_rx, NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "only one target_name");

      continue;
    }

    for (x = 0, violation = 0; x < p->br->custom_locations->nelts && violation == 0; x++) {
      /* does custom location targets a body var ? */
      if (custloc_array(p->br->custom_locations->elts)[x].body_var) {
        rx_match = ngx_http_naxsi_pcre_wrapper(
          custloc_array(p->br->custom_locations->elts)[x].target_rx, name->data, name->len);
        if (rx_match < 0) {
          violation = 1;
          NX_DEBUG(wl_debug_rx,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "[BODY] FAIL:%d (rx:%V, str:%V)",
                   rx_match,
                   &(custloc_array(p->br->custom_locations->elts)[x].target_rx->pattern),
                   name);

          break;
        }
        NX_DEBUG(wl_debug_rx,
                 NGX_LOG_DEBUG_HTTP,
                 req->connection->log,
                 0,
                 "[BODY] Match:%d (rx:%V, str:%V)",
                 rx_match,
                 &(custloc_array(p->br->custom_locations->elts)[x].target_rx->pattern),
                 name);
      }

      if (custloc_array(p->br->custom_locations->elts)[x].args_var) {
        rx_match = ngx_http_naxsi_pcre_wrapper(
          custloc_array(p->br->custom_locations->elts)[x].target_rx, name->data, name->len);
        if (rx_match < 0) {
          violation = 1;
          NX_DEBUG(wl_debug_rx,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "[ARGS] FAIL:%d (rx:%V, str:%V)",
                   rx_match,
                   &(custloc_array(p->br->custom_locations->elts)[x].target_rx->pattern),
                   name);

          break;
        }
        NX_DEBUG(wl_debug_rx,
                 NGX_LOG_DEBUG_HTTP,
                 req->connection->log,
                 0,
                 "[ARGS] Match:%d (rx:%V, str:%V)",
                 rx_match,
                 &(custloc_array(p->br->custom_locations->elts)[x].target_rx->pattern),
                 name);
      }

      if (custloc_array(p->br->custom_locations->elts)[x].specific_url) {
        /* if there is a specific url, check it regardless of zone. */
        rx_match = ngx_http_naxsi_pcre_wrapper(
          custloc_array(p->br->custom_locations->elts)[x].target_rx, req->uri.data, req->uri.len);
        if (rx_match < 0) {
          NX_DEBUG(wl_debug_rx,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "[URI] FAIL:%d (rx:%V, str:%V)",
                   rx_match,
                   &(custloc_array(p->br->custom_locations->elts)[x].target_rx->pattern),
                   &(req->uri));

          violation = 1;
          break;
        }
        NX_DEBUG(wl_debug_rx,
                 NGX_LOG_DEBUG_HTTP,
                 req->connection->log,
                 0,
                 "[URI] Match:%d (rx:%V, str:%V)",
                 rx_match,
                 &(custloc_array(p->br->custom_locations->elts)[x].target_rx->pattern),
                 &(req->uri));
      }
    }
    if (violation == 0) {
      NX_DEBUG(
        wl_debug_rx, NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "wut, rule whitelisted by rx.");

      if (nx_check_ids(r->rule_id, p->wlid_array) == 1)
        return (1);
    } else {
      NX_DEBUG(wl_debug_rx, NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "not good ----");
    }
  }
  return (0);
}

int
ngx_http_naxsi_is_rule_whitelisted_n(ngx_http_request_t*        req,
                                     ngx_http_naxsi_loc_conf_t* cf,
                                     ngx_http_rule_t*           r,
                                     ngx_str_t*                 name,
                                     naxsi_match_zone_t         zone,
                                     ngx_int_t                  target_name)
{
  ngx_int_t                  k;
  ngx_http_whitelist_rule_t* b = NULL;
  unsigned int               i;
  ngx_http_rule_t**          dr;
  ngx_str_t                  tmp_hashname;
  ngx_str_t                  nullname = ngx_null_string;

  /* if name is NULL, replace it by an empty string */
  if (!name)
    name = &nullname;

  NX_DEBUG(_debug_whitelist_compat,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "is rule [%d] whitelisted in zone %s for item %V",
           r->rule_id,
           zone == ARGS
             ? "ARGS"
             : zone == HEADERS
                 ? "HEADERS"
                 : zone == BODY
                     ? "BODY"
                     : zone == URL ? "URL"
                                   : zone == FILE_EXT ? "FILE_EXT"
                                                      : zone == RAW_BODY ? "RAW_BODY" : "UNKNOWN",
           name);
  if (target_name)
    NX_DEBUG(_debug_whitelist_compat,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "extra: exception happened in |NAME");
  tmp_hashname.data = NULL;

  /* Check if the rule is part of disabled rules for this location */
  if (cf->disabled_rules) {
    dr = cf->disabled_rules->elts;
    for (i = 0; i < cf->disabled_rules->nelts; i++) {

      /* Is rule disabled ? */
      if (nx_check_ids(r->rule_id, dr[i]->wlid_array)) {

        NX_DEBUG(_debug_whitelist_compat,
                 NGX_LOG_DEBUG_HTTP,
                 req->connection->log,
                 0,
                 "rule %d is disabled somewhere",
                 r->rule_id);
        /* if it doesn't specify zone, skip zone-check */
        if (!dr[i]->br) {
          NX_DEBUG(_debug_whitelist_compat,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "no zone, skip zone-check");
          continue;
        }

        /* If rule target nothing, it's whitelisted everywhere */
        if (!(dr[i]->br->args || dr[i]->br->headers || dr[i]->br->body || dr[i]->br->url)) {
          NX_DEBUG(_debug_whitelist_compat,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "rule %d is fully disabled",
                   r->rule_id);
          return (1);
        }

        /* if exc is in name, but rule is not specificaly disabled for name (and
         * targets a zone)  */
        if (target_name != dr[i]->br->target_name)
          continue;

        switch (zone) {
          case ARGS:
            if (dr[i]->br->args) {
              NX_DEBUG(_debug_whitelist_compat,
                       NGX_LOG_DEBUG_HTTP,
                       req->connection->log,
                       0,
                       "rule %d is disabled in ARGS",
                       r->rule_id);
              return (1);
            }
            break;
          case HEADERS:
            if (dr[i]->br->headers) {
              NX_DEBUG(_debug_whitelist_compat,
                       NGX_LOG_DEBUG_HTTP,
                       req->connection->log,
                       0,
                       "rule %d is disabled in HEADERS",
                       r->rule_id);
              return (1);
            }
            break;
          case BODY:
            if (dr[i]->br->body) {
              NX_DEBUG(_debug_whitelist_compat,
                       NGX_LOG_DEBUG_HTTP,
                       req->connection->log,
                       0,
                       "rule %d is disabled in BODY",
                       r->rule_id);
              return (1);
            }
            break;
          case RAW_BODY:
            if (dr[i]->br->body) {
              NX_DEBUG(_debug_whitelist_compat,
                       NGX_LOG_DEBUG_HTTP,
                       req->connection->log,
                       0,
                       "rule %d is disabled in BODY",
                       r->rule_id);
              return (1);
            }
            break;
          case FILE_EXT:
            if (dr[i]->br->file_ext) {
              NX_DEBUG(_debug_whitelist_compat,
                       NGX_LOG_DEBUG_HTTP,
                       req->connection->log,
                       0,
                       "rule %d is disabled in FILE_EXT",
                       r->rule_id);
              return (1);
            }
            break;
          case URL:
            if (dr[i]->br->url) {
              NX_DEBUG(_debug_whitelist_compat,
                       NGX_LOG_DEBUG_HTTP,
                       req->connection->log,
                       0,
                       "rule %d is disabled in URL zone:%d",
                       r->rule_id,
                       zone);
              return (1);
            }
            break;
          default:
            break;
        }
      }
    }
  }
  NX_DEBUG(_debug_whitelist_compat,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "hashing varname [%V]",
           name);
  /*
  ** check for ARGS_VAR:x(|NAME) whitelists.
  ** (name) or (#name)
  */
  if (name->len > 0) {
    NX_DEBUG(_debug_whitelist_compat,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "hashing varname [%V] (rule:%d) - 'wl:X_VAR:%V'",
             name,
             r->rule_id,
             name);
    /* try to find in hashtables */
    b = nx_find_wl_in_hash(req, name, cf, zone);
    if (b && ngx_http_naxsi_is_whitelist_adapted(b, name, zone, r, req, NAME_ONLY, target_name))
      return (1);
    /*prefix hash with '#', to find whitelists that would be done only on
     * ARGS_VAR:X|NAME */
    tmp_hashname.len = name->len + 1;
    /* too bad we have to realloc just to add the '#' */
    tmp_hashname.data    = ngx_pcalloc(req->pool, tmp_hashname.len + 1);
    tmp_hashname.data[0] = '#';
    memcpy(tmp_hashname.data + 1, name->data, name->len);
    NX_DEBUG(_debug_whitelist_compat,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "hashing varname [%V] (rule:%d) - 'wl:X_VAR:%V|NAME'",
             name,
             r->rule_id,
             name);
    b = nx_find_wl_in_hash(req, &tmp_hashname, cf, zone);
    ngx_pfree(req->pool, tmp_hashname.data);
    tmp_hashname.data = NULL;
    if (b && ngx_http_naxsi_is_whitelist_adapted(b, name, zone, r, req, NAME_ONLY, target_name))
      return (1);
  }

  /* Plain URI whitelists */
  if (cf->wlr_url_hash && cf->wlr_url_hash->size > 0) {

    /* check the URL no matter what zone we're in */
    tmp_hashname.data = ngx_pcalloc(req->pool, req->uri.len + 1);
    /* mimic find_wl_in_hash, we are looking in a different hashtable */
    if (!tmp_hashname.data)
      return (0);
    tmp_hashname.len = req->uri.len;
    k                = ngx_hash_strlow(tmp_hashname.data, req->uri.data, req->uri.len);
    NX_DEBUG(_debug_whitelist_compat,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "hashing uri [%V] (rule:%d) 'wl:$URI:%V|*'",
             &(tmp_hashname),
             r->rule_id,
             &(tmp_hashname));

    b = (ngx_http_whitelist_rule_t*)ngx_hash_find(
      cf->wlr_url_hash, k, (u_char*)tmp_hashname.data, tmp_hashname.len);
    ngx_pfree(req->pool, tmp_hashname.data);
    tmp_hashname.data = NULL;
    if (b && ngx_http_naxsi_is_whitelist_adapted(b, name, zone, r, req, URI_ONLY, target_name))
      return (1);
  }

  /* Lookup for $URL|URL (uri)*/
  tmp_hashname.data = ngx_pcalloc(req->pool, req->uri.len + 1);
  if (!tmp_hashname.data)
    return (0);
  tmp_hashname.len = req->uri.len;
  ngx_memcpy(tmp_hashname.data, req->uri.data, req->uri.len);
  NX_DEBUG(_debug_whitelist_compat,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "hashing uri#1 [%V] (rule:%d) ($URL:X|URI)",
           &(tmp_hashname),
           r->rule_id);
  b = nx_find_wl_in_hash(req, &(tmp_hashname), cf, zone);
  ngx_pfree(req->pool, tmp_hashname.data);
  tmp_hashname.data = NULL;
  if (b && ngx_http_naxsi_is_whitelist_adapted(b, name, zone, r, req, URI_ONLY, target_name))
    return (1);

  /* Looking $URL:x|ZONE|NAME */
  tmp_hashname.data = ngx_pcalloc(req->pool, req->uri.len + 2);
  /* should make it sound crit isn't it ?*/
  if (!tmp_hashname.data)
    return (0);
  tmp_hashname.len     = req->uri.len + 1;
  tmp_hashname.data[0] = '#';
  ngx_memcpy(tmp_hashname.data + 1, req->uri.data, req->uri.len);
  NX_DEBUG(_debug_whitelist_compat,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "hashing uri#3 [%V] (rule:%d) ($URL:X|ZONE|NAME)",
           &(tmp_hashname),
           r->rule_id);
  b = nx_find_wl_in_hash(req, &(tmp_hashname), cf, zone);
  ngx_pfree(req->pool, tmp_hashname.data);
  tmp_hashname.data = NULL;
  if (b && ngx_http_naxsi_is_whitelist_adapted(b, name, zone, r, req, URI_ONLY, target_name))
    return (1);

  /* Maybe it was $URL+$VAR (uri#name) or (#uri#name) */
  tmp_hashname.len = req->uri.len + 1 + name->len;
  /* one extra byte for target_name '#' */
  tmp_hashname.data = ngx_pcalloc(req->pool, tmp_hashname.len + 2);
  if (target_name) {
    tmp_hashname.len++;
    strcat((char*)tmp_hashname.data, "#");
  }
  strncat((char*)tmp_hashname.data, (char*)req->uri.data, req->uri.len);
  strcat((char*)tmp_hashname.data, "#");
  strncat((char*)tmp_hashname.data, (char*)name->data, name->len);

  NX_DEBUG(_debug_whitelist_compat,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "hashing MIX [%V] ($URL:x|$X_VAR:y) or ($URL:x|$X_VAR:y|NAME)",
           &tmp_hashname);
  b = nx_find_wl_in_hash(req, &(tmp_hashname), cf, zone);
  ngx_pfree(req->pool, tmp_hashname.data);

  if (b && ngx_http_naxsi_is_whitelist_adapted(b, name, zone, r, req, MIXED, target_name))
    return (1);

  /*
  ** Look it up in regexed whitelists for matchzones
  */
  if (ngx_http_naxsi_is_rule_whitelisted_rx(req, cf, r, name, zone, target_name) == 1) {
    NX_DEBUG(wl_debug_rx, NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "Whitelisted by RX !");

    return (1);
  }

  return (0);
}

/*
** Create log lines, possibly splitted
** and linked by random numbers.
*/
#define MAX_LINE_SIZE (NGX_MAX_ERROR_STR - 100)
#define MAX_SEED_LEN  17 /*seed_start=10000*/

ngx_str_t*
ngx_http_append_log(ngx_http_request_t* r, ngx_array_t* ostr, ngx_str_t* fragment, u_int* offset)
{
  u_int        seed, sub;
  static u_int prev_seed = 0;

  /*
  ** avoid random collisions, as we % 1000 them,
  ** this is very likely to happen !
  */

  /*
  ** extra space has been reserved to append the seed.
  */
  while ((seed = random() % 1000) == prev_seed)
    ;
  sub           = snprintf((char*)(fragment->data + *offset), MAX_SEED_LEN, "&seed_start=%d", seed);
  fragment->len = *offset + sub;
  fragment      = ngx_array_push(ostr);
  if (!fragment)
    return (NULL);
  fragment->data = ngx_pcalloc(r->pool, MAX_LINE_SIZE + 1);
  if (!fragment->data)
    return (NULL);
  sub       = snprintf((char*)fragment->data, MAX_SEED_LEN, "seed_end=%d", seed);
  prev_seed = seed;
  *offset   = sub;
  return (fragment);
}

ngx_int_t
ngx_http_nx_log(ngx_http_request_ctx_t* ctx,
                ngx_http_request_t*     r,
                ngx_array_t*            ostr,
                ngx_str_t**             ret_uri)
{
  u_int                     sz_left, sub, offset = 0, i;
  ngx_str_t *               fragment, *tmp_uri;
  ngx_http_special_score_t* sc;
  const char*               fmt_base = "ip=%.*s&server=%.*s&uri=%.*s&vers=%.*s&total_"
                         "processed=%zu&total_blocked=%zu&config=%.*s";
  const char* fmt_score  = "&cscore%d=%.*s&score%d=%zu";
  const char* fmt_rm     = "&zone%d=%s&id%d=%d&var_name%d=%.*s";
  const char* fmt_config = "";

  if (ctx->learning) {
    fmt_config = ctx->drop ? "learning-drop" : "learning";
  } else if (ctx->drop) {
    fmt_config = "drop";
  } else if (ctx->block) {
    fmt_config = "block";
  } else if (ctx->ignore) {
    fmt_config = "ignore";
  }

  ngx_http_naxsi_loc_conf_t* cf;
  ngx_http_matched_rule_t*   mr;
  char                       tmp_zone[30];

  cf = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);

  tmp_uri = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
  if (!tmp_uri)
    return (NGX_ERROR);
  *ret_uri = tmp_uri;

  if (r->uri.len >= (NGX_MAX_UINT32_VALUE / 4) - 1) {
    r->uri.len /= 4;
  }

  tmp_uri->len  = r->uri.len + (2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len, NGX_ESCAPE_ARGS));
  tmp_uri->data = ngx_pcalloc(r->pool, tmp_uri->len + 1);
  ngx_escape_uri(tmp_uri->data, r->uri.data, r->uri.len, NGX_ESCAPE_ARGS);

  fragment = ngx_array_push(ostr);
  if (!fragment)
    return (NGX_ERROR);
  fragment->data = ngx_pcalloc(r->pool, MAX_LINE_SIZE + 1);
  if (!fragment->data)
    return (NGX_ERROR);
  sub = offset = 0;
  /* we keep extra space for seed*/
  sz_left = MAX_LINE_SIZE - MAX_SEED_LEN - 1;

  /*
  ** don't handle uri > 4k, string will be split
  */

  sub = snprintf((char*)fragment->data,
                 sz_left,
                 fmt_base,
                 r->connection->addr_text.len,
                 r->connection->addr_text.data,
                 r->headers_in.server.len,
                 r->headers_in.server.data,
                 tmp_uri->len,
                 tmp_uri->data,
                 strlen(NAXSI_VERSION),
                 NAXSI_VERSION,
                 cf->request_processed,
                 cf->request_blocked,
                 strlen(fmt_config),
                 fmt_config);

  if (sub >= sz_left)
    sub = sz_left - 1;
  sz_left -= sub;
  offset += sub;
  /*
  ** if URI exceeds the MAX_LINE_SIZE, log directly, avoid null deref (#178)
  */
  if (sz_left < 100) {
    fragment = ngx_http_append_log(r, ostr, fragment, &offset);
    if (!fragment)
      return (NGX_ERROR);
    sz_left = MAX_LINE_SIZE - MAX_SEED_LEN - offset - 1;
  }

  /*
  ** append scores
  */
  for (i = 0; ctx->special_scores && i < ctx->special_scores->nelts; i++) {
    sc = ctx->special_scores->elts;
    if (sc[i].sc_score != 0) {
      sub = snprintf(0, 0, fmt_score, i, sc[i].sc_tag->len, sc[i].sc_tag->data, i, sc[i].sc_score);
      if (sub >= sz_left) {
        /*
        ** ngx_http_append_log will add seed_start and seed_end, and adjust the
        *offset.
        */
        fragment = ngx_http_append_log(r, ostr, fragment, &offset);
        if (!fragment)
          return (NGX_ERROR);
        sz_left = MAX_LINE_SIZE - MAX_SEED_LEN - offset - 1;
      }
      sub = snprintf((char*)(fragment->data + offset),
                     sz_left,
                     fmt_score,
                     i,
                     sc[i].sc_tag->len,
                     sc[i].sc_tag->data,
                     i,
                     sc[i].sc_score);
      if (sub >= sz_left)
        sub = sz_left - 1;
      offset += sub;
      sz_left -= sub;
    }
  }
  /*
  ** and matched zone/id/name
  */
  if (ctx->matched) {
    mr  = ctx->matched->elts;
    sub = 0;
    i   = 0;
    do {
      memset(tmp_zone, 0, sizeof(tmp_zone));
      if (mr[i].body_var)
        strcat(tmp_zone, "BODY");
      else if (mr[i].args_var)
        strcat(tmp_zone, "ARGS");
      else if (mr[i].headers_var)
        strcat(tmp_zone, "HEADERS");
      else if (mr[i].url)
        strcat(tmp_zone, "URL");
      else if (mr[i].file_ext)
        strcat(tmp_zone, "FILE_EXT");
      if (mr[i].target_name)
        strcat(tmp_zone, "|NAME");

      ngx_str_t tmp_val;

      if (mr[i].name->len >= (NGX_MAX_UINT32_VALUE / 4) - 1) {
        mr[i].name->len /= 4;
      }

      tmp_val.len =
        mr[i].name->len +
        (2 * ngx_escape_uri(NULL, mr[i].name->data, mr[i].name->len, NGX_ESCAPE_URI_COMPONENT));

      tmp_val.data = ngx_pcalloc(r->pool, tmp_val.len + 1);
      ngx_escape_uri(tmp_val.data, mr[i].name->data, mr[i].name->len, NGX_ESCAPE_URI_COMPONENT);

      sub =
        snprintf(0, 0, fmt_rm, i, tmp_zone, i, mr[i].rule->rule_id, i, tmp_val.len, tmp_val.data);
      /*
      ** This one would not fit :
      ** append a seed to the current fragment,
      ** and start a new one
      */
      if (sub >= sz_left) {
        fragment = ngx_http_append_log(r, ostr, fragment, &offset);
        if (!fragment)
          return (NGX_ERROR);
        sz_left = MAX_LINE_SIZE - MAX_SEED_LEN - offset - 1;
      }
      sub = snprintf((char*)fragment->data + offset,
                     sz_left,
                     fmt_rm,
                     i,
                     tmp_zone,
                     i,
                     mr[i].rule->rule_id,
                     i,
                     tmp_val.len,
                     tmp_val.data);
      if (sub >= sz_left)
        sub = sz_left - 1;
      offset += sub;
      sz_left -= sub;
      i += 1;
    } while (i < ctx->matched->nelts);
  }
  fragment->len = offset;
  return (NGX_HTTP_OK);
}

char*
replace_str(const char* s, const char* oldW, const char* newW)
{
  char* result;
  int   i, cnt = 0;
  int   newWlen = strlen(newW);
  int   oldWlen = strlen(oldW);

  // Counting the number of times old word
  // occur in the string
  for (i = 0; s[i] != '\0'; i++) {
    if (strstr(&s[i], oldW) == &s[i]) {
      cnt++;
      // Jumping to index after the old word.
      i += oldWlen - 1;
    }
  }

  // Making new string of enough length
  result = (char*)malloc(i + cnt * (newWlen - oldWlen) + 1);

  if (!result)
    return 0;

  i = 0;
  while (*s) {
    // compare the substring with the result
    if (strstr(s, oldW) == s) {
      strcpy(&result[i], newW);
      i += newWlen;
      s += oldWlen;
    } else {
      result[i++] = *s++;
    }
  }

  result[i] = '\0';
  return result;
}

ngx_int_t
ngx_http_output_forbidden_page(ngx_http_request_ctx_t* ctx, ngx_http_request_t* r)
{
  ngx_str_t *                tmp_uri, denied_args;
  ngx_str_t                  empty = ngx_string("");
  ngx_http_naxsi_loc_conf_t* cf;
  ngx_array_t*               ostr;
  ngx_table_elt_t*           h;
  unsigned int               i = 0;

  cf = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
  /* get array of signatures strings */
  ostr = ngx_array_create(r->pool, 1, sizeof(ngx_str_t));
  if (ngx_http_nx_log(ctx, r, ostr, &tmp_uri) != NGX_HTTP_OK)
    return (NGX_ERROR);

  if (!ctx->json_log) {
    for (i = 0; i < ostr->nelts; i++) {
      ngx_log_error(
        NGX_LOG_ERR, cf->log ? cf->log : r->connection->log, 0, "NAXSI_FMT: %s", ((ngx_str_t*)ostr->elts)[i].data);
    }
  } else {
    const char* hex  = "0123456789abcdef";
    ngx_str_t*  elts = (ngx_str_t*)ostr->elts;
    for (i = 0; i < ostr->nelts; i++) {
      char json[NGX_MAX_ERROR_STR - 100] = { 0 };
      // line only
      const char* line = (const char*)elts[i].data;
      char*       curr = json + 2;
      char*       end  = (curr + sizeof(json)) - 4;

      json[0] = '{';
      json[1] = '"';

      size_t i;
      for (i = 0; line[i] && curr < end; i++) {
        if (line[i] == '=') {
          *curr = '"';
          curr++;
          break_if(curr >= end);
          *curr = ':';
          curr++;
          break_if(curr >= end);
          *curr = '"';
        } else if (line[i] == '&') {
          *curr = '"';
          curr++;
          break_if(curr >= end);
          *curr = ',';
          curr++;
          break_if(curr >= end);
          *curr = '"';
        } else if (line[i] == '"' || line[i] == '\\' /* || line[i] == '/'*/) {
          *curr = '\\';
          curr++;
          break_if(curr >= end);
          *curr = line[i];
        } else if (line[i] == '\b') {
          *curr = '\\';
          curr++;
          break_if(curr >= end);
          *curr = 'b';
        } else if (line[i] == '\f') {
          *curr = '\\';
          curr++;
          break_if(curr >= end);
          *curr = 'f';
        } else if (line[i] == '\n') {
          *curr = '\\';
          curr++;
          break_if(curr >= end);
          *curr = 'n';
        } else if (line[i] == '\r') {
          *curr = '\\';
          curr++;
          break_if(curr >= end);
          *curr = 'r';
        } else if (line[i] == '\t') {
          *curr = '\\';
          curr++;
          break_if(curr >= end);
          *curr = 't';
        } else if (is_printable(line[i])) {
          *curr = line[i];
        } else {
          *curr = '\\';
          curr++;
          break_if(curr >= end);
          *curr = 'u';
          curr++;
          break_if(curr >= end);
          *curr = '0';
          curr++;
          break_if(curr >= end);
          *curr = '0';
          curr++;
          break_if(curr >= end);
          *curr = hex[line[i] >> 8];
          curr++;
          break_if(curr >= end);
          *curr = hex[line[i] & 0x0F];
        }
        curr++;
      }

      if (curr >= end) {
        ngx_log_error(NGX_LOG_ERR,
                      r->connection->log,
                      0,
                      "cannot generate json structure due NGX_MAX_ERROR_STR size.");
        continue;
      }

      *curr = '"';
      curr++;
      *curr = '}';
      curr++;
      *curr = 0;

      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", json);
    }
  }

  if (ostr->nelts >= 1) {
    denied_args.data = ((ngx_str_t*)ostr->elts)[0].data;
    denied_args.len  = ((ngx_str_t*)ostr->elts)[0].len;
  } else {
    denied_args.data = empty.data;
    denied_args.len  = empty.len;
  }

  /*
  ** If we shouldn't block the request,
  ** but a log score was reached, stop.
  */
  if (ctx->log && (!ctx->block && !ctx->drop)) {
    return (NGX_DECLINED);
  }

  /*
  ** If we are in learning without post_action and without drop
  ** stop here as well.
  */
  if (ctx->learning && !ctx->post_action && !ctx->drop) {
    return (NGX_DECLINED);
  }
  /*
  ** add headers with original url
  ** and arguments, as well as
  ** the first fragment of log
  */

#define NAXSI_HEADER_ORIG_URL  "x-orig_url"
#define NAXSI_HEADER_ORIG_ARGS "x-orig_args"
#define NAXSI_HEADER_NAXSI_SIG "x-naxsi_sig"

  if (r->headers_in.headers.last) {

    h = ngx_list_push(&(r->headers_in.headers));
    if (!h)
      return (NGX_ERROR);
    h->key.len  = strlen(NAXSI_HEADER_ORIG_URL);
    h->key.data = ngx_pcalloc(r->pool, strlen(NAXSI_HEADER_ORIG_URL) + 1);
    if (!h->key.data)
      return (NGX_ERROR);
    memcpy(h->key.data, NAXSI_HEADER_ORIG_URL, strlen(NAXSI_HEADER_ORIG_URL));
    h->lowcase_key = ngx_pcalloc(r->pool, strlen(NAXSI_HEADER_ORIG_URL) + 1);
    memcpy(h->lowcase_key, NAXSI_HEADER_ORIG_URL, strlen(NAXSI_HEADER_ORIG_URL));
    h->value.len  = tmp_uri->len;
    h->value.data = ngx_pcalloc(r->pool, tmp_uri->len + 1);
    memcpy(h->value.data, tmp_uri->data, tmp_uri->len);

    h = ngx_list_push(&(r->headers_in.headers));
    if (!h)
      return (NGX_ERROR);
    h->key.len  = strlen(NAXSI_HEADER_ORIG_ARGS);
    h->key.data = ngx_pcalloc(r->pool, strlen(NAXSI_HEADER_ORIG_ARGS) + 1);
    if (!h->key.data)
      return (NGX_ERROR);
    memcpy(h->key.data, NAXSI_HEADER_ORIG_ARGS, strlen(NAXSI_HEADER_ORIG_ARGS));
    h->lowcase_key = ngx_pcalloc(r->pool, strlen(NAXSI_HEADER_ORIG_ARGS) + 1);
    memcpy(h->lowcase_key, NAXSI_HEADER_ORIG_ARGS, strlen(NAXSI_HEADER_ORIG_ARGS));
    h->value.len  = r->args.len;
    h->value.data = ngx_pcalloc(r->pool, r->args.len + 1);
    memcpy(h->value.data, r->args.data, r->args.len);

    h = ngx_list_push(&(r->headers_in.headers));
    if (!h)
      return (NGX_ERROR);
    h->key.len  = strlen(NAXSI_HEADER_NAXSI_SIG);
    h->key.data = ngx_pcalloc(r->pool, strlen(NAXSI_HEADER_NAXSI_SIG) + 1);
    if (!h->key.data)
      return (NGX_ERROR);
    memcpy(h->key.data, NAXSI_HEADER_NAXSI_SIG, strlen(NAXSI_HEADER_NAXSI_SIG));
    h->lowcase_key = ngx_pcalloc(r->pool, strlen(NAXSI_HEADER_NAXSI_SIG) + 1);
    memcpy(h->lowcase_key, NAXSI_HEADER_NAXSI_SIG, strlen(NAXSI_HEADER_NAXSI_SIG));
    h->value.len  = denied_args.len;
    h->value.data = denied_args.data;
  }

  if (ctx->learning && !ctx->drop) {
    if (ctx->post_action) {
      ngx_http_core_loc_conf_t* clcf;
      clcf                   = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
      clcf->post_action.data = cf->denied_url->data;
      clcf->post_action.len  = cf->denied_url->len;
    }
    return (NGX_DECLINED);
  } else {
    ngx_http_internal_redirect(r, cf->denied_url, &empty);
    return (NGX_HTTP_OK);
  }
  return (NGX_ERROR);
}

/*
** new rulematch, less arguments ^
*/
int
ngx_http_apply_rulematch_v_n(ngx_http_rule_t*        r,
                             ngx_http_request_ctx_t* ctx,
                             ngx_http_request_t*     req,
                             ngx_str_t*              name,
                             ngx_str_t*              value,
                             naxsi_match_zone_t      zone,
                             ngx_int_t               nb_match,
                             ngx_int_t               target_name)
{
  unsigned int               found = 0, i, z;
  ngx_http_special_score_t * sc, *rsc;
  ngx_http_naxsi_loc_conf_t* cf;
  ngx_http_matched_rule_t*   mr;
  ngx_str_t                  empty = ngx_string("");

  if (!name) {
    name = &empty;
  }
  if (!value) {
    value = &empty;
  }

  cf = ngx_http_get_module_loc_conf(req, ngx_http_naxsi_module);
  if (!cf || !ctx)
    return (0);
  if (ngx_http_naxsi_is_rule_whitelisted_n(req, cf, r, name, zone, target_name) == 1) {

    NX_DEBUG(
      _debug_whitelist_light, NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "rule is whitelisted.");

    return (0);
  }
  NX_DEBUG(_debug_extensive_log,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "Current extensive log value: %d",
           ctx->extensive_log);

  if (ctx->extensive_log) {
    if (target_name)
      naxsi_log_offending(value, name, req, r, zone, target_name);
    else
      naxsi_log_offending(name, value, req, r, zone, target_name);
  }
  if (nb_match == 0)
    nb_match = 1;
  if (!ctx->matched)
    ctx->matched = ngx_array_create(req->pool, 2, sizeof(ngx_http_matched_rule_t));
  /* log stuff, cause this case sux */
  if (!ctx->matched)
    return (0);
  mr = ngx_array_push(ctx->matched);
  if (!mr)
    return (0);
  memset(mr, 0, sizeof(ngx_http_matched_rule_t));
  if (target_name)
    mr->target_name = 1;
  switch (zone) {
    case HEADERS:
      mr->headers_var = 1;
      break;
    case URL:
      mr->url = 1;
      break;
    case ARGS:
      mr->args_var = 1;
      break;
    case BODY:
      mr->body_var = 1;
      break;
    case FILE_EXT:
      mr->file_ext = 1;
      break;
    default:
      break;
  };
  mr->rule = r;
  // the current "name" ptr will be free by caller, so make a copy
  mr->name = ngx_pcalloc(req->pool, sizeof(ngx_str_t));
  if (name->len > 0) {
    mr->name->data = ngx_pcalloc(req->pool, name->len + 1);
    memcpy(mr->name->data, name->data, name->len);
    mr->name->len = name->len;
  } else {
    mr->name->data = NULL;
    mr->name->len  = 0;
  }
  /* apply special score on rulematch */
  if (r->sscores) {
    NX_DEBUG(_debug_whitelist,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "Rule applies %d custom scores",
             r->sscores->nelts);

    if (!ctx->special_scores) // create the list
      ctx->special_scores = ngx_array_create(req->pool, 1, sizeof(ngx_http_special_score_t));
    rsc = r->sscores->elts;
    for (z = 0; z < r->sscores->nelts; z++) {
      // search into the list for matching special score
      found = 0;
      sc    = ctx->special_scores->elts;
      for (i = 0; i < ctx->special_scores->nelts; i++) {
        if (rsc[z].sc_tag && sc[i].sc_tag && sc[i].sc_tag->len == rsc[z].sc_tag->len &&
            !ngx_strcmp(sc[i].sc_tag->data, rsc[z].sc_tag->data)) {
          NX_DEBUG(_debug_whitelist,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "Special Score (%V) actual=%d,next=%d",
                   rsc[z].sc_tag,
                   sc[i].sc_score,
                   sc[i].sc_score + (rsc[z].sc_score * nb_match));

          sc[i].sc_score += (rsc[z].sc_score * nb_match);
          found = 1;
          break;
        }
      }

      if (!found) {
        NX_DEBUG(_debug_whitelist,
                 NGX_LOG_DEBUG_HTTP,
                 req->connection->log,
                 0,
                 "Special Score (%V)  next=%d",
                 rsc[z].sc_tag,
                 (rsc[z].sc_score * nb_match));

        sc = ngx_array_push(ctx->special_scores);
        if (!sc)
          return (0);
        memset(sc, 0, sizeof(ngx_http_special_score_t));
        sc->sc_tag   = rsc[z].sc_tag;
        sc->sc_score = (rsc[z].sc_score * nb_match);
      }
    }
  }
  /* else, apply normal score */
  ctx->score += (r->score * nb_match);
  if (r->block)
    ctx->block = 1;
  if (r->allow)
    ctx->allow = 1;
  if (r->drop)
    ctx->drop = 1;
  if (r->log)
    ctx->log = 1;
  ngx_http_naxsi_update_current_ctx_status(ctx, cf, req, name, value);
  return (1);
}

/*
** does : this functions receives an string in the form [foo=bar&bla=foo..]
**    it splits the string into varname/value couples, and then pass
**    this couple along with valid rules to checking func.
** WARN/TODO : Even I tried to make my code bof proof, this should be seriously
*audited :)
*/
int
ngx_http_spliturl_ruleset(ngx_pool_t*             pool,
                          ngx_str_t*              nx_str,
                          ngx_array_t*            rules,
                          ngx_array_t*            main_rules,
                          ngx_http_request_t*     req,
                          ngx_http_request_ctx_t* ctx,
                          naxsi_match_zone_t      zone)
{
  ngx_str_t name, val;
  char *    eq, *ev, *orig, *str;
  int       len, full_len;
  int       nullbytes = 0;

  if (naxsi_escape_nullbytes(nx_str) > 0) {
    ngx_str_t dummy;
    dummy.data = NULL;
    dummy.len  = 0;
    ngx_http_apply_rulematch_v_n(
      &nx_int__uncommon_hex_encoding, ctx, req, &dummy, &dummy, zone, 1, 0);
  }
  str = (char*)nx_str->data;

  NX_DEBUG(_debug_spliturl_ruleset,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "XX-check url-like [%s]",
           str);

  orig     = str;
  full_len = strlen(orig);
  while (str < (orig + full_len) && *str) {
    if (*str == '&') {
      str++;
      continue;
    }
    if ((ctx->block && !ctx->learning) || ctx->drop)
      return (0);
    eq = strchr(str, '=');
    ev = strchr(str, '&');

    if ((!eq && !ev) /*?foobar */ || (eq && ev && eq > ev)) /*?foobar&bla=test*/ {
      NX_DEBUG(_debug_spliturl_ruleset,
               NGX_LOG_DEBUG_HTTP,
               req->connection->log,
               0,
               "XX-url has no '&' and '=' or has both [%s]",
               str);

      if (!ev)
        ev = str + strlen(str);
      /* len is now [name] */
      len       = ev - str;
      val.data  = (unsigned char*)str;
      val.len   = ev - str;
      name.data = (unsigned char*)NULL;
      name.len  = 0;
    }
    /* ?&&val | ?var&& | ?val& | ?&val | ?val&var */
    else if (!eq && ev) {
      NX_DEBUG(_debug_spliturl_ruleset,
               NGX_LOG_DEBUG_HTTP,
               req->connection->log,
               0,
               "XX-url has no '=' but has '&' [%s]",
               str);

      ngx_http_apply_rulematch_v_n(&nx_int__uncommon_url, ctx, req, NULL, NULL, zone, 1, 0);
      if (ev > str) /* ?var& | ?var&val */ {
        val.data  = (unsigned char*)str;
        val.len   = ev - str;
        name.data = (unsigned char*)NULL;
        name.len  = 0;
        len       = ev - str;
      } else /* ?& | ?&&val */ {
        val.data = name.data = NULL;
        val.len = name.len = 0;
        len                = 1;
      }
    } else /* should be normal like ?var=bar& ..*/ {
      NX_DEBUG(_debug_spliturl_ruleset,
               NGX_LOG_DEBUG_HTTP,
               req->connection->log,
               0,
               "XX-Classic format url [%s]",
               str);

      if (!ev) /* ?bar=lol */
        ev = str + strlen(str);
      /* len is now [name]=[content] */
      len = ev - str;
      eq  = strnchr(str, '=', len);
      if (!eq) {
        if (ngx_http_apply_rulematch_v_n(&nx_int__uncommon_url, ctx, req, NULL, NULL, zone, 1, 0)) {
          naxsi_error_fatal(ctx, req, "malformed url, possible attack [%s]", str);
        }
        return (1);
      }
      eq++;
      val.data  = (unsigned char*)eq;
      val.len   = ev - eq;
      name.data = (unsigned char*)str;
      name.len  = eq - str - 1;
    }
    if (name.len) {
      nullbytes = naxsi_unescape(&name);
      if (nullbytes > 0) {
        ngx_http_apply_rulematch_v_n(
          &nx_int__uncommon_hex_encoding, ctx, req, &name, &val, zone, 1, 1);
      }
    }
    if (val.len) {
      nullbytes = naxsi_unescape(&val);
      if (nullbytes > 0) {
        ngx_http_apply_rulematch_v_n(
          &nx_int__uncommon_hex_encoding, ctx, req, &name, &val, zone, 1, 0);
      }
    }
    NX_DEBUG(_debug_spliturl_ruleset,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "XX-extract  [%V]=[%V]",
             &(name),
             &(val));

    if (rules)
      ngx_http_basestr_ruleset_n(pool, &name, &val, rules, req, ctx, zone);
    else
      NX_DEBUG(
        _debug_spliturl_ruleset, NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "XX-no arg rules ?");

    if (main_rules)
      ngx_http_basestr_ruleset_n(pool, &name, &val, main_rules, req, ctx, zone);
    else
      NX_DEBUG(
        _debug_spliturl_ruleset, NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "XX-no main rules ?");

    str += len;
  }

  return (0);
}

/*
** check variable + name against a set of rules, checking against 'custom'
*location rules too.
*/

void
ngx_http_libinjection(ngx_pool_t*             pool,
                      ngx_str_t*              name,
                      ngx_str_t*              value,
                      ngx_http_request_ctx_t* ctx,
                      ngx_http_request_t*     req,
                      naxsi_match_zone_t      zone)
{
  /*
  ** Libinjection integration :
  ** 1 - check if libinjection_sql is explicitly enabled
  ** 2 - check if libinjection_xss is explicitly enabled
  ** if 1 is true : perform check on both name and content,
  **        in case of match, apply internal rule
  **        increasing the LIBINJECTION_SQL score
  ** if 2 is true ; same as for '1' but with
  **        LIBINJECTION_XSS
  */
  sfilter state;
  int     issqli;

  if (ctx->libinjection_sql) {

    /* hardcoded call to libinjection on NAME, apply internal rule if matched.
     */
    libinjection_sqli_init(&state, (const char*)name->data, name->len, FLAG_NONE);
    issqli = libinjection_is_sqli(&state);
    if (issqli == 1) {
      ngx_http_apply_rulematch_v_n(nx_int__libinject_sql, ctx, req, name, value, zone, 1, 1);
    }

    /* hardcoded call to libinjection on CONTENT, apply internal rule if
     * matched. */
    libinjection_sqli_init(&state, (const char*)value->data, value->len, FLAG_NONE);
    issqli = libinjection_is_sqli(&state);
    if (issqli == 1) {
      ngx_http_apply_rulematch_v_n(nx_int__libinject_sql, ctx, req, name, value, zone, 1, 0);
    }
  }

  if (ctx->libinjection_xss) {
    /* first on var_name */
    issqli = libinjection_xss((const char*)name->data, name->len);
    if (issqli == 1) {
      ngx_http_apply_rulematch_v_n(nx_int__libinject_xss, ctx, req, name, value, zone, 1, 1);
    }

    /* hardcoded call to libinjection on CONTENT, apply internal rule if
     * matched. */
    issqli = libinjection_xss((const char*)value->data, value->len);
    if (issqli == 1) {
      ngx_http_apply_rulematch_v_n(nx_int__libinject_xss, ctx, req, name, value, zone, 1, 0);
    }
  }
}

int
ngx_http_basestr_ruleset_n(ngx_pool_t*             pool,
                           ngx_str_t*              name,
                           ngx_str_t*              value,
                           ngx_array_t*            rules,
                           ngx_http_request_t*     req,
                           ngx_http_request_ctx_t* ctx,
                           naxsi_match_zone_t      zone)
{
  ngx_http_rule_t*                 r;
  unsigned int                     i, ret, z, uri_constraint_ok = 1, rule_matched = 0;
  ngx_int_t                        nb_match = 0;
  ngx_http_custom_rule_location_t* location;

  naxsi_escape_nullbytes(value);

  NX_DEBUG(_debug_basestr_ruleset,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "XX- check check [%V]=[%V] in zone %s",
           name,
           value,
           zone == BODY
             ? "BODY"
             : zone == HEADERS
                 ? "HEADERS"
                 : zone == URL
                     ? "URL"
                     : zone == ARGS ? "ARGS"
                                    : zone == FILE_EXT ? "FILE_EXT"
                                                       : zone == RAW_BODY ? "RAW_BODY" : "UNKNOWN");

  if (!rules) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "XX-no rules, wtf ?!");
    return (0);
  }
  r = rules->elts;
  NX_DEBUG(_debug_basestr_ruleset,
           NGX_LOG_DEBUG_HTTP,
           req->connection->log,
           0,
           "XX-checking %d rules ...",
           rules->nelts);

  /* check for overlong/surrogate utf8 encoding */
  if (ngx_utf8_check(name) != NULL) {
    ngx_http_apply_rulematch_v_n(&nx_int__bad_utf8, ctx, req, NULL, NULL, zone, 1, 1);
    return (0);
  } else if (ngx_utf8_check(value) != NULL) {
    ngx_http_apply_rulematch_v_n(&nx_int__bad_utf8, ctx, req, NULL, NULL, zone, 1, 0);
    return (0);
  }

  /* call to libinjection */
  ngx_http_libinjection(pool, name, value, ctx, req, zone);

  for (i = 0; i < rules->nelts && ((!ctx->block || ctx->learning) && !ctx->drop); i++) {
    /*properly reset counter*/
    uri_constraint_ok = 1;
    rule_matched      = 0;
    NX_DEBUG(_debug_basestr_ruleset,
             NGX_LOG_DEBUG_HTTP,
             req->connection->log,
             0,
             "XX-RULE %d : START",
             r[i].rule_id);

    /* does the rule have a custom location ? custom location means checking
     * only on a specific argument */
    if (name && r[i].br->custom_location) {
      location = r[i].br->custom_locations->elts;

      /*
      ** make a first pass, just in order to check that any
      ** $URL / $URL_X constraints are validated before checking any other
      ** parameters.
      ** Unlike other criterias (wich are treated as 'OR')
      ** this one must be valid to go forward
      */
      for (z = 0; z < r[i].br->custom_locations->nelts; z++) {

        if (location[z].specific_url) {
          /* if matchzone is a regex, ensure it matches (ie. BODY_VAR_X /
           * ARGS_VAR_X / ..) */
          if (r[i].br->rx_mz) {

            if (ngx_http_naxsi_pcre_wrapper(location[z].target_rx, req->uri.data, req->uri.len) ==
                -1) {
              uri_constraint_ok = 0;
            }
          }

          /* if it was a static string, ensure it matches (ie. BODY_VAR /
           * ARGS_VAR / ..) */
          if (!r[i].br->rx_mz) {
            if (req->uri.len != location[z].target.len ||
                strncasecmp((const char*)req->uri.data,
                            (const char*)location[z].target.data,
                            req->uri.len) != 0) {
              uri_constraint_ok = 0;
            }
          }
          break;
        }
      }

      /*
      ** if one of the custom location rule specifies an $URL/$URL_X
      ** and it was mismatched, skip the rule.
      */
      if (uri_constraint_ok == 0) {
        NX_DEBUG(_debug_basestr_ruleset,
                 NGX_LOG_DEBUG_HTTP,
                 req->connection->log,
                 0,
                 "XX URI CONSTRAINT MISMATCH, SKIP");
        continue;
      }

      /* for each custom location */
      for (z = 0; z < r[i].br->custom_locations->nelts; z++) {

        rule_matched = 0;
        /* check if zone is correct before checking names cf. issue #120 */
        if (!(zone == BODY && location[z].body_var != 0) &&
            !(zone == HEADERS && location[z].headers_var != 0) &&
            !(zone == ARGS && location[z].args_var != 0))
          continue;

        /* if matchzone is a regex, ensure it matches (ie. BODY_VAR_X /
         * ARGS_VAR_X / ..) */
        if (r[i].br->rx_mz &&
            ngx_http_naxsi_pcre_wrapper(location[z].target_rx, name->data, name->len) == -1)
          continue;

        /* if it was a static string, ensure it matches (ie. BODY_VAR / ARGS_VAR
         * / ..) */
        if ((!r[i].br->rx_mz) && (name->len != location[z].target.len ||
                                  strncasecmp((const char*)name->data,
                                              (const char*)location[z].target.data,
                                              location[z].target.len)))
          continue;

        NX_DEBUG(_debug_basestr_ruleset,
                 NGX_LOG_DEBUG_HTTP,
                 req->connection->log,
                 0,
                 "XX-[SPECIFIC] check one rule [%d] iteration %d * %d",
                 r[i].rule_id,
                 i,
                 z);

        /* match rule against var content, */
        ret = ngx_http_process_basic_rule_buffer(value, &(r[i]), &nb_match);
        if (ret == 1) {
          NX_DEBUG(_debug_basestr_ruleset,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "XX-apply rulematch [%V]=[%V] [rule=%d] (match %d times)",
                   name,
                   value,
                   r[i].rule_id,
                   nb_match);
          rule_matched = 1;
          ngx_http_apply_rulematch_v_n(&(r[i]), ctx, req, name, value, zone, nb_match, 0);
        }

        if (!r[i].br->negative) {
          /* match rule against var name, */
          ret = ngx_http_process_basic_rule_buffer(name, &(r[i]), &nb_match);
          /* if our rule matched, apply effects (score etc.) */
          if (ret == 1) {
            NX_DEBUG(_debug_basestr_ruleset,
                     NGX_LOG_DEBUG_HTTP,
                     req->connection->log,
                     0,
                     "XX-apply rulematch[in name] [%V]=[%V] [rule=%d] (match "
                     "%d times)",
                     name,
                     value,
                     r[i].rule_id,
                     nb_match);
            rule_matched = 1;
            ngx_http_apply_rulematch_v_n(&(r[i]), ctx, req, name, name, zone, nb_match, 1);
          }
        }
        if (rule_matched == 1) {
          NX_DEBUG(_debug_basestr_ruleset,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "XX-[SPECIFIC] Rule %d matched in custom_location, go to next rule",
                   r[i].rule_id);

          break;
        }
      }
    }

    /*
    ** check against the rule if the current zone is matching
    ** the zone the rule is meant to be check against
    */
    if ((zone == HEADERS && r[i].br->headers) || (zone == URL && r[i].br->url) ||
        (zone == ARGS && r[i].br->args) || (zone == BODY && r[i].br->raw_body) ||
        (zone == BODY && r[i].br->body_rule) || (zone == FILE_EXT && r[i].br->file_ext)) {

      /*
      ** If the Rule **specifically** targets name (ie. mz:BODY|NAME), only
      *check against name
      */
      if (!r[i].br->target_name) {
        NX_DEBUG(_debug_basestr_ruleset,
                 NGX_LOG_DEBUG_HTTP,
                 req->connection->log,
                 0,
                 "XX-test rulematch (value) [zone-wide]!1 [%V]=[%V] [rule =%d] "
                 "(%d times)",
                 name,
                 value,
                 r[i].rule_id,
                 nb_match);

        /* check the rule against the value*/
        ret = ngx_http_process_basic_rule_buffer(value, &(r[i]), &nb_match);
        /*if our rule matched, apply effects (score etc.)*/
        if (ret == 1) {
          NX_DEBUG(_debug_basestr_ruleset,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "XX-apply rulematch (value) [%V]=[%V] [rule=%d] (%d times)",
                   name,
                   value,
                   r[i].rule_id,
                   nb_match);

          ngx_http_apply_rulematch_v_n(&(r[i]), ctx, req, name, value, zone, nb_match, 0);
        }
      }

      if (!r[i].br->negative) {
        NX_DEBUG(_debug_basestr_ruleset,
                 NGX_LOG_DEBUG_HTTP,
                 req->connection->log,
                 0,
                 "XX-test rulematch [against-name]!1 [%V]=[%V] [rule=%d] (%d times)",
                 name,
                 value,
                 r[i].rule_id,
                 nb_match);

        /* check the rule against the name*/
        ret = ngx_http_process_basic_rule_buffer(name, &(r[i]), &nb_match);
        /*if our rule matched, apply effects (score etc.)*/
        if (ret == 1) {
          NX_DEBUG(_debug_basestr_ruleset,
                   NGX_LOG_DEBUG_HTTP,
                   req->connection->log,
                   0,
                   "XX-apply rulematch!1 [%V]=[%V] [rule=%d] (%d times)",
                   name,
                   value,
                   r[i].rule_id,
                   nb_match);

          ngx_http_apply_rulematch_v_n(&(r[i]), ctx, req, name, value, zone, nb_match, 1);
        }
      }
    }
  }
  return (0);
}

/*
** does : parse body data, a.k.a POST/PUT datas. identifies content-type,
**    and, if appropriate, boundary. then parse the stuff if multipart/for..
**    or rely on spliturl if application/x-w..
** this function sucks ! I don't parse bigger-than-body-size posts that
**     are partially stored in files, TODO ;)
*/

/*
** Parse content-disposition line.
*/
int
nx_content_disposition_parse(unsigned char*      str,
                             unsigned char*      line_end,
                             unsigned char**     fvarn_start,
                             unsigned char**     fvarn_end,
                             unsigned char**     ffilen_start,
                             unsigned char**     ffilen_end,
                             ngx_http_request_t* r)
{

  unsigned char *varn_start = NULL, *varn_end = NULL;
  unsigned char *filen_start = NULL, *filen_end = NULL;
  /* we have two cases :
  ** ---- file upload
  ** Content-Disposition: form-data; name="somename";
  *filename="NetworkManager.conf"\r\n
  ** Content-Type: application/octet-stream\r\n\r\n
  ** <DATA>
  ** ---- normal post var
  ** Content-Disposition: form-data; name="lastname"\r\n\r\n
  ** <DATA>
  */

  while (str < line_end) {
    /* rfc allow spaces and tabs inbetween */
    while (str < line_end && (*str == ' ' || *str == '\t')) {
      str++;
    }
    if (str < line_end && *str == ';') {
      str++;
    }
    while (str < line_end && (*str == ' ' || *str == '\t')) {
      str++;
    }

    if (str >= line_end) {
      break;
    }

    if (!ngx_strncmp(str, "name=\"", 6)) {
      /* we already successfully parsed a name, reject that. */
      if (varn_end || varn_start) {
        return (NGX_ERROR);
      }

      varn_end = varn_start = str + 6;
      do {
        varn_end = (unsigned char*)strnchr((const char*)varn_end, '"', line_end - varn_start);
        if (!varn_end || (varn_end && *(varn_end - 1) != '\\')) {
          break;
        }
        varn_end++;
      } while (varn_end && varn_end < line_end);

      if (!varn_end || !*varn_end) {
        return (NGX_ERROR);
      }

      str = varn_end;
      if (str < line_end + 1) {
        str++;
      } else {
        return (NGX_ERROR);
      }
      *fvarn_start = varn_start;
      *fvarn_end   = varn_end;
    } else if (!ngx_strncmp(str, "filename=\"", 10)) {
      /* we already successfully parsed a filename, reject that. */
      if (filen_end || filen_start) {
        return (NGX_ERROR);
      }
      filen_end = filen_start = str + 10;
      do {
        filen_end = (unsigned char*)strnchr((const char*)filen_end, '"', line_end - filen_start);
        if (!filen_end) {
          break;
        }
        if (filen_end && *(filen_end - 1) != '\\') {
          break;
        }
        filen_end++;
      } while (filen_end && filen_end < line_end);
      if (!filen_end) {
        return (NGX_ERROR);
      }
      str = filen_end;
      if (str < line_end + 1) {
        str++;
      } else {
        return (NGX_ERROR);
      }
      *ffilen_end   = filen_end;
      *ffilen_start = filen_start;
    } else if (str == line_end - 1) {
      break;
    } else {
      /* gargabe is present ?*/
      NX_DEBUG(_debug_post_heavy,
               NGX_LOG_DEBUG_HTTP,
               r->connection->log,
               0,
               "extra data in content-disposition ? end:%p, str:%p, diff=%d",
               line_end,
               str,
               line_end - str);

      return (NGX_ERROR);
    }
  }
  /* tssk tssk */
  if (filen_end > line_end || varn_end > line_end) {
    return (NGX_ERROR);
  }
  return (NGX_OK);
}

int
nx_content_type_parse(ngx_http_request_t* r, unsigned char** boundary, unsigned int* boundary_len)
{
  unsigned char* h;
  unsigned char* end;

  h   = r->headers_in.content_type->value.data + strlen("multipart/form-data;");
  end = r->headers_in.content_type->value.data + r->headers_in.content_type->value.len;
  /* skip potential whitespace/tabs */
  while (h < end && *h && (*h == ' ' || *h == '\t'))
    h++;
  if (strncmp((const char*)h, "boundary=", 9))
    return (NGX_ERROR);
  h += 9;
  *boundary_len = end - h;
  *boundary     = h;
  /* RFC 1867/1341 says 70 char max,
     I arbitrarily set min to 3 (yes) */
  if (*boundary_len > 70 || *boundary_len < 3)
    return (NGX_ERROR);
  return (NGX_OK);
}

void
ngx_http_naxsi_multipart_parse(ngx_http_request_ctx_t* ctx,
                               ngx_http_request_t*     r,
                               u_char*                 src,
                               u_int                   len)
{
  ngx_str_t                   final_var, final_data;
  u_char *                    boundary, *varn_start, *varn_end;
  u_char *                    filen_start, *filen_end;
  u_char *                    end, *line_end;
  u_int                       boundary_len, varn_len, varc_len, idx, nullbytes;
  ngx_http_naxsi_loc_conf_t*  cf;
  ngx_http_naxsi_main_conf_t* main_cf;

  cf      = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
  main_cf = ngx_http_get_module_main_conf(r, ngx_http_naxsi_module);

  /*extract boundary*/
  if (nx_content_type_parse(r, (unsigned char**)&boundary, &boundary_len) != NGX_OK) {
    if (boundary && boundary_len > 1)
      NX_DEBUG(_debug_post_heavy,
               NGX_LOG_DEBUG_HTTP,
               r->connection->log,
               0,
               "XX-POST boundary : (%s) : %d",
               boundary,
               boundary_len);
    ngx_http_apply_rulematch_v_n(&nx_int__uncommon_post_boundary, ctx, r, NULL, NULL, BODY, 1, 0);
    return;
  }
  NX_DEBUG(_debug_post_heavy,
           NGX_LOG_DEBUG_HTTP,
           r->connection->log,
           0,
           "XX-POST boundary : (%s) : %d",
           boundary,
           boundary_len);

  /* fetch every line starting with boundary */
  idx = 0;
  while (idx < len) {

    NX_DEBUG(_debug_post_heavy,
             NGX_LOG_DEBUG_HTTP,
             r->connection->log,
             0,
             "XX-POST data : (%s)",
             src + idx);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP,
                  r->connection->log,
                  0,
                  "Remaining Len:%d (boundary len:%d)",
                  len - idx,
                  boundary_len);

    /* if we've reached the last boundary '--' + boundary + '--' + '\r\n'$END */
    /* Authorize requests that don't have the leading \r\n */
    if (idx + boundary_len + 6 == len || idx + boundary_len + 4 == len) {
      if (ngx_strncmp(src + idx, "--", 2) || ngx_strncmp(src + idx + 2, boundary, boundary_len) ||
          ngx_strncmp(src + idx + boundary_len + 2, "--", 2)) {
        /* bad closing boundary ?*/
        ngx_http_apply_rulematch_v_n(
          &nx_int__uncommon_post_boundary, ctx, r, NULL, NULL, BODY, 1, 0);
        return;
      } else
        break;
    }

    /* --boundary\r\n : New var */
    if ((len - idx < 4 + boundary_len) || src[idx] != '-' || src[idx + 1] != '-' ||
        /* and if it's really followed by a boundary */
        ngx_strncmp(src + idx + 2, boundary, boundary_len) ||
        /* and if it's not the last boundary of the buffer */
        idx + boundary_len + 2 + 2 >= len ||
        /* and if it's followed by \r\n */
        src[idx + boundary_len + 2] != '\r' || src[idx + boundary_len + 3] != '\n') {
      /* bad boundary */
      ngx_http_apply_rulematch_v_n(&nx_int__uncommon_post_boundary, ctx, r, NULL, NULL, BODY, 1, 0);
      return;
    }
    idx += boundary_len + 4;
    /* we have two cases :
    ** ---- file upload
    ** Content-Disposition: form-data; name="somename";
    *filename="NetworkManager.conf"\r\n
    ** Content-Type: application/octet-stream\r\n\r\n
    ** <DATA>
    ** ---- normal post var
    ** Content-Disposition: form-data; name="lastname"\r\n\r\n
    ** <DATA>
    */
    /* 31 = echo -n "content-disposition: form-data;" | wc -c */
    if (ngx_strncasecmp(src + idx, (u_char*)"content-disposition: form-data;", 31)) {
      ngx_log_debug(
        NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Unknown content-type: [%s]", src + idx);
      if (ngx_http_apply_rulematch_v_n(
            &nx_int__uncommon_post_format, ctx, r, NULL, NULL, BODY, 1, 0)) {
        naxsi_error_fatal(ctx, r, "POST data : unknown content-disposition");
      }
      return;
    }
    idx += 31;
    line_end = (u_char*)ngx_strchr(src + idx, '\n');
    if (!line_end) {
      if (ngx_http_apply_rulematch_v_n(
            &nx_int__uncommon_post_format, ctx, r, NULL, NULL, BODY, 1, 0)) {
        naxsi_error_fatal(ctx, r, "POST data : malformed boundary line");
      }
      return;
    }
    /* Parse content-disposition, extract name / filename */
    varn_start = varn_end = filen_start = filen_end = NULL;
    if (nx_content_disposition_parse(
          src + idx, line_end, &varn_start, &varn_end, &filen_start, &filen_end, r) != NGX_OK) {
      ngx_http_apply_rulematch_v_n(&nx_int__uncommon_post_format, ctx, r, NULL, NULL, BODY, 1, 0);
      return;
    }
    /* var name is mandatory */
    if (!varn_start || !varn_end || varn_end <= varn_start) {
      if (ngx_http_apply_rulematch_v_n(
            &nx_int__uncommon_post_format, ctx, r, NULL, NULL, BODY, 1, 0)) {
        naxsi_error_fatal(ctx, r, "POST data : no 'name' in POST var");
      }
      return;
    }
    varn_len = varn_end - varn_start;

    /* If there is a filename, it is followed by a "content-type" line, skip it
     */
    if (filen_start && filen_end) {
      line_end = (u_char*)ngx_strchr(line_end + 1, '\n');
      if (!line_end) {
        if (ngx_http_apply_rulematch_v_n(
              &nx_int__uncommon_post_format, ctx, r, NULL, NULL, BODY, 1, 0)) {
          naxsi_error_fatal(ctx, r, "POST data : malformed filename (no content-type ?)");
        }
        return;
      }
    }
    /*
    ** now idx point to the end of the
    ** content-disposition: form-data; filename="" name=""
    */
    idx += (u_char*)line_end - (src + idx) + 1;
    if (src[idx] != '\r' || src[idx + 1] != '\n') {
      if (ngx_http_apply_rulematch_v_n(
            &nx_int__uncommon_post_format, ctx, r, NULL, NULL, BODY, 1, 0)) {
        naxsi_error_fatal(ctx, r, "POST data : malformed content-disposition line");
      }
      return;
    }
    idx += 2;
    /* seek the end of the data */
    end = NULL;
    while (idx < len) {
      end = (u_char*)sstrfaststr(src + idx, len - idx, "\r\n--", strlen("\r\n--"));
      /* file data can contain \x0 */
      while (!end) {
        idx += strlen((const char*)src + idx);
        if (idx < len - 2) {
          idx++;
          end = (u_char*)sstrfaststr(src + idx, len - idx, "\r\n--", strlen("\r\n--"));
        } else {
          break;
        }
      }
      if (!end || ngx_strncmp(end + 4, boundary, boundary_len)) {
        if (ngx_http_apply_rulematch_v_n(
              &nx_int__uncommon_post_format, ctx, r, NULL, NULL, BODY, 1, 0)) {
          naxsi_error_fatal(ctx, r, "POST data : malformed content-disposition line");
        }
        return;
      }
      if (!ngx_strncmp(end + 4, boundary, boundary_len)) {
        break;
      } else {
        idx += ((u_char*)end - (src + idx)) + 1;
        end = NULL;
      }
    }
    if (!end) {
      naxsi_error_fatal(ctx, r, "POST data : malformed line");
      return;
    }
    if (filen_start) {
      final_var.data  = (unsigned char*)varn_start;
      final_var.len   = varn_len;
      final_data.data = (unsigned char*)filen_start;
      final_data.len  = filen_end - filen_start;
      nullbytes       = naxsi_unescape(&final_var);
      if (nullbytes > 0) {
        ngx_http_apply_rulematch_v_n(
          &nx_int__uncommon_hex_encoding, ctx, r, &final_var, &final_data, BODY, 1, 1);
      }
      nullbytes = naxsi_unescape(&final_data);
      if (nullbytes > 0) {
        ngx_http_apply_rulematch_v_n(
          &nx_int__uncommon_hex_encoding, ctx, r, &final_var, &final_data, BODY, 1, 0);
      }

      NX_DEBUG(_debug_post_heavy,
               NGX_LOG_DEBUG_HTTP,
               r->connection->log,
               0,
               "[POST] checking filename [%V] = [%V]",
               &final_var,
               &final_data);

      /* here we got val name + val content !*/
      if (cf->body_rules) {
        ngx_http_basestr_ruleset_n(
          r->pool, &final_var, &final_data, cf->body_rules, r, ctx, FILE_EXT);
      } else {
        NX_DEBUG(_debug_post_heavy,
                 /* here we got val name + val content !*/
                 NGX_LOG_DEBUG_HTTP,
                 r->connection->log,
                 0,
                 "[POST] No local body rules");
      }

      if (main_cf->body_rules) {
        ngx_http_basestr_ruleset_n(
          r->pool, &final_var, &final_data, main_cf->body_rules, r, ctx, FILE_EXT);
      } else {
        NX_DEBUG(_debug_post_heavy,
                 /* here we got val name + val content !*/
                 NGX_LOG_DEBUG_HTTP,
                 r->connection->log,
                 0,
                 "[POST] No main body rules");
      }

      idx += (u_char*)end - (src + idx);
    } else if (varn_start) {
      varc_len        = (u_char*)end - (src + idx);
      final_var.data  = (unsigned char*)varn_start;
      final_var.len   = varn_len;
      final_data.data = src + idx;
      final_data.len  = varc_len;
      nullbytes       = naxsi_unescape(&final_var);
      if (nullbytes > 0) {
        ngx_http_apply_rulematch_v_n(
          &nx_int__uncommon_hex_encoding, ctx, r, &final_var, &final_data, BODY, 1, 1);
      }
      nullbytes = naxsi_unescape(&final_data);
      if (nullbytes > 0) {
        ngx_http_apply_rulematch_v_n(
          &nx_int__uncommon_hex_encoding, ctx, r, &final_var, &final_data, BODY, 1, 0);
      }

      NX_DEBUG(_debug_post_heavy,
               NGX_LOG_DEBUG_HTTP,
               r->connection->log,
               0,
               "[POST] [%V]=[%V]",
               &final_var,
               &final_data);

      /* here we got val name + val content !*/
      if (cf->body_rules)
        ngx_http_basestr_ruleset_n(r->pool, &final_var, &final_data, cf->body_rules, r, ctx, BODY);
      else
        NX_DEBUG(_debug_post_heavy,
                 /* here we got val name + val content !*/
                 NGX_LOG_DEBUG_HTTP,
                 r->connection->log,
                 0,
                 "No local body rules ?!");

      if (main_cf->body_rules)
        ngx_http_basestr_ruleset_n(
          r->pool, &final_var, &final_data, main_cf->body_rules, r, ctx, BODY);
      else
        NX_DEBUG(_debug_post_heavy,
                 /* here we got val name + val content !*/
                 NGX_LOG_DEBUG_HTTP,
                 r->connection->log,
                 0,
                 "No main body rules ?!");

      idx += (u_char*)end - (src + idx);
    } else {
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "(multipart) : ");
    }
    if (!ngx_strncmp(end, "\r\n", 2))
      idx += 2;
  }
}

void
ngx_http_naxsi_body_parse(ngx_http_request_ctx_t*     ctx,
                          ngx_http_request_t*         r,
                          ngx_http_naxsi_loc_conf_t*  cf,
                          ngx_http_naxsi_main_conf_t* main_cf)
{
  u_char*      src;
  ngx_str_t    tmp;
  ngx_chain_t* bb;
  u_char*      full_body;
  u_int        full_body_len;

  NX_DEBUG(_debug_body_parse, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-BODY PARSE");

  if (!r->request_body->bufs) {
    ngx_http_apply_rulematch_v_n(&nx_int__empty_post_body, ctx, r, NULL, NULL, BODY, 1, 0);
    return;
  }
  if (!r->headers_in.content_type) {
    NX_DEBUG(_debug_body_parse, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-No content type ..");

    ngx_http_apply_rulematch_v_n(&nx_int__uncommon_content_type, ctx, r, NULL, NULL, BODY, 1, 0);
    return;
  }

  if (r->request_body->temp_file) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP,
                  r->connection->log,
                  0,
                  "naxsi: POST REQUEST to temp_file, partially parsed.");
    ngx_http_apply_rulematch_v_n(&nx_int__big_request, ctx, r, NULL, NULL, BODY, 1, 0);
    return;
  }

  NX_DEBUG(_debug_body_parse, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-VALID BODY");

  /* request body in single buffer */
  if (r->request_body->bufs->next == NULL) {
    full_body_len = (u_int)(r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos);
    full_body     = ngx_pcalloc(r->pool, (u_int)(full_body_len + 1));
    memcpy(full_body, r->request_body->bufs->buf->pos, full_body_len);
  }

  /* request body in chain */
  else {
    NX_DEBUG(_debug_body_parse,
             NGX_LOG_DEBUG_HTTP,
             r->connection->log,
             0,
             "[POST] REQUEST BODY IN CHAIN !");

    for (full_body_len = 0, bb = r->request_body->bufs; bb; bb = bb->next)
      full_body_len += (bb->buf->last - bb->buf->pos);
    full_body = ngx_pcalloc(r->pool, full_body_len + 1);
    src       = full_body;
    if (!full_body)
      return;
    for (bb = r->request_body->bufs; bb; bb = bb->next)
      full_body = ngx_cpymem(full_body, bb->buf->pos, bb->buf->last - bb->buf->pos);
    full_body = src;
    NX_DEBUG(_debug_body_parse,
             NGX_LOG_DEBUG_HTTP,
             r->connection->log,
             0,
             "[POST] REQUEST BODY IN CHAIN [%s] (len=%d)",
             full_body,
             full_body_len);
  }

  NX_DEBUG(_debug_body_parse,
           NGX_LOG_DEBUG_HTTP,
           r->connection->log,
           0,
           "content-len header (%d) mismatch actual len (%d) ??",
           r->headers_in.content_length_n,
           full_body_len);

  /* File probably got buffered. */
  if (r->headers_in.content_length_n != full_body_len) {
    ngx_http_apply_rulematch_v_n(&nx_int__big_request, ctx, r, NULL, NULL, BODY, 1, 0);
    return;
  }

  /* x-www-form-urlencoded POSTs */
  /* 33 = echo -n "application/x-www-form-urlencoded" | wc -c */
  if (!ngx_strncasecmp(
        r->headers_in.content_type->value.data, (u_char*)"application/x-www-form-urlencoded", 33)) {
    NX_DEBUG(
      _debug_post_heavy, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-application/x-www..");

    tmp.len  = full_body_len;
    tmp.data = full_body;

    NX_DEBUG(
      _debug_post_heavy, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-POST DATA [%V]", &tmp);

    if (ngx_http_spliturl_ruleset(
          r->pool, &tmp, cf->body_rules, main_cf->body_rules, r, ctx, BODY)) {
      ngx_http_apply_rulematch_v_n(&nx_int__uncommon_url, ctx, r, NULL, NULL, BODY, 1, 0);
      return;
    }
  }
  /* 19 = echo -n "multipart/form-data" | wc -c */
  else if (!ngx_strncasecmp(
             r->headers_in.content_type->value.data, (u_char*)"multipart/form-data", 19)) {
    ngx_http_naxsi_multipart_parse(ctx, r, full_body, full_body_len);
  }
  /* 16 = echo -n "application/json" | wc -c */
  else if (!ngx_strncasecmp(
             r->headers_in.content_type->value.data, (u_char*)"application/json", 16)) {
    ngx_http_naxsi_json_parse(ctx, r, full_body, full_body_len);
  }
  /* 24 = echo -n "application/vnd.api+json" | wc -c */
  else if (!ngx_strncasecmp(
             r->headers_in.content_type->value.data, (u_char*)"application/vnd.api+json", 24)) {
    ngx_http_naxsi_json_parse(ctx, r, full_body, full_body_len);
  }
  /* 22 = echo -n "application/csp-report" | wc -c */
  else if (!ngx_strncasecmp(
             r->headers_in.content_type->value.data, (u_char*)"application/csp-report", 22)) {
    ngx_http_naxsi_json_parse(ctx, r, full_body, full_body_len);
  } else {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[POST] Unknown content-type");
    ngx_http_apply_rulematch_v_n(&nx_int__uncommon_content_type, ctx, r, NULL, NULL, BODY, 1, 0);
    /*
    ** Only attempt to process "raw" body if id:nx_int__uncommon_content_type
    *was
    ** whitelisted. Else, it should be blocking and stop processing here.
    */
    if ((!ctx->block || ctx->learning) && !ctx->drop) {
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "After uncommon content-type");
      ngx_http_naxsi_rawbody_parse(ctx, r, full_body, full_body_len);
    }
  }
}

/*
** does : this is a 'main' function, all the stuff goes from here.
**    to make it short, it does the following :
** - if we got header rules, apply header_rules on each.
** - apply generic_rules on url decoded URI.
** - if we got get_rules and get args, apply get_rules varname/value couple.
** - if we are in a POST/PUT request and we got body_rules, apply rules :)
*/
void
ngx_http_naxsi_uri_parse(ngx_http_naxsi_main_conf_t* main_cf,
                         ngx_http_naxsi_loc_conf_t*  cf,
                         ngx_http_request_ctx_t*     ctx,
                         ngx_http_request_t*         r)
{
  ngx_str_t tmp, name;

  if (!r->uri.len)
    return;
  if ((ctx->block && !ctx->learning) || ctx->drop)
    return;
  if (!main_cf->generic_rules && !cf->generic_rules) {
    tmp.data = NULL;
    tmp.len  = 0;
    ngx_http_apply_rulematch_v_n(&nx_int__no_rules, ctx, r, &tmp, &tmp, URL, 1, 0);
    return;
  }
  tmp.len  = r->uri.len;
  tmp.data = ngx_pcalloc(r->pool, r->uri.len + 1);
  if (!tmp.data) {
    naxsi_error_fatal(ctx, r, "failed alloc of %d", r->uri.len + 1);
    return;
  }
  memcpy(tmp.data, r->uri.data, r->uri.len);
  if (naxsi_escape_nullbytes(&tmp) > 0) {
    ngx_str_t tmp_name, tmp_val;
    tmp_name.data = tmp_val.data = NULL;
    tmp_name.len = tmp_val.len = 0;
    ngx_http_apply_rulematch_v_n(
      &nx_int__uncommon_hex_encoding, ctx, r, &tmp_name, &tmp_val, URL, 1, 0);
  }
  name.data = NULL;
  name.len  = 0;
  if (cf->generic_rules)
    ngx_http_basestr_ruleset_n(r->pool, &name, &tmp, cf->generic_rules, r, ctx, URL);
  if (main_cf->generic_rules)
    ngx_http_basestr_ruleset_n(r->pool, &name, &tmp, main_cf->generic_rules, r, ctx, URL);
  ngx_pfree(r->pool, tmp.data);
}

void
ngx_http_naxsi_args_parse(ngx_http_naxsi_main_conf_t* main_cf,
                          ngx_http_naxsi_loc_conf_t*  cf,
                          ngx_http_request_ctx_t*     ctx,
                          ngx_http_request_t*         r)
{
  ngx_str_t tmp;

  if ((ctx->block && !ctx->learning) || ctx->drop)
    return;
  if (!r->args.len)
    return;
  if (!cf->get_rules && !main_cf->get_rules)
    return;
  tmp.len  = r->args.len;
  tmp.data = ngx_pcalloc(r->pool, r->args.len + 1);
  if (!tmp.data) {
    naxsi_error_fatal(ctx, r, "failed alloc");
    return;
  }
  memcpy(tmp.data, r->args.data, r->args.len);

  if (ngx_http_spliturl_ruleset(r->pool, &tmp, cf->get_rules, main_cf->get_rules, r, ctx, ARGS)) {
    naxsi_error_fatal(ctx, r, "spliturl error : malformed url, possible attack");
    return;
  }
  ngx_pfree(r->pool, tmp.data);
}

void
ngx_http_naxsi_headers_parse(ngx_http_naxsi_main_conf_t* main_cf,
                             ngx_http_naxsi_loc_conf_t*  cf,
                             ngx_http_request_ctx_t*     ctx,
                             ngx_http_request_t*         r)
{
  ngx_list_part_t* part;
  ngx_table_elt_t* h;
  unsigned int     i;
  ngx_str_t        lowcase_header;

  if (!cf->header_rules && !main_cf->header_rules)
    return;
  // this check may be removed, as it shouldn't be needed anymore !
  if ((ctx->block && !ctx->learning) || ctx->drop)
    return;
  part = &r->headers_in.headers.part;
  h    = part->elts;
  // this check may be removed, as it shouldn't be needed anymore !
  for (i = 0; ((!ctx->block || ctx->learning) && !ctx->block); i++) {
    if (i >= part->nelts) {
      if (part->next == NULL)
        break;
      part = part->next;
      h    = part->elts;
      i    = 0;
    }
    lowcase_header.data = h[i].lowcase_key;
    lowcase_header.len  = h[i].key.len;
    if (naxsi_escape_nullbytes(&lowcase_header) > 0) {
      ngx_http_apply_rulematch_v_n(
        &nx_int__uncommon_hex_encoding, ctx, r, &h[i].key, &h[i].value, HEADERS, 1, 1);
    }
    if (naxsi_escape_nullbytes(&h[i].value) > 0) {
      ngx_http_apply_rulematch_v_n(
        &nx_int__uncommon_hex_encoding, ctx, r, &h[i].key, &h[i].value, HEADERS, 1, 0);
    }
    if (cf->header_rules)
      ngx_http_basestr_ruleset_n(
        r->pool, &lowcase_header, &(h[i].value), cf->header_rules, r, ctx, HEADERS);
    if (main_cf->header_rules)
      ngx_http_basestr_ruleset_n(
        r->pool, &lowcase_header, &(h[i].value), main_cf->header_rules, r, ctx, HEADERS);
  }
  return;
}

void
ngx_http_naxsi_data_parse(ngx_http_request_ctx_t* ctx, ngx_http_request_t* r)
{
  ngx_http_naxsi_loc_conf_t*  cf;
  ngx_http_naxsi_main_conf_t* main_cf;
  ngx_http_core_main_conf_t*  cmcf;

  cf      = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
  cmcf    = ngx_http_get_module_main_conf(r, ngx_http_core_module);
  main_cf = ngx_http_get_module_main_conf(r, ngx_http_naxsi_module);
  if (!cf || !ctx || !cmcf) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "naxsi: unable to parse data.");
    return;
  }
  /* process rules only if request is not already blocked or if
     the learning mode is enabled */
  ngx_http_naxsi_headers_parse(main_cf, cf, ctx, r);
  /* check uri */
  ngx_http_naxsi_uri_parse(main_cf, cf, ctx, r);
  /* check args */
  ngx_http_naxsi_args_parse(main_cf, cf, ctx, r);
  /* check method */
  if ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT) &&
      /* presence of body rules (POST/PUT rules) */
      (cf->body_rules || main_cf->body_rules) &&
      /* and the presence of data to parse */
      r->request_body && ((!ctx->block || ctx->learning) && !ctx->drop))
    ngx_http_naxsi_body_parse(ctx, r, cf, main_cf);
  ngx_str_t tag;
  tag.len  = 15;
  tag.data = ngx_pcalloc(r->pool, tag.len + 1);
  if (tag.data)
    memcpy(tag.data, "x-forwarded-for", 15);
  unsigned int      n = 0;
  ngx_table_elt_t** h = NULL;
  ngx_array_t       a;
#if (NGX_HTTP_X_FORWARDED_FOR)
  if (r->headers_in.x_forwarded_for.nelts >= 1) {
    a = r->headers_in.x_forwarded_for;
    n = a.nelts;
  }
#endif
  if (n >= 1)
    h = a.elts;
  if (n >= 1) {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "xfor %s", h[0]->value.data);

    ngx_http_naxsi_update_current_ctx_status(ctx, cf, r, &tag, (ngx_str_t*)h[0]->value.data);
  }
}

void
ngx_http_naxsi_update_current_ctx_status(ngx_http_request_ctx_t*    ctx,
                                         ngx_http_naxsi_loc_conf_t* cf,
                                         ngx_http_request_t*        r,
                                         ngx_str_t*                 name,
                                         ngx_str_t*                 value)
{
  unsigned int           i, z;
  unsigned int           matched;
  ngx_http_check_rule_t* cr;

  ngx_http_special_score_t* sc;
  unsigned int              n = 0;

  NX_DEBUG(_debug_custom_score, NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-custom check rules");

  int               ignore = 0;
  ngx_table_elt_t** h;
  ngx_array_t       a;

  ctx->ignore = 0;

  /*cr, sc, cf, ctx*/
  if (cf->check_rules && ctx->special_scores) {
#if (NGX_HTTP_X_FORWARDED_FOR)
    if (r->headers_in.x_forwarded_for.nelts >= 1) {
      a = r->headers_in.x_forwarded_for;
      n = a.nelts;
      if (n >= 1) {
        h = a.elts;
        NX_DEBUG(_debug_whitelist_ignore,
                 NGX_LOG_DEBUG_HTTP,
                 r->connection->log,
                 0,
                 "XX- lookup ignore X-Forwarded-For: %s",
                 h[0]->value.data);
        ngx_str_t ip;
        ip.len  = strlen((char*)h[0]->value.data);
        ip.data = ngx_pcalloc(r->pool, ip.len + 1);
        memcpy(ip.data, h[0]->value.data, ip.len);
        ignore = nx_can_ignore_ip(&ip, cf) || nx_can_ignore_cidr(&ip, cf);
      }
    } else
#endif
    {
      ngx_str_t* ip = &r->connection->addr_text;
      NX_DEBUG(_debug_whitelist_ignore,
               NGX_LOG_DEBUG_HTTP,
               r->connection->log,
               0,
               "XX- lookup ignore client ip: %s",
               ip->data);
      ignore = nx_can_ignore_ip(ip, cf) || nx_can_ignore_cidr(ip, cf);
    }

    NX_DEBUG(_debug_custom_score,
             NGX_LOG_DEBUG_HTTP,
             r->connection->log,
             0,
             "XX-we have custom check rules and CTX got special score :)");

    cr = cf->check_rules->elts;
    sc = ctx->special_scores->elts;
    for (z = 0; z < ctx->special_scores->nelts; z++)
      for (i = 0; i < cf->check_rules->nelts; i++) {
        NX_DEBUG(_debug_custom_score,
                 NGX_LOG_DEBUG_HTTP,
                 r->connection->log,
                 0,
                 "XX- rule says :(%s:%d) vs current context:(%s:%d) (flag=%d)",
                 cr[i].sc_tag.data,
                 cr[i].sc_score,
                 sc[z].sc_tag->data,
                 sc[z].sc_score,
                 cr[i].cmp);

        if (!ngx_strcmp(sc[z].sc_tag->data, cr[i].sc_tag.data)) {
          NX_DEBUG(_debug_custom_score,
                   NGX_LOG_DEBUG_HTTP,
                   r->connection->log,
                   0,
                   "XX- rule says :(%s:%d) vs current context:(%s:%d) (flag=%d)",
                   cr[i].sc_tag.data,
                   cr[i].sc_score,
                   sc[z].sc_tag->data,
                   sc[z].sc_score,
                   cr[i].cmp);

          matched = 0;
          // huglier than your mom :)
          switch (cr[i].cmp) {
            case SUP:
              matched = sc[z].sc_score > cr[i].sc_score ? 1 : 0;
              break;
            case SUP_OR_EQUAL:
              matched = sc[z].sc_score >= cr[i].sc_score ? 1 : 0;
              break;
            case INF:
              matched = sc[z].sc_score < cr[i].sc_score ? 1 : 0;
              break;
            case INF_OR_EQUAL:
              matched = sc[z].sc_score <= cr[i].sc_score ? 1 : 0;
              break;
          }
          if (matched) {
            NX_DEBUG(_debug_custom_score,
                     NGX_LOG_DEBUG_HTTP,
                     r->connection->log,
                     0,
                     "XX- custom score rule triggered ..");
            ctx->ignore = ignore;
            if (cr[i].block && !ignore) {
              ctx->block = 1;
            } else {
              ctx->block = 0;
            }
            if (cr[i].drop && !ignore) {
              ctx->drop = 1;
            }
            if (cr[i].allow) {
              ctx->allow = 1;
            }
            if (cr[i].log || ignore) {
              ctx->log = 1;
            }
          }
        }
      }
  }
}

/*
** This function is called when the body is read.
** Will set-up flags to tell that parsing can be done,
** and then run the core phases again
** (WARNING: check backward compatibility of count--
** with older version of nginx 0.7.x)
*/
void
ngx_http_naxsi_payload_handler(ngx_http_request_t* r)
{
  ngx_http_request_ctx_t* ctx;
  ctx        = ngx_http_get_module_ctx(r, ngx_http_naxsi_module);
  ctx->ready = 1;
  r->count--;
  NX_DEBUG(_debug_payload_handler,
           NGX_LOG_DEBUG_HTTP,
           r->connection->log,
           0,
           "XX-dummy PAYLOAD HANDLER !");

  if (ctx->wait_for_body) {
    NX_DEBUG(_debug_payload_handler,
             NGX_LOG_DEBUG_HTTP,
             r->connection->log,
             0,
             "XX-dummy : AFTER NGX_AGAIN");

    ctx->wait_for_body = 0;
    ngx_http_core_run_phases(r);
  }
}
