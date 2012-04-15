/*
 * NAXSI, a web application firewall for NGINX
 * Copyright (C) 2011, Thibault 'bui' Koechlin
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

/* used to store locations during the configuration time. 
   then, accessed by the hashtable building feature during "init" time. */
ngx_http_dummy_loc_conf_t *dummy_lc;


/*
** Static defined rules struct for internal rules.
** We use those to be able to call is_rule_whitelisted_n() on those
** rules at any time ;)
*/
//nx_int__post_without_data
//nx_int__no_headers
//nx_int__weird_url
//nx_int__weird_body
//nx_int__weird_args
//nx_int__post_without_content_type


ngx_http_rule_t nx_int__weird_request = {/*type*/ 0, /*whitelist flag*/ 0, 
					 /*wl_id ptr*/ NULL, /*rule_id*/ 1,
					 /*log_msg*/ NULL, /*score*/ 0, 
					 /*sscores*/ NULL,
					 /*sc_block*/ 0,  /*sc_allow*/ 0, 
					 /*block*/ 1,  /*allow*/ 0, 
					 /*lnk_to & from*/ 0, 0,
					 /*br ptrs*/ NULL};
ngx_http_rule_t nx_int__big_request = {/*type*/ 0, /*whitelist flag*/ 0, 
				       /*wl_id ptr*/ NULL, /*rule_id*/ 2,
				       /*log_msg*/ NULL, /*score*/ 0, 
				       /*sscores*/ NULL,
				       /*sc_block*/ 0,  /*sc_allow*/ 0, 
				       /*block*/ 1,  /*allow*/ 0, 
				       /*lnk_to & from*/ 0, 0,
				       /*br ptrs*/ NULL};

#define dummy_error_fatal(ctx, r, ...) do {				\
    if (ctx) ctx->block = 1;						\
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "XX-******** NGINX NAXSI INTERNAL ERROR ********"); \
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, __VA_ARGS__); \
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-func:%s file:%s line:%d", __func__, __FILE__, __LINE__); \
    if (r && r->uri.data) ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "XX-uri:%s", r->uri.data); \
  } while (0)



void			ngx_http_dummy_update_current_ctx_status(ngx_http_request_ctx_t	*ctx, 
								 ngx_http_dummy_loc_conf_t	*cf, ngx_http_request_t *r);
int			ngx_http_process_basic_rule_buffer(ngx_str_t *str, ngx_http_rule_t *rl, ngx_int_t *match);
void			ngx_http_dummy_payload_handler(ngx_http_request_t *r);
int			ngx_http_basestr_ruleset_n(ngx_pool_t *pool,
						   ngx_str_t	*name,
						   ngx_str_t	*value,
						   ngx_array_t *rules,
						   ngx_http_request_t *req,
						   ngx_http_request_ctx_t *ctx,
						   enum DUMMY_MATCH_ZONE zone);
void			ngx_http_dummy_body_parse(ngx_http_request_ctx_t *ctx, 
						  ngx_http_request_t	 *r,
						  ngx_http_dummy_loc_conf_t *cf,
						  ngx_http_dummy_main_conf_t *main_cf);




/*
** in : string to inspect, associated rule
** does : apply the rule on the string, return 1 if matched, 
**	  0 else and -1 on error
*/
int	
ngx_http_process_basic_rule_buffer(ngx_str_t *str,
				   ngx_http_rule_t *rl,
				   ngx_int_t	*nb_match)
  
{
  ngx_int_t	match, tmp_idx, len, i;
  unsigned char *ret;
  int		captures[6];
  if (!rl->br || !nb_match) return (-1);
  
  
  *nb_match = 0;
  if (rl->br->rx) {
    tmp_idx = 0;
    len = str->len;
    while 
#if defined nginx_version && (nginx_version > 1001011)
      (tmp_idx < len && 
       (match = pcre_exec(rl->br->rx->regex->pcre, 0, 
			  (const char *) str->data, str->len, tmp_idx, 0, 
			  captures, 6)) >= 0)
#elif defined nginx_version && (nginx_version <= 1001011)
      (tmp_idx < len && 
       (match = pcre_exec(rl->br->rx->regex, 0, 
			  (const char *) str->data, str->len, 
			  tmp_idx, 0, captures, 6)) >= 0)
#elif defined nginx_version
#error "Inconsistent nginx version."
	(0)
#else
#error "nginx_version not defined."
	(0)
#endif
	{
	  for(i = 0; i < match; ++i)
	    *nb_match += 1;
	  tmp_idx = captures[1];
	}
    if (*nb_match > 0) {
      if (rl->br->negative)
	return (0);
      else 
	return (1);
    }
    else if (*nb_match == 0) {
      if (rl->br->negative)
	return (1);
      else
	return (0);
    }
    return (-1);
  }
  else if (rl->br->str) {
    match = 0;
    tmp_idx = 0;
    while (1)	{
      ret = (unsigned char *) strfaststr((unsigned char *)str->data+tmp_idx,
					 (unsigned int)str->len - tmp_idx,
					 (unsigned char *)rl->br->str->data,
					 (unsigned int)rl->br->str->len);
      if (ret) {
	match = 1;
	*nb_match = *nb_match+1;
      }
      else
	break;
      if (nb_match && ret < (str->data + str->len)) {
	tmp_idx = (ret - str->data) + 1;
	if (tmp_idx > (int) (str->len - 1))
	  break;
      }
      else
	break;
    }
    if (match) {
      if (rl->br->negative)
	return (0);
      else
	return (1);
    }
    else {
      if (rl->br->negative)
	return (1);
      else
	return (0);
    }
  }
  return (0);
}


/*
** Check if a (matched) rule is whitelisted.
** This func will look for the current URI in the wlr_url_hash [hashtable]
** It will also look for varname in the wlr_body|args|headers_hash [hashtable]
** and It will also look for disabled rules.
** 1 - If the rule is disabled, it's whitelisted
** 2 - If a matching URL is found, check if the further information confirms that the rule should be whitelisted
** ($URL:/bar|$ARGS_VAR:foo : it's not because URL matches that we should whitelist rule)
** 3 - If a matching varname is found, check zone and rules IDs.
** [TODO] : Add mz matches with style BODY|HEADERS|...
** returns (1) if rule is whitelisted, else (0)
*/

/* #define whitelist_debug */
/* #define whitelist_heavy_debug */

int
ngx_http_dummy_is_whitelist_adapted(ngx_http_whitelist_rule_t *b,
				    ngx_str_t *name, 
				    enum DUMMY_MATCH_ZONE zone,
				    ngx_http_rule_t	*r,
				    ngx_http_request_t	*req,
				    enum MATCH_TYPE type,
				    ngx_int_t target_name) {
  unsigned int i;
  
  /* if something was found, check the rule ID */
  if (!b) return (0);

  /* if whitelist targets arg name, but the rules hit content*/
  if (b->target_name && !target_name)
    {
#ifdef whitelist_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "whitelist targets name, but rule matched content.");
#endif
      return (0);
    }
  /* if if the whitelist target contents, but the rule hit arg name*/
  if (!b->target_name && target_name)
    {
#ifdef whitelist_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "whitelist targets content, but rule matched name.");
#endif
      return (0);
    }

  
  if (type == NAME_ONLY) {
#ifdef whitelist_debug
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "Name match in zone %s",
		  zone == ARGS ? "ARGS" : zone == BODY ? "BODY" : zone == HEADERS ? "HEADERS" : "UNKNOWN!!!!!");
#endif
    //False Positive, there was a whitelist that matches the argument name,
    // But is was actually matching an existing URI name.
    if (zone != b->zone || b->uri_only) {
#ifdef whitelist_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "bad whitelist, name match, but WL was only on URL.");
#endif
      return (0);
    }
    
    for (i = 0; i < b->ids->nelts; i++) {
      if ( ((int *)b->ids->elts)[i] == r->rule_id ||
	   ((int *)b->ids->elts)[i] == 0) {
#ifdef whitelist_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
		      "WhiteListing0 rule %d on var [%V] at uri [%V] (dst id:%d)",
		      r->rule_id, name, &(req->uri), ((int *)b->ids->elts)[i]);
#endif
	return (1);
      }
    }
    return (0);
  }
  
  if (type == URI_ONLY ||
      type == MIXED) {
    /* zone must match */
    if (zone != b->zone ||
	/* if the whitelist matched on an URI, check
	   that the 'name' field in the whitelist is really an URI
	   and not an argument name. */
	(type == URI_ONLY && !b->uri_only)) {
#ifdef whitelist_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "bad whitelist, URL match, but WL was not on URL.");
#endif
      
      return (0);
    }
    
    for (i = 0; i < b->ids->nelts; i++) {
#ifdef whitelist_heavy_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
		    "wl : %d, matched rule : %d", ((int *)b->ids->elts)[i], r->rule_id);
#endif      
      if ( ((int *)b->ids->elts)[i] == r->rule_id || 
	   ((int *)b->ids->elts)[i] == 0) { 
#ifdef whitelist_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
		      "WhiteListing1 rule %d/ wl[%d] = %d (wl had %d wl ids) on var [%V] at uri [%V] (zone:%s)",
		      r->rule_id, i, ((int *)b->ids->elts)[i], b->ids->nelts, name, &(req->uri), 
		      zone == HEADERS ? "HEADERS" : zone == URL ? "URL" : zone == BODY ? "BODY" :
		      zone == ARGS ? "ARGS" : "UNKNOWN!!!!");
#endif
	return (1);
      }
    }
    return (0);
  }
  return (0);
}

//#define whitelist_debug

int	
ngx_http_dummy_is_rule_whitelisted_n(ngx_http_request_t *req, 
				     ngx_http_dummy_loc_conf_t *cf, 
				     ngx_http_rule_t *r, ngx_str_t *name, 
				     enum DUMMY_MATCH_ZONE zone,
				     ngx_int_t target_name) {
  ngx_int_t			k;
  ngx_http_whitelist_rule_t	*b = NULL;
  unsigned int		i, z;
  ngx_http_rule_t	**dr;
  ngx_str_t tmp_hashname;
  ngx_str_t nullname = ngx_null_string;
  
  /* if name is NULL, replace it by an empty string */
  if (!name) name = &nullname;
  
#ifdef whitelist_debug
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		"is rule [%d] whitelisted in zone %s for item %V", r->rule_id,
		zone == ARGS ? "ARGS" : zone == HEADERS ? "HEADERS" : zone == BODY ? "BODY" : zone == URL ? "URL" : "UNKNOWN",
		name);
#endif
  tmp_hashname.data = NULL;
  
  /* Check if the rule is part of disabled rules for this location */
  if (cf->disabled_rules) {
    dr = cf->disabled_rules->elts;
    for (i = 0; i < cf->disabled_rules->nelts; i++) {
#ifdef whitelist_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, "id:%d", i);
#endif
      for (z = 0; dr[i]->wl_id[z] >= 0; z++) {
	/* if it's the same ID or that the WL id is 0 (which means ALL RULES), it's whitelisted ! */
	/* TODO : test case for WL on rule_id 0 */
	if (dr[i]->wl_id[z] == r->rule_id || dr[i]->wl_id[z] == 0) {
	  /* matched in args zone and whitelisted in full args zone */
	  if (zone == ARGS && dr[i]->br && dr[i]->br->args) {
	    if (dr[i]->br->target_name && target_name)
	      return (1);
	    if (!dr[i]->br->target_name && !target_name)
	      return (1);
	  }
	  /* matched in headers zone and whitelisted in full headers zone */
	  else if (zone == HEADERS && dr[i]->br && dr[i]->br->headers) {
	    if (dr[i]->br->target_name && target_name)
	      return (1);
	    if (!dr[i]->br->target_name && !target_name)
	      return (1);
	  }
	  else if (zone == BODY && dr[i]->br && dr[i]->br->body) {
	    if (dr[i]->br->target_name && target_name)
	      return (1);
	    if (!dr[i]->br->target_name && !target_name)
	      return (1);
	  }
	  else if (zone == URL && dr[i]->br && dr[i]->br->url) return (1);
	  /* this one, with no match zone at all, means the rule is purely disabled */
	  else if (dr[i]->br && !(dr[i]->br->args ||  dr[i]->br->headers ||
				  dr[i]->br->body ||  dr[i]->br->url)) return (1);
	}
      }
    }
  }
#ifdef whitelist_debug
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		"hashing (varname)[%V]", name);
#endif
  if (name->len > 0) {
    /* lower case the var name before checking it against hash tables */
    /* TODO : should do the same with uri ? but it's case sensitive ... */
    for (i = 0; i < name->len; i++)
      name->data[i] = tolower(name->data[i]);
    /* search if there is WL on this ARGS name */
    k = ngx_hash_key_lc(name->data, name->len);
    if (cf->wlr_args_hash && cf->wlr_args_hash->size > 0 && zone == ARGS)
      b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_args_hash, k, 
						     (u_char*) name->data, 
						     name->len);
    else
      /* search if there is WL on this BODY name */
      if (cf->wlr_body_hash && cf->wlr_body_hash->size > 0 && zone == BODY)
	b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_body_hash, k, 
						       (u_char*) name->data, 
						       name->len); 
      else
	/* or if there is a WL on this HEADER name */
	if (cf->wlr_headers_hash && cf->wlr_headers_hash->size > 0 && zone == HEADERS)
	  b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_headers_hash, k, 
							 (u_char*) name->data, 
							 name->len); 
  }
  if (b)
    if (ngx_http_dummy_is_whitelist_adapted(b, name, zone, r, req, NAME_ONLY, target_name))
      return (1);
#ifdef whitelist_debug
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		"hashing (uri) [%V]", &(req->uri));
#endif
  k = ngx_hash_key_lc(req->uri.data, req->uri.len);
    
  /* check the URL no matter what zone we're in */
  if (cf->wlr_url_hash && cf->wlr_url_hash->size > 0) {
    /* check if the rule was not whitelisted */  
#ifdef whitelist_debug
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		  "Check if rule [%d] is whitelist on arg [%V] from uri [%V]",
		  r->rule_id, name, &(req->uri));
#endif
    b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_url_hash, k, 
						   (u_char*) req->uri.data, 
						   req->uri.len);
    if (b)
      if (ngx_http_dummy_is_whitelist_adapted(b, name, zone, r, req, URI_ONLY, target_name))
	return (1);
  }
  /* check URL against every hashlist, as $URL:bla|ARGS will be put in the ARGS 
     whitelist, and so on. */
  if (cf->wlr_args_hash && cf->wlr_args_hash->size > 0 && zone == ARGS)
    b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_args_hash, k, 
						   (u_char*) req->uri.data, 
						   req->uri.len);
  else 
    /* search if there is WL on this BODY name */
    if (cf->wlr_body_hash && cf->wlr_body_hash->size > 0 && zone == BODY)
      b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_body_hash, k, 
						     (u_char*) req->uri.data, 
						     req->uri.len); 
    else
      /* or if there is a WL on this HEADER name */
      if (cf->wlr_headers_hash && cf->wlr_headers_hash->size > 0 && zone == HEADERS)
	b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_headers_hash, k, 
						       (u_char*) req->uri.data, 
						       req->uri.len); 
    
    
  if (b)
    if (ngx_http_dummy_is_whitelist_adapted(b, name, zone, r, req, URI_ONLY, target_name))
      return (1);
  
  /* maybe it was $URL+$VAR ? */
  if (!b) {
    tmp_hashname.len = req->uri.len + 1 + name->len;
    /* one extra byte for target_name '#' */
    tmp_hashname.data = ngx_pcalloc(req->pool, tmp_hashname.len+2);
    if (!tmp_hashname.data)
      return (NGX_ERROR);
    if (target_name) {
      tmp_hashname.len++;
      ngx_memset(tmp_hashname.data, 0, tmp_hashname.len+1);
      strncat((char*)tmp_hashname.data, "#", 1);
    }
    else
      ngx_memset(tmp_hashname.data, 0, tmp_hashname.len+1);
    strncat((char*) tmp_hashname.data, (char*)req->uri.data, req->uri.len);
    strncat((char*)tmp_hashname.data, "#", 1);
    strncat((char*)tmp_hashname.data, (char*)name->data, name->len);
    
#ifdef whitelist_debug
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		  "hashing [%V]", &tmp_hashname);
#endif
    k = ngx_hash_key_lc(tmp_hashname.data, tmp_hashname.len);
    if (zone == BODY && cf->wlr_body_hash && cf->wlr_body_hash->size > 0)
      b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_body_hash, k, 
						     (u_char*) tmp_hashname.data, 
						     tmp_hashname.len);
    else if (zone == HEADERS && cf->wlr_headers_hash && 
	     cf->wlr_headers_hash->size > 0)
      b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_headers_hash, k, 
						     (u_char*) tmp_hashname.data, 
						     tmp_hashname.len);
    else if (zone == URL && cf->wlr_url_hash && cf->wlr_url_hash->size > 0)
      b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_url_hash, k, 
						     (u_char*) tmp_hashname.data, 
						     tmp_hashname.len);
    else if (zone == ARGS && cf->wlr_args_hash && cf->wlr_args_hash->size > 0)
      b = (ngx_http_whitelist_rule_t*) ngx_hash_find(cf->wlr_args_hash, k, 
						     (u_char*) tmp_hashname.data, 
						     tmp_hashname.len);
  }
  
  if (b)
    if (ngx_http_dummy_is_whitelist_adapted(b, name, zone, r, req, MIXED, target_name))
      {
	if (tmp_hashname.data)
	  ngx_pfree(req->pool, tmp_hashname.data);
	return (1);
      }
  if (tmp_hashname.data)
    ngx_pfree(req->pool, tmp_hashname.data);
  return (0);
}


//#define output_forbidden
ngx_int_t  
ngx_http_output_forbidden_page(ngx_http_request_ctx_t *ctx, 
			       ngx_http_request_t *r)
{
  ngx_int_t     rc, w;
  u_int		i;
  char		*fmt;
  const char 	*fmt_base = "ip=%.*s&server=%.*s&uri=%.*s&total_processed=%lld&total_blocked=%lld";
  const char	*fmt_rm = "&zone%d=%s&id%d=%d&var_name%d=%.*s";
  ngx_str_t	denied_args, tmp_uri;
  ngx_http_dummy_loc_conf_t	*cf;
  ngx_http_matched_rule_t	*mr;
  
  /*
    create output message
  */
  cf = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
#ifdef output_forbidden
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "#Forbidding page");
#endif
  tmp_uri.len = r->uri.len + (2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
						 NGX_ESCAPE_ARGS));
  tmp_uri.data = ngx_pcalloc(r->pool, tmp_uri.len+1);
  ngx_escape_uri(tmp_uri.data, r->uri.data, r->uri.len, NGX_ESCAPE_ARGS);
  rc = snprintf(0, 0, fmt_base, r->connection->addr_text.len,
		r->connection->addr_text.data,
		r->headers_in.server.len, r->headers_in.server.data,
		tmp_uri.len, tmp_uri.data,
		cf->request_processed, cf->request_blocked);

  
  if (ctx->matched) {
    mr = ctx->matched->elts;
    for (i = 0; i < ctx->matched->nelts; i++)
      rc += snprintf(0, 0, fmt_rm, i, 
		     "-----BODY|ARGS|HEADERS|URL----", 
		     i, mr[i].rule->rule_id, i, mr[i].name->len, 
		     mr[i].name->data);
  }
  else {
    if (ctx->weird_request || ctx->big_request)
      rc += snprintf(0, 0, fmt_rm, 99, 
		     "-----BODY|ARGS|HEADERS|URL----", 
		     99, 99, 99, 99, 
		     "REQUEST_LONG_LONG");
  }
  fmt = ngx_pcalloc(r->pool, rc+2);
  if (!fmt)
    return (NGX_ERROR);
  w = snprintf(fmt, rc, fmt_base, r->connection->addr_text.len,
	       r->connection->addr_text.data,
	       r->headers_in.server.len, r->headers_in.server.data,
	       tmp_uri.len, tmp_uri.data,
	       cf->request_processed, cf->request_blocked);
  
  char	tmp_zone[30]; 
  /*<- should be a dynamic allocation, no bof here, just mem waste
    , but i'm lazy :) */
  if (ctx->matched) {
    mr = ctx->matched->elts;
    for (i = 0; i < ctx->matched->nelts; i++) {
      memset(tmp_zone, 0, 30);
#ifdef output_forbidden
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		    "----"); 
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		    "zones:H:%d/U:%d/A:%d/B:%d", mr[i].headers_var ,
		    mr[i].url, mr[i].args_var , mr[i].body_var );
#endif
      //zone = UNKNOWN;
      if (mr[i].body_var) 
	strcat(tmp_zone, "BODY");
      if (mr[i].args_var) 
	strcat(tmp_zone, "ARGS");
      if (mr[i].headers_var) 
	strcat(tmp_zone, "HEADERS");
      if (mr[i].url)
	strcat(tmp_zone, "URL");
      if (mr[i].target_name)
	strcat(tmp_zone, "|NAME");
      
      w += snprintf(fmt+w, rc, fmt_rm, i, tmp_zone, i, 
		    mr[i].rule->rule_id, i, mr[i].name->len, 
		    mr[i].name->data);
#ifdef whitelist_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		    "FMT (sub) (%d) LEN:%s", i, fmt); 
#endif
    }
  }
  else {
    if (ctx->weird_request)
      w += snprintf(fmt+w, rc, fmt_rm, 0, "REQUEST", 0, 1, 0, 5, "WEIRD");
    if (ctx->big_request)
      w += snprintf(fmt+w, rc, fmt_rm, 0, "REQUEST", 0, 2, 0, 8, "BIG_REQUEST");
  }
  denied_args.data = (unsigned char *)fmt;
  denied_args.len = w;
  /* add headers with original url and arguments */
  ngx_table_elt_t	    *h;
  
  
  if(r->headers_in.headers.last)  {
    
    h = ngx_list_push(&(r->headers_in.headers));
    h->key.len = strlen("orig_url");
    h->key.data = ngx_pcalloc(r->pool, strlen("orig_url")+1);
    memcpy(h->key.data, "orig_url", strlen("orig_url"));
    h->value.len = tmp_uri.len;
    h->value.data = ngx_pcalloc(r->pool, tmp_uri.len+1);
    memcpy(h->value.data, tmp_uri.data, tmp_uri.len);
    
    h = ngx_list_push(&(r->headers_in.headers));
    h->key.len = strlen("orig_args");
    h->key.data = ngx_pcalloc(r->pool, strlen("orig_args")+1);
    memcpy(h->key.data, "orig_args", strlen("orig_args"));
    h->value.len = r->args.len;
    h->value.data = ngx_pcalloc(r->pool, r->args.len+1);
    memcpy(h->value.data, r->args.data, r->args.len);
    
    h = ngx_list_push(&(r->headers_in.headers));
    h->key.len = strlen("naxsi_sig");
    h->key.data = ngx_pcalloc(r->pool, strlen("naxsi_sig")+1);
    memcpy(h->key.data, "naxsi_sig", strlen("naxsi_sig"));
    h->value.len = denied_args.len;
    h->value.data = denied_args.data;
  }
  else if (cf->learning)
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 
		  0, "[naxsi] no headers_in, not forwarded to learning mode.");
  
  if (cf->learning) {
    ngx_http_core_loc_conf_t  *clcf;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    clcf->post_action.data = cf->denied_url->data;
    clcf->post_action.len = cf->denied_url->len;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 
		  0, "NAXSI_FMT: %s", fmt);
    return (NGX_DECLINED);
  }
  else {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 
		  0, "NAXSI_FMT: %s", fmt);
    rc = ngx_http_internal_redirect(r, cf->denied_url,  
				    &denied_args); 
    return (NGX_HTTP_OK);
  }
  return (NGX_ERROR);
}

/*
** new rulematch, less arguments ^
*/
#define whitelist_debug 
/* #define whitelist_light_debug */
/* #define whitelist_heavy_debug */

void	
ngx_http_apply_rulematch_v_n(ngx_http_rule_t *r, ngx_http_request_ctx_t *ctx, 
			     ngx_http_request_t *req, ngx_str_t *name, 
			     ngx_str_t *value, enum DUMMY_MATCH_ZONE zone, 
			     ngx_int_t nb_match, ngx_int_t target_name)
{
  unsigned int		found = 0, i, z;
  ngx_http_special_score_t	*sc, *rsc;
  ngx_http_dummy_loc_conf_t	*cf;
  ngx_http_matched_rule_t	*mr;
  
  cf = ngx_http_get_module_loc_conf(req, ngx_http_naxsi_module);
  if (!cf || !ctx )
    return ;
  if (ngx_http_dummy_is_rule_whitelisted_n(req, cf, r, name, 
					   zone, target_name) == 1) {
  #ifdef whitelist_light_debug
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
		  "rule is whitelisted.");
  #endif  
    return ;
  }
  if (nb_match == 0)
    nb_match = 1;
  if (!ctx->matched)
    ctx->matched = ngx_array_create(req->pool, 2, 
				    sizeof(ngx_http_matched_rule_t));
  /* log stuff, cause this case sux */
  if (!ctx->matched)
    return ;
  mr = ngx_array_push(ctx->matched);
  if (!mr)
    return ;
  memset(mr, 0, sizeof(ngx_http_matched_rule_t));
  if (target_name)
    mr->target_name = 1;
  switch(zone) {
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
  default:
    break;
  };
  mr->rule = r;
  // the current "name" ptr will be free by caller, so make a copy
  mr->name = ngx_pcalloc(req->pool, sizeof(ngx_str_t));
  if (name->len > 0) {
    mr->name->data = ngx_pcalloc(req->pool, name->len+1);
    memcpy(mr->name->data, name->data, name->len);
    mr->name->len = name->len; 
  }
  else {
    mr->name->data = NULL; 
    mr->name->len = 0; 
  }
  /* apply special score on rulematch */
  if (r->sscores) {
#ifdef whitelist_debug
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		  "Rule applies %d custom scores", r->sscores->nelts);
#endif
    if (!ctx->special_scores) //create the list
      ctx->special_scores = ngx_array_create(req->pool, 1, 
					     sizeof(ngx_http_special_score_t));
    found = 0;
    rsc = r->sscores->elts;
    for (z = 0; z < r->sscores->nelts; z++) {
      //search into the list for matching special score
      found = 0;
      sc = ctx->special_scores->elts;
      for (i = 0; i < ctx->special_scores->nelts; i++) {
	if (rsc[z].sc_tag && sc[i].sc_tag && sc[i].sc_tag->len == rsc[z].sc_tag->len && 
	    !ngx_strcmp(sc[i].sc_tag->data, rsc[z].sc_tag->data)) {
#ifdef whitelist_debug
	  ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
			"Special Score (%V) actual=%d,next=%d", rsc[z].sc_tag,
			sc[i].sc_score, sc[i].sc_score+(rsc[z].sc_score * nb_match));
#endif
	  sc[i].sc_score += (rsc[z].sc_score * nb_match);
	  found = 1;
	  break;
	}
      }
      
      
      if (!found) {
#ifdef whitelist_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		      "Special Score (%V)  next=%d", 
		      rsc[z].sc_tag, (rsc[z].sc_score * nb_match));
#endif
	sc = ngx_array_push(ctx->special_scores);
	if (!sc)
	  return ;
	memset(sc, 0, sizeof(ngx_http_special_score_t));
	sc->sc_tag = rsc[z].sc_tag;
	sc->sc_score = (rsc[z].sc_score * nb_match);	
      }
    }
  }
  //else {
  /* else, apply normal score */
  ctx->score += (r->score * nb_match);
  if (r->block)
    ctx->block = 1;
  if (r->allow)
    ctx->allow = 1;
  //}
  
  ngx_http_dummy_update_current_ctx_status(ctx, cf, req);
  return ;
}


/*
** does : this functions receives an string in the form [foo=bar&bla=foo..]
**	  it splits the string into varname/value couples, and then pass 
**	  this couple along with valid rules to checking func.
** WARN/TODO : Even I tried to make my code bof proof, this should be seriously audited :)
*/
//#define spliturl_ruleset_debug
int 
ngx_http_spliturl_ruleset(ngx_pool_t *pool,
			  char	*str,
			  ngx_array_t *rules,
			  ngx_array_t *main_rules,
			  ngx_http_request_t *req,
			  ngx_http_request_ctx_t *ctx,
			  enum DUMMY_MATCH_ZONE	zone)
{
  ngx_str_t	name, val;
  unsigned int		i;
  char		*eq, *ev, *orig;
  int		len, full_len;
  ngx_http_dummy_loc_conf_t	*cf;   
  unsigned char			*dst, *src;

  
  cf = ngx_http_get_module_loc_conf(req, ngx_http_naxsi_module);
    
#ifdef spliturl_ruleset_debug
  ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
		"XX-check url-like [%s]", str);
#endif

  orig = str;
  full_len = strlen(orig);
  while (str < (orig+full_len) && *str) {
    if (*str == '&') {
      str++;
      continue;
    }
    if (ctx->block && !cf->learning)
      return (0);
    eq = strchr(str, '=');
    ev = strchr(str, '&');
      
    if ((!eq && !ev) /*?foobar */ ||
	(eq && ev && eq > ev)) /*?foobar&bla=test*/ {
      if (!ev)
	ev = str+strlen(str);
      /* len is now [name] */
      len = ev - str;
      val.data = (unsigned char *) str;
      val.len = ev - str;
      name.data = (unsigned char *) NULL;
      name.len = 0;
    }
    /* ?&&val | ?var&& | ?val& | ?&val | ?val&var */
    else if (!eq && ev) {
      if (ngx_http_dummy_is_rule_whitelisted_n(req, cf, &nx_int__weird_request, NULL, zone, 0) == 0)
	ctx->weird_request = 1;
      if (ev > str) /* ?var& | ?var&val */ {
	val.data = (unsigned char *) str;
	val.len = ev - str;
	name.data = (unsigned char *) NULL;
	name.len = 0;
	len = ev - str;
      }
      else /* ?& | ?&&val */ {
	val.data = name.data = NULL;
	val.len = name.len = 0;
	len = 1;
      }
    }
    else /* should be normal like ?var=bar& ..*/ {
      if (!ev) /* ?bar=lol */
	ev = str+strlen(str);
      /* len is now [name]=[content] */
      len = ev - str;
      eq = strnchr(str, '=', len);
      if (!eq) {
	dummy_error_fatal(ctx, req, 
			  "malformed url, possible attack [%s]", str);
	return (1);
      }
      eq++;
      val.data = (unsigned char *) eq;
      val.len = ev - eq;
      name.data = (unsigned char *) str;
      name.len = eq - str - 1;
    }
    if (val.len || name.len) {
      //start
      dst = val.data;
      src = val.data;
      /* ngx_unescape_uri(&src, &dst, */
      /* 		       val.len, NGX_UNESCAPE_URI);       */
      naxsi_unescape_uri(&src, &dst,
			 val.len, 0);      
      val.len =  src - val.data;
      //tmp hack fix, avoid %00 & co (null byte) encoding :p
      for (i = 0; i < val.len; i++)
	if (val.data[i] == 0x0)
	  val.data[i] = '0';
      //end
#ifdef spliturl_ruleset_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
		    "XX-extract  [%V]=[%V]", &(name), &(val));
#endif
      if (rules)
	ngx_http_basestr_ruleset_n(pool, &name, &val, rules, req,  ctx, zone);
#ifdef spliturl_ruleset_debug
      else
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
		      "XX-no arg rules ?");
#endif	  

	
      if (main_rules)
	ngx_http_basestr_ruleset_n(pool, &name, &val, main_rules, req,  ctx, 
				   zone);
#ifdef spliturl_ruleset_debug
      else
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
		      "XX-no main rules ?");
#endif	  
    }
    str += len; 
  }

  return (0);
}

    /*
    ** check variable + name against a set of rules, checking against 'custom' location rules too.
    */
#define basestr_ruleset_debug

    int 
      ngx_http_basestr_ruleset_n(ngx_pool_t *pool,
				 ngx_str_t	*name,
				 ngx_str_t	*value,
				 ngx_array_t *rules,
				 ngx_http_request_t *req,
				 ngx_http_request_ctx_t *ctx,
				 enum DUMMY_MATCH_ZONE	zone)
    {
      ngx_http_rule_t		   *r;
      unsigned int			   i, ret, z;
      ngx_int_t			   nb_match;
      ngx_http_custom_rule_location_t *location;
      ngx_http_dummy_loc_conf_t	*cf;
  
#ifdef basestr_ruleset_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		    "XX-check check [%V]=[%V] in zone %s", name, value,
		    zone == BODY ? "BODY" : zone == HEADERS ? "HEADERS" : zone == URL ? "URL" :
		    zone == ARGS ? "ARGS" : "UNKNOWN"); 
#endif
  
      if (!rules) {
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		      "XX-no rules, wtf ?!"); 
	return (0);
      }
      r = rules->elts;
      cf = ngx_http_get_module_loc_conf(req, ngx_http_naxsi_module);
#ifdef basestr_ruleset_debug 
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		    "XX-checking rules ..."); 
#endif
  
      for (i = 0; i < rules->nelts && (!ctx->block || cf->learning) ; i++) {
#ifdef basestr_ruleset_debug 
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
		      "XX-rule %d (%V=%V)", r[i].rule_id, name, value); 
#endif
      
	/* does the rule have a custom location ? custom location means checking only on a specific argument */
	if (name && name->len > 0 && r[i].br->custom_location) {
	  location = r[i].br->custom_locations->elts;
	  /* for each custom location */
	  for (z = 0; z < r[i].br->custom_locations->nelts; z++) {
	    /* if the name are the same, check */
	    if (name->len == location[z].target.len &&
		!strncasecmp((const char *)name->data, 
			     (const char *) location[z].target.data, 
			     location[z].target.len)) {
	    
#ifdef basestr_ruleset_debug
	      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
			    "XX-[SPECIFIC] check one rule [%d] iteration %d * %d", r[i].rule_id, i, z);
#endif
	      /* match rule against var content, */
	      ret = ngx_http_process_basic_rule_buffer(value, &(r[i]), &nb_match);
	      //if our rule matched, apply effects (score etc.)
	      if (ret == 1) {
#ifdef basestr_ruleset_debug
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
			      "XX-apply rulematch!! [%V]=[%V] [rule=%d] (match %d times)", name, value, r[i].rule_id, nb_match); 
#endif
		ngx_http_apply_rulematch_v_n(&(r[i]), ctx, req, name, value, zone, nb_match, 0);	    
	      }
	  
	      if (!r[i].br->negative) {  
		/* match rule against var name, */
		ret = ngx_http_process_basic_rule_buffer(name, &(r[i]), &nb_match);
		//if our rule matched, apply effects (score etc.)
		if (ret == 1) {
#ifdef basestr_ruleset_debug
		  ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
				"XX-apply rulematch[in name] [%V]=[%V] [rule=%d] (match %d times)", name, value, r[i].rule_id, nb_match); 
#endif
		  ngx_http_apply_rulematch_v_n(&(r[i]), ctx, req, name, name, zone, nb_match, 1);
		}
	      }
	  
	    }
	  }
      
	}
    
    
    
	/*
	** check against the rule if the current zone is matching 
	** the zone the rule is meant to be check against
	*/
	if ( (zone == HEADERS && r[i].br->headers) ||
	     (zone == URL && r[i].br->url) ||
	     (zone == ARGS && r[i].br->args) ||
	     (zone == BODY && r[i].br->body && !r[i].br->file_ext) ||
	     (zone == FILE_EXT && r[i].br->file_ext) ) {

	  /* #ifdef basestr_ruleset_debug */
	  /* 	ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,  */
	  /* 		      "XX-check [%V]=[%V] [rule=%d] (%d times)", name, value, r[i].rule_id, nb_match);  */
	  /* #endif */

#ifdef basestr_ruleset_debug
	  ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
			"XX-test rulematch!1 [%V]=[%V] [rule=%d] (%d times)", name, value, r[i].rule_id, nb_match); 
#endif
    
	  /* check the rule against the value*/
	  ret = ngx_http_process_basic_rule_buffer(value, &(r[i]), &nb_match);
	  /*if our rule matched, apply effects (score etc.)*/
	  if (ret == 1) {
#ifdef basestr_ruleset_debug
	    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
			  "XX-apply rulematch!1 [%V]=[%V] [rule=%d] (%d times)", name, value, r[i].rule_id, nb_match); 
#endif
	    ngx_http_apply_rulematch_v_n(&(r[i]), ctx, req, name, value, zone, nb_match, 0);
	  }
    
	  if (!r[i].br->negative) {
#ifdef basestr_ruleset_debug
	    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
			  "XX-test rulematch!1 [%V]=[%V] [rule=%d] (%d times)", name, value, r[i].rule_id, nb_match); 
#endif
	    /* check the rule against the name*/
	    ret = ngx_http_process_basic_rule_buffer(name, &(r[i]), &nb_match);
	    /*if our rule matched, apply effects (score etc.)*/
	    if (ret == 1) {
#ifdef basestr_ruleset_debug
	      ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0, 
			    "XX-apply rulematch!1 [%V]=[%V] [rule=%d] (%d times)", name, value, r[i].rule_id, nb_match); 
#endif
	      ngx_http_apply_rulematch_v_n(&(r[i]), ctx, req, name, value, zone, nb_match, 1);
	    }
	  }
	}
      }
      return (0);
    }
  



    /*
    ** does : parse body data, a.k.a POST/PUT datas. identifies content-type,
    **	  and, if appropriate, boundary. then parse the stuff if multipart/for..
    **	  or rely on spliturl if application/x-w..
    ** [XXX] : this function sucks ! I don't parse bigger-than-body-size posts that 
    **	   are partially stored in files, TODO ;)
    */
    //#define post_heavy_debug
    //#define dummy_body_parse_debug
    void	ngx_http_dummy_multipart_parse(ngx_http_request_ctx_t *ctx, 
					       ngx_http_request_t	 *r,
					       u_char			*src,
					       u_int			 len)
    {
      ngx_str_t				final_var, final_data;
      char				*boundary, *varn_start, *varn_end;
      char				*filen_start, *filen_end;
      char				*end, *line_end;
      u_int				boundary_len, varn_len, varc_len, idx;
      ngx_http_dummy_loc_conf_t		*cf;
      ngx_http_dummy_main_conf_t		*main_cf;
  
      cf = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
      main_cf = ngx_http_get_module_main_conf(r, ngx_http_naxsi_module);
  
#ifdef post_heavy_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		    "XX-multipart/form-data");
#endif
      /* So far, I have noticed to correct ways of putting the boundary in a multipart post :
      ** 1: in the content-type header, after multipart/form-data
      ** 2: at the very begining of the body. */
      /*extract boundary*/
      boundary = ngx_strstr(src, "boundary=");
      if (!boundary)
	boundary = ngx_strstr(r->headers_in.content_type->value.data, "boundary=");
      if (!boundary)
	{
	  dummy_error_fatal(ctx, r, "no boundary present in POST data ?");
	  return ;
	}
      boundary += 9; //strlen ("boundary=")
      boundary_len = strlen(boundary);
   
      /* fetch every line starting with boundary */
      idx = 0;
      while (idx < len) {
#ifdef post_heavy_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		      "XX-POST data : (%s)", src+idx);
#endif
	//dummy_error_fatal(ctx, r, "POST data : (%s)", src+idx);
	/* if we've reached the last boundary '--' + boundary + '--' + '\r\n'*/
	if (idx+boundary_len+6 >= len)
	  {
#ifdef post_heavy_debug
	    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			  "XX-reached end, not enough len");
#endif
	    break;
	  }
	//check if line starts with -- (pre-boundary stuff) 
	if (src[idx] != '-' || src[idx+1] != '-' || 
	    //and if it's really followed by a boundary
	    ngx_strncmp(src+idx+2, boundary, boundary_len) || 
	    //and if it's not the last boundary of the buffer
	    idx+boundary_len + 2 + 2  >= len ||  
	    //and if it's followed by \r\n
	    src[idx+boundary_len+2] != '\r' || src[idx+boundary_len+3] != '\n') {
      
	  dummy_error_fatal(ctx, r, "POST data is malformed (%s)", src+idx);
	  return ;
	}
	idx += boundary_len + 4;
	/* we have two cases :
	** ---- file upload
	** Content-Disposition: form-data; name="somename"; filename="NetworkManager.conf"\r\n
	** Content-Type: application/octet-stream\r\n\r\n
	** <DATA>
	** ---- normal post var
	** Content-Disposition: form-data; name="lastname"\r\n\r\n
	** <DATA>
	*/
	if (ngx_strncasecmp(src+idx, 
			    (u_char *) "content-disposition: form-data;", 30)) {
	  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"Unknown content-type: [%s]", src+idx);
	  dummy_error_fatal(ctx, r, "POST data : unknown content-disposition");
      
	  return ;
	}
	idx += 30;
	line_end = ngx_strchr(src+idx, '\n');
	if (!line_end) {
	  dummy_error_fatal(ctx, r, "POST data : malformed boundary line");
	  return ;
	}
	// seek for name="<var>" and filename="<var>" in the current line
	// verify that the name/filename tag founds are present
	varn_end = filen_end = NULL;
	varn_start = ngx_strstr(src+idx, "name=\"");
	if (varn_start && varn_start < line_end) {
	  varn_start += 6;
	  varn_end = ngx_strchr(varn_start, '"');
	}
	else
	  varn_start = NULL;
	filen_start = ngx_strstr(src+idx, "filename=\"");
	if (filen_start && filen_start < line_end) {
	  filen_start += 10;
	  /* avoid being bypassed by filenames like bla\"aa.php */
	  filen_end = filen_start;
	  do {
	    filen_end = ngx_strchr(filen_end, '"');
	    if (*(filen_end - 1) != '\\')
	      break;
	    filen_end++;
	  } while (filen_end < line_end);
	  /* here add support :
	  ** - when a file is here, the line bellow 'content-disposition' is content-type.
	  ** - skip this line. we should probably parse it ... to make regex on it :D
	  */
	  line_end = ngx_strchr(line_end+1, '\n');
	  if (!line_end) {
	    dummy_error_fatal(ctx, r, "POST data : malformed 'filename' field");
	    return ;
	  }
	}
	else
	  filen_start = NULL;
	  
	// check that var name is present and not malformed
	if (!varn_start || !varn_end || varn_end <= varn_start) {
	  dummy_error_fatal(ctx, r, "POST data : no 'name' in POST var");
	  return ;
	}
	varn_len = varn_end - varn_start;
	// now idx point to the end of the
	// content-disposition: form-data; filename="" name=""
	idx += (u_char *)line_end - (src+idx) + 1;
	if (src[idx] != '\r' || src[idx+1] != '\n') {
	  dummy_error_fatal(ctx, r, "POST data : malformed content-disposition line");
	  return ;
	}
	idx += 2;
	// seek the end of the data too
	end = NULL;
	while (idx < len) {
	  end = ngx_strstr(src+idx, "\r\n--");
	  if (!end) {
	    dummy_error_fatal(ctx, r, "POST data : malformed content-disposition line");
	    return ;
	  }
	  if (!ngx_strncmp(end+4, boundary, boundary_len))
	    break;
	  else {
	    idx += ((u_char *) end - (src+idx)) + 1;
	    end = NULL;
	  }
	}
	if (!end) {
	  dummy_error_fatal(ctx, r, "POST data : malformed line");
	  return ;
	}
	if (filen_start) {
	  final_var.data = (unsigned char *)varn_start;
	  final_var.len = varn_len;
	  final_data.data = (unsigned char *)filen_start;
	  final_data.len = filen_end - filen_start;
#ifdef post_heavy_debug
	  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"[POST] checking filename [%V] = [%V]",
			&final_var, &final_data);
#endif
	  /* here we got val name + val content !*/	      
	  if (cf->body_rules)
	    ngx_http_basestr_ruleset_n(r->pool, &final_var, &final_data,
				       cf->body_rules, r, ctx, FILE_EXT);
#ifdef post_heavy_debug
	  else
	    /* here we got val name + val content !*/	      
	    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			  "No local body rules ?!");
#endif
		
	  if (main_cf->body_rules)
	    ngx_http_basestr_ruleset_n(r->pool, &final_var, &final_data,
				       main_cf->body_rules, r, ctx, FILE_EXT);
#ifdef post_heavy_debug
	  else
	    /* here we got val name + val content !*/	      
	    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			  "No main body rules ?!");
#endif
      
	  idx += (u_char *) end - (src+idx);
	}
	else
	  if (varn_start) {
	    varc_len = (u_char *) end - (src+idx);
	    final_var.data = (unsigned char *)varn_start;
	    final_var.len = varn_len;
	    final_data.data = src+idx;
	    final_data.len = varc_len;
#ifdef post_heavy_debug
	    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			  "[POST] [%V]=[%V]",
			  &final_var, &final_data);
#endif
	    /* here we got val name + val content !*/	      
	    if (cf->body_rules)
	      ngx_http_basestr_ruleset_n(r->pool, &final_var, &final_data,
					 cf->body_rules, r, ctx, BODY);
#ifdef post_heavy_debug
	    else
	      /* here we got val name + val content !*/	      
	      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			    "No local body rules ?!");
#endif
		
	    if (main_cf->body_rules)
	      ngx_http_basestr_ruleset_n(r->pool, &final_var, &final_data,
					 main_cf->body_rules, r, ctx, BODY);
#ifdef post_heavy_debug
	    else
	      /* here we got val name + val content !*/	      
	      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			    "No main body rules ?!");
#endif
	      
	    idx += (u_char *) end - (src+idx);
	  }
	  else {
	    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			  "(multipart) : ");

	  }
	if (!ngx_strncmp(end, "\r\n", 2))
	  idx += 2;
      }
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		    "(multipart) : OVER");

    }

    //#define dummy_body_parse_debug

    void	
      ngx_http_dummy_body_parse(ngx_http_request_ctx_t *ctx, 
				ngx_http_request_t	 *r,
				ngx_http_dummy_loc_conf_t *cf,
				ngx_http_dummy_main_conf_t *main_cf)
    {
      u_char			*src; 
      ngx_str_t			tmp;
      ngx_chain_t			*bb;
      u_char			*full_body;
      u_int				full_body_len;
  
  
#ifdef dummy_body_parse_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		    "XX-BODY PARSE");
#endif
      if (!r->request_body->bufs || !r->headers_in.content_type) {
#ifdef dummy_body_parse_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		      "XX-No content type ..");
#endif
	if (ngx_http_dummy_is_rule_whitelisted_n(r, cf, &nx_int__weird_request, NULL, BODY, 0) == 0)
	  ctx->weird_request = 1;
	return ;
      }

      if (r->request_body->temp_file) {
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		      "naxsi: POST REQUEST to temp_file, partially parsed.");
	if (ngx_http_dummy_is_rule_whitelisted_n(r, cf, &nx_int__big_request, NULL, BODY, 0) == 0)
	  ctx->big_request = 1;
	return ;
      }

#ifdef dummy_body_parse_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		    "XX-VALID BODY");
#endif
      /* request body in single buffer */
      if (r->request_body->bufs->next == NULL) {
	full_body_len = (u_int) (r->request_body->bufs->buf->last - 
				 r->request_body->bufs->buf->pos);
	full_body =  ngx_pcalloc(r->pool, (u_int) (full_body_len+1));
	memcpy(full_body, r->request_body->bufs->buf->pos, full_body_len);
      }
      /* request body in chain */
      else {
#ifdef dummy_body_parse_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		      "[POST] REQUEST BODY IN CHAIN !");
#endif
	for (full_body_len = 0, bb = r->request_body->bufs; bb; bb = bb->next)
	  full_body_len += (bb->buf->last - bb->buf->pos);
	full_body = ngx_pcalloc(r->pool, full_body_len+1);
	src = full_body;
	if (!full_body) 
	  return ;
	for(bb = r->request_body->bufs ; bb ; bb = bb->next)
	  full_body = ngx_cpymem(full_body, bb->buf->pos, 
				 bb->buf->last - bb->buf->pos);
	full_body = src;
#ifdef dummy_body_parse_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		      "[POST] REQUEST BODY IN CHAIN [%s] (len=%d)", 
		      full_body, full_body_len);
#endif
      }
#ifdef dummy_body_parse_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		    "content-len header (%d) mismatch actual len (%d) ??", 
		    r->headers_in.content_length_n, full_body_len);
#endif
      /* File probably got buffered. */
      if (r->headers_in.content_length_n != full_body_len) {
	if (ngx_http_dummy_is_rule_whitelisted_n(r, cf, &nx_int__weird_request, NULL, BODY, 0) == 0)
	  ctx->weird_request = 1;
	return ;
      }
      /* x-www-form-urlencoded POSTs */
      //33 = echo -n "application/x-www-form-urlencoded" | wc -c
      if (!ngx_strncasecmp(r->headers_in.content_type->value.data, 
			   (u_char *)"application/x-www-form-urlencoded", 33)) {
#ifdef post_heavy_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		      "XX-application/x-www..");
#endif
	tmp.len = full_body_len;
	tmp.data = full_body;

#ifdef post_heavy_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		      "XX-POST DATA [%V]", &tmp);
#endif
	if(ngx_http_spliturl_ruleset(r->pool, (char *)tmp.data, 
				     cf->body_rules, main_cf->body_rules, 
				     r, ctx, BODY)) {
#ifdef post_heavy_debug
	  dummy_error_fatal(ctx, r, "spliturl failed, someone is trying to trick us");
#endif
	  if (ngx_http_dummy_is_rule_whitelisted_n(r, cf, &nx_int__weird_request, NULL, BODY, 0) == 0)
	    ctx->weird_request = 1;
	  return ;
	}
      }
      //19 = echo -n "multipart/form-data" | wc -c
      else if (!ngx_strncasecmp(r->headers_in.content_type->value.data, 
				(u_char *) "multipart/form-data", 19)) {
	ngx_http_dummy_multipart_parse(ctx, r, full_body, full_body_len);
      }
      else {
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
		      "[POST] Unknown content-type, gtfo");
	if (ngx_http_dummy_is_rule_whitelisted_n(r, cf, &nx_int__weird_request, NULL, BODY, 0) == 0)
	  ctx->weird_request = 1;
      }
    }



    /*
    ** does : bui ! this is a 'main' function, all the stuff goes from here.
    **	  to make it short, it does the following :
    ** - if we got header rules, apply header_rules on each.
    ** - apply generic_rules on url decoded URI.
    ** - if we got get_rules and get args, apply get_rules varname/value couple.
    ** - if we are in a POST/PUT request and we got body_rules, apply rules :)
    */
    void	
      ngx_http_dummy_uri_parse(ngx_http_dummy_main_conf_t *main_cf, 
			       ngx_http_dummy_loc_conf_t *cf, 
			       ngx_http_request_ctx_t *ctx, ngx_http_request_t *r)
    {
      ngx_str_t			tmp, name;
  
      if (!r->uri.len)
	return ;
      if (ctx->block && !cf->learning)
	return ;
      if (!main_cf->generic_rules && !cf->generic_rules) {
	dummy_error_fatal(ctx, r, "no generic rules ?!");
	return ;
      }
      tmp.len = r->uri.len;
      tmp.data = ngx_pcalloc(r->pool, r->uri.len+1);
      if (!tmp.data) {
	dummy_error_fatal(ctx, r, "failed alloc of %d", r->uri.len+1);
	return ;
      }
      memcpy(tmp.data, r->uri.data, r->uri.len);
      name.data = NULL;
      name.len = 0;
      if (cf->generic_rules)
	ngx_http_basestr_ruleset_n(r->pool, &name, &tmp, cf->generic_rules, 
				   r, ctx, URL);
      if (main_cf->generic_rules)
	ngx_http_basestr_ruleset_n(r->pool, &name, &tmp, main_cf->generic_rules, 
				   r, ctx, URL);
      ngx_pfree(r->pool, tmp.data);
    }

    void	
      ngx_http_dummy_args_parse(ngx_http_dummy_main_conf_t *main_cf, 
				ngx_http_dummy_loc_conf_t *cf, 
				ngx_http_request_ctx_t *ctx, ngx_http_request_t *r)
    {
      ngx_str_t			tmp;
  
      if (ctx->block && !cf->learning)
	return ;
      if (!r->args.len)
	return ;
      if (!cf->get_rules && !main_cf->get_rules)
	return ;
      tmp.len = r->args.len;
      tmp.data = ngx_pcalloc(r->pool, r->args.len+1);
      if (!tmp.data) {
	dummy_error_fatal(ctx, r, "failed alloc");
	return ;
      }
      memcpy(tmp.data, r->args.data, r->args.len);
      if(ngx_http_spliturl_ruleset(r->pool, (char *)tmp.data, 
				   cf->get_rules, main_cf->get_rules, r, 
				   ctx, ARGS)) {
	dummy_error_fatal(ctx, r, 
			  "spliturl error : malformed url, possible attack");
	return ;
      }
      ngx_pfree(r->pool, tmp.data);
    }

    void	
      ngx_http_dummy_headers_parse(ngx_http_dummy_main_conf_t *main_cf, 
				   ngx_http_dummy_loc_conf_t *cf, 
				   ngx_http_request_ctx_t *ctx, ngx_http_request_t *r)
    {
      ngx_list_part_t	    *part;
      ngx_table_elt_t	    *h;
      unsigned int		     i;

      if (!cf->header_rules && !main_cf->header_rules)
	return ;
      // this check may be removed, as it shouldn't be needed anymore !
      if (ctx->block && !cf->learning)
	return ;
      part = &r->headers_in.headers.part;
      h = part->elts;
      // this check may be removed, as it shouldn't be needed anymore !
      for (i = 0; !ctx->block ; i++) {
	if (i >= part->nelts) {
	  if (part->next == NULL) 
	    break;
	  part = part->next;
	  h = part->elts;
	  i = 0;
	}
	if (cf->header_rules)
	  ngx_http_basestr_ruleset_n(r->pool, &(h[i].key), &(h[i].value), 
				     cf->header_rules, r, ctx, HEADERS);
	if (main_cf->header_rules)
	  ngx_http_basestr_ruleset_n(r->pool, &(h[i].key), &(h[i].value), 
				     main_cf->header_rules, r, ctx, HEADERS);
      }
      return ;
    }

    void	
      ngx_http_dummy_data_parse(ngx_http_request_ctx_t *ctx, 
				ngx_http_request_t	 *r)
    {
      ngx_http_dummy_loc_conf_t	*cf;
      ngx_http_dummy_main_conf_t	*main_cf;
      ngx_http_core_main_conf_t  *cmcf;

      cf = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
      cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
      main_cf = ngx_http_get_module_main_conf(r, ngx_http_naxsi_module);
      if (!cf || !ctx || !cmcf) {
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		      "XX-UNABLE TO PARSE IN DATA PARSE !!");
	return ;
      }
      /* process rules only if request is not already blocked or if
	 the learning mode is enabled */
      ngx_http_dummy_headers_parse(main_cf, cf, ctx, r);
      //check uri
      ngx_http_dummy_uri_parse(main_cf, cf, ctx, r);
      //check args
      ngx_http_dummy_args_parse(main_cf, cf, ctx, r);
      // check method
      if ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT) && 
	  //presence of body rules (POST/PUT rules)
	  (cf->body_rules || main_cf->body_rules) && 
	  //and the presence of data to parse
	  r->request_body && (!ctx->block || cf->learning)) 
	ngx_http_dummy_body_parse(ctx, r, cf, main_cf);
      ngx_http_dummy_update_current_ctx_status(ctx, cf, r);
    }



    //#define custom_score_debug
    void	
      ngx_http_dummy_update_current_ctx_status(ngx_http_request_ctx_t	*ctx, 
					       ngx_http_dummy_loc_conf_t	*cf, 
					       ngx_http_request_t *r)
    {
      unsigned int	i, z, matched;
      ngx_http_check_rule_t		*cr;
      ngx_http_special_score_t	*sc;
      /* ngx_http_whitelist_rule_t	*b; */
      /* //ngx_http_whitelist_location_t	*cl; */
      /* ngx_int_t			k; */
      //ngx_int_t			*tmp_ptr;

#ifdef custom_score_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		    "XX-custom check rules");
#endif
      if (ctx->weird_request) {
#ifdef custom_score_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		      "XX-blocking, weird_request flag set");
#endif
	ctx->block = 1;
      }
      if (ctx->big_request) {
#ifdef custom_score_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		      "XX-blocking unexpected big request");
#endif
	ctx->block = 1;
      }
      /*cr, sc, cf, ctx*/
      if (cf->check_rules && ctx->special_scores) {
#ifdef custom_score_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		      "XX-we have custom check rules and CTX got special score :)");
#endif
	cr = cf->check_rules->elts;
	sc = ctx->special_scores->elts;
	for (z = 0; z < ctx->special_scores->nelts; z++)
	  for (i = 0; i < cf->check_rules->nelts; i++) {
#ifdef custom_score_debug
	    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			  "XX- rule says :(%s:%d) vs current context:(%s:%d) (flag=%d)",
			  cr[i].sc_tag.data, cr[i].sc_score,
			  sc[z].sc_tag->data, sc[z].sc_score, cr[i].cmp);
#endif
	    if (!ngx_strcmp(sc[z].sc_tag->data, cr[i].sc_tag.data)) {
#ifdef custom_score_debug
	      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			    "XX- rule says :(%s:%d) vs current context:(%s:%d) (flag=%d)",
			    cr[i].sc_tag.data, cr[i].sc_score,
			    sc[z].sc_tag->data, sc[z].sc_score, cr[i].cmp);
#endif
	      matched=0;
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
#ifdef custom_score_debug
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			      "XX- custom score rule triggered ..");
#endif

		if (cr[i].block)
		  ctx->block = 1;
		if (cr[i].allow)
		  ctx->allow = 1;
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
    //#define payload_handler_debug
    void 
      ngx_http_dummy_payload_handler(ngx_http_request_t *r) {
      ngx_http_request_ctx_t  *ctx;
      ctx = ngx_http_get_module_ctx(r, ngx_http_naxsi_module);
      ctx->ready = 1;
      r->count--;
#ifdef payload_handler_debug
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		    "XX-dummy PAYLOAD HANDLER !");
#endif
      if (ctx->wait_for_body) {
#ifdef payload_handler_debug
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		      "XX-dummy : AFTER NGX_AGAIN");
#endif
	ctx->wait_for_body = 0;
	ngx_http_core_run_phases(r);
      }
    }

