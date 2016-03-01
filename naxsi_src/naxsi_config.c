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
/*
** TOP LEVEL configuration parsing code
*/
/*
** code to parse FLAGS and OPTIONS on each line.
*/
void *dummy_id(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule);
void *dummy_score(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule);
void *dummy_msg(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule);
void *dummy_rx(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule);
void *dummy_zone(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule);
void *dummy_str(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule);
void	*dummy_negative(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule);
void	*dummy_whitelist(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule);
/*
** Structures related to the configuration parser
*/
typedef struct  {
  char	*prefix;
  void	*(*pars)(ngx_conf_t *, ngx_str_t *, ngx_http_rule_t *);
} ngx_http_dummy_parser_t;



static ngx_http_dummy_parser_t rule_parser[] = {
  {ID_T, dummy_id},
  {SCORE_T, dummy_score},
  {MSG_T, dummy_msg},
  {RX_T, dummy_rx},
  {STR_T, dummy_str},
  {MATCH_ZONE_T, dummy_zone},
  {NEGATIVE_T, dummy_negative},
  {WHITELIST_T, dummy_whitelist},
  {NULL, NULL}
};



void	*
dummy_negative(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  rule->br->negative = 1;
  return (NGX_CONF_OK);
}

void	*
dummy_score(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  int				score, len;
  char				*tmp_ptr, *tmp_end;
  ngx_http_special_score_t	*sc;
  
  rule->score = 0;
  rule->block = 0;
  rule->allow = 0;
  rule->drop = 0;
  tmp_ptr = (char *) (tmp->data + strlen(SCORE_T));
  NX_LOG_DEBUG(_debug_score, NGX_LOG_EMERG, r, 0,
	       "XX-(debug) dummy score (%V)",
	       tmp);
  /*allocate scores array*/
  if (!rule->sscores) {
    rule->sscores = ngx_array_create(r->pool, 1, sizeof(ngx_http_special_score_t));
  }

  while (*tmp_ptr) { 
    if (tmp_ptr[0] == '$') {
      NX_LOG_DEBUG(_debug_score, NGX_LOG_EMERG, r, 0,
		   "XX-(debug) special scoring rule (%s)",
		   tmp_ptr);
      tmp_end = strchr(tmp_ptr, ':');
      if (!tmp_end)
	return (NGX_CONF_ERROR);
      len = tmp_end - tmp_ptr;
      if (len <= 0)
	return (NGX_CONF_ERROR);
      sc = ngx_array_push(rule->sscores);
      if (!sc)
	return (NGX_CONF_ERROR);
      sc->sc_tag = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
      if (!sc->sc_tag)
	return (NGX_CONF_ERROR);
      sc->sc_tag->data = ngx_pcalloc(r->pool, len+1);
      if (!sc->sc_tag->data)
	return (NGX_CONF_ERROR);
      //memset(rule->sc_tag->data, 0, len+1);
      memcpy(sc->sc_tag->data, tmp_ptr, len);
      sc->sc_tag->len = len;
      sc->sc_score = atoi(tmp_end+1);
      NX_LOG_DEBUG(_debug_score, NGX_LOG_EMERG, r, 0,
		   "XX-(debug) special scoring (%V) => (%d)",
		   sc->sc_tag, sc->sc_score);
      
      /* move to end of score. */
      while ( /*don't overflow*/((unsigned int)((unsigned char *)tmp_ptr - tmp->data)) < tmp->len &&
	      /*and seek for next score */ *tmp_ptr != ',')
	++tmp_ptr;
    }
    else if (tmp_ptr[0] == ',')
      ++tmp_ptr;
    else if (!strcasecmp(tmp_ptr, "BLOCK")) {
      rule->block = 1;
      tmp_ptr += 5;
    }
    else if (!strcasecmp(tmp_ptr, "DROP")) {
      rule->drop = 1;
      tmp_ptr += 4;
    }
    else if (!strcasecmp(tmp_ptr, "ALLOW")) {
      rule->allow = 1;
      tmp_ptr += 5;
    }
    else if (!strcasecmp(tmp_ptr, "LOG")) {
      rule->log = 1;
      tmp_ptr += 3;
    }
    
    //or maybe you just want to assign a score
    else if ( (tmp_ptr[0] >= '0' && tmp_ptr[0] <= '9') || tmp_ptr[0] == '-') {
      score = atoi((const char *)tmp->data+2);
      rule->score = score;
      break;
    }
    else
      return (NGX_CONF_ERROR);
  }
#if defined(_debug_score) && _debug_score != 0
  unsigned int z;
  ngx_http_special_score_t	*scr;
  scr = rule->sscores->elts;
  if (rule->sscores) {
    for (z = 0; z < rule->sscores->nelts; z++) {
      ngx_conf_log_error(NGX_LOG_EMERG, r, 0,
			 "XX-score n°%d special scoring (%V) => (%d)",
			 z, scr[z].sc_tag, scr[z].sc_score);
      
    }
  }
  else
    ngx_conf_log_error(NGX_LOG_EMERG, r, 0,
		       "XX-no custom scores for this rule.");
#endif
  return (NGX_CONF_OK);
}

void	*
dummy_zone(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  int					tmp_len;
  ngx_http_custom_rule_location_t	*custom_rule;
  char *tmp_ptr, *tmp_end;


  if (!rule->br)
    return (NGX_CONF_ERROR);
  
  tmp_ptr = (char *) tmp->data+strlen(MATCH_ZONE_T);
  while (*tmp_ptr) {
    
    if (tmp_ptr[0] == '|')
      tmp_ptr++;
    /* match global zones */
    if (!strncmp(tmp_ptr, "RAW_BODY", strlen("RAW_BODY"))) {
      rule->br->raw_body = 1;
      tmp_ptr += strlen("RAW_BODY");
      continue;
    }
    else
      if (!strncmp(tmp_ptr, "BODY", strlen("BODY"))) {
	rule->br->body = 1;
	tmp_ptr += strlen("BODY");
	continue;
      }
      else
	if (!strncmp(tmp_ptr, "HEADERS", strlen("HEADERS"))) {
	  rule->br->headers = 1;
	  tmp_ptr += strlen("HEADERS");
	  continue;
	}
	else
	  if (!strncmp(tmp_ptr, "URL", strlen("URL"))) {
	    rule->br->url = 1;
	    tmp_ptr += strlen("URL");
	    continue;
	  }
	  else
	    if (!strncmp(tmp_ptr, "ARGS", strlen("ARGS"))) {
	      rule->br->args = 1;
	      tmp_ptr += strlen("ARGS");
	      continue;
	    }
	    else
	      /* match against variable name*/
	      if (!strncmp(tmp_ptr, "NAME", strlen("NAME"))) {
		rule->br->target_name = 1;
		tmp_ptr += strlen("NAME");
		continue;
	      }
	      else
		/* for file_ext, just push'em in the body rules.
		   when multipart parsing comes in, it'll tag the zone as
		   FILE_EXT as the rule will be pushed in body rules it'll be 
		   checked !*/
		if (!strncmp(tmp_ptr, "FILE_EXT", strlen("FILE_EXT"))) {
		  rule->br->file_ext = 1;
		  rule->br->body = 1;
		  tmp_ptr += strlen("FILE_EXT");
		  continue;
		}
		else
		  /* custom match  zones */
#define MZ_GET_VAR_T "$ARGS_VAR:"
#define MZ_HEADER_VAR_T "$HEADERS_VAR:"
#define MZ_POST_VAR_T "$BODY_VAR:"
#define MZ_SPECIFIC_URL_T "$URL:"
		  //probably a custom zone
		  if (tmp_ptr[0] == '$') {
		    // tag as a custom_location rule.
		    rule->br->custom_location = 1;
		    if (!rule->br->custom_locations) {
		      rule->br->custom_locations = ngx_array_create(r->pool, 1, 
								    sizeof(ngx_http_custom_rule_location_t));
		      if (!rule->br->custom_locations)
			return (NGX_CONF_ERROR);
		    }
		    custom_rule = ngx_array_push(rule->br->custom_locations);
		    if (!custom_rule)
		      return (NGX_CONF_ERROR);
		    memset(custom_rule, 0, sizeof(ngx_http_custom_rule_location_t));
		    if (!strncmp(tmp_ptr, MZ_GET_VAR_T, strlen(MZ_GET_VAR_T))) {
		      custom_rule->args_var = 1;
		      rule->br->args_var = 1;
		      tmp_ptr += strlen(MZ_GET_VAR_T);
		    }
		    else if (!strncmp(tmp_ptr, MZ_POST_VAR_T, 
				      strlen(MZ_POST_VAR_T))) {
		      custom_rule->body_var = 1;
		      rule->br->body_var = 1;
		      tmp_ptr += strlen(MZ_POST_VAR_T);
		    }
		    else if (!strncmp(tmp_ptr, MZ_HEADER_VAR_T, 
				      strlen(MZ_HEADER_VAR_T))) {
		      custom_rule->headers_var = 1;
		      rule->br->headers_var = 1;
		      tmp_ptr += strlen(MZ_HEADER_VAR_T);
		    }
		    else if (!strncmp(tmp_ptr, MZ_SPECIFIC_URL_T, 
				      strlen(MZ_SPECIFIC_URL_T))) { 
		      custom_rule->specific_url = 1; 
		      tmp_ptr += strlen(MZ_SPECIFIC_URL_T);
		    }
		    else 
		      /* add support for regex-style match zones. 
		      ** this whole function should be rewritten as it's getting
		      ** messy as hell
		      */
#define MZ_GET_VAR_X "$ARGS_VAR_X:"
#define MZ_HEADER_VAR_X "$HEADERS_VAR_X:"
#define MZ_POST_VAR_X "$BODY_VAR_X:"
#define MZ_SPECIFIC_URL_X "$URL_X:"
		      if (!strncmp(tmp_ptr, MZ_GET_VAR_X, strlen(MZ_GET_VAR_X))) {
			custom_rule->args_var = 1;
			rule->br->args_var = 1;
			rule->br->rx_mz = 1;
			tmp_ptr += strlen(MZ_GET_VAR_X);
		      }
		      else if (!strncmp(tmp_ptr, MZ_POST_VAR_X, 
					strlen(MZ_POST_VAR_X))) {
			rule->br->rx_mz = 1;
			custom_rule->body_var = 1;
			rule->br->body_var = 1;
			tmp_ptr += strlen(MZ_POST_VAR_X);
		      }
		      else if (!strncmp(tmp_ptr, MZ_HEADER_VAR_X, 
					strlen(MZ_HEADER_VAR_X))) {
			custom_rule->headers_var = 1;
			rule->br->headers_var = 1;
			rule->br->rx_mz = 1;
			tmp_ptr += strlen(MZ_HEADER_VAR_X);
		      }
		      else if (!strncmp(tmp_ptr, MZ_SPECIFIC_URL_X, 
					strlen(MZ_SPECIFIC_URL_X))) { 
			custom_rule->specific_url = 1;
			rule->br->rx_mz = 1;
			tmp_ptr += strlen(MZ_SPECIFIC_URL_X);
		      }
		      else 
			return (NGX_CONF_ERROR);
		  
		    /*		  else 
				  return (NGX_CONF_ERROR);*/
		    tmp_end = strchr((const char *) tmp_ptr, '|');
		    if (!tmp_end) 
		      tmp_end = tmp_ptr + strlen(tmp_ptr);
		    tmp_len = tmp_end - tmp_ptr;
		    if (tmp_len <= 0)
		      return (NGX_CONF_ERROR);
		    custom_rule->target.data = ngx_pcalloc(r->pool, tmp_len+1);
		    if (!custom_rule->target.data)
		      return (NGX_CONF_ERROR);
		    custom_rule->target.len = tmp_len;
		    memcpy(custom_rule->target.data, tmp_ptr, tmp_len);
		    custom_rule->hash = ngx_hash_key_lc(custom_rule->target.data, 
							custom_rule->target.len);

		    NX_LOG_DEBUG(_debug_zone, NGX_LOG_EMERG, r, 0, "XX- ZONE:[%V]", 
				 &(custom_rule->target));  
		    tmp_ptr += tmp_len;
		    continue;
		  }
		  else
		    return (NGX_CONF_ERROR);
  }
  return (NGX_CONF_OK);
}

void	*
dummy_id(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  rule->rule_id = atoi((const char *) tmp->data+strlen(ID_T));
  return (NGX_CONF_OK);
}

void	*
dummy_str(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  ngx_str_t	*str;
  uint		i;
  
  if (!rule->br)
    return (NGX_CONF_ERROR);
  str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
  if (!str)
    return (NGX_CONF_ERROR);
  str->data = tmp->data + strlen(STR_T);
  str->len = tmp->len - strlen(STR_T);
  for (i = 0; i < str->len; i++)
    str->data[i] = tolower(str->data[i]);
  rule->br->str = str;
  return (NGX_CONF_OK);
}

void	*
dummy_msg(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  ngx_str_t	*str;
  
  if (!rule->br)
    return (NGX_CONF_ERROR);
  str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
  if (!str)
    return (NGX_CONF_ERROR);
  str->data = tmp->data + strlen(STR_T);
  str->len = tmp->len - strlen(STR_T);
  rule->log_msg = str;
  return (NGX_CONF_OK);
}

void	*
dummy_whitelist(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  
  ngx_array_t	*wl_ar;
  unsigned int	i, ct;
  ngx_int_t	*id;
  ngx_str_t	str;
  
  str.data = tmp->data + strlen(WHITELIST_T);
  str.len = tmp->len - strlen(WHITELIST_T);
  for (ct = 1, i = 0; i < str.len; i++)
    if (str.data[i] == ',')
      ct++;
  wl_ar = ngx_array_create(r->pool, ct, sizeof(ngx_int_t));
  if (!wl_ar)
    return (NGX_CONF_ERROR);
  NX_LOG_DEBUG(_debug_whitelist, NGX_LOG_EMERG, r, 0, "XX- allocated %d elems for WL", ct);
  for (i = 0; i < str.len; i++) {
    if (i == 0 || str.data[i-1] == ',') {
      id = (ngx_int_t *) ngx_array_push(wl_ar);
      if (!id) 
	return (NGX_CONF_ERROR);
      *id = (ngx_int_t) atoi((const char *)str.data+i);
    }
  }
  rule->wlid_array = wl_ar;
  return (NGX_CONF_OK);
}

void	*
dummy_rx(ngx_conf_t *r, ngx_str_t *tmp, ngx_http_rule_t *rule)
{
  ngx_regex_compile_t  *rgc;
  ngx_str_t	       ha;
  

  if (!rule->br)
    return (NGX_CONF_ERROR);
  //just prepare a string to hold the directive without 'rx:'
  ha.data = tmp->data+strlen(RX_T);
  ha.len = tmp->len-strlen(RX_T);
  rgc = ngx_pcalloc(r->pool, sizeof(ngx_regex_compile_t));
  if (!rgc)
    return (NGX_CONF_ERROR);
  rgc->options = PCRE_CASELESS|PCRE_MULTILINE;
  rgc->pattern = ha;
  rgc->pool = r->pool;
  rgc->err.len = 0;
  rgc->err.data = NULL;
  
  if (ngx_regex_compile(rgc) != NGX_OK) {
    NX_LOG_DEBUG(_debug_rx, NGX_LOG_EMERG, r, 0, "XX-FAILED RX:%V",
		 tmp);
      return (NGX_CONF_ERROR);
    }
  rule->br->rx = rgc;
  NX_LOG_DEBUG(_debug_rx, NGX_LOG_EMERG, r, 0, "XX- RX:[%V]",
	       &(rule->br->rx->pattern));  
  return (NGX_CONF_OK);
}

/* Parse one rule line */
/*
** in : nb elem, value array, rule to fill
** does : creates a rule struct from configuration line
** For each element name matching a tag 
** (cf. rule_parser), then call the associated func.
*/
void	*
ngx_http_dummy_cfg_parse_one_rule(ngx_conf_t *cf, 
				  ngx_str_t	*value,
				  ngx_http_rule_t *current_rule,
				  ngx_int_t	nb_elem)
{
  int	i, z;
  void  *ret;
  int	valid;

  if (!value || !value[0].data)
    return NGX_CONF_ERROR;
  /*
  ** parse basic rule
  */
  if (!ngx_strcmp(value[0].data, TOP_CHECK_RULE_T) ||
      !ngx_strcmp(value[0].data, TOP_CHECK_RULE_N) ||
      !ngx_strcmp(value[0].data, TOP_BASIC_RULE_T) ||
      !ngx_strcmp(value[0].data, TOP_BASIC_RULE_N) ||
      !ngx_strcmp(value[0].data, TOP_MAIN_BASIC_RULE_T) ||
      !ngx_strcmp(value[0].data, TOP_MAIN_BASIC_RULE_N)) {
    NX_LOG_DEBUG(_debug_cfg_parse_one_rule, NGX_LOG_EMERG, cf, 0, "XX-basic rule %V", &(value[1]));  
    current_rule->type = BR;
    current_rule->br = ngx_pcalloc(cf->pool, sizeof(ngx_http_basic_rule_t));
    if (!current_rule->br)
      return (NGX_CONF_ERROR);
  }
  else 
    {
      NX_LOG_DEBUG(_debug_cfg_parse_one_rule, NGX_LOG_EMERG, cf, 0, 
		   "XX-crit in rule %V", &(value[1]));  
      return (NGX_CONF_ERROR);
    }
  
  // check each word of config line against each rule
  for(i = 1; i < nb_elem && value[i].len > 0; i++) {
    valid = 0;
    for (z = 0; rule_parser[z].pars; z++) {
      if (!ngx_strncmp(value[i].data, 
		       rule_parser[z].prefix, 
		       strlen(rule_parser[z].prefix))) {
	ret = rule_parser[z].pars(cf, &(value[i]), 
				  current_rule);
	if (ret != NGX_CONF_OK) {
	  NX_LOG_DEBUG(_debug_cfg_parse_one_rule, NGX_LOG_EMERG, cf, 0, 
		       "XX-FAILED PARSING '%s'",
		       value[i].data);
	  return (ret);
	}
	valid = 1;
      }
    }
    if (!valid)
      return (NGX_CONF_ERROR);
  }
  /* validate the structure, and fill empty fields.*/
  if (!current_rule->log_msg)
    {
      current_rule->log_msg = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
      current_rule->log_msg->data = NULL;
      current_rule->log_msg->len = 0;
    }
  return (NGX_CONF_OK);
}


