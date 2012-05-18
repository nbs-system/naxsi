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

#ifndef __FOO_H__
#define __FOO_H__

#define NAXSI_VERSION "0.46-1"

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>
#include <ngx_md5.h>
#include <ngx_http_core_module.h>
#include <pcre.h>
#include <ctype.h>


extern ngx_module_t ngx_http_naxsi_module;

/*
** Here is globally how the structures are organized :
**
** [[ngx_http_dummy_main_conf_t]] is the main structure for the module.
** it contains the core rules and a set of ngx_http_dummy_loc_conf_t,
** for each NGINX location.
** ---
** [[ngx_http_dummy_loc_conf_t]] is the main structure for any NGINX
** locations, that is - a web site. It contains both pointers to the core
** rules, as well as whitelists, scores, denied_url and all flags. all 
** the data of a nginx location is held into the loc_conf_t struct.
** The sets of rules are actually containted into [[ngx_http_rule_t]] structs.
** ---
** [[ngx_http_rule_t]] structs are used to hold any info about a rule, as well
** as whitelists. (whitelists is just a 'kind' of rule).
**
*/

enum MATCH_TYPE {
  URI_ONLY=0,
  NAME_ONLY,
  MIXED
};

enum DUMMY_MATCH_ZONE {
  HEADERS=0,
  URL,
  ARGS,
  BODY,
  FILE_EXT,
  UNKNOWN
};


/*
** struct used to store a specific match zone
** in conf : MATCH_ZONE:[GET_VAR|HEADER|POST_VAR]:VAR_NAME:
*/
typedef struct
{
  /* match in [name] var of body */
  ngx_flag_t		body_var:1;
  /* match in [name] var of headers */
  ngx_flag_t		headers_var:1;
  /* match in [name] var of args */
  ngx_flag_t		args_var:1;
  /* match on URL [name] */
  ngx_flag_t		specific_url:1;
  ngx_str_t		target;
  ngx_uint_t		hash;
} ngx_http_custom_rule_location_t;


/*
** WhiteList Rules Definition :
** A whitelist contains :
** - an URI
**
** - one or several sets containing :
**	- an variable name ('foo') associated with a zone ($GET_VAR:foo)
**	- one or several rules id to whitelist
*/

#define WEIRD_REQUEST_INTERNAL_RULE_ID 1
#define BIG_BODY_INTERNAL_RULE_ID 2
typedef struct
{
  /* match in full body (POST DATA) */
  ngx_flag_t		body:1;
  /* match in [name] var of body */
  ngx_flag_t		body_var:1;
  /* match in all headers */
  ngx_flag_t		headers:1;
  /* match in [name] var of headers */
  ngx_flag_t		headers_var:1;
  /* match in URI */
  ngx_flag_t		url:1;
  /* match in args (bla.php?<ARGS>) */
  ngx_flag_t		args:1;
  /* match in [name] var of args */
  ngx_flag_t		args_var:1;
  /* match on a global flag : weird_request, big_body etc. */
  ngx_flag_t		flags:1;
  /* match on file upload extension */
  ngx_flag_t		file_ext:1;
  /* set if defined "custom" match zone (GET_VAR/POST_VAR/...)  */
  ngx_array_t		*ids;
  ngx_str_t		*name;
} ngx_http_whitelist_location_t;


/* 
** this struct is used to aggregate all whitelist 
** that point to the same URI or the same VARNAME 
** all the "subrules" will then be stored in the "whitelist_locations"
*/
typedef struct
{
  //ngx_http_whitelist_location_t
  ngx_array_t			*whitelist_locations; 
  // zone to wich the WL applies
  enum DUMMY_MATCH_ZONE		zone;
  // if the "name" is only an url, specify it
  int				uri_only:1;
  /* does the rule targets the name 
     instead of the content ?*/
  int				target_name;
  
  ngx_str_t			*name;
  ngx_int_t			hash;
  ngx_array_t			*ids;
} ngx_http_whitelist_rule_t;






/* basic rule */
typedef struct
{
  ngx_str_t		*str; // string
  ngx_regex_compile_t   *rx;  // or regex
  ngx_int_t		transform; //transform rule to apply, as flags.
  /* ~~~~~ match zones ~~~~~~ */
  /* match in full body (POST DATA) */
  ngx_flag_t		body:1;
  ngx_flag_t		body_var:1;
  /* match in all headers */
  ngx_flag_t		headers:1;
  ngx_flag_t		headers_var:1;
  /* match in URI */
  ngx_flag_t		url:1;
  /* match in args (bla.php?<ARGS>) */
  ngx_flag_t		args:1;
  ngx_flag_t		args_var:1;
  /* match on flags (weird_uri, big_body etc. */
  ngx_flag_t		flags:1;
  /* match on file upload extension */
  ngx_flag_t		file_ext:1;
  /* set if defined "custom" match zone (GET_VAR/POST_VAR/...)  */
  ngx_flag_t		custom_location:1;
  ngx_int_t		custom_location_only;
  /* does the rule targets variable name instead ? */
  ngx_int_t		target_name;
  
  /* custom location match zones list (GET_VAR/POST_VAR ...) */
  ngx_array_t		*custom_locations;
  /* ~~~~~~~ specific flags ~~~~~~~~~ */
  ngx_flag_t		negative:1;
} ngx_http_basic_rule_t;



/* define for RULE TYPE in rule_t */
#define BR 1 
//#define FR 2 UNUSED
//#define WR 3 UNUSED

/* flags used for 'custom match rules', like $XSS > 7 */
#define SUP 1
#define SUP_OR_EQUAL 2
#define INF 3
#define INF_OR_EQUAL 4

/*
** This struct is used to store custom scores at runtime.
**  ie : $XSS = 7
** tag is the $XSS and sc_score is 7
*/
typedef struct
{
  ngx_str_t	*sc_tag;
  ngx_int_t	sc_score;
  ngx_flag_t	block:1;
  ngx_flag_t	allow:1;
} ngx_http_special_score_t;

/*
** This one is very related to the previous one,
** it's used to store a score rule comparison.
** ie : $XSS > 7
*/
typedef struct
{
  ngx_str_t	sc_tag;
  ngx_int_t	sc_score;
  ngx_int_t	cmp;
  ngx_flag_t	block:1;
  ngx_flag_t	allow:1;
  //ngx_flag_t	log:1;  /*unused*/
} ngx_http_check_rule_t;

/* TOP level rule structure */
typedef struct
{
  /* type of the rule */
  ngx_int_t			type;
  // simply put a flag if it's a wlr, wl_id array will be used to store the whitelisted IDs
  ngx_flag_t			whitelist:1;
  ngx_int_t			*wl_id;
  /* "common" data for all rules */
  ngx_int_t			rule_id;
  ngx_str_t			*log_msg; // a specific log message
  ngx_int_t			score; //also handles DENY and ALLOW
  
  /* List of scores increased on rule match. */
  ngx_array_t			*sscores;
  /*ngx_str_t			*sc_tag; //specific score tag
    ngx_int_t			sc_score;  //specific score value*/
  ngx_flag_t			sc_block:1; //
  ngx_flag_t			sc_allow:1; //
  // end of specific score tag stuff
  ngx_flag_t			block:1;
  ngx_flag_t			allow:1;
  /* flag set if we're linked FROM or TO another rule  */
  ngx_flag_t			lnk_to:1;
  ngx_flag_t			lnk_from:1;
  /* pointers on specific rule stuff */
  ngx_http_basic_rule_t		*br;
} ngx_http_rule_t;

typedef struct
{
  ngx_array_t	*get_rules; /*ngx_http_rule_t*/
  ngx_array_t	*body_rules;
  ngx_array_t	*header_rules;
  ngx_array_t	*generic_rules; 
  ngx_array_t	*locations; /*ngx_http_dummy_loc_conf_t*/
  ngx_log_t	*log;
} ngx_http_dummy_main_conf_t;


/* TOP level configuration structure */
typedef struct
{
  ngx_array_t	*get_rules;
  ngx_array_t	*body_rules;
  ngx_array_t	*header_rules;
  ngx_array_t	*generic_rules;
  ngx_array_t	*check_rules;
  /* raw array of whitelisted rules */
  ngx_array_t   *whitelist_rules;
  /* raw array of transformed whitelists */
  ngx_array_t	*tmp_wlr;
  /* hash table of whitelisted URL rules */
  ngx_hash_t	*wlr_url_hash;
  /* hash table of whitelisted ARGS rules */
  ngx_hash_t	*wlr_args_hash;
  /* hash table of whitelisted BODY rules */
  ngx_hash_t	*wlr_body_hash;
  /* hash table of whitelisted HEADERS rules */
  ngx_hash_t	*wlr_headers_hash;
  /* rules that are globally disabled in one location */
  ngx_array_t	*disabled_rules;
  /* counters for both processed requests and
     blocked requests, used in naxsi_fmt */
  ngx_int_t	request_processed;
  ngx_int_t	request_blocked;
  ngx_int_t	error;
  ngx_array_t	*persistant_data;
  ngx_flag_t	learning:1;
  ngx_flag_t	enabled:1;
  ngx_flag_t	force_disabled:1;
  ngx_flag_t	pushed:1;
  ngx_str_t	*denied_url;
} ngx_http_dummy_loc_conf_t;


/*
** used to store sets of matched rules during runtime
*/
typedef struct
{
  /* matched in [name] var of body */
  ngx_flag_t		body_var:1;
  /* matched in [name] var of headers */
  ngx_flag_t		headers_var:1;
  /* matched in [name] var of args */
  ngx_flag_t		args_var:1;
  /* matched on URL */
  ngx_flag_t		url:1;
  /* matched within the 'NAME' */
  ngx_flag_t		target_name:1;

  ngx_str_t		*name;
  ngx_http_rule_t	*rule;
} ngx_http_matched_rule_t;

/*
** Context structure
*/
typedef struct
{
  ngx_array_t	*special_scores;
  ngx_int_t	score;
  // blocking flags
  ngx_flag_t	block:1;
  ngx_flag_t	allow:1;
  // state
  ngx_flag_t	wait_for_body:1;
  ngx_flag_t	ready:1;
  ngx_flag_t	over:1;
  // flag request
  ngx_flag_t	weird_request:1;
  ngx_flag_t	big_request:1;
  //
  // matched rules
  ngx_array_t	*matched;
} ngx_http_request_ctx_t;

#define TOP_DENIED_URL_T	"DeniedUrl"
#define TOP_LEARNING_FLAG_T	"LearningMode"
#define TOP_ENABLED_FLAG_T	"SecRulesEnabled"
#define TOP_DISABLED_FLAG_T	"SecRulesDisabled"
#define TOP_CHECK_RULE_T	"CheckRule"
#define TOP_BASIC_RULE_T	"BasicRule"
#define TOP_MAIN_BASIC_RULE_T	"MainRule"

/*possible 'tokens' in rule */
#define ID_T "id:"
#define TRANSFORM_T "t:"
#define SCORE_T "s:"
#define PERSISTANT_SCORE_T "ps:"
#define MSG_T "msg:"
#define RX_T "rx:"
#define STR_T "str:"
#define MATCH_ZONE_T "mz:"
#define WHITELIST_T "wl:"
#define NEGATIVE_T  "negative"



extern ngx_http_dummy_loc_conf_t *dummy_lc;



void		*ngx_http_dummy_cfg_parse_one_rule(ngx_conf_t *cf,
						   ngx_str_t	*value,
						   ngx_http_rule_t *rule,
						   ngx_int_t	nb_elem);
char		*strfaststr(unsigned char *haystack, unsigned int hl,
			    unsigned char *needle, unsigned int nl);
char		*strnchr(const char *s, int c, int len);
char		*strncasechr(const char *s, int c, int len);
ngx_int_t	ngx_http_dummy_create_hashtables(ngx_http_dummy_loc_conf_t *dlc,
						 ngx_conf_t *cf);
ngx_int_t	ngx_http_dummy_create_hashtables_n(ngx_http_dummy_loc_conf_t *dlc,
						 ngx_conf_t *cf);
void		ngx_http_dummy_data_parse(ngx_http_request_ctx_t *ctx, 
						  ngx_http_request_t	 *r);
ngx_int_t	ngx_http_output_forbidden_page(ngx_http_request_ctx_t *ctx, 
					       ngx_http_request_t *r);
void
naxsi_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type);

/* static ngx_int_t ngx_http_dummy_subrequest(ngx_http_request_t *r,  */
/* 					   ngx_chain_t *in); */
//ngx_int_t ngx_http_dummy_subrequest(ngx_http_request_t *r);
#endif

