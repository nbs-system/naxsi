// SPDX-FileCopyrightText: 2022 wargio <deroad@libero.it>
// SPDX-FileCopyrightText: 2016-2019, Thibault 'bui' Koechlin <tko@nbs-system.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef __NAXSI_H__
#define __NAXSI_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>
#include <ngx_md5.h>

#include <ctype.h>

#include <naxsi_const.h>

#include "libinjection/src/libinjection_sqli.h"
#include "libinjection/src/libinjection_xss.h"

extern ngx_module_t ngx_http_naxsi_module;

/**
 * Enable this to debug naxsi
 */
#define _debug_naxsi_logs 0

/*
** as the #ifdef #endif for debug are getting really messy ...
** Bellow are all the possibles debug defines. To enable associated feature
** debug, just set it to 1. Do not comment the actual define except if you
** know all the associated debug calls are deleted.
** The idea is that the compiler will optimize out the do { if (0) ... } while
*(0);
*/

#define _debug_basestr_ruleset    0
#define _debug_custom_score       0
#define _debug_body_parse         0
#define _debug_cfg_parse_one_rule 0
#define _debug_zone               0
#define _debug_extensive_log      0
#define _debug_loc_conf           0
#define _debug_main_conf          0
#define _debug_mechanics          0
#define _debug_json               0
#define _debug_modifier           0
#define _debug_payload_handler    0
#define _debug_post_heavy         0
#define _debug_rawbody            0
#define _debug_readconf           0
#define _debug_rx                 0
#define _debug_score              0
#define _debug_spliturl_ruleset   0
#define _debug_whitelist_compat   0
#define _debug_whitelist          0
#define _debug_whitelist_heavy    0
#define _debug_whitelist_light    0
#define _debug_whitelist_ignore   0
#define _debug_libinj_sqli        0
#define _debug_libinj_xss         0
#define _debug_wl_debug_rx        0

#if _debug_naxsi_logs
#define NX_DEBUG(FEATURE, DEF, LOG, ST, ...)                                                       \
  do {                                                                                             \
    if (FEATURE)                                                                                   \
      ngx_log_debug(DEF, LOG, ST, __VA_ARGS__);                                                    \
  } while (0)
#define NX_LOG_DEBUG(FEATURE, DEF, LOG, ST, ...)                                                   \
  do {                                                                                             \
    if (FEATURE)                                                                                   \
      ngx_conf_log_error(DEF, LOG, ST, __VA_ARGS__);                                               \
  } while (0)
#else
#define NX_DEBUG(FEATURE, DEF, LOG, ST, ...)
#define NX_LOG_DEBUG(FEATURE, DEF, LOG, ST, ...)
#endif

/*
** Here is globally how the structures are organized :
**
** [[ngx_http_naxsi_main_conf_t]] is the main structure for the module.
** it contains the core rules and a set of ngx_http_naxsi_loc_conf_t,
** for each NGINX location.
** ---
** [[ngx_http_naxsi_loc_conf_t]] is the main structure for any NGINX
** locations, that is - a web site. It contains both pointers to the core
** rules, as well as whitelists, scores, denied_url and all flags. all
** the data of a nginx location is held into the loc_conf_t struct.
** The sets of rules are actually containted into [[ngx_http_rule_t]] structs.
** ---
** [[ngx_http_rule_t]] structs are used to hold any info about a rule, as well
** as whitelists. (whitelists is just a 'kind' of rule).
**
*/

/*
** basic rule can have 4 (so far) kind of matching mechanisms
** RX
** STR
** LIBINJ_XSS
** LIBINJ_SQL
*/

typedef enum DETECT_MECHANISM
{
  NONE = -1,
  RX,
  STR,
  LIBINJ_XSS,
  LIBINJ_SQL
} naxsi_detect_mechanism_t;

typedef enum MATCH_TYPE
{
  URI_ONLY = 0,
  NAME_ONLY,
  MIXED
} naxsi_match_type_t;

typedef enum NAXSI_MATCH_ZONE
{
  HEADERS = 0,
  URL,
  ARGS,
  BODY,
  RAW_BODY,
  FILE_EXT,
  UNKNOWN
} naxsi_match_zone_t;

/*
** struct used to store a specific match zone
** in conf : MATCH_ZONE:[GET_VAR|HEADER|POST_VAR]:VAR_NAME:
*/
typedef struct
{
  /* match in [name] var of body */
  ngx_flag_t body_var : 1;
  /* match in [name] var of headers */
  ngx_flag_t headers_var : 1;
  /* match in [name] var of args */
  ngx_flag_t args_var : 1;
  /* match on URL [name] */
  ngx_flag_t specific_url : 1;
  ngx_str_t  target;
  /* to be used for regexed match zones */
  ngx_regex_compile_t* target_rx;
  ngx_uint_t           hash;

} ngx_http_custom_rule_location_t;

/*
** WhiteList Rules Definition :
** A whitelist contains :
** - an URI
**
** - one or several sets containing :
**  - an variable name ('foo') associated with a zone ($GET_VAR:foo)
**  - one or several rules id to whitelist
*/

typedef struct
{
  /* match in full body (POST DATA) */
  ngx_flag_t body : 1;
  /* match in [name] var of body */
  ngx_flag_t body_var : 1;
  /* match in all headers */
  ngx_flag_t headers : 1;
  /* match in [name] var of headers */
  ngx_flag_t headers_var : 1;
  /* match in URI */
  ngx_flag_t url : 1;
  /* match in args (bla.php?<ARGS>) */
  ngx_flag_t args : 1;
  /* match in [name] var of args */
  ngx_flag_t args_var : 1;
  /* match on a global flag : weird_request, big_body etc. */
  ngx_flag_t flags : 1;
  /* match on file upload extension */
  ngx_flag_t file_ext : 1;
  /* set if defined "custom" match zone (GET_VAR/POST_VAR/...)  */
  ngx_array_t* ids;
  ngx_str_t*   name;
} ngx_http_whitelist_location_t;

/*
** this struct is used to aggregate all whitelist
** that point to the same URI or the same VARNAME
** all the "subrules" will then be stored in the "whitelist_locations"
*/
typedef struct
{
  /*ngx_http_whitelist_location_t **/
  ngx_array_t* whitelist_locations;
  /* zone to wich the WL applies */
  naxsi_match_zone_t zone;
  /* if the "name" is only an url, specify it */
  int uri_only : 1;
  /* does the rule targets the name
     instead of the content ?*/
  int target_name;

  ngx_str_t*   name;
  ngx_int_t    hash;
  ngx_array_t* ids;
} ngx_http_whitelist_rule_t;

/* basic rule */
typedef struct
{
  ngx_str_t*           str; // string
  ngx_regex_compile_t* rx;  // or regex
  /*
  ** basic rule can have 4 (so far) kind of matching mechanisms :
  ** RX, STR, LIBINJ_XSS, LIBINJ_SQL
  */
  naxsi_detect_mechanism_t match_type;
  /* is the match zone a regex or a string (hashtable) */
  ngx_int_t rx_mz;
  /* ~~~~~ match zones ~~~~~~ */
  ngx_int_t zone;
  /* match in full body (POST DATA) */
  ngx_flag_t body_rule : 1;
  ngx_flag_t body : 1;
  ngx_flag_t raw_body : 1;
  ngx_flag_t body_var : 1;
  /* match in all headers */
  ngx_flag_t headers : 1;
  ngx_flag_t headers_var : 1;
  /* match in URI */
  ngx_flag_t url : 1;
  /* match in args (bla.php?<ARGS>) */
  ngx_flag_t args : 1;
  ngx_flag_t args_var : 1;
  /* match on flags (weird_uri, big_body etc. */
  ngx_flag_t flags : 1;
  /* match on file upload extension */
  ngx_flag_t file_ext : 1;
  /* set if defined "custom" match zone (GET_VAR/POST_VAR/...)  */
  ngx_flag_t custom_location : 1;
  ngx_int_t  custom_location_only;
  /* does the rule targets variable name instead ? */
  ngx_int_t target_name;

  /* custom location match zones list (GET_VAR/POST_VAR ...) */
  ngx_array_t* custom_locations;
  /* ~~~~~~~ specific flags ~~~~~~~~~ */
  ngx_flag_t negative : 1;
} ngx_http_basic_rule_t;

/* define for RULE TYPE in rule_t */
#define BR 1

/* flags used for 'custom match rules', like $XSS > 7 */
#define SUP          1
#define SUP_OR_EQUAL 2
#define INF          3
#define INF_OR_EQUAL 4

/*
** This struct is used to store custom scores at runtime.
**  ie : $XSS = 7
** tag is the $XSS and sc_score is 7
*/
typedef struct
{
  ngx_str_t* sc_tag;
  ngx_int_t  sc_score;
  ngx_flag_t block : 1;
  ngx_flag_t allow : 1;
  ngx_flag_t drop : 1;
  ngx_flag_t log : 1;
} ngx_http_special_score_t;

/*
** This one is very related to the previous one,
** it's used to store a score rule comparison.
** ie : $XSS > 7
*/
typedef struct
{
  ngx_str_t  sc_tag;
  ngx_int_t  sc_score;
  ngx_int_t  cmp;
  ngx_flag_t block : 1;
  ngx_flag_t allow : 1;
  ngx_flag_t drop : 1;
  ngx_flag_t log : 1;
} ngx_http_check_rule_t;

/* TOP level rule structure */
typedef struct
{
  /* type of the rule */
  ngx_int_t type;
  /* simply put a flag if it's a wlr,
     wl_id array will be used to store the whitelisted IDs */
  ngx_flag_t   whitelist : 1;
  ngx_array_t* wlid_array;
  /* "common" data for all rules */
  ngx_int_t  rule_id;
  ngx_str_t* log_msg; // a specific log message
  ngx_int_t  score;   // also handles DENY and ALLOW

  /* List of scores increased on rule match. */
  ngx_array_t* sscores;
  ngx_flag_t   sc_block : 1; //
  ngx_flag_t   sc_allow : 1; //
  // end of specific score tag stuff
  ngx_flag_t block : 1;
  ngx_flag_t allow : 1;
  ngx_flag_t drop : 1;
  ngx_flag_t log : 1;
  /* pointers on specific rule stuff */
  ngx_http_basic_rule_t* br;
} ngx_http_rule_t;

typedef struct
{
  ngx_array_t* get_rules; /*ngx_http_rule_t*/
  ngx_array_t* body_rules;
  ngx_array_t* header_rules;
  ngx_array_t* generic_rules;
  ngx_array_t* raw_body_rules;

  ngx_array_t* locations; /*ngx_http_naxsi_loc_conf_t*/

} ngx_http_naxsi_main_conf_t;

/* TOP level configuration structure */
typedef struct
{
  /*
  ** basicrule / mainrules, sorted by target zone
  */
  ngx_array_t* get_rules;
  ngx_array_t* body_rules;
  ngx_array_t* raw_body_rules;
  ngx_array_t* header_rules;
  ngx_array_t* generic_rules;
  ngx_array_t* check_rules;
  /* raw array of whitelisted rules */
  ngx_array_t* whitelist_rules;
  /* raw array of transformed whitelists */
  ngx_array_t* tmp_wlr;
  /* raw array of regex-mz whitelists */
  ngx_array_t* rxmz_wlr;
  /* hash table of whitelisted URL rules */
  ngx_hash_t* wlr_url_hash;
  /* hash table of whitelisted ARGS rules */
  ngx_hash_t* wlr_args_hash;
  /* hash table of whitelisted BODY rules */
  ngx_hash_t* wlr_body_hash;
  /* hash table of whitelisted HEADERS rules */
  ngx_hash_t* wlr_headers_hash;
  /* hash table of ips to ignore */
  ngx_hash_t*            ignore_ips;
  ngx_hash_keys_arrays_t ignore_ips_ha;
  /* raw array  of cidrs to ignore */
  ngx_array_t* ignore_cidrs;
  /* rules that are globally disabled in one location */
  ngx_array_t* disabled_rules;
  /* counters for both processed requests and
     blocked requests, used in naxsi_fmt */
  size_t       request_processed;
  size_t       request_blocked;
  ngx_int_t    error;
  ngx_array_t* persistant_data;
  ngx_flag_t   extensive : 1;
  ngx_flag_t   learning : 1;
  ngx_flag_t   enabled : 1;
  ngx_flag_t   force_disabled : 1;
  ngx_flag_t   pushed : 1;
  ngx_flag_t   libinjection_sql_enabled : 1;
  ngx_flag_t   libinjection_xss_enabled : 1;
  ngx_str_t*   denied_url;
  /* precomputed hash for dynamic variable lookup,
     variable themselves are boolean */
  ngx_uint_t flag_enable_h;
  ngx_uint_t flag_learning_h;
  ngx_uint_t flag_post_action_h;
  ngx_uint_t flag_extensive_log_h;
  ngx_uint_t flag_json_log_h;
  /* precomputed hash for
     libinjection dynamic flags */
  ngx_uint_t flag_libinjection_xss_h;
  ngx_uint_t flag_libinjection_sql_h;
  ngx_log_t* log;

} ngx_http_naxsi_loc_conf_t;

/*
** used to store sets of matched rules during runtime
*/
typedef struct
{
  /* matched in [name] var of body */
  ngx_flag_t body_var : 1;
  /* matched in [name] var of headers */
  ngx_flag_t headers_var : 1;
  /* matched in [name] var of args */
  ngx_flag_t args_var : 1;
  /* matched on URL */
  ngx_flag_t url : 1;
  /* matched in filename [name] of args*/
  ngx_flag_t file_ext : 1;
  /* matched within the 'NAME' */
  ngx_flag_t target_name : 1;

  ngx_str_t*       name;
  ngx_http_rule_t* rule;
} ngx_http_matched_rule_t;

/*
** Context structure
*/
typedef struct
{
  ngx_array_t* special_scores;
  ngx_int_t    score;
  /* blocking flags */
  ngx_flag_t log : 1;
  ngx_flag_t block : 1;
  ngx_flag_t allow : 1;
  ngx_flag_t drop : 1;
  ngx_flag_t ignore : 1;
  /* state */
  ngx_flag_t wait_for_body : 1;
  ngx_flag_t ready : 1;
  ngx_flag_t over : 1;
  /* matched rules */
  ngx_array_t* matched;
  /* runtime flags (modifiers) */
  ngx_flag_t learning : 1;
  ngx_flag_t enabled : 1;
  ngx_flag_t post_action : 1;
  ngx_flag_t extensive_log : 1;
  ngx_flag_t json_log : 1;
  /* did libinjection sql/xss matched ? */
  ngx_flag_t libinjection_sql : 1;
  ngx_flag_t libinjection_xss : 1;
} ngx_http_request_ctx_t;

/*
** this structure is used only for json parsing.
*/
typedef struct ngx_http_nx_json_s
{
  ngx_str_t                   json;
  u_char*                     src;
  ngx_int_t                   off, len;
  u_char                      c;
  int                         depth;
  ngx_http_request_t*         r;
  ngx_http_request_ctx_t*     ctx;
  ngx_str_t                   ckey;
  ngx_http_naxsi_main_conf_t* main_cf;
  ngx_http_naxsi_loc_conf_t*  loc_cf;
} ngx_json_t;

#define TOP_DENIED_URL_T       "DeniedUrl"
#define TOP_IGNORE_IP_T        "IgnoreIP"
#define TOP_IGNORE_CIDR_T      "IgnoreCIDR"
#define TOP_LEARNING_FLAG_T    "LearningMode"
#define TOP_ENABLED_FLAG_T     "SecRulesEnabled"
#define TOP_DISABLED_FLAG_T    "SecRulesDisabled"
#define TOP_CHECK_RULE_T       "CheckRule"
#define TOP_BASIC_RULE_T       "BasicRule"
#define TOP_MAIN_BASIC_RULE_T  "MainRule"
#define TOP_LIBINJECTION_SQL_T "LibInjectionSql"
#define TOP_LIBINJECTION_XSS_T "LibInjectionXss"
#define TOP_NAXSI_LOGFILE_T    "NaxsiLogFile"

/* nginx-style names */
#define TOP_DENIED_URL_N       "denied_url"
#define TOP_IGNORE_IP_N        "ignore_ip"
#define TOP_IGNORE_CIDR_N      "ignore_cidr"
#define TOP_LEARNING_FLAG_N    "learning_mode"
#define TOP_ENABLED_FLAG_N     "rules_enabled"
#define TOP_DISABLED_FLAG_N    "rules_disabled"
#define TOP_CHECK_RULE_N       "check_rule"
#define TOP_BASIC_RULE_N       "basic_rule"
#define TOP_MAIN_BASIC_RULE_N  "main_rule"
#define TOP_LIBINJECTION_SQL_N "libinjection_sql"
#define TOP_LIBINJECTION_XSS_N "libinjection_xss"
#define TOP_NAXSI_LOGFILE_N    "naxsi_log"

/*possible 'tokens' in rule */
#define ID_T         "id:"
#define SCORE_T      "s:"
#define MSG_T        "msg:"
#define RX_T         "rx:"
#define STR_T        "str:"
#define MATCH_ZONE_T "mz:"
#define WHITELIST_T  "wl:"
#define LIBINJ_XSS_T "d:libinj_xss"
#define LIBINJ_SQL_T "d:libinj_sql"
#define NEGATIVE_T   "negative"

/*
** name of hardcoded variables to
** change behavior of naxsi at runtime
*/
#define RT_EXTENSIVE_LOG    "naxsi_extensive_log"
#define RT_JSON_LOG         "naxsi_json_log"
#define RT_ENABLE           "naxsi_flag_enable"
#define RT_LEARNING         "naxsi_flag_learning"
#define RT_POST_ACTION      "naxsi_flag_post_action"
#define RT_LIBINJECTION_SQL "naxsi_flag_libinjection_sql"
#define RT_LIBINJECTION_XSS "naxsi_flag_libinjection_xss"

/*
** To avoid getting DoS'ed, define max depth
** for JSON parser, as it is recursive
*/
#define JSON_MAX_DEPTH 10

void*
ngx_http_naxsi_cfg_parse_one_rule(ngx_conf_t*      cf,
                                  ngx_str_t*       value,
                                  ngx_http_rule_t* rule,
                                  ngx_int_t        nb_elem);

char*
strfaststr(const unsigned char* haystack,
           unsigned int         hl,
           const unsigned char* needle,
           unsigned int         nl);

#define sstrfaststr(h, hl, n, nl)                                                                  \
  strfaststr(                                                                                      \
    (const unsigned char*)(h), (unsigned int)(hl), (const unsigned char*)(n), (unsigned int)(nl));

char*
strnchr(const char* s, int c, int len);

ngx_int_t
ngx_http_naxsi_create_hashtables_n(ngx_http_naxsi_loc_conf_t* dlc, ngx_conf_t* cf);

void
ngx_http_naxsi_data_parse(ngx_http_request_ctx_t* ctx, ngx_http_request_t* r);

ngx_int_t
ngx_http_output_forbidden_page(ngx_http_request_ctx_t* ctx, ngx_http_request_t* r);

int
nx_check_ids(ngx_int_t match_id, ngx_array_t* wl_ids);

int
naxsi_unescape(ngx_str_t* str);

u_int
naxsi_escape_nullbytes(ngx_str_t* str);

void
ngx_http_naxsi_json_parse(ngx_http_request_ctx_t* ctx,
                          ngx_http_request_t*     r,
                          u_char*                 src,
                          u_int                   len);

void
ngx_http_libinjection(ngx_pool_t*             pool,
                      ngx_str_t*              name,
                      ngx_str_t*              value,
                      ngx_http_request_ctx_t* ctx,
                      ngx_http_request_t*     req,
                      naxsi_match_zone_t      zone);
/*
** JSON parsing prototypes.
*/
ngx_int_t
ngx_http_nx_json_forward(ngx_json_t* js);
ngx_int_t
ngx_http_nx_json_seek(ngx_json_t* js, unsigned char seek);
ngx_int_t
ngx_http_nx_json_quoted(ngx_json_t* js, ngx_str_t* ve);
ngx_int_t
ngx_http_nx_json_array(ngx_json_t* js);
ngx_int_t
ngx_http_nx_json_val(ngx_json_t* js);
ngx_int_t
ngx_http_nx_json_obj(ngx_json_t* js);

/*
** naxsi_runtime
**
*/

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

int
ngx_http_apply_rulematch_v_n(ngx_http_rule_t*        r,
                             ngx_http_request_ctx_t* ctx,
                             ngx_http_request_t*     req,
                             ngx_str_t*              name,
                             ngx_str_t*              value,
                             naxsi_match_zone_t      zone,
                             ngx_int_t               nb_match,
                             ngx_int_t               target_name);

/*
** externs for internal rules that requires it.
*/
extern ngx_http_rule_t* nx_int__libinject_sql;
extern ngx_http_rule_t* nx_int__libinject_xss;

/*libinjection_xss wrapper not exported by libinject_xss.h.*/
int
libinjection_xss(const char* s, size_t len);

#endif /* __NAXSI_H__ */
