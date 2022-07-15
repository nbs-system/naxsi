// SPDX-FileCopyrightText: 2022 wargio <deroad@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef __NAXSI_CONST_H__
#define __NAXSI_CONST_H__

#define NAXSI_VERSION "1.4"

/**
 * All possible keywords to be defined in nginx.cfg to setup naxsi
 */
#define NAXSI_CFG_DENIED_URL       "DeniedUrl"
#define NAXSI_CFG_LEARNING_FLAG    "LearningMode"
#define NAXSI_CFG_ENABLED_FLAG     "SecRulesEnabled"
#define NAXSI_CFG_DISABLED_FLAG    "SecRulesDisabled"
#define NAXSI_CFG_CHECK_RULE       "CheckRule"
#define NAXSI_CFG_BASIC_RULE       "BasicRule"
#define NAXSI_CFG_MAIN_BASIC_RULE  "MainRule"
#define NAXSI_CFG_LIBINJECTION_SQL "LibInjectionSql"
#define NAXSI_CFG_LIBINJECTION_XSS "LibInjectionXss"

/**
 * All possible arguments of BasicRule/MainRule
 */
#define NAXSI_RULE_ID         "id:"
#define NAXSI_RULE_SCORE      "s:"
#define NAXSI_RULE_MSG        "msg:"
#define NAXSI_RULE_RX         "rx:"
#define NAXSI_RULE_STR        "str:"
#define NAXSI_RULE_MATCH_ZONE "mz:"
#define NAXSI_RULE_WHITELIST  "wl:"
#define NAXSI_RULE_LIBINJ_XSS "d:libinj_xss"
#define NAXSI_RULE_LIBINJ_SQL "d:libinj_sql"
#define NAXSI_RULE_NEGATIVE   "negative"

#if defined nginx_version && (nginx_version >= 1021005)
// after 1.21.5 NGX_REGEX_MULTILINE is present.
#define NAXSI_REGEX_OPTIONS (NGX_REGEX_CASELESS | NGX_REGEX_MULTILINE)
#else
#if (NGX_PCRE2)
#define NAXSI_REGEX_OPTIONS (PCRE2_CASELESS | PCRE2_MULTILINE)
#else
#define NAXSI_REGEX_OPTIONS (PCRE_CASELESS | PCRE_MULTILINE)
#endif
#endif

#endif /* __NAXSI_CONST_H__ */
