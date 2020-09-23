/*
 * NAXSI, a web application firewall for NGINX
 * Copyright (C) NBS System – All Rights Reserved
 * Licensed under GNU GPL v3.0 – See the LICENSE notice for details
 */

#ifndef __NAXSI_CONFIG_H__
#define __NAXSI_CONFIG_H__

/* custom match  zones */
#define MZ_GET_VAR_T      "$ARGS_VAR:"
#define MZ_HEADER_VAR_T   "$HEADERS_VAR:"
#define MZ_POST_VAR_T     "$BODY_VAR:"
#define MZ_SPECIFIC_URL_T "$URL:"

/* add support for regex-style match zones.
** this whole function should be rewritten as it's getting
** messy as hell
*/
#define MZ_GET_VAR_X      "$ARGS_VAR_X:"
#define MZ_HEADER_VAR_X   "$HEADERS_VAR_X:"
#define MZ_POST_VAR_X     "$BODY_VAR_X:"
#define MZ_SPECIFIC_URL_X "$URL_X:"

#endif /* __NAXSI_CONFIG_H__ */
