/*
 * NAXSI, a web application firewall for NGINX
 * Copyright (C) NBS System – All Rights Reserved
 * Licensed under GNU GPL v3.0 – See the LICENSE notice for details
 */

#ifndef __NAXSI_MACROS_H__
#define __NAXSI_MACROS_H__

#define is_whitespace(c) ((c) == ' ' || (c) == '\t' || (c) == '\n' || (c) == '\r')
#define is_printable(c)  ((c) >= ' ' && (c) <= '~')
#define is_numeric(c)    ((c) >= '0' && (c) <= '9')
#define const_len(s)     (sizeof(s) - sizeof(s[0]))

#define return_value_if(cond, val)                                                                 \
  if ((cond))                                                                                      \
  return (val)
#define return_void_if(cond)                                                                       \
  if ((cond))                                                                                      \
  return
#define break_if(cond)                                                                             \
  if ((cond))                                                                                      \
  break

#endif /* __NAXSI_MACROS_H__ */
